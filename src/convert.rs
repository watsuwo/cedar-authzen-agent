use std::str::FromStr;

use cedar_policy::{
    Context, Entities, EntityId, EntityTypeName, EntityUid, Policy, PolicyId, PolicySet, Request,
    Schema,
};
use serde_json::{json, Map, Value};
use thiserror::Error;
use tracing::warn;

use crate::authzen::EvaluationRequest;

const ACTION_TYPE: &str = "Action";
// レスポンスにcontextを付与するためにポリシーに付与するアノテーションのprefix
const DECISION_CONTEXT_PREFIX: &str = "decision_context_";
// 監査ログ・優先度のタイブレークに使う可読idのアノテーション
const ID_ANNOTATION: &str = "id";
// 決定ポリシーが複数あるときにcontextの出所を選ぶためのアノテーション
pub const PRIORITY_ANNOTATION: &str = "priority";
// @priority 未指定のポリシーの優先度(値が小さいほど優先)
const LOWEST_PRIORITY: u32 = u32::MAX;

#[derive(Debug, Error)]
pub enum ConversionError {
    #[error("invalid entity reference: {0}")]
    Entity(String),
    #[error("invalid context: {0}")]
    Context(String),
    #[error("invalid properties: {0}")]
    Properties(String),
    #[error("invalid request: {0}")]
    Request(String),
}

impl ConversionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Entity(_) => "invalid_entity",
            Self::Context(_) => "invalid_context",
            Self::Properties(_) => "invalid_properties",
            Self::Request(_) => "invalid_request",
        }
    }
}

//  CedarのEntityIdを生成する
fn entity_uid(entity_type: &str, id: &str) -> Result<EntityUid, ConversionError> {
    let type_name = EntityTypeName::from_str(entity_type)
        .map_err(|e| ConversionError::Entity(format!("type `{entity_type}`: {e}")))?;
    let entity_id =
        EntityId::from_str(id).map_err(|e| ConversionError::Entity(format!("id `{id}`: {e}")))?;
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
}

// Entity生成用の中間処理
// 生成したEntityId とpropertiesをJSONに変換する
fn entity_json(entity_type: &str, id: &str, properties: &Map<String, Value>) -> Value {
    json!({
        "uid": { "type": entity_type, "id": id },
        "attrs": properties,
        "parents": [],
    })
}

// AuthZEN リクエストをCedarに変換する
pub fn to_cedar(
    req: &EvaluationRequest,
    schema: &Schema,
) -> Result<(Request, Entities), ConversionError> {
    let principal = entity_uid(&req.subject.entity_type, &req.subject.id)?;
    let action = entity_uid(ACTION_TYPE, &req.action.name)?;
    let resource = entity_uid(&req.resource.entity_type, &req.resource.id)?;

    let context = match &req.context {
        Some(value) => Context::from_json_value(value.clone(), Some((schema, &action)))
            .map_err(|e| ConversionError::Context(e.to_string()))?,
        None => Context::empty(),
    };

    let request = Request::new(principal, action, resource, context, Some(schema))
        .map_err(|e| ConversionError::Request(e.to_string()))?;

    let empty = Map::new();
    let subject_props = req.subject.properties.as_ref().unwrap_or(&empty);
    let mut entity_values = vec![entity_json(
        &req.subject.entity_type,
        &req.subject.id,
        subject_props,
    )];
    if let Some(props) = req.resource.properties.as_ref().filter(|p| !p.is_empty()) {
        entity_values.push(entity_json(
            &req.resource.entity_type,
            &req.resource.id,
            props,
        ));
    }

    let entities = Entities::from_json_value(Value::Array(entity_values), Some(schema))
        .map_err(|e| ConversionError::Properties(e.to_string()))?;

    Ok((request, entities))
}

// ポリシーの可読id。@id が無ければ内部id(policy0 等)にフォールバックする
pub fn display_id(policy: &Policy) -> String {
    policy
        .annotation(ID_ANNOTATION)
        .map(str::to_string)
        .unwrap_or_else(|| policy.id().to_string())
}

// @priority の値。非負整数のみ有効で、それ以外は不正値として None を返す
pub fn parse_priority(raw: &str) -> Option<u32> {
    raw.parse::<u32>().ok()
}

// ポリシーの優先度。値が小さいほど優先、未指定は最低優先度
fn priority_of(policy: &Policy) -> u32 {
    let Some(raw) = policy.annotation(PRIORITY_ANNOTATION) else {
        return LOWEST_PRIORITY;
    };
    parse_priority(raw).unwrap_or_else(|| {
        // 不正値はロード時に弾いているため通常は到達しない
        warn!(
            policy_id = %display_id(policy),
            "invalid `@priority` value {raw:?}; treating as lowest priority"
        );
        LOWEST_PRIORITY
    })
}

// アノテーションで定義されているdecision用のcontextを生成する。
// 決定ポリシーが複数ある場合は最優先の1件だけを採用し、キー単位のマージはしない
// (文言と次アクションの出所を1ポリシーに揃えるため)。
pub fn to_decision_context(
    policy_set: &PolicySet,
    reason_ids: &[&PolicyId],
) -> Option<(String, Map<String, Value>)> {
    let winner = reason_ids
        .iter()
        .filter_map(|id| policy_set.policy(id))
        .min_by(|a, b| {
            priority_of(a)
                .cmp(&priority_of(b))
                // 同値は @id の文字列順で先勝ち
                .then_with(|| display_id(a).cmp(&display_id(b)))
        })?;

    let mut context = Map::new();
    for (key, value) in winner.annotations() {
        insert_decision_context(&mut context, winner.id(), key, value);
    }

    // 0件ならcontextは付与しない(下位のポリシーにはフォールバックしない)
    (!context.is_empty()).then(|| (display_id(winner), context))
}

// PDP が予約するフィールド。作者の `@decision_context_*` と衝突した場合はこちらで上書きする。
const RESERVED_REASON_KEY: &str = "reason";
const RESERVED_ERRORS_KEY: &str = "errors";

// アノテーション由来の context に、cedar-local-agent の応答情報（determining policies の
// `reason`、評価エラーの `errors`）を予約フィールドとしてマージする。
// どちらも該当が空なら付与しない。全て空なら context 自体を省略する（None）。
pub fn build_context(
    annotation_context: Option<Map<String, Value>>,
    reason: &[String],
    errors: &[String],
) -> Option<Map<String, Value>> {
    let mut context = annotation_context.unwrap_or_default();

    if !reason.is_empty() {
        insert_reserved(&mut context, RESERVED_REASON_KEY, string_array(reason));
    }
    if !errors.is_empty() {
        insert_reserved(&mut context, RESERVED_ERRORS_KEY, string_array(errors));
    }

    (!context.is_empty()).then_some(context)
}

fn string_array(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

// 予約キーは PDP 値を優先する。作者アノテーションを上書きした場合は warn を残す。
fn insert_reserved(context: &mut Map<String, Value>, key: &str, value: Value) {
    if context.insert(key.to_string(), value).is_some() {
        warn!(
            context_key = key,
            "PDP-reserved context key overwrote an author `@decision_context_` annotation"
        );
    }
}

fn insert_decision_context(
    context: &mut Map<String, Value>,
    id: &PolicyId,
    key: &str,
    value: &str,
) {
    let Some(context_key) = key.strip_prefix(DECISION_CONTEXT_PREFIX) else {
        return;
    };

    // キー名が空の場合は設定不備のため無視する
    if context_key.is_empty() {
        warn!(
            policy_id = %id,
            "ignoring `@decision_context_` annotation without a context key"
        );
        return;
    }

    // 採用するのは単一ポリシーで、Cedar は同一ポリシー内のキー重複を許さないため衝突しない
    context.insert(context_key.to_string(), Value::String(value.to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_set(src: &str) -> PolicySet {
        PolicySet::from_str(src).expect("test policy set should parse")
    }

    // `@id` の値からポリシー id を引く（内部 id `policy0` 等に依存しない）
    fn find_id<'a>(ps: &'a PolicySet, name: &str) -> &'a PolicyId {
        ps.policies()
            .find(|p| p.annotation("id") == Some(name))
            .map(|p| p.id())
            .unwrap_or_else(|| panic!("policy `{name}` not found"))
    }

    // 採用ポリシーの `@id` と context をまとめて検証するためのヘルパ
    fn context_of(ps: &PolicySet, reason: &[&PolicyId]) -> (String, Map<String, Value>) {
        to_decision_context(ps, reason).expect("context should be present")
    }

    fn string(value: &str) -> Option<Value> {
        Some(Value::String(value.into()))
    }

    #[test]
    fn maps_prefixed_annotations_to_context() {
        let ps = policy_set(
            r#"
            @id("deny-admins")
            @decision_context_reason_user("additional authentication required")
            @decision_context_step_up("mfa")
            forbid(principal, action, resource);
            "#,
        );
        let reason = [find_id(&ps, "deny-admins")];

        let (policy_id, context) = context_of(&ps, &reason);
        assert_eq!(policy_id, "deny-admins");
        assert_eq!(
            context.get("reason_user").cloned(),
            string("additional authentication required")
        );
        assert_eq!(context.get("step_up").cloned(), string("mfa"));
        assert_eq!(context.len(), 2, "`@id` must not leak into the context");
    }

    #[test]
    fn returns_none_without_matching_annotations() {
        let ps = policy_set(
            r#"
            @id("allow-all")
            permit(principal, action, resource);
            "#,
        );
        let reason = [find_id(&ps, "allow-all")];

        // `@id` しか付いていないポリシー、および reason が空のケースは共に None。
        assert_eq!(to_decision_context(&ps, &reason), None);
        assert_eq!(to_decision_context(&ps, &[]), None);
    }

    #[test]
    fn lower_priority_value_wins() {
        let ps = policy_set(
            r#"
            @id("routine")
            @priority("10")
            @decision_context_reason_user("from routine")
            @decision_context_step_up("external-auth")
            forbid(principal, action, resource);

            @id("urgent")
            @priority("1")
            @decision_context_reason_user("from urgent")
            forbid(principal, action, resource);
            "#,
        );
        // 渡す順に関わらず @priority が小さい "urgent" が勝つ。
        let reason = [find_id(&ps, "routine"), find_id(&ps, "urgent")];

        let (policy_id, context) = context_of(&ps, &reason);
        assert_eq!(policy_id, "urgent");
        assert_eq!(context.get("reason_user").cloned(), string("from urgent"));
        // 採用は 1 ポリシーのみ。下位ポリシー固有のキーはマージされない。
        assert_eq!(context.get("step_up"), None);
        assert_eq!(context.len(), 1);
    }

    #[test]
    fn missing_priority_is_lowest() {
        let ps = policy_set(
            r#"
            @id("aaa-no-priority")
            @decision_context_reason_user("from no-priority")
            forbid(principal, action, resource);

            @id("zzz-with-priority")
            @priority("50")
            @decision_context_reason_user("from priority-50")
            forbid(principal, action, resource);
            "#,
        );
        // @id 順では "aaa-*" が先だが、@priority 指定のある方が優先される。
        let reason = [
            find_id(&ps, "aaa-no-priority"),
            find_id(&ps, "zzz-with-priority"),
        ];

        let (policy_id, context) = context_of(&ps, &reason);
        assert_eq!(policy_id, "zzz-with-priority");
        assert_eq!(
            context.get("reason_user").cloned(),
            string("from priority-50")
        );
    }

    #[test]
    fn equal_priority_falls_back_to_id_order() {
        let ps = policy_set(
            r#"
            @id("second")
            @priority("10")
            @decision_context_reason_user("from second")
            forbid(principal, action, resource);

            @id("first")
            @priority("10")
            @decision_context_reason_user("from first")
            forbid(principal, action, resource);
            "#,
        );
        let reason = [find_id(&ps, "second"), find_id(&ps, "first")];

        let (policy_id, context) = context_of(&ps, &reason);
        assert_eq!(policy_id, "first");
        assert_eq!(context.get("reason_user").cloned(), string("from first"));
    }

    #[test]
    fn winner_without_context_annotations_yields_none() {
        let ps = policy_set(
            r#"
            @id("silent-urgent")
            @priority("1")
            forbid(principal, action, resource);

            @id("verbose-routine")
            @priority("10")
            @decision_context_reason_user("from routine")
            forbid(principal, action, resource);
            "#,
        );
        let reason = [
            find_id(&ps, "silent-urgent"),
            find_id(&ps, "verbose-routine"),
        ];

        // 最優先ポリシーが無注釈なら、下位ポリシーにフォールバックせず context を省略する。
        assert_eq!(to_decision_context(&ps, &reason), None);
    }

    #[test]
    fn priority_annotation_is_not_exposed() {
        let ps = policy_set(
            r#"
            @id("with-priority")
            @priority("1")
            @decision_context_reason_user("shown")
            forbid(principal, action, resource);
            "#,
        );
        let reason = [find_id(&ps, "with-priority")];

        let (_, context) = context_of(&ps, &reason);
        assert_eq!(context.get("priority"), None);
        assert_eq!(context.len(), 1);
    }

    #[test]
    fn parses_only_non_negative_integers_as_priority() {
        assert_eq!(parse_priority("0"), Some(0));
        assert_eq!(parse_priority("1"), Some(1));
        assert_eq!(parse_priority("4294967295"), Some(u32::MAX));

        // 値なし `@priority` は空文字として渡るため不正値。
        for invalid in ["", "abc", "-1", "1.5", " 1", "4294967296"] {
            assert_eq!(
                parse_priority(invalid),
                None,
                "{invalid:?} must be rejected"
            );
        }
    }

    #[test]
    fn display_id_falls_back_to_internal_id() {
        let ps = policy_set("permit(principal, action, resource);");
        let policy = ps.policies().next().expect("one policy");

        assert_eq!(display_id(policy), policy.id().to_string());
    }

    #[test]
    fn valueless_annotation_maps_to_empty_string() {
        let ps = policy_set(
            r#"
            @id("flag-only")
            @decision_context_flag
            forbid(principal, action, resource);
            "#,
        );
        let reason = [find_id(&ps, "flag-only")];

        let (_, context) = context_of(&ps, &reason);
        assert_eq!(context.get("flag").cloned(), string(""));
    }

    #[test]
    fn skips_prefix_only_annotation() {
        let ps = policy_set(
            r#"
            @id("broken")
            @decision_context_("no key")
            forbid(principal, action, resource);
            "#,
        );
        let reason = [find_id(&ps, "broken")];

        assert_eq!(to_decision_context(&ps, &reason), None);
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn build_context_adds_reason_and_errors_as_string_arrays() {
        let reason = strings(&["deny-one", "deny-two"]);
        let errors = strings(&["policy0 evaluation error"]);

        let context = build_context(None, &reason, &errors).expect("context should be present");
        assert_eq!(
            context.get("reason"),
            Some(&json!(["deny-one", "deny-two"]))
        );
        assert_eq!(
            context.get("errors"),
            Some(&json!(["policy0 evaluation error"]))
        );
    }

    #[test]
    fn build_context_merges_with_annotation_context() {
        let mut annotations = Map::new();
        annotations.insert("reason_user".into(), Value::String("mfa".into()));

        let context = build_context(Some(annotations), &strings(&["deny-one"]), &[])
            .expect("context should be present");

        // 作者アノテーションと予約フィールドが共存する。
        assert_eq!(
            context.get("reason_user"),
            Some(&Value::String("mfa".into()))
        );
        assert_eq!(context.get("reason"), Some(&json!(["deny-one"])));
        // errors は空なので付かない。
        assert!(!context.contains_key("errors"));
    }

    #[test]
    fn build_context_omits_empty_arrays_and_returns_none_when_empty() {
        // reason / errors が空、アノテーションも無ければ context 自体を省略。
        assert_eq!(build_context(None, &[], &[]), None);
        // 空アノテーション + 空 reason/errors も None。
        assert_eq!(build_context(Some(Map::new()), &[], &[]), None);
    }

    #[test]
    fn build_context_reserved_key_overwrites_author_annotation() {
        // 作者が `@decision_context_reason` を使うと予約フィールドで上書きされる。
        let mut annotations = Map::new();
        annotations.insert("reason".into(), Value::String("author value".into()));

        let context = build_context(Some(annotations), &strings(&["deny-one"]), &[])
            .expect("context should be present");
        assert_eq!(context.get("reason"), Some(&json!(["deny-one"])));
    }
}
