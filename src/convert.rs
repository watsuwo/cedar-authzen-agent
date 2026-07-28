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
/// レスポンスに context を付与するためにポリシーに付与するアノテーションの prefix
const DECISION_CONTEXT_PREFIX: &str = "decision_context_";
/// 監査ログ・優先度のタイブレークに使う可読 id のアノテーション
const ID_ANNOTATION: &str = "id";
/// 決定ポリシーが複数あるときに context の出所を選ぶためのアノテーション
pub const PRIORITY_ANNOTATION: &str = "priority";
/// `@priority` 未指定のポリシーの優先度(値が小さいほど優先)
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

/// Cedar の `EntityUid` を生成する。
fn entity_uid(entity_type: &str, id: &str) -> Result<EntityUid, ConversionError> {
    let type_name = EntityTypeName::from_str(entity_type)
        .map_err(|e| ConversionError::Entity(format!("type `{entity_type}`: {e}")))?;
    let entity_id =
        EntityId::from_str(id).map_err(|e| ConversionError::Entity(format!("id `{id}`: {e}")))?;
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
}

/// Entity 生成用の中間処理。`EntityUid` と properties を Cedar の entity JSON に変換する。
fn entity_json(entity_type: &str, id: &str, properties: &Map<String, Value>) -> Value {
    json!({
        "uid": { "type": entity_type, "id": id },
        "attrs": properties,
        "parents": [],
    })
}

/// AuthZEN リクエストを Cedar のリクエストとエンティティに変換する。
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

    let no_properties = Map::new();
    let subject_props = req.subject.properties.as_ref().unwrap_or(&no_properties);
    let mut entities_json = vec![entity_json(
        &req.subject.entity_type,
        &req.subject.id,
        subject_props,
    )];
    if let Some(props) = req.resource.properties.as_ref().filter(|p| !p.is_empty()) {
        entities_json.push(entity_json(
            &req.resource.entity_type,
            &req.resource.id,
            props,
        ));
    }

    let entities = Entities::from_json_value(Value::Array(entities_json), Some(schema))
        .map_err(|e| ConversionError::Properties(e.to_string()))?;

    Ok((request, entities))
}

/// ポリシーの可読 id。`@id` が無ければ内部 id(`policy0` 等)にフォールバックする。
pub fn display_id(policy: &Policy) -> String {
    policy
        .annotation(ID_ANNOTATION)
        .map_or_else(|| policy.id().to_string(), str::to_string)
}

/// `@priority` の値。非負整数のみ有効で、それ以外は不正値として `None` を返す。
pub fn parse_priority(raw: &str) -> Option<u32> {
    raw.parse::<u32>().ok()
}

/// ポリシーの優先度。値が小さいほど優先、未指定は最低優先度。
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

/// アノテーション由来の decision context と、その出所として採用したポリシー。
#[derive(Debug, PartialEq)]
pub struct DecisionContext {
    /// 採用したポリシーの可読 id([`display_id`])
    pub policy_id: String,
    /// `@decision_context_*` アノテーション由来の context
    pub context: Map<String, Value>,
}

/// アノテーションで定義されている decision 用の context を生成する。
/// 決定ポリシーが複数ある場合は最優先の1件だけを採用し、キー単位のマージはしない
/// (文言と次アクションの出所を1ポリシーに揃えるため)。
pub fn to_decision_context(
    policy_set: &PolicySet,
    reason_ids: &[&PolicyId],
) -> Option<DecisionContext> {
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
        insert_annotation_entry(&mut context, winner.id(), key, value);
    }

    // 0件なら context は付与しない(下位のポリシーにはフォールバックしない)
    (!context.is_empty()).then(|| DecisionContext {
        policy_id: display_id(winner),
        context,
    })
}

/// PDP が予約するフィールド。作者の `@decision_context_*` と衝突した場合はこちらで上書きする。
const RESERVED_REASON_KEY: &str = "reason";
const RESERVED_ERRORS_KEY: &str = "errors";

/// アノテーション由来の context に、cedar-local-agent の応答情報(determining policies の
/// `reason`、評価エラーの `errors`)を予約フィールドとしてマージする。
/// どちらも該当が空なら付与しない。全て空なら context 自体を省略する(`None`)。
pub fn build_response_context(
    annotation_context: Option<Map<String, Value>>,
    reason: &[String],
    errors: &[String],
) -> Option<Map<String, Value>> {
    let mut context = annotation_context.unwrap_or_default();

    if !reason.is_empty() {
        insert_reserved(&mut context, RESERVED_REASON_KEY, json_string_array(reason));
    }
    if !errors.is_empty() {
        insert_reserved(&mut context, RESERVED_ERRORS_KEY, json_string_array(errors));
    }

    (!context.is_empty()).then_some(context)
}

fn json_string_array(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

/// 予約キーは PDP 値を優先する。作者アノテーションを上書きした場合は warn を残す。
fn insert_reserved(context: &mut Map<String, Value>, key: &str, value: Value) {
    if context.insert(key.to_string(), value).is_some() {
        warn!(
            context_key = key,
            "PDP-reserved context key overwrote an author `@decision_context_` annotation"
        );
    }
}

/// `@decision_context_*` アノテーション1件を context のキーへ写す。
fn insert_annotation_entry(
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
            .find(|p| p.annotation(ID_ANNOTATION) == Some(name))
            .map_or_else(|| panic!("policy `{name}` not found"), Policy::id)
    }

    // 変換テスト用の自己完結スキーマ。principal/resource ともに任意属性を1つ持ち、
    // action `login` は任意の context 属性を1つ受け取る。
    fn schema() -> Schema {
        Schema::from_json_value(json!({
            "": {
                "entityTypes": {
                    "User": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "user_type": { "type": "String", "required": false },
                                "department": { "type": "String", "required": false }
                            }
                        }
                    },
                    "Client": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "tier": { "type": "String", "required": false }
                            }
                        }
                    }
                },
                "actions": {
                    "login": {
                        "appliesTo": {
                            "principalTypes": ["User"],
                            "resourceTypes": ["Client"],
                            "context": {
                                "type": "Record",
                                "attributes": {
                                    "access_route": { "type": "String", "required": false }
                                }
                            }
                        }
                    }
                }
            }
        }))
        .expect("test schema should parse")
    }

    // 既定は schema 上有効な `User` -> `login` -> `Client` のリクエスト
    fn request() -> EvaluationRequest {
        serde_json::from_value(json!({
            "subject": { "type": "User", "id": "alice" },
            "action": { "name": "login" },
            "resource": { "type": "Client", "id": "a-client" }
        }))
        .expect("test request should deserialize")
    }

    // 採用ポリシーの `@id` と context をまとめて検証するためのヘルパ
    fn context_of(ps: &PolicySet, reason: &[&PolicyId]) -> DecisionContext {
        to_decision_context(ps, reason).expect("context should be present")
    }

    fn string(value: &str) -> Value {
        Value::String(value.into())
    }

    fn uid(entity_type: &str, id: &str) -> EntityUid {
        entity_uid(entity_type, id).expect("test entity uid should build")
    }

    #[test]
    fn to_cedar_builds_principal_action_resource() {
        // AuthZEN の subject/action/resource が Cedar の三つ組へ 1:1 で写ること。
        // action だけは AuthZEN に型が無く、固定の `Action` 型を補って組み立てる。
        let (request, _) = to_cedar(&request(), &schema()).expect("conversion should succeed");

        assert_eq!(request.principal(), Some(&uid("User", "alice")));
        assert_eq!(request.action(), Some(&uid("Action", "login")));
        assert_eq!(request.resource(), Some(&uid("Client", "a-client")));
    }

    #[test]
    fn to_cedar_carries_subject_properties_into_entities() {
        // リクエストの subject.properties がポリシーから `principal.xxx` として
        // 参照できるよう、エンティティの属性として渡ること。
        let mut req = request();
        req.subject.properties = Some(
            json!({ "user_type": "employee", "department": "A1" })
                .as_object()
                .cloned()
                .expect("object"),
        );

        let (_, entities) = to_cedar(&req, &schema()).expect("conversion should succeed");

        let subject = entities
            .get(&uid("User", "alice"))
            .expect("subject entity should be present");
        assert!(subject.attr("user_type").is_some());
        assert!(subject.attr("department").is_some());
    }

    #[test]
    fn to_cedar_always_emits_the_subject_entity() {
        // properties 未指定でも principal は属性なしエンティティとして必ず渡す。
        // エンティティが無いとポリシーの `principal has xxx` が評価エラーになるため。
        let (_, entities) = to_cedar(&request(), &schema()).expect("conversion should succeed");

        assert!(entities.get(&uid("User", "alice")).is_some());
    }

    #[test]
    fn to_cedar_omits_the_resource_entity_without_properties() {
        // subject と違い resource は属性が無ければエンティティを作らない。スキーマが
        // 必須属性を課している場合に、空エンティティで検証を落とさないための非対称。
        let (_, entities) = to_cedar(&request(), &schema()).expect("conversion should succeed");

        assert!(entities.get(&uid("Client", "a-client")).is_none());
    }

    #[test]
    fn to_cedar_emits_the_resource_entity_with_properties() {
        // 属性がある場合は resource もエンティティ化する（上のテストの裏返し）。
        let mut req = request();
        req.resource.properties = Some(
            json!({ "tier": "gold" })
                .as_object()
                .cloned()
                .expect("object"),
        );

        let (_, entities) = to_cedar(&req, &schema()).expect("conversion should succeed");

        assert!(entities.get(&uid("Client", "a-client")).is_some());
    }

    #[test]
    fn to_cedar_treats_empty_resource_properties_as_absent() {
        // `"properties": {}` は「属性なし」と同じ扱い。PEP が空オブジェクトを
        // 送ってきても未指定時と挙動が変わらないことを保証する。
        let mut req = request();
        req.resource.properties = Some(Map::new());

        let (_, entities) = to_cedar(&req, &schema()).expect("conversion should succeed");

        assert!(entities.get(&uid("Client", "a-client")).is_none());
    }

    #[test]
    fn to_cedar_accepts_context_declared_by_the_schema() {
        // スキーマの action が宣言した context 属性はそのまま通す。
        let mut req = request();
        req.context = Some(json!({ "access_route": "internet" }));

        assert!(to_cedar(&req, &schema()).is_ok());
    }

    #[test]
    fn to_cedar_rejects_malformed_entity_type() {
        // Cedar の型名として成立しない文字列は entity uid の組み立て段階で弾く。
        let mut req = request();
        req.subject.entity_type = "1nvalid".to_string();

        let error = to_cedar(&req, &schema()).expect_err("malformed type must be rejected");
        assert_eq!(error.code(), "invalid_entity");
    }

    #[test]
    fn to_cedar_rejects_principal_type_the_action_does_not_accept() {
        // 型名としては正しいが、action の principalTypes に無い型はリクエスト
        // 構築段階で弾く（`login` の principal は `User` のみ）。
        let mut req = request();
        req.subject.entity_type = "Client".to_string();

        let error = to_cedar(&req, &schema()).expect_err("principal type must be rejected");
        assert_eq!(error.code(), "invalid_request");
    }

    #[test]
    fn to_cedar_rejects_context_not_declared_by_the_schema() {
        // スキーマ未宣言の context キーは黙って捨てず、400 として返す。
        let mut req = request();
        req.context = Some(json!({ "undeclared": "value" }));

        let error = to_cedar(&req, &schema()).expect_err("unknown context key must be rejected");
        assert_eq!(error.code(), "invalid_context");
    }

    #[test]
    fn to_cedar_rejects_properties_not_declared_by_the_schema() {
        // properties も同様。PEP 側の綴り間違いを黙認すると、ポリシーが意図せず
        // 不成立になって allow に倒れるため。
        let mut req = request();
        req.subject.properties = Some(
            json!({ "undeclared": "value" })
                .as_object()
                .cloned()
                .expect("object"),
        );

        let error = to_cedar(&req, &schema()).expect_err("unknown property must be rejected");
        assert_eq!(error.code(), "invalid_properties");
    }

    #[test]
    fn conversion_error_codes_are_stable() {
        // レスポンスの `error` フィールドとして外部に出るため、値を固定する。
        let cases = [
            (ConversionError::Entity(String::new()), "invalid_entity"),
            (ConversionError::Context(String::new()), "invalid_context"),
            (
                ConversionError::Properties(String::new()),
                "invalid_properties",
            ),
            (ConversionError::Request(String::new()), "invalid_request"),
        ];

        for (error, expected) in cases {
            assert_eq!(error.code(), expected);
        }
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

        // `@decision_context_` prefix を剥がしたキー名で context に載ること。
        // prefix を持たない `@id` は context に混ざらないこと。
        let DecisionContext { policy_id, context } = context_of(&ps, &reason);
        assert_eq!(policy_id, "deny-admins");
        assert_eq!(
            context.get("reason_user"),
            Some(&string("additional authentication required"))
        );
        assert_eq!(context.get("step_up"), Some(&string("mfa")));
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

        // `@id` は `@decision_context_` prefix を持たないため context にならない。
        assert_eq!(to_decision_context(&ps, &reason), None);
    }

    #[test]
    fn returns_none_for_empty_reason() {
        let ps = policy_set(
            r#"
            @id("deny-all")
            @decision_context_reason_user("nope")
            forbid(principal, action, resource);
            "#,
        );

        // 決定ポリシーが1件も無ければ、注釈付きポリシーが存在しても採用しない。
        assert_eq!(to_decision_context(&ps, &[]), None);
    }

    #[test]
    fn lower_priority_value_wins() {
        // 決定ポリシーが複数あるとき、context の出所は `@priority` の小さい方に決まる。
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

        let DecisionContext { policy_id, context } = context_of(&ps, &reason);
        assert_eq!(policy_id, "urgent");
        assert_eq!(context.get("reason_user"), Some(&string("from urgent")));
        // 採用は 1 ポリシーのみ。下位ポリシー固有のキーはマージされない。
        assert_eq!(context.get("step_up"), None);
        assert_eq!(context.len(), 1);
    }

    #[test]
    fn missing_priority_is_lowest() {
        // `@priority` 未指定は最低優先度として扱う。付け忘れたポリシーが
        // 意図せず最優先になることを防ぐ。
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

        let DecisionContext { policy_id, context } = context_of(&ps, &reason);
        assert_eq!(policy_id, "zzz-with-priority");
        assert_eq!(
            context.get("reason_user"),
            Some(&string("from priority-50"))
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
        // 同一 `@priority` では `@id` の文字列順で決める。`reason()` の反復順が
        // 非決定的なため、タイブレークを入れないとレスポンスが揺れる。
        let reason = [find_id(&ps, "second"), find_id(&ps, "first")];

        let DecisionContext { policy_id, context } = context_of(&ps, &reason);
        assert_eq!(policy_id, "first");
        assert_eq!(context.get("reason_user"), Some(&string("from first")));
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
        // `@priority` は内部の優先度制御用。PEP へ返す context には出さない。
        let ps = policy_set(
            r#"
            @id("with-priority")
            @priority("1")
            @decision_context_reason_user("shown")
            forbid(principal, action, resource);
            "#,
        );
        let reason = [find_id(&ps, "with-priority")];

        let context = context_of(&ps, &reason).context;
        assert_eq!(context.get("priority"), None);
        assert_eq!(context.len(), 1);
    }

    #[test]
    fn parses_only_non_negative_integers_as_priority() {
        // `@priority` の受理範囲。境界（0 と u32 上限）と代表的な不正値を固定する。
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
        // `@id` を付け忘れたポリシーでもログ・レスポンスから追跡できるよう、
        // Cedar が採番する内部 id（`policy0` 等）を代わりに使う。
        let ps = policy_set("permit(principal, action, resource);");
        let policy = ps.policies().next().expect("one policy");

        assert_eq!(display_id(policy), policy.id().to_string());
    }

    #[test]
    fn valueless_annotation_maps_to_empty_string() {
        // 値なしアノテーション（`@decision_context_flag`）はフラグとして扱い、
        // 空文字を値にしてキーだけ立てる。
        let ps = policy_set(
            r#"
            @id("flag-only")
            @decision_context_flag
            forbid(principal, action, resource);
            "#,
        );
        let reason = [find_id(&ps, "flag-only")];

        let context = context_of(&ps, &reason).context;
        assert_eq!(context.get("flag"), Some(&string("")));
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

        // prefix だけでキー名が無い注釈は設定不備として無視する（空キーを作らない）。
        assert_eq!(to_decision_context(&ps, &reason), None);
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn build_response_context_adds_reason_and_errors_as_string_arrays() {
        // PDP 予約フィールドは、要素1件でも常に文字列配列として返す
        // （PEP 側が型分岐しなくて済むように）。
        let reason = strings(&["deny-one", "deny-two"]);
        let errors = strings(&["policy0 evaluation error"]);

        let context =
            build_response_context(None, &reason, &errors).expect("context should be present");
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
    fn build_response_context_merges_with_annotation_context() {
        // 作者が書いた `@decision_context_*` と PDP 予約フィールドは同じ context に同居する。
        let mut annotations = Map::new();
        annotations.insert("reason_user".into(), Value::String("mfa".into()));

        let context = build_response_context(Some(annotations), &strings(&["deny-one"]), &[])
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
    fn build_response_context_returns_none_when_nothing_to_report() {
        // reason / errors が空、アノテーションも無ければ context 自体を省略。
        assert_eq!(build_response_context(None, &[], &[]), None);
        // 空アノテーション + 空 reason/errors も None。
        assert_eq!(build_response_context(Some(Map::new()), &[], &[]), None);
    }

    #[test]
    fn build_response_context_omits_empty_reserved_keys() {
        // アノテーションだけがある場合、それ単体で context として成立する。
        let mut annotations = Map::new();
        annotations.insert("reason_user".into(), Value::String("mfa".into()));

        let context = build_response_context(Some(annotations), &[], &[])
            .expect("annotation context should survive on its own");

        // 空の予約フィールドは空配列ではなくキーごと省略する。
        assert!(!context.contains_key("reason"));
        assert!(!context.contains_key("errors"));
        assert_eq!(context.len(), 1);
    }

    #[test]
    fn build_response_context_reserved_key_overwrites_author_annotation() {
        // 作者が `@decision_context_reason` を使うと予約フィールドで上書きされる。
        let mut annotations = Map::new();
        annotations.insert("reason".into(), Value::String("author value".into()));

        let context = build_response_context(Some(annotations), &strings(&["deny-one"]), &[])
            .expect("context should be present");
        assert_eq!(context.get("reason"), Some(&json!(["deny-one"])));
    }
}
