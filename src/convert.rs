use std::str::FromStr;

use cedar_policy::{
    Context, Entities, EntityId, EntityTypeName, EntityUid, PolicyId, PolicySet, Request, Schema,
};
use serde_json::{json, Map, Value};
use thiserror::Error;
use tracing::warn;

use crate::authzen::EvaluationRequest;

const ACTION_TYPE: &str = "Action";
// レスポンスにcontextを付与するためにポリシーに付与するアノテーションのprefix
const DECISION_CONTEXT_PREFIX: &str = "decision_context_";

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

// アノテーションで定義されているdecision用のcontextを生成する
pub fn to_decision_context(
    policy_set: &PolicySet,
    reason_ids: &[&PolicyId],
) -> Option<Map<String, Value>> {
    let mut ids = reason_ids.to_vec();
    ids.sort_unstable_by_key(|id| id.to_string());

    let mut context = Map::new();
    for id in ids {
        let Some(policy) = policy_set.policy(id) else {
            continue;
        };
        for (key, value) in policy.annotations() {
            insert_decision_context(&mut context, id, key, value);
        }
    }

    // 0件ならcontextは付与しない
    (!context.is_empty()).then_some(context)
}

fn insert_decision_context(context: &mut Map<String, Value>, id: &PolicyId, key: &str, value: &str) {
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

    match context.entry(context_key.to_string()) {
        serde_json::map::Entry::Vacant(entry) => {
            entry.insert(Value::String(value.to_string()));
        }
        // 同一名のポリシーを定義していた場合は先勝にする
        serde_json::map::Entry::Occupied(_) => {
            warn!(
                policy_id = %id,
                context_key,
                "conflicting `@decision_context_` annotation across determining policies; \
                 keeping the value from the lexicographically first policy id"
            );
        }
    }
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

        let context = to_decision_context(&ps, &reason).expect("context should be present");
        assert_eq!(
            context.get("reason_user"),
            Some(&Value::String("additional authentication required".into()))
        );
        assert_eq!(context.get("step_up"), Some(&Value::String("mfa".into())));
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
    fn first_policy_in_id_order_wins_on_conflict() {
        let ps = policy_set(
            r#"
            @id("first")
            @decision_context_reason_user("from first")
            forbid(principal, action, resource);

            @id("second")
            @decision_context_reason_user("from second")
            @decision_context_extra("kept")
            forbid(principal, action, resource);
            "#,
        );
        // 逆順で渡しても、id の文字列順ソートにより "first" の値が勝つ。
        let reason = [find_id(&ps, "second"), find_id(&ps, "first")];

        let context = to_decision_context(&ps, &reason).expect("context should be present");
        assert_eq!(
            context.get("reason_user"),
            Some(&Value::String("from first".into()))
        );
        // 衝突しないキーは全ポリシーからマージされる。
        assert_eq!(context.get("extra"), Some(&Value::String("kept".into())));
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

        let context = to_decision_context(&ps, &reason).expect("context should be present");
        assert_eq!(context.get("flag"), Some(&Value::String(String::new())));
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
}
