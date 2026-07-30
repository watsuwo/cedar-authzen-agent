use std::str::FromStr;

use cedar_policy::{
    Context, Entities, EntityId, EntityTypeName, EntityUid, Policy, PolicyId, PolicySet, Request,
    Schema,
};
use serde_json::{Map, Value, json};
use thiserror::Error;
use tracing::warn;

use crate::authzen::EvaluationRequest;

const ID_ANNOTATION: &str = "id";

/// レスポンスに context に任意の値を付与するためのアノテーション
const DECISION_CONTEXT_PREFIX: &str = "decision_context_";

/// アノテーションで定義されるポリシーの優先度
pub const PRIORITY_ANNOTATION: &str = "priority";

/// `@priority`や未指定のポリシーの優先度(値が小さいほど優先)
const LOWEST_PRIORITY: u32 = u32::MAX;

/// Cedar標準レスポンスを `context` に付与するための予約キー
const RESERVED_REASON_KEY: &str = "reason";
const RESERVED_ERRORS_KEY: &str = "errors";

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

/// Cedar の `EntityUid` を生成する
fn entity_uid(entity_type: &str, id: &str) -> Result<EntityUid, ConversionError> {
    let type_name = EntityTypeName::from_str(entity_type)
        .map_err(|e| ConversionError::Entity(format!("type `{entity_type}`: {e}")))?;
    let entity_id =
        EntityId::from_str(id).map_err(|e| ConversionError::Entity(format!("id `{id}`: {e}")))?;
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
}

/// `EntityUid` と properties を Cedar の entity JSON に変換する
fn entity_json(entity_type: &str, id: &str, properties: &Map<String, Value>) -> Value {
    json!({
        "uid": { "type": entity_type, "id": id },
        "attrs": properties,
        "parents": [],
    })
}

/// AuthZEN リクエストを Cedar のリクエストとエンティティに変換する
pub fn to_cedar(
    req: &EvaluationRequest,
    schema: &Schema,
) -> Result<(Request, Entities), ConversionError> {
    let principal = entity_uid(&req.subject.entity_type, &req.subject.id)?;
    let action = entity_uid("Action", &req.action.name)?;
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

pub fn display_id(policy: &Policy) -> String {
    policy
        .annotation(ID_ANNOTATION)
        .map_or_else(|| policy.id().to_string(), str::to_string)
}

pub fn parse_priority(raw: &str) -> Option<u32> {
    raw.parse::<u32>().ok()
}

fn priority_of(policy: &Policy) -> u32 {
    let Some(raw) = policy.annotation(PRIORITY_ANNOTATION) else {
        return LOWEST_PRIORITY;
    };
    parse_priority(raw).unwrap_or_else(|| {
        // 不正なポリシーはロード時に弾いているため通常は到達しない
        warn!(
            policy_id = %display_id(policy),
            "invalid `@priority` value {raw:?}; treating as lowest priority"
        );
        LOWEST_PRIORITY
    })
}

#[derive(Debug, PartialEq)]
pub struct DecisionContext {
    pub policy_id: String,
    pub context: Map<String, Value>,
}

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
        insert_annotation_entry(&mut context, key, value);
    }

    // アノテーションが設定されていなければ context はレスポンスしない
    (!context.is_empty()).then(|| DecisionContext {
        policy_id: display_id(winner),
        context,
    })
}

/// `@decision_context_*` アノテーションの context キー部分。prefix が付かないキーは `None`
pub fn decision_context_key(annotation_key: &str) -> Option<&str> {
    annotation_key.strip_prefix(DECISION_CONTEXT_PREFIX)
}

/// PDP が予約している context キーか。予約キーは作者アノテーションより優先される
pub fn is_reserved_context_key(key: &str) -> bool {
    matches!(key, RESERVED_REASON_KEY | RESERVED_ERRORS_KEY)
}

/// アノテーション由来の context へ `reason`/`errors` を予約フィールドとしてマージする
pub fn build_response_context(
    annotation_context: Option<Map<String, Value>>,
    reason: &[String],
    errors: &[String],
) -> Option<Map<String, Value>> {
    let mut context = annotation_context.unwrap_or_default();

    // 予約キーと衝突するアノテーションはロード時に弾いている
    // (`policy::validate_decision_contexts`)ため、ここでの上書きは起こらない。
    if !reason.is_empty() {
        context.insert(RESERVED_REASON_KEY.to_string(), json_string_array(reason));
    }
    if !errors.is_empty() {
        context.insert(RESERVED_ERRORS_KEY.to_string(), json_string_array(errors));
    }

    (!context.is_empty()).then_some(context)
}

fn json_string_array(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

fn insert_annotation_entry(context: &mut Map<String, Value>, key: &str, value: &str) {
    let Some(context_key) = decision_context_key(key) else {
        return;
    };

    // キー名なしはロード時に弾いているため通常は到達しない
    // (`policy::validate_decision_contexts`)
    if context_key.is_empty() {
        return;
    }

    context.insert(context_key.to_string(), Value::String(value.to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_set(src: &str) -> PolicySet {
        PolicySet::from_str(src).expect("test policy set should parse")
    }

    fn find_id<'a>(ps: &'a PolicySet, name: &str) -> &'a PolicyId {
        ps.policies()
            .find(|p| p.annotation(ID_ANNOTATION) == Some(name))
            .map_or_else(|| panic!("policy `{name}` not found"), Policy::id)
    }

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

    fn request() -> EvaluationRequest {
        serde_json::from_value(json!({
            "subject": { "type": "User", "id": "alice" },
            "action": { "name": "login" },
            "resource": { "type": "Client", "id": "a-client" }
        }))
        .expect("test request should deserialize")
    }

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
        let (request, _) = to_cedar(&request(), &schema()).expect("conversion should succeed");

        assert_eq!(request.principal(), Some(&uid("User", "alice")));
        assert_eq!(request.action(), Some(&uid("Action", "login")));
        assert_eq!(request.resource(), Some(&uid("Client", "a-client")));
    }

    #[test]
    fn to_cedar_carries_subject_properties_into_entities() {
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
        let (_, entities) = to_cedar(&request(), &schema()).expect("conversion should succeed");

        assert!(entities.get(&uid("User", "alice")).is_some());
    }

    #[test]
    fn to_cedar_omits_the_resource_entity_without_properties() {
        let (_, entities) = to_cedar(&request(), &schema()).expect("conversion should succeed");

        assert!(entities.get(&uid("Client", "a-client")).is_none());
    }

    #[test]
    fn to_cedar_emits_the_resource_entity_with_properties() {
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
        let mut req = request();
        req.resource.properties = Some(Map::new());

        let (_, entities) = to_cedar(&req, &schema()).expect("conversion should succeed");

        assert!(entities.get(&uid("Client", "a-client")).is_none());
    }

    #[test]
    fn to_cedar_accepts_context_declared_by_the_schema() {
        let mut req = request();
        req.context = Some(json!({ "access_route": "internet" }));

        assert!(to_cedar(&req, &schema()).is_ok());
    }

    #[test]
    fn to_cedar_rejects_malformed_entity_type() {
        let mut req = request();
        req.subject.entity_type = "1nvalid".to_string();

        let error = to_cedar(&req, &schema()).expect_err("malformed type must be rejected");
        assert_eq!(error.code(), "invalid_entity");
    }

    #[test]
    fn to_cedar_rejects_principal_type_the_action_does_not_accept() {
        let mut req = request();
        req.subject.entity_type = "Client".to_string();

        let error = to_cedar(&req, &schema()).expect_err("principal type must be rejected");
        assert_eq!(error.code(), "invalid_request");
    }

    #[test]
    fn to_cedar_rejects_context_not_declared_by_the_schema() {
        let mut req = request();
        req.context = Some(json!({ "undeclared": "value" }));

        let error = to_cedar(&req, &schema()).expect_err("unknown context key must be rejected");
        assert_eq!(error.code(), "invalid_context");
    }

    #[test]
    fn to_cedar_rejects_properties_not_declared_by_the_schema() {
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
        let reason = [find_id(&ps, "routine"), find_id(&ps, "urgent")];

        let DecisionContext { policy_id, context } = context_of(&ps, &reason);
        assert_eq!(policy_id, "urgent");
        assert_eq!(context.get("reason_user"), Some(&string("from urgent")));
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

        let context = context_of(&ps, &reason).context;
        assert_eq!(context.get("priority"), None);
        assert_eq!(context.len(), 1);
    }

    #[test]
    fn parses_only_non_negative_integers_as_priority() {
        assert_eq!(parse_priority("0"), Some(0));
        assert_eq!(parse_priority("1"), Some(1));
        assert_eq!(parse_priority("4294967295"), Some(u32::MAX));

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

        assert_eq!(to_decision_context(&ps, &reason), None);
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn build_response_context_adds_reason_and_errors_as_string_arrays() {
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
        let mut annotations = Map::new();
        annotations.insert("reason_user".into(), Value::String("mfa".into()));

        let context = build_response_context(Some(annotations), &strings(&["deny-one"]), &[])
            .expect("context should be present");

        assert_eq!(
            context.get("reason_user"),
            Some(&Value::String("mfa".into()))
        );
        assert_eq!(context.get("reason"), Some(&json!(["deny-one"])));
        assert!(!context.contains_key("errors"));
    }

    #[test]
    fn build_response_context_returns_none_when_nothing_to_report() {
        assert_eq!(build_response_context(None, &[], &[]), None);
        assert_eq!(build_response_context(Some(Map::new()), &[], &[]), None);
    }

    #[test]
    fn build_response_context_omits_empty_reserved_keys() {
        let mut annotations = Map::new();
        annotations.insert("reason_user".into(), Value::String("mfa".into()));

        let context = build_response_context(Some(annotations), &[], &[])
            .expect("annotation context should survive on its own");

        assert!(!context.contains_key("reason"));
        assert!(!context.contains_key("errors"));
        assert_eq!(context.len(), 1);
    }

    #[test]
    fn build_response_context_reserved_key_overwrites_author_annotation() {
        let mut annotations = Map::new();
        annotations.insert("reason".into(), Value::String("author value".into()));

        let context = build_response_context(Some(annotations), &strings(&["deny-one"]), &[])
            .expect("context should be present");
        assert_eq!(context.get("reason"), Some(&json!(["deny-one"])));
    }
}
