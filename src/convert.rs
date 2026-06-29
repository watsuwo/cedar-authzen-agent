//! Converts an AuthZEN [`EvaluationRequest`] into a schema-validated Cedar
//! [`Request`] plus the request-time [`Entities`] (DESIGN.md §2.1, §4 ③).
//!
//! - `subject.type`/`id` -> Cedar principal (`User::"<id>"`)
//! - `action.name`       -> Cedar action (`Action::"<name>"`)
//! - `resource.type`/`id`-> Cedar resource (`Client::"<id>"`)
//! - `subject.properties`-> principal entity attributes (identity ABAC)
//! - `context`           -> Cedar `Context` (environment attributes)
//!
//! All inputs are validated against the Cedar [`Schema`]: unknown
//! types/actions/attributes are rejected (mapped to HTTP 400 by the caller).

use std::str::FromStr;

use cedar_policy::{
    Context, Entities, EntityId, EntityTypeName, EntityUid, Request, Schema,
};
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::authzen::EvaluationRequest;

/// Cedar entity type used for AuthZEN actions.
const ACTION_TYPE: &str = "Action";

/// Errors raised while translating an AuthZEN request into Cedar inputs.
///
/// All variants map to an HTTP 400 (bad request) in the handler. The shared
/// `Invalid` prefix mirrors the stable error codes (`invalid_*`) returned to
/// the client (see [`ConversionError::code`]), so it is kept deliberately.
#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
pub enum ConversionError {
    /// A `type`/`id`/`name` could not be parsed into a Cedar entity uid.
    #[error("invalid entity reference: {0}")]
    InvalidEntity(String),
    /// The AuthZEN `context` failed schema validation.
    #[error("invalid context: {0}")]
    InvalidContext(String),
    /// The `properties` failed schema validation as entity attributes.
    #[error("invalid properties: {0}")]
    InvalidProperties(String),
    /// The assembled request failed schema validation (unknown action/type, etc.).
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

impl ConversionError {
    /// Stable error code for the JSON error body (DESIGN.md §8).
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidEntity(_) => "invalid_entity",
            Self::InvalidContext(_) => "invalid_context",
            Self::InvalidProperties(_) => "invalid_properties",
            Self::InvalidRequest(_) => "invalid_request",
        }
    }
}

/// Build a Cedar entity uid from a `type` + `id` pair, used verbatim.
fn entity_uid(entity_type: &str, id: &str) -> Result<EntityUid, ConversionError> {
    let type_name = EntityTypeName::from_str(entity_type)
        .map_err(|e| ConversionError::InvalidEntity(format!("type `{entity_type}`: {e}")))?;
    let entity_id = EntityId::from_str(id)
        .map_err(|e| ConversionError::InvalidEntity(format!("id `{id}`: {e}")))?;
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
}

/// A single Cedar entity JSON object `{ "uid", "attrs", "parents" }`.
fn entity_json(entity_type: &str, id: &str, properties: &Map<String, Value>) -> Value {
    json!({
        "uid": { "type": entity_type, "id": id },
        "attrs": properties,
        "parents": [],
    })
}

/// Translate an AuthZEN evaluation request into a `(Request, Entities)` pair,
/// validated against `schema`.
///
/// The principal entity is always injected (so its attributes are readable by
/// policies); the resource entity is injected only when it carries properties.
/// No static entity store is used, so there is never a uid collision (§4 ②).
pub fn to_cedar(
    req: &EvaluationRequest,
    schema: &Schema,
) -> Result<(Request, Entities), ConversionError> {
    let principal = entity_uid(&req.subject.entity_type, &req.subject.id)?;
    let action = entity_uid(ACTION_TYPE, &req.action.name)?;
    let resource = entity_uid(&req.resource.entity_type, &req.resource.id)?;

    let context = match &req.context {
        Some(value) => Context::from_json_value(value.clone(), Some((schema, &action)))
            .map_err(|e| ConversionError::InvalidContext(e.to_string()))?,
        None => Context::empty(),
    };

    let request = Request::new(
        principal,
        action,
        resource,
        context,
        Some(schema),
    )
    .map_err(|e| ConversionError::InvalidRequest(e.to_string()))?;

    // Inject the principal entity (with attributes from `subject.properties`,
    // possibly empty) plus the resource entity when it carries properties.
    let empty = Map::new();
    let subject_props = req.subject.properties.as_ref().unwrap_or(&empty);
    let mut entity_values = vec![entity_json(
        &req.subject.entity_type,
        &req.subject.id,
        subject_props,
    )];
    if let Some(props) = req.resource.properties.as_ref().filter(|p| !p.is_empty()) {
        entity_values.push(entity_json(&req.resource.entity_type, &req.resource.id, props));
    }

    let entities = Entities::from_json_value(Value::Array(entity_values), Some(schema))
        .map_err(|e| ConversionError::InvalidProperties(e.to_string()))?;

    Ok((request, entities))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authzen::{Action, Resource, Subject};

    /// A schema mirroring `policies/schema.cedar.json`: a `login` action from
    /// `User` to `Client`, with optional identity attributes and a `context.ip`.
    fn schema() -> Schema {
        Schema::from_json_value(json!({
            "": {
                "entityTypes": {
                    "User": { "shape": { "type": "Record", "attributes": {
                        "user_type": { "type": "String", "required": false },
                        "department": { "type": "String", "required": false }
                    }}},
                    "Client": { "shape": { "type": "Record", "attributes": {} } }
                },
                "actions": {
                    "login": { "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Client"],
                        "context": { "type": "Record", "attributes": {
                            "ip": { "type": "String", "required": false }
                        }}
                    }}
                }
            }
        }))
        .expect("test schema is valid")
    }

    /// Build a `login` request for `User::"<user>"` -> `Client::"<client>"`.
    fn login_request(
        user: &str,
        client: &str,
        properties: Option<Map<String, Value>>,
        context: Option<Value>,
    ) -> EvaluationRequest {
        EvaluationRequest {
            subject: Subject {
                entity_type: "User".into(),
                id: user.into(),
                properties,
            },
            action: Action {
                name: "login".into(),
                properties: None,
            },
            resource: Resource {
                entity_type: "Client".into(),
                id: client.into(),
                properties: None,
            },
            context,
        }
    }

    fn props(pairs: &[(&str, &str)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), Value::String((*v).to_string())))
            .collect()
    }

    /// Is an entity with `<entity_type>::"<id>"` present in the store?
    /// (Cedar also materialises schema action entities, so exact counts are
    /// brittle; we assert on the specific uids we care about instead.)
    fn contains(entities: &Entities, entity_type: &str, id: &str) -> bool {
        let uid = entity_uid(entity_type, id).expect("valid uid");
        entities.iter().any(|e| e.uid() == uid)
    }

    #[test]
    fn valid_request_with_subject_properties() {
        let req = login_request(
            "alice",
            "a-client",
            Some(props(&[("user_type", "employee"), ("department", "eng")])),
            Some(json!({ "ip": "10.0.0.1" })),
        );
        let (_request, entities) = to_cedar(&req, &schema()).expect("should convert");
        // The principal entity is always injected, carrying its attributes.
        assert!(contains(&entities, "User", "alice"));
    }

    #[test]
    fn valid_request_without_properties_or_context() {
        let req = login_request("bob", "b-client", None, None);
        let (_request, entities) = to_cedar(&req, &schema()).expect("should convert");
        assert!(contains(&entities, "User", "bob"));
    }

    #[test]
    fn resource_entity_injected_only_with_properties() {
        // Without properties the resource entity is not injected...
        let req = login_request("alice", "a-client", None, None);
        let (_r, entities) = to_cedar(&req, &schema()).expect("convert");
        assert!(contains(&entities, "User", "alice"));
        assert!(!contains(&entities, "Client", "a-client"));

        // ...an empty properties map is treated the same (filtered out)...
        let mut req = login_request("alice", "a-client", None, None);
        req.resource.properties = Some(props(&[]));
        let (_r, entities) = to_cedar(&req, &schema()).expect("convert");
        assert!(!contains(&entities, "Client", "a-client"));
    }

    #[test]
    fn unknown_context_attribute_is_rejected() {
        let req = login_request(
            "alice",
            "a-client",
            None,
            Some(json!({ "unknown_attr": "x" })),
        );
        let err = to_cedar(&req, &schema()).expect_err("should reject unknown context attr");
        assert_eq!(err.code(), "invalid_context");
    }

    #[test]
    fn unknown_subject_property_is_rejected() {
        let req = login_request(
            "alice",
            "a-client",
            Some(props(&[("not_in_schema", "x")])),
            None,
        );
        let err = to_cedar(&req, &schema()).expect_err("should reject unknown property");
        assert_eq!(err.code(), "invalid_properties");
    }

    #[test]
    fn unknown_action_is_rejected() {
        let mut req = login_request("alice", "a-client", None, None);
        req.action.name = "logout".into();
        let err = to_cedar(&req, &schema()).expect_err("should reject unknown action");
        assert_eq!(err.code(), "invalid_request");
    }

    #[test]
    fn principal_type_not_allowed_for_action_is_rejected() {
        let mut req = login_request("alice", "a-client", None, None);
        // `Client` is a valid schema type but not a valid principal for `login`.
        req.subject.entity_type = "Client".into();
        let err = to_cedar(&req, &schema()).expect_err("should reject wrong principal type");
        assert_eq!(err.code(), "invalid_request");
    }

    #[test]
    fn malformed_entity_type_is_rejected() {
        let mut req = login_request("alice", "a-client", None, None);
        req.subject.entity_type = "123 not a type".into();
        let err = to_cedar(&req, &schema()).expect_err("should reject malformed type name");
        assert_eq!(err.code(), "invalid_entity");
    }
}
