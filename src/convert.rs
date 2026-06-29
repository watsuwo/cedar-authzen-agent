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
/// All variants map to an HTTP 400 (bad request) in the handler.
#[derive(Debug, Error)]
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
