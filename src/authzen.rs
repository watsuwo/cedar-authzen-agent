//! Serde types for the OpenID AuthZEN Authorization API (Access Evaluation +
//! discovery metadata). See <https://openid.github.io/authzen/> and DESIGN.md §2.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The Access Evaluation request body (`POST /access/v1/evaluation`).
///
/// `subject`, `action` and `resource` are REQUIRED; `context` is OPTIONAL.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationRequest {
    /// The principal asking for access (mapped to the Cedar principal).
    pub subject: Subject,
    /// The action being attempted (mapped to the Cedar action).
    pub action: Action,
    /// The resource being accessed (mapped to the Cedar resource).
    pub resource: Resource,
    /// Environment attributes. Mapped onto the Cedar `Context` (DESIGN.md §2.1).
    #[serde(default)]
    pub context: Option<Value>,
}

/// AuthZEN Subject: REQUIRED `type` and `id`, OPTIONAL `properties`.
///
/// `properties` carry identity attributes (e.g. `user_type`, `department`) and
/// are injected as Cedar principal entity attributes (DESIGN.md §2.1).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subject {
    /// The subject type. Used verbatim as the Cedar entity type name.
    #[serde(rename = "type")]
    pub entity_type: String,
    /// The subject id. Used verbatim as the Cedar entity id.
    pub id: String,
    /// Subject attributes. Mapped onto the Cedar principal entity's attributes.
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
}

/// AuthZEN Resource: REQUIRED `type` and `id`, OPTIONAL `properties`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resource {
    /// The resource type. Used verbatim as the Cedar entity type name.
    #[serde(rename = "type")]
    pub entity_type: String,
    /// The resource id. Used verbatim as the Cedar entity id.
    pub id: String,
    /// Resource attributes. Mapped onto the Cedar resource entity's attributes.
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
}

/// AuthZEN Action: REQUIRED `name`, OPTIONAL `properties`.
///
/// The Cedar action entity type is always `Action`; `name` becomes the action id.
/// The set of accepted actions is governed by the Cedar schema (DESIGN.md §2.1),
/// not hardcoded here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Action {
    /// The action name. Used verbatim as the Cedar `Action` entity id.
    pub name: String,
    /// Action attributes. Accepted for spec compliance but not evaluated.
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
}

/// The Access Evaluation response body.
///
/// `decision: true` = Cedar `Allow` (normal login permitted, external auth not
/// forced); `decision: false` = Cedar `Deny` (a `forbid` matched → external auth
/// is forced). See DESIGN.md §2.1.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationResponse {
    /// The boolean authorization decision.
    pub decision: bool,
}

impl EvaluationResponse {
    /// Build a response carrying only a decision.
    pub fn new(decision: bool) -> Self {
        Self { decision }
    }
}

/// PDP metadata returned by `GET /.well-known/authzen-configuration`.
///
/// Only the Access Evaluation capability is advertised in the MVP (DESIGN.md §2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthzenConfiguration {
    /// Base URL of this PDP (must match the URL used to fetch this document).
    pub policy_decision_point: String,
    /// Absolute URL of the Access Evaluation endpoint.
    pub access_evaluation_endpoint: String,
}

/// Minimal error body returned for 4xx/5xx responses (DESIGN.md §8).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    /// A short, stable error code (e.g. `invalid_request`).
    pub error: String,
    /// A human-readable detail message.
    pub message: String,
}

impl ErrorBody {
    /// Build an error body from a code and detail message.
    pub fn new(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
        }
    }
}
