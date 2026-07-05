use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationRequest {
    pub subject: Subject,
    pub action: Action,
    pub resource: Resource,
    #[serde(default)]
    pub context: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subject {
    #[serde(rename = "type")]
    pub entity_type: String,
    pub id: String,
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resource {
    #[serde(rename = "type")]
    pub entity_type: String,
    pub id: String,
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Action {
    pub name: String,
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationResponse {
    pub decision: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Map<String, Value>>,
}

impl EvaluationResponse {
    pub fn new(decision: bool) -> Self {
        Self {
            decision,
            context: None,
        }
    }

    pub fn with_context(mut self, context: Option<Map<String, Value>>) -> Self {
        self.context = context;
        self
    }
}

/// well-known
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthzenConfiguration {
    pub policy_decision_point: String,
    pub access_evaluation_endpoint: String,
}

/// error
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
    pub message: String,
}

impl ErrorBody {
    pub fn new(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
        }
    }
}
