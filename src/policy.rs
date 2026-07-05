use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use cedar_local_agent::public::events::core::{file_inspector_task, RefreshRate};
use cedar_local_agent::public::file::policy_set_provider::{self, PolicySetProvider};
use cedar_local_agent::public::UpdateProviderData;
use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
use thiserror::Error;
use tracing::{error, info};

use crate::state::Readiness;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("read `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("parse `{path}`: {source}")]
    Parse {
        path: String,
        #[source]
        source: Box<cedar_policy::ParseErrors>,
    },
    #[error("schema validation: {0}")]
    Validation(String),
}

pub fn load_schema(path: &str) -> Result<Schema, crate::Error> {
    let file = std::fs::File::open(path).map_err(|e| format!("open schema `{path}`: {e}"))?;
    let schema = Schema::from_json_file(file).map_err(|e| format!("parse schema `{path}`: {e}"))?;
    Ok(schema)
}

pub fn new_provider(policy_path: &str) -> Result<Arc<PolicySetProvider>, crate::Error> {
    let config = policy_set_provider::ConfigBuilder::default()
        .policy_set_path(policy_path.to_string())
        .build()
        .map_err(|e| format!("policy provider config: {e}"))?;
    Ok(Arc::new(PolicySetProvider::new(config)?))
}

pub fn validate(policy_path: &str, schema: &Schema) -> Result<usize, PolicyError> {
    let src = std::fs::read_to_string(policy_path).map_err(|source| PolicyError::Read {
        path: policy_path.to_string(),
        source,
    })?;
    let policy_set = PolicySet::from_str(&src).map_err(|source| PolicyError::Parse {
        path: policy_path.to_string(),
        source: Box::new(source),
    })?;

    let result = Validator::new(schema.clone()).validate(&policy_set, ValidationMode::Strict);
    if result.validation_passed() {
        return Ok(policy_set.policies().count());
    }
    let errors = result
        .validation_errors()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    Err(PolicyError::Validation(errors))
}

pub fn spawn_reload_task(
    provider: Arc<PolicySetProvider>,
    schema: Arc<Schema>,
    policy_path: String,
    refresh: Duration,
    readiness: Readiness,
) {
    let (inspector, mut receiver) =
        file_inspector_task(RefreshRate::Other(refresh), policy_path.clone());

    tokio::spawn(async move {
        let _guard = inspector;
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    reload(&provider, &schema, &policy_path, &readiness, &event).await;
                }
                Err(error) => {
                    error!("policy reload channel closed: {error:?}");
                    break;
                }
            }
        }
    });
}

async fn reload(
    provider: &PolicySetProvider,
    schema: &Schema,
    policy_path: &str,
    readiness: &Readiness,
    event: &impl std::fmt::Debug,
) {
    let policy_count = match validate(policy_path, schema) {
        Ok(count) => count,
        Err(error) => {
            error!(
                "policy reload rejected: schema validation failed ({error}); serving previous policy"
            );
            readiness.set(false);
            return;
        }
    };
    match provider.update_provider_data().await {
        Ok(()) => {
            info!("policy reloaded: {policy_count} policies ({event:?})");
            readiness.set(true);
        }
        Err(error) => {
            error!("policy reload failed (serving previous policy): {error:?}");
            readiness.set(false);
        }
    }
}