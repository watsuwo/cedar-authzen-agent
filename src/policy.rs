use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use cedar_local_agent::public::UpdateProviderData;
use cedar_local_agent::public::events::core::{RefreshRate, file_inspector_task};
use cedar_local_agent::public::file::policy_set_provider::{self, PolicySetProvider};
use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
use thiserror::Error;
use tracing::{error, info};

use crate::convert;
use crate::state::Readiness;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("read `{path}`: {source}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("parse `{path}`: {source}")]
    PolicyParse {
        path: String,
        #[source]
        source: Box<cedar_policy::ParseErrors>,
    },
    #[error("parse schema `{path}`: {source}")]
    SchemaParse {
        path: String,
        #[source]
        source: Box<cedar_policy::SchemaError>,
    },
    #[error("policy provider configuration: {0}")]
    ProviderConfig(#[source] Box<policy_set_provider::ConfigBuilderError>),
    #[error("policy provider: {0}")]
    Provider(#[source] Box<policy_set_provider::ProviderError>),
    #[error("schema validation: {0}")]
    Validation(String),
    #[error("invalid annotation: {0}")]
    Annotation(String),
}

/// Cedar スキーマを JSON ファイルから読み込む
pub fn load_schema(path: &str) -> Result<Schema, PolicyError> {
    let file = std::fs::File::open(path).map_err(|source| PolicyError::FileRead {
        path: path.to_string(),
        source,
    })?;
    Schema::from_json_file(file).map_err(|source| PolicyError::SchemaParse {
        path: path.to_string(),
        source: Box::new(source),
    })
}

/// ポリシーファイルを読み込む `PolicySetProvider` を生成する
pub fn new_provider(policy_path: &str) -> Result<Arc<PolicySetProvider>, PolicyError> {
    let config = policy_set_provider::ConfigBuilder::default()
        .policy_set_path(policy_path.to_string())
        .build()
        .map_err(|source| PolicyError::ProviderConfig(Box::new(source)))?;
    let provider =
        PolicySetProvider::new(config).map_err(|source| PolicyError::Provider(Box::new(source)))?;
    Ok(Arc::new(provider))
}

/// ポリシーをスキーマ・アノテーションの両面から検証しポリシー数を返す
pub fn validate(policy_path: &str, schema: &Schema) -> Result<usize, PolicyError> {
    let src = std::fs::read_to_string(policy_path).map_err(|source| PolicyError::FileRead {
        path: policy_path.to_string(),
        source,
    })?;
    let policy_set = PolicySet::from_str(&src).map_err(|source| PolicyError::PolicyParse {
        path: policy_path.to_string(),
        source: Box::new(source),
    })?;

    let validation = Validator::new(schema.clone()).validate(&policy_set, ValidationMode::Strict);
    if !validation.validation_passed() {
        let errors = validation
            .validation_errors()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(PolicyError::Validation(errors));
    }

    validate_priorities(&policy_set)?;

    Ok(policy_set.policies().count())
}

/// `@priority` は非負整数のみで、不正値を含むポリシーセットは反映しない
fn validate_priorities(policy_set: &PolicySet) -> Result<(), PolicyError> {
    let errors = policy_set
        .policies()
        .filter_map(|policy| {
            let raw = policy.annotation(convert::PRIORITY_ANNOTATION)?;
            convert::parse_priority(raw).is_none().then(|| {
                format!(
                    "policy `{}`: invalid @priority value {raw:?}",
                    convert::display_id(policy)
                )
            })
        })
        .collect::<Vec<_>>();

    if errors.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::Annotation(errors.join("; ")))
    }
}

/// ポリシーの変更を監視し検証を通ったものだけを反映するタスクを起動する
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

/// 変更を検知したポリシーを再検証し成功時のみ provider へ反映する
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
            error!("policy reload rejected: {error}; serving previous policy");
            readiness.set_ready(false);
            return;
        }
    };
    match provider.update_provider_data().await {
        Ok(()) => {
            info!("policy reloaded: {policy_count} policies ({event:?})");
            readiness.set_ready(true);
        }
        Err(error) => {
            error!("policy reload failed (serving previous policy): {error:?}");
            readiness.set_ready(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_set(src: &str) -> PolicySet {
        PolicySet::from_str(src).expect("test policy set should parse")
    }

    #[test]
    fn accepts_valid_priority() {
        let ps = policy_set(
            r#"
            @id("lowest-value")
            @priority("0")
            forbid(principal, action, resource);

            @id("highest-value")
            @priority("4294967295")
            forbid(principal, action, resource);

            @id("no-priority")
            permit(principal, action, resource);
            "#,
        );

        assert!(validate_priorities(&ps).is_ok());
    }

    #[test]
    fn rejects_invalid_priority() {
        for invalid in [r#"("abc")"#, r#"("-1")"#, r#"("1.5")"#, ""] {
            let ps = policy_set(&format!(
                r#"
                @id("broken")
                @priority{invalid}
                forbid(principal, action, resource);
                "#
            ));

            let error = validate_priorities(&ps)
                .expect_err(&format!("@priority{invalid} must be rejected"));
            assert!(
                matches!(error, PolicyError::Annotation(_)),
                "expected Annotation variant, got {error:?}"
            );
            assert!(
                error.to_string().contains("broken"),
                "error should name the policy: {error}"
            );
        }
    }

    const TEST_SCHEMA: &str = r#"{
        "": {
            "entityTypes": {
                "User": { "shape": { "type": "Record", "attributes": {} } },
                "Client": { "shape": { "type": "Record", "attributes": {} } }
            },
            "actions": {
                "login": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Client"]
                    }
                }
            }
        }
    }"#;

    fn write_file(dir: &tempfile::TempDir, name: &str, contents: &str) -> String {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).expect("test fixture should be writable");
        path.to_str().expect("utf-8 path").to_string()
    }

    fn test_schema() -> Schema {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, "schema.json", TEST_SCHEMA);
        load_schema(&path).expect("test schema should load")
    }

    #[test]
    fn load_schema_reports_missing_file() {
        let error = load_schema("/nonexistent/schema.json").expect_err("missing file must fail");

        assert!(
            matches!(error, PolicyError::FileRead { .. }),
            "expected FileRead variant, got {error:?}"
        );
    }

    #[test]
    fn load_schema_reports_malformed_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, "schema.json", "{ not json");

        let error = load_schema(&path).expect_err("malformed schema must fail");
        assert!(
            matches!(error, PolicyError::SchemaParse { .. }),
            "expected SchemaParse variant, got {error:?}"
        );
    }

    #[test]
    fn validate_counts_policies_that_pass() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(
            &dir,
            "policies.cedar",
            r#"
            @id("allow-login")
            permit(principal, action == Action::"login", resource);

            @id("deny-one")
            @priority("10")
            forbid(principal, action == Action::"login", resource == Client::"a");
            "#,
        );

        let count = validate(&path, &test_schema()).expect("policies should validate");
        assert_eq!(count, 2);
    }

    #[test]
    fn validate_reports_missing_policy_file() {
        let error = validate("/nonexistent/policies.cedar", &test_schema())
            .expect_err("missing file must fail");

        assert!(
            matches!(error, PolicyError::FileRead { .. }),
            "expected FileRead variant, got {error:?}"
        );
    }

    #[test]
    fn validate_reports_unparsable_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, "policies.cedar", "this is not cedar");

        let error = validate(&path, &test_schema()).expect_err("malformed policy must fail");
        assert!(
            matches!(error, PolicyError::PolicyParse { .. }),
            "expected PolicyParse variant, got {error:?}"
        );
    }

    #[test]
    fn validate_reports_schema_violation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(
            &dir,
            "policies.cedar",
            r#"
            @id("bad-principal-type")
            permit(principal == Client::"a", action == Action::"login", resource);
            "#,
        );

        let error = validate(&path, &test_schema()).expect_err("schema violation must fail");
        assert!(
            matches!(error, PolicyError::Validation(_)),
            "expected Validation variant, got {error:?}"
        );
    }

    #[test]
    fn validate_rejects_invalid_priority_annotation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(
            &dir,
            "policies.cedar",
            r#"
            @id("bad-priority")
            @priority("high")
            permit(principal, action == Action::"login", resource);
            "#,
        );

        let error = validate(&path, &test_schema()).expect_err("invalid @priority must fail");
        assert!(
            matches!(error, PolicyError::Annotation(_)),
            "expected Annotation variant, got {error:?}"
        );
    }
}
