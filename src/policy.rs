use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use cedar_local_agent::public::UpdateProviderData;
use cedar_local_agent::public::events::core::{RefreshRate, file_inspector_task};
use cedar_local_agent::public::file::policy_set_provider::{self, PolicySetProvider};
use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
use thiserror::Error;
use tracing::{debug, error, info};

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

pub fn new_provider(policy_path: &str) -> Result<Arc<PolicySetProvider>, PolicyError> {
    let config = policy_set_provider::ConfigBuilder::default()
        .policy_set_path(policy_path.to_string())
        .build()
        .map_err(|source| PolicyError::ProviderConfig(Box::new(source)))?;
    let provider =
        PolicySetProvider::new(config).map_err(|source| PolicyError::Provider(Box::new(source)))?;
    Ok(Arc::new(provider))
}

/// ポリシーファイルの内容を読む
fn read_source(policy_path: &str) -> Result<String, PolicyError> {
    std::fs::read_to_string(policy_path).map_err(|source| PolicyError::FileRead {
        path: policy_path.to_string(),
        source,
    })
}

/// ポリシーを検証して成功したら内容とポリシー数を返す。
/// 内容を返すのはリロード時に「前回適用した内容と同じか」を判定するため（[`spawn_reload_task`]）
pub fn load_and_validate(
    policy_path: &str,
    schema: &Schema,
) -> Result<(String, usize), PolicyError> {
    let src = read_source(policy_path)?;
    let count = validate_source(&src, policy_path, schema)?;
    Ok((src, count))
}

/// 読み込み済みのポリシーソースを検証してポリシー数を返す
fn validate_source(src: &str, policy_path: &str, schema: &Schema) -> Result<usize, PolicyError> {
    let policy_set = PolicySet::from_str(src).map_err(|source| PolicyError::PolicyParse {
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
    validate_decision_contexts(&policy_set)?;

    Ok(policy_set.policies().count())
}

/// `@decision_context_*` のキー名を検証する。どちらのケースも「作者が書いた値が
/// レスポンスに出ない」不備で、黙って無視すると気付けないためロード時に弾く
fn validate_decision_contexts(policy_set: &PolicySet) -> Result<(), PolicyError> {
    let mut errors = policy_set
        .policies()
        .flat_map(|policy| {
            policy.annotations().filter_map(|(key, _)| {
                let context_key = convert::decision_context_key(key)?;
                let policy_id = convert::display_id(policy);

                if context_key.is_empty() {
                    Some(format!(
                        "policy `{policy_id}`: `@decision_context_` without a context key"
                    ))
                } else if convert::is_reserved_context_key(context_key) {
                    Some(format!(
                        "policy `{policy_id}`: `@decision_context_{context_key}` collides with a PDP-reserved context key"
                    ))
                } else {
                    None
                }
            })
        })
        .collect::<Vec<_>>();

    if errors.is_empty() {
        Ok(())
    } else {
        // `annotations()` の反復順は非決定的なので、メッセージを安定させる
        errors.sort_unstable();
        Err(PolicyError::Annotation(errors.join("; ")))
    }
}

/// @priority アノテーションの値を検証する
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

/// ポリシーの変更を監視し検証を通った場合は反映するタスクを起動する。
/// `loaded_src` は起動時に検証を通した内容。監視タスクは起動後の初回通知を必ず発火させる
/// (内容ハッシュの比較対象を持たないため)ので、これと突き合わせて空振りを握り潰す
pub fn spawn_reload_task(
    provider: Arc<PolicySetProvider>,
    schema: Arc<Schema>,
    policy_path: String,
    refresh: Duration,
    readiness: Readiness,
    loaded_src: String,
) {
    let (inspector, mut receiver) =
        file_inspector_task(RefreshRate::Other(refresh), policy_path.clone());

    tokio::spawn(async move {
        let _guard = inspector;
        let mut loaded_src = loaded_src;
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    reload(
                        &provider,
                        &schema,
                        &policy_path,
                        &readiness,
                        &event,
                        &mut loaded_src,
                    )
                    .await;
                }
                Err(error) => {
                    error!("policy reload channel closed: {error:?}");
                    break;
                }
            }
        }
    });
}

/// 変更を検知したポリシーを再検証し成功時のみ provider へ反映する。
/// `loaded_src` は provider が現在配っている内容で、反映に成功したときだけ更新する
async fn reload(
    provider: &PolicySetProvider,
    schema: &Schema,
    policy_path: &str,
    readiness: &Readiness,
    event: &impl std::fmt::Debug,
    loaded_src: &mut String,
) {
    let src = match read_source(policy_path) {
        Ok(src) => src,
        Err(error) => {
            error!("policy reload rejected: {error}; serving previous policy");
            readiness.set_ready(false);
            return;
        }
    };

    if src == *loaded_src {
        // 監視タスクの初回通知、および失敗後に元の内容へ戻された場合がここに来る。
        // provider は既にこの内容を配っているので、readiness も戻してよい。
        debug!("policy file event without a content change; skipping reload");
        readiness.set_ready(true);
        return;
    }

    let policy_count = match validate_source(&src, policy_path, schema) {
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
            *loaded_src = src;
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

    /// 検証結果のポリシー数だけを見るテスト向けラッパ。
    fn validate(policy_path: &str, schema: &Schema) -> Result<usize, PolicyError> {
        load_and_validate(policy_path, schema).map(|(_, count)| count)
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

    #[test]
    fn rejects_decision_context_without_a_context_key() {
        // `@decision_context_` だけではキー名が無く、レスポンスに載せようが無い。
        // 黙って無視すると作者は書いた値が出ない理由に気付けないため弾く。
        let ps = policy_set(
            r#"
            @id("no-key")
            @decision_context_("value")
            forbid(principal, action, resource);
            "#,
        );

        let error = validate_decision_contexts(&ps).expect_err("missing key must be rejected");
        assert!(
            error.to_string().contains("no-key"),
            "error should name the policy: {error}"
        );
    }

    #[test]
    fn rejects_decision_context_colliding_with_reserved_keys() {
        // 予約キーは PDP 値で上書きされるため、作者の値はレスポンスに出ない。
        // 出ない値を書けてしまう状態を残さない。全件を1メッセージで報告する。
        let ps = policy_set(
            r#"
            @id("reserved")
            @decision_context_reason("author value")
            @decision_context_errors("author value")
            forbid(principal, action, resource);
            "#,
        );

        let error = validate_decision_contexts(&ps).expect_err("reserved keys must be rejected");
        let message = error.to_string();
        // `annotations()` の反復順は非決定的だが、ソート済みなので順序は固定される。
        assert!(
            message.find("@decision_context_errors").unwrap()
                < message.find("@decision_context_reason").unwrap(),
            "messages should be sorted: {message}"
        );
    }

    #[test]
    fn accepts_well_formed_decision_context_annotations() {
        // 予約キーの「前方一致」で誤検知しないこと（`reason_user` は予約ではない）。
        // `decision_context_` prefix を持たないアノテーションにも反応しない。
        let ps = policy_set(
            r#"
            @id("fine")
            @priority("10")
            @description("not a decision context")
            @decision_context_reason_user("外部認証が必要です")
            @decision_context_step_up("external-auth")
            forbid(principal, action, resource);
            "#,
        );

        assert!(validate_decision_contexts(&ps).is_ok());
    }

    #[test]
    fn validate_rejects_invalid_decision_context_annotation() {
        // スキーマ検証を通っても、`@decision_context_*` が不正なら反映しない。
        // リロード時はこのエラーで readiness を落とし、直前のポリシーを配り続ける。
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(
            &dir,
            "policies.cedar",
            r#"
            @id("reserved")
            @decision_context_reason("author value")
            permit(principal, action == Action::"login", resource);
            "#,
        );

        let error = validate(&path, &test_schema()).expect_err("reserved key must fail validation");
        assert!(
            matches!(error, PolicyError::Annotation(_)),
            "expected Annotation variant, got {error:?}"
        );
    }

    // 検証テスト用の自己完結スキーマ。`User` -> `login` -> `Client` のみ許可する。
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
    fn load_and_validate_returns_the_source_it_validated() {
        // 返した内容は reload 時の「実変更があったか」の比較対象になる。
        // ファイルの中身と一致していないと、変更が無いのにリロードが走る
        // （または実変更を握り潰す）。
        let dir = tempfile::tempdir().expect("tempdir");
        let src = r#"
            @id("allow-login")
            permit(principal, action == Action::"login", resource);
            "#;
        let path = write_file(&dir, "policies.cedar", src);

        let (returned, count) =
            load_and_validate(&path, &test_schema()).expect("policies should validate");

        assert_eq!(returned, src);
        assert_eq!(count, 1);
    }

    #[test]
    fn load_and_validate_distinguishes_whitespace_only_edits() {
        // 比較は内容の完全一致で行う。エディタが末尾に改行を足しただけでも
        // 「変更あり」として再検証されること（取りこぼすより安全側に倒す）。
        let dir = tempfile::tempdir().expect("tempdir");
        let src = r#"@id("allow-login")
            permit(principal, action == Action::"login", resource);"#;
        let path = write_file(&dir, "a.cedar", src);
        let path_with_newline = write_file(&dir, "b.cedar", &format!("{src}\n"));

        let (a, _) = load_and_validate(&path, &test_schema()).expect("should validate");
        let (b, _) =
            load_and_validate(&path_with_newline, &test_schema()).expect("should validate");

        assert_ne!(a, b);
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
