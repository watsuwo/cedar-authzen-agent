//! Cedar ポリシー/スキーマの読み込み・検証・ホットリロード
//! （DESIGN.md §4 ⑤, §10）。
//!
//! サーバ配線（`server`）から「ポリシーのライフサイクル」に関する責務を
//! 切り出したモジュール。起動時の fail-fast 検証と、稼働中のホットリロード
//! （検証つき）の両方をここで担う。

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

/// ポリシーの読み込み・検証で生じるエラー。どの段階（読み込み / 構文 /
/// 型検査）で失敗したかをバリアントで区別し、文脈（パス）を持たせる。
#[derive(Debug, Error)]
pub enum PolicyError {
    /// ポリシーファイルを読み込めなかった。
    #[error("read `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// Cedar ポリシーとしてパースできなかった（構文エラー）。
    /// `ParseErrors` はサイズが大きいため、`Result` の肥大化を避けて Box に包む。
    #[error("parse `{path}`: {source}")]
    Parse {
        path: String,
        #[source]
        source: Box<cedar_policy::ParseErrors>,
    },
    /// スキーマに対する型検査（strict validation)に失敗した。
    #[error("schema validation: {0}")]
    Validation(String),
}

/// cedar-policy の `Schema` を JSON ファイルからロードする。不正・欠損時は
/// 即時失敗（fail-fast。DESIGN.md §4 ⑤）。`Schema` はリクエスト・ポリシー
/// 双方を strict 検証する際の型情報そのもので、起動時に一度だけパースし
/// `Arc` で全ハンドラとリロードタスクに共有する。
pub fn load_schema(path: &str) -> Result<Schema, crate::Error> {
    let file = std::fs::File::open(path).map_err(|e| format!("open schema `{path}`: {e}"))?;
    let schema = Schema::from_json_file(file).map_err(|e| format!("parse schema `{path}`: {e}"))?;
    Ok(schema)
}

/// cedar-local-agent の `PolicySetProvider` を構築する。S3 Files マウント上の
/// ポリシーファイルを読み込み、Cedar の `PolicySet` として保持するプロバイダ。
///
/// - `Authorizer` は評価のたびにこのプロバイダから現在のポリシー集合を取得する。
/// - `UpdateProviderData::update_provider_data()` を呼ぶとファイルを読み直し、
///   内部の `PolicySet` をアトミックに差し替える（ホットリロードの実体）。
/// - 重要: このプロバイダが行う検証は「構文（パース）」のみ。スキーマに対する
///   型検査は行わないため、型レベルの検証は [`validate`] で別途実施する。
///
/// 構築時にファイルが不正・欠損ならエラー = 起動時 fail-fast。
pub fn new_provider(policy_path: &str) -> Result<Arc<PolicySetProvider>, crate::Error> {
    let config = policy_set_provider::ConfigBuilder::default()
        .policy_set_path(policy_path.to_string())
        .build()
        .map_err(|e| format!("policy provider config: {e}"))?;
    Ok(Arc::new(PolicySetProvider::new(config)?))
}

/// `policy_path` の Cedar ポリシーファイルを `schema` に対して strict に検証する。
///
/// 型検査に通らない場合（スキーマが定義しないエンティティ型・属性・アクションを
/// 参照している等）に、人間可読な要約付きで `Err` を返す。起動時（fail-fast）と
/// 各ホットリロード前（新ポリシーを却下し直前のものを維持）の両方で使う
/// （DESIGN.md §4 ⑤）。
pub fn validate(policy_path: &str, schema: &Schema) -> Result<(), PolicyError> {
    // ファイルを読み、cedar-policy の `PolicySet` としてパースする（構文検証）。
    let src = std::fs::read_to_string(policy_path).map_err(|source| PolicyError::Read {
        path: policy_path.to_string(),
        source,
    })?;
    let policy_set = PolicySet::from_str(&src).map_err(|source| PolicyError::Parse {
        path: policy_path.to_string(),
        source: Box::new(source),
    })?;

    // cedar-policy の `Validator` でポリシー集合を型検査する。`ValidationMode::Strict`
    // はスキーマに厳密一致しない参照をすべて誤りとして扱う最も厳しいモード。
    let result = Validator::new(schema.clone()).validate(&policy_set, ValidationMode::Strict);
    if result.validation_passed() {
        return Ok(());
    }
    let errors = result
        .validation_errors()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    Err(PolicyError::Validation(errors))
}

/// S3 Files マウント上のポリシーファイルを監視し、変更があればリロードする
/// バックグラウンドタスクを起動する。成否を `readiness` に記録するので、
/// `/readyz` がリロードの健全性を反映する。
///
/// あえて cedar-local-agent の `update_provider_data_task` は使わない。あの
/// ヘルパーはリロードの成否を握り潰してしまうため、本実装では成否シグナルを
/// 取得すべく `file_inspector_task` を使った自前のループを回す（DESIGN.md §10）。
///
/// 各変更はプロバイダが差し替える *前* にスキーマ検証する。型検査に通らなく
/// なったポリシーは決して本番に出さず、直前の正常なポリシーで提供を継続しつつ
/// readiness を false に倒す（DESIGN.md §10）。
pub fn spawn_reload_task(
    provider: Arc<PolicySetProvider>,
    schema: Arc<Schema>,
    policy_path: String,
    refresh: Duration,
    readiness: Readiness,
) {
    // cedar-local-agent の `file_inspector_task`: 指定ファイルを `RefreshRate` の
    // 間隔でポーリングし、変更を検知すると `receiver` にイベントを送るバックグラウンド
    // タスクを起動する。返り値の `inspector` ハンドルを保持している間だけ監視が続く。
    let (inspector, mut receiver) =
        file_inspector_task(RefreshRate::Other(refresh), policy_path.clone());

    tokio::spawn(async move {
        // 監視タスクをこの spawn の生存期間中ずっと生かしておく。
        let _guard = inspector;
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    reload(&provider, &schema, &policy_path, &readiness, &event).await;
                }
                Err(error) => {
                    // チャネルが閉じた = 監視タスクが終了した。ループを抜ける。
                    error!("policy reload channel closed: {error:?}");
                    break;
                }
            }
        }
    });
}

/// 変更イベント 1 件ぶんのリロードを行い、結果を `readiness` に反映する。
async fn reload(
    provider: &PolicySetProvider,
    schema: &Schema,
    policy_path: &str,
    readiness: &Readiness,
    event: &impl std::fmt::Debug,
) {
    // 差し替え前に新ファイルをスキーマ検証する。失敗時は直前のポリシーを維持し、
    // 不正なポリシーを提供する代わりに not-ready を報告する。
    if let Err(error) = validate(policy_path, schema) {
        error!(
            "policy reload rejected: schema validation failed ({error}); serving previous policy"
        );
        readiness.set(false);
        return;
    }
    // 検証を通過したので、プロバイダにファイルを読み直させ内部の `PolicySet` を
    // 差し替える（`UpdateProviderData` トレイト）。
    match provider.update_provider_data().await {
        Ok(()) => {
            info!("policy reloaded: {event:?}");
            readiness.set(true);
        }
        Err(error) => {
            error!("policy reload failed (serving previous policy): {error:?}");
            readiness.set(false);
        }
    }
}
