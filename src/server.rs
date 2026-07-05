//! サーバの組み立てと起動（配線・ルーティング・グレースフルシャットダウン）。
//!
//! 各コンポーネントの構築は専用モジュール（`policy`, `telemetry` など）に委譲し、
//! ここでは「順番につなぐ」ことだけに徹する。

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use tracing::info;

use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};

use crate::config::Config;
use crate::state::{AppState, Readiness, SidecarAuthorizer};
use crate::{handlers, policy, telemetry};

/// トレーシング（認可器が発行する OCSF 認可イベントを含む）を初期化し、S3 Files
/// マウント上のポリシー/スキーマから認可器を構築し、ポリシーのホットリロード
/// タスクを起動して、SIGTERM/Ctrl-C を受け取るまで HTTP API を提供する。
pub async fn run() -> Result<(), crate::Error> {
    telemetry::init();

    let cfg = Config::from_env()?;
    info!(
        "starting authzen-sidecar: bind={} policy={} schema={} refresh={:?}",
        cfg.bind, cfg.policy_path, cfg.schema_path, cfg.refresh
    );

    let schema = Arc::new(policy::load_schema(&cfg.schema_path)?);
    let provider = policy::new_provider(&cfg.policy_path)?;

    // スキーマに対して型検査に通らないポリシーは提供開始前に弾く
    // （DESIGN.md §4 ⑤, §10）。`PolicySetProvider` は構文しか見ないため、
    // スキーマが定義しない型・属性・アクションへの参照はこの strict 検証で
    // 初めて捕捉できる。失敗時は起動を中止する（fail-fast）。
    let policy_count = policy::validate(&cfg.policy_path, &schema)
        .map_err(|e| format!("startup policy schema validation failed: {e}"))?;
    info!("loaded and validated policy set: {policy_count} policies");

    let authorizer = new_authorizer(provider.clone())?;

    // 起動時ロードが成功したので readiness は true で開始する。以降のリロードが
    // 失敗したときだけ、リロードタスクが false に倒す（DESIGN.md §10）。
    let readiness = Readiness::new(true);

    policy::spawn_reload_task(
        provider.clone(),
        schema.clone(),
        cfg.policy_path.clone(),
        cfg.refresh,
        readiness.clone(),
    );

    let state = AppState {
        authorizer,
        provider,
        schema,
        readiness,
    };
    let app = router(state).layer(DefaultBodyLimit::max(cfg.body_limit));

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    info!("listening on http://{}", cfg.bind);
    // axum サーバを起動し、SIGTERM/Ctrl-C でグレースフルにシャットダウンする。
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// 認可器を構築する。`Authorizer` は cedar-local-agent の高レベル API で、
/// 「ポリシー供給（PolicySetProvider）＋ エンティティ供給（EntityProvider）＋
/// cedar-policy の評価エンジン」を束ねる。`is_authorized()` に AuthZEN リクエスト
/// 由来の `Request`/`Entities` を渡すと `Decision`（Allow/Deny）を返し、同時に
/// OCSF 形式の認可ログを自動発行する。
///
/// エンティティストアは空（`EntityProvider::default()`）にする。本来 cedar-local-agent
/// の `EntityProvider` はファイルから主体・リソースの静的属性を読み込むが、本 PDP
/// では静的ストアを持たない。アイデンティティ属性はリクエストごとに AuthZEN の
/// `subject.properties` として届き、convert 層が Cedar の principal エンティティ
/// 属性として注入する（§2.1）。静的ストアを使わないことで uid 衝突が原理的に
/// 起きない（§4 ②）。
fn new_authorizer(
    provider: Arc<PolicySetProvider>,
) -> Result<Arc<SidecarAuthorizer>, crate::Error> {
    let config = AuthorizerConfigBuilder::default()
        .policy_set_provider(provider)
        .entity_provider(Arc::new(EntityProvider::default()))
        .build()
        .map_err(|e| format!("authorizer config: {e}"))?;
    Ok(Arc::new(Authorizer::new(config)))
}

/// ルーティングテーブル（DESIGN.md §2, §10）。
fn router(state: AppState) -> Router {
    Router::new()
        .route("/access/v1/evaluation", post(handlers::evaluate))
        .route(
            "/.well-known/authzen-configuration",
            get(handlers::metadata),
        )
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz))
        .with_state(state)
}

/// SIGTERM（unix）または Ctrl-C を受信したら解決する Future。グレースフル
/// シャットダウン用に `axum::serve` へ渡す。
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(error) => tracing::error!("failed to install SIGTERM handler: {error}"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    // どちらかのシグナルが先に来た時点で解決する。
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    info!("shutdown signal received");
}
