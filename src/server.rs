use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tracing::info;

use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};

use crate::config::Config;
use crate::state::{AppState, Readiness, SidecarAuthorizer};
use crate::{handlers, policy, telemetry};

pub async fn run() -> Result<(), crate::Error> {
    telemetry::init();

    let cfg = Config::from_env()?;
    info!(
        "starting authzen-sidecar: bind={} policy={} schema={} refresh={:?}",
        cfg.bind, cfg.policy_path, cfg.schema_path, cfg.refresh
    );

    let schema = Arc::new(policy::load_schema(&cfg.schema_path)?);
    let provider = policy::new_provider(&cfg.policy_path)?;

    // スキーマ検証に失敗するポリシーは適用しない
    let policy_count = policy::validate(&cfg.policy_path, &schema)
        .map_err(|e| format!("startup policy schema validation failed: {e}"))?;
    info!("loaded and validated policy set: {policy_count} policies");

    let authorizer = new_authorizer(provider.clone())?;

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
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    info!("listening on http://{}", cfg.bind);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn new_authorizer(
    provider: Arc<PolicySetProvider>,
) -> Result<Arc<SidecarAuthorizer>, crate::Error> {
    let config = AuthorizerConfigBuilder::default()
        .policy_set_provider(provider)
        // リクエストから属性値を取得するので、EntityProvider は空でよい
        .entity_provider(Arc::new(EntityProvider::default()))
        .build()
        .map_err(|e| format!("authorizer config: {e}"))?;
    Ok(Arc::new(Authorizer::new(config)))
}

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

// SIGTERMを受信すると終了させる
async fn shutdown_signal() {
    #[cfg(unix)]
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut sig) => {
            sig.recv().await;
        }
        Err(error) => tracing::error!("failed to install SIGTERM handler: {error}"),
    }

    #[cfg(not(unix))]
    std::future::pending::<()>().await;

    info!("shutdown signal received");
}
