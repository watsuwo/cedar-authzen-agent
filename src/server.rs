use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use tracing::info;
use tracing_subscriber::EnvFilter;

use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};

use crate::config::Config;
use crate::state::{AppState, PdpAuthorizer, Readiness};
use crate::{handlers, policy};

pub async fn run() -> Result<(), crate::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let cfg = Config::from_env()?;
    info!(
        "starting: bind={} policy={} schema={} refresh={:?}",
        cfg.bind, cfg.policy_path, cfg.schema_path, cfg.refresh
    );

    let schema = Arc::new(policy::load_schema(&cfg.schema_path)?);
    let provider = policy::new_provider(&cfg.policy_path)?;
    let policy_count = policy::validate(&cfg.policy_path, &schema)
        .map_err(|e| format!("startup policy validation failed: {e}"))?;
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

fn new_authorizer(provider: Arc<PolicySetProvider>) -> Result<Arc<PdpAuthorizer>, crate::Error> {
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
