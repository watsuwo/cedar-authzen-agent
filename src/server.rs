use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use tracing::info;
use tracing_subscriber::EnvFilter;

use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::log::{
    Config as LogConfig, ConfigBuilder as LogConfigBuilder, FieldLevel, FieldSetBuilder,
};
use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};

use crate::config::Config;
use crate::state::{AppState, PdpAuthorizer, Readiness};
use crate::{handlers, policy};

const DEFAULT_LOG_FILTER: &str = "info,cedar_local_agent=warn";

pub async fn run() -> Result<(), crate::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER)),
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
    let (policy_src, policy_count) = policy::load_and_validate(&cfg.policy_path, &schema)
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
        policy_src,
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
        // リクエストから属性値を取得するのでEntityProviderは空でよい
        .entity_provider(Arc::new(EntityProvider::default()))
        .log_config(log_config()?)
        .build()
        .map_err(|e| format!("authorizer config: {e}"))?;
    Ok(Arc::new(Authorizer::new(config)))
}

fn log_config() -> Result<LogConfig, crate::Error> {
    let field_set = FieldSetBuilder::default()
        .principal(true)
        .action(true)
        .resource(true)
        .context(true)
        .entities(FieldLevel::All)
        .build()
        .map_err(|e| format!("field set: {e}"))?;

    LogConfigBuilder::default()
        .field_set(field_set)
        .build()
        .map_err(|e| format!("log config: {e}").into())
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
