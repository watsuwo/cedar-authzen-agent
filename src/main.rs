//! AuthZEN-compliant authorization sidecar (PDP) backed by `cedar-local-agent`.
//!
//! Runs alongside Keycloak (same ECS task, localhost) and answers, during the
//! authentication flow, whether external authentication federation must be
//! forced for a given user + client. See `DESIGN.md`.
//!
//! Subcommand:
//! - `authzen-sidecar`          — run the HTTP server (default).
//! - `authzen-sidecar health`   — probe a running server's `/healthz` and exit
//!   0/1 (used as the container `healthCheck`, DESIGN.md §10).

mod authzen;
mod config;
mod convert;
mod handlers;
mod state;

use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use cedar_local_agent::public::events::core::{file_inspector_task, RefreshRate};
use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::{self, PolicySetProvider};
use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};
use cedar_local_agent::public::UpdateProviderData;
use cedar_policy::Schema;

use crate::config::Config;
use crate::state::AppState;

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("health") {
        return health_check();
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to start tokio runtime: {error}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run_server()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!("fatal: {error}");
            eprintln!("fatal: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Initialise tracing (incl. the OCSF authorization events emitted by the
/// authorizer), build the authorizer over the S3 Files mount, start the policy
/// reload task, and serve the HTTP API until SIGTERM/Ctrl-C.
async fn run_server() -> Result<(), Box<dyn Error>> {
    init_tracing();

    let cfg = Config::from_env()?;
    info!(
        "starting authzen-sidecar: bind={} policy={} schema={} refresh={:?}",
        cfg.bind, cfg.policy_path, cfg.schema_path, cfg.refresh
    );

    // Load schema (fail-fast on malformed/missing — DESIGN.md §4 ⑤).
    let schema = Arc::new(Schema::from_json_file(File::open(&cfg.schema_path)?)?);

    // Policy provider over the S3 Files mount (fail-fast on malformed/missing).
    let provider = Arc::new(PolicySetProvider::new(
        policy_set_provider::ConfigBuilder::default()
            .policy_set_path(cfg.policy_path.clone())
            .build()
            .map_err(|e| format!("policy provider config: {e}"))?,
    )?);

    // Empty entity store: identity attributes arrive per-request in
    // `subject.properties` and are injected by the convert layer (§2.1).
    let authorizer: Arc<state::SidecarAuthorizer> = Arc::new(Authorizer::new(
        AuthorizerConfigBuilder::default()
            .policy_set_provider(provider.clone())
            .entity_provider(Arc::new(EntityProvider::default()))
            .build()
            .map_err(|e| format!("authorizer config: {e}"))?,
    ));

    // Readiness starts true (startup load succeeded). The reload task flips it
    // to false if a later reload fails (DESIGN.md §10).
    let ready = Arc::new(AtomicBool::new(true));

    spawn_reload_task(provider.clone(), cfg.policy_path.clone(), cfg.refresh, ready.clone());

    let state = AppState {
        authorizer,
        schema,
        ready,
    };

    let app = Router::new()
        .route("/access/v1/evaluation", post(handlers::evaluate))
        .route("/.well-known/authzen-configuration", get(handlers::metadata))
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz))
        .layer(DefaultBodyLimit::max(cfg.body_limit))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    info!("listening on http://{}", cfg.bind);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Watch the policy file (over the S3 Files mount) for changes and reload,
/// recording success/failure into `ready` so `/readyz` reflects reload health.
///
/// This intentionally does not use the library's `update_provider_data_task`,
/// which swallows the result; we need the success/failure signal (DESIGN.md §10).
fn spawn_reload_task(
    provider: Arc<PolicySetProvider>,
    policy_path: String,
    refresh: Duration,
    ready: Arc<AtomicBool>,
) {
    let (_inspector, mut receiver) =
        file_inspector_task(RefreshRate::Other(refresh), policy_path);

    tokio::spawn(async move {
        // Keep the inspector task alive for the lifetime of this task.
        let _inspector = _inspector;
        loop {
            match receiver.recv().await {
                Ok(event) => match provider.update_provider_data().await {
                    Ok(()) => {
                        info!("policy reloaded: {event:?}");
                        ready.store(true, Ordering::Relaxed);
                    }
                    Err(error) => {
                        error!("policy reload failed (serving previous policy): {error:?}");
                        ready.store(false, Ordering::Relaxed);
                    }
                },
                Err(error) => {
                    error!("policy reload channel closed: {error:?}");
                    break;
                }
            }
        }
    });
}

/// Configure the tracing subscriber. Honors `AUTHZ_LOG_FORMAT=json`.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if std::env::var("AUTHZ_LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt().with_env_filter(filter).json().init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

/// Resolve when SIGTERM (unix) or Ctrl-C is received, for graceful shutdown.
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
            Err(error) => error!("failed to install SIGTERM handler: {error}"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    info!("shutdown signal received");
}

/// `health` subcommand: connect to the running server's `/healthz` and exit
/// 0 (healthy) or 1. Uses a blocking TCP client so it works in distroless
/// images with no shell or curl (DESIGN.md §10).
fn health_check() -> ExitCode {
    let target = Config::health_target();
    let stream = match TcpStream::connect_timeout(&target, Duration::from_secs(2)) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("health: connect to {target} failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut stream = stream;
    if stream
        .write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return ExitCode::FAILURE;
    }

    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return ExitCode::FAILURE;
    }

    if response
        .lines()
        .next()
        .is_some_and(|status_line| status_line.contains(" 200"))
    {
        ExitCode::SUCCESS
    } else {
        eprintln!("health: unexpected response: {:?}", response.lines().next());
        ExitCode::FAILURE
    }
}
