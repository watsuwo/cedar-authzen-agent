//! Runtime configuration, loaded from environment variables (DESIGN.md §6).

use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;

/// Minimum policy refresh interval enforced by the library guidance (>= 15s).
const MIN_REFRESH_SECS: u64 = 15;

/// Sidecar configuration resolved from the environment.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to bind the HTTP server to (`AUTHZ_BIND`).
    pub bind: SocketAddr,
    /// Path to the Cedar policy file on the S3 Files mount (`AUTHZ_POLICY_PATH`).
    pub policy_path: String,
    /// Path to the Cedar schema (JSON) on the S3 Files mount (`AUTHZ_SCHEMA_PATH`).
    pub schema_path: String,
    /// Polling interval for detecting policy file changes (`AUTHZ_POLICY_REFRESH_SECS`).
    pub refresh: Duration,
    /// Maximum request body size in bytes (`AUTHZ_REQUEST_BODY_LIMIT`).
    pub body_limit: usize,
}

/// Errors raised while loading configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// A required environment variable was not set.
    #[error("missing required environment variable: {0}")]
    Missing(&'static str),
    /// An environment variable held an unparseable value.
    #[error("invalid value for {0}: {1}")]
    Invalid(&'static str, String),
}

impl Config {
    /// Load configuration from the process environment, applying defaults.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind = env_or("AUTHZ_BIND", "127.0.0.1:9000");
        let bind: SocketAddr = bind
            .parse()
            .map_err(|e| ConfigError::Invalid("AUTHZ_BIND", format!("{e}")))?;

        let policy_path = require("AUTHZ_POLICY_PATH")?;
        let schema_path = require("AUTHZ_SCHEMA_PATH")?;

        let refresh_secs: u64 = env_or("AUTHZ_POLICY_REFRESH_SECS", "30")
            .parse()
            .map_err(|e| ConfigError::Invalid("AUTHZ_POLICY_REFRESH_SECS", format!("{e}")))?;
        let refresh = Duration::from_secs(refresh_secs.max(MIN_REFRESH_SECS));

        let body_limit: usize = env_or("AUTHZ_REQUEST_BODY_LIMIT", "65536")
            .parse()
            .map_err(|e| ConfigError::Invalid("AUTHZ_REQUEST_BODY_LIMIT", format!("{e}")))?;

        Ok(Self {
            bind,
            policy_path,
            schema_path,
            refresh,
            body_limit,
        })
    }

    /// Resolve the address the `health` subcommand should connect to.
    ///
    /// Reads only `AUTHZ_BIND`; if the bind host is unspecified (`0.0.0.0`),
    /// connect over loopback instead.
    pub fn health_target() -> SocketAddr {
        let bind = env_or("AUTHZ_BIND", "127.0.0.1:9000");
        let addr: SocketAddr = bind.parse().unwrap_or_else(|_| {
            SocketAddr::from(([127, 0, 0, 1], 9000))
        });
        if addr.ip().is_unspecified() {
            SocketAddr::from(([127, 0, 0, 1], addr.port()))
        } else {
            addr
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn require(key: &'static str) -> Result<String, ConfigError> {
    std::env::var(key).map_err(|_| ConfigError::Missing(key))
}
