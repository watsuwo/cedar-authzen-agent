//! 環境変数から読み込むランタイム設定。

use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Config {
    // バインドアドレス（AUTHZ_BIND）
    pub bind: SocketAddr,
    // ポリシーファイルのパス（AUTHZ_POLICY_PATH）
    pub policy_path: String,
    // スキーマファイルのパス（AUTHZ_SCHEMA_PATH）
    pub schema_path: String,
    // ポリシー変更検知のポーリング間隔（AUTHZ_POLICY_REFRESH_SECS）
    pub refresh: Duration,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    Missing(&'static str),
    #[error("invalid value for {0}: {1}")]
    Invalid(&'static str, String),
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind = parse_env("AUTHZ_BIND", "127.0.0.1:9000")?;
        let policy_path = require("AUTHZ_POLICY_PATH")?;
        let schema_path = require("AUTHZ_SCHEMA_PATH")?;
        let refresh_secs: u64 = parse_env("AUTHZ_POLICY_REFRESH_SECS", "30")?;
        Ok(Self {
            bind,
            policy_path,
            schema_path,
            refresh: Duration::from_secs(refresh_secs),
        })
    }

    pub fn health_target() -> SocketAddr {
        let bind = env_or("AUTHZ_BIND", "127.0.0.1:9000");
        let addr: SocketAddr = bind
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 9000)));
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

fn parse_env<T>(key: &'static str, default: &str) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    env_or(key, default)
        .parse()
        .map_err(|e: T::Err| ConfigError::Invalid(key, e.to_string()))
}