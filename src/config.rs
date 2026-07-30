//! 環境変数から読み込むランタイム設定

use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;

const DEFAULT_BIND: &str = "127.0.0.1:9000";

#[derive(Debug, Clone)]
pub struct Config {
    /// バインドアドレス（`AUTHZ_BIND`）
    pub bind: SocketAddr,
    /// ポリシーファイルのパス（`AUTHZ_POLICY_PATH`）
    pub policy_path: String,
    /// スキーマファイルのパス（`AUTHZ_SCHEMA_PATH`）
    pub schema_path: String,
    /// ポリシー変更検知のポーリング間隔（`AUTHZ_POLICY_REFRESH_SECS`）
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
        let bind = parse_env("AUTHZ_BIND", DEFAULT_BIND)?;
        let policy_path = require_env("AUTHZ_POLICY_PATH")?;
        let schema_path = require_env("AUTHZ_SCHEMA_PATH")?;
        let refresh_secs: u64 = parse_env("AUTHZ_POLICY_REFRESH_SECS", "30")?;
        Ok(Self {
            bind,
            policy_path,
            schema_path,
            refresh: Duration::from_secs(refresh_secs),
        })
    }

    pub fn health_target() -> SocketAddr {
        resolve_health_target(&env_or("AUTHZ_BIND", DEFAULT_BIND))
    }
}

fn resolve_health_target(bind: &str) -> SocketAddr {
    let Ok(addr) = bind.parse::<SocketAddr>() else {
        return DEFAULT_BIND.parse().expect("default bind must be valid");
    };
    if addr.ip().is_unspecified() {
        SocketAddr::from(([127, 0, 0, 1], addr.port()))
    } else {
        addr
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn require_env(key: &'static str) -> Result<String, ConfigError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(value: &str) -> SocketAddr {
        value.parse().expect("test address should parse")
    }

    #[test]
    fn health_target_keeps_a_concrete_address() {
        assert_eq!(
            resolve_health_target("10.0.0.5:8080"),
            addr("10.0.0.5:8080")
        );
    }

    #[test]
    fn health_target_rewrites_unspecified_addresses_to_loopback() {
        assert_eq!(
            resolve_health_target("0.0.0.0:8080"),
            addr("127.0.0.1:8080")
        );
        assert_eq!(resolve_health_target("[::]:8080"), addr("127.0.0.1:8080"));
    }

    #[test]
    fn health_target_keeps_the_configured_port() {
        assert_eq!(resolve_health_target("0.0.0.0:1234").port(), 1234);
    }

    #[test]
    fn health_target_falls_back_when_unparsable() {
        assert_eq!(resolve_health_target("not-an-address"), addr(DEFAULT_BIND));
        assert_eq!(resolve_health_target(""), addr(DEFAULT_BIND));
    }
}
