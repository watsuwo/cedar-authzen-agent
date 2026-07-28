//! 環境変数から読み込むランタイム設定。

use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;

/// `AUTHZ_BIND` 未設定時のバインドアドレス
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
    /// 環境変数から設定を読み込む。必須変数が無い場合はエラー。
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

    /// ヘルスチェックの接続先。`0.0.0.0` 等の未指定アドレスはループバックへ読み替える。
    pub fn health_target() -> SocketAddr {
        resolve_health_target(&env_or("AUTHZ_BIND", DEFAULT_BIND))
    }
}

/// バインドアドレス文字列をヘルスチェックの接続先へ解決する。
/// 未指定アドレス（`0.0.0.0` 等）とパース不能な値はループバックへ読み替える。
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
        // 具体アドレス指定はそのまま使う（読み替えが効きすぎないこと）。
        assert_eq!(
            resolve_health_target("10.0.0.5:8080"),
            addr("10.0.0.5:8080")
        );
    }

    #[test]
    fn health_target_rewrites_unspecified_addresses_to_loopback() {
        // コンテナでは 0.0.0.0 にバインドするが、これは「全 IF で待ち受ける」
        // 意味で接続先にはできない。HEALTHCHECK 用にループバックへ読み替える。
        // IPv6 の未指定アドレス `[::]` も同様に扱う。
        assert_eq!(
            resolve_health_target("0.0.0.0:8080"),
            addr("127.0.0.1:8080")
        );
        assert_eq!(resolve_health_target("[::]:8080"), addr("127.0.0.1:8080"));
    }

    #[test]
    fn health_target_keeps_the_configured_port() {
        // 読み替えるのは IP だけ。ポートを既定値に戻すと接続先を間違える。
        assert_eq!(resolve_health_target("0.0.0.0:1234").port(), 1234);
    }

    #[test]
    fn health_target_falls_back_when_unparsable() {
        // 不正な `AUTHZ_BIND` でもヘルスチェックは動かす必要があるため、
        // panic せず既定値へ落とす。
        assert_eq!(resolve_health_target("not-an-address"), addr(DEFAULT_BIND));
        assert_eq!(resolve_health_target(""), addr(DEFAULT_BIND));
    }
}
