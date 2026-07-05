//! 環境変数から読み込むランタイム設定（DESIGN.md §6）。

use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;

/// ライブラリ（cedar-local-agent）の指針で推奨される、ポリシー更新間隔の最小値
/// （15 秒以上）。これより短い値が指定されても 15 秒に切り上げる。
const MIN_REFRESH_SECS: u64 = 15;

/// 環境から解決したサイドカーの設定。
#[derive(Debug, Clone)]
pub struct Config {
    /// HTTP サーバをバインドするアドレス（`AUTHZ_BIND`）。
    pub bind: SocketAddr,
    /// S3 Files マウント上の Cedar ポリシーファイルのパス（`AUTHZ_POLICY_PATH`）。
    pub policy_path: String,
    /// S3 Files マウント上の Cedar スキーマ（JSON）のパス（`AUTHZ_SCHEMA_PATH`）。
    pub schema_path: String,
    /// ポリシーファイル変更検知のためのポーリング間隔（`AUTHZ_POLICY_REFRESH_SECS`）。
    pub refresh: Duration,
    /// リクエストボディの最大サイズ（バイト, `AUTHZ_REQUEST_BODY_LIMIT`）。
    pub body_limit: usize,
}

/// 設定読み込み中に生じるエラー。
#[derive(Debug, Error)]
pub enum ConfigError {
    /// 必須の環境変数が設定されていない。
    #[error("missing required environment variable: {0}")]
    Missing(&'static str),
    /// 環境変数の値をパースできなかった。
    #[error("invalid value for {0}: {1}")]
    Invalid(&'static str, String),
}

impl Config {
    /// プロセスの環境から設定を読み込み、デフォルトを適用する。
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind = parse_env("AUTHZ_BIND", "127.0.0.1:9000")?;

        let policy_path = require("AUTHZ_POLICY_PATH")?;
        let schema_path = require("AUTHZ_SCHEMA_PATH")?;

        let refresh_secs: u64 = parse_env("AUTHZ_POLICY_REFRESH_SECS", "30")?;
        let refresh = Duration::from_secs(refresh_secs.max(MIN_REFRESH_SECS));

        let body_limit = parse_env("AUTHZ_REQUEST_BODY_LIMIT", "65536")?;

        Ok(Self {
            bind,
            policy_path,
            schema_path,
            refresh,
            body_limit,
        })
    }

    /// `health` サブコマンドが接続すべきアドレスを解決する。
    ///
    /// `AUTHZ_BIND` のみを読む。バインドホストが未指定（`0.0.0.0`）の場合は、
    /// 代わりにループバック宛てに接続する。
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

/// 環境変数（未設定時は `default`）を任意の `FromStr` 型としてパースする。
/// 失敗時はどの変数が不正かを示す `ConfigError::Invalid` を返す。
fn parse_env<T>(key: &'static str, default: &str) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    env_or(key, default)
        .parse()
        .map_err(|e: T::Err| ConfigError::Invalid(key, e.to_string()))
}
