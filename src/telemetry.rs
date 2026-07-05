//! トレーシング（ログ）サブスクライバの初期化。
//!
//! 認可器が発行する OCSF 認可イベントもこのサブスクライバを通って出力される。

use tracing_subscriber::EnvFilter;

/// トレーシングサブスクライバを設定する。`AUTHZ_LOG_FORMAT=json` を尊重し、
/// 設定時は OCSF 認可ログを含む全ログを JSON 形式で出力する。
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if std::env::var("AUTHZ_LOG_FORMAT").as_deref() == Ok("json") {
        builder.json().init();
    } else {
        builder.init();
    }
}
