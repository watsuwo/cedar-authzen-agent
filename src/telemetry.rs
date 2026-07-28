use tracing_subscriber::EnvFilter;

/// トレーシングを初期化する。`AUTHZ_LOG_FORMAT=json` の場合はログを JSON 形式で出力する。
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if std::env::var("AUTHZ_LOG_FORMAT").as_deref() == Ok("json") {
        builder.json().init();
    } else {
        builder.init();
    }
}
