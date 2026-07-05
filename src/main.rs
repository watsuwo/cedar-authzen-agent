mod authzen;
mod config;
mod convert;
mod error;
mod handlers;
mod health;
mod policy;
mod server;
mod state;
mod telemetry;

use std::process::ExitCode;

use tracing::error;

/// crate 共通のボックス化エラー型。起動経路のように「呼び出し元が種別で分岐
/// しない」エラーはこれで十分で、`?` と `format!` による文脈付与だけで済む
/// （linkerd2-proxy の `linkerd_error::Error` と同じ流儀）。
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

/// エントリポイント。サブコマンドの振り分けとランタイム起動のみを行い、
/// サーバ本体の組み立ては `server::run` に委譲する。
fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("health") {
        return health::run();
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

    match runtime.block_on(server::run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!("fatal: {error}");
            eprintln!("fatal: {error}");
            ExitCode::FAILURE
        }
    }
}
