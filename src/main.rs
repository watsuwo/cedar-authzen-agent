mod authzen;
mod config;
mod convert;
mod error;
mod handlers;
mod health;
mod policy;
mod server;
mod state;

use std::process::ExitCode;

use tracing::error;

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

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
