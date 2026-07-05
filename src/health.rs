//! `health` サブコマンド: 稼働中サーバの `/healthz` を叩くヘルスチェック
//! クライアント（DESIGN.md §10）。
//!
//! シェルや curl の無い distroless イメージの `healthCheck` から呼ばれるため、
//! 依存を増やさずブロッキングな自前 TCP クライアントで実装する。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::time::Duration;

use crate::config::Config;

/// 接続タイムアウト。コンテナのヘルスチェックが応答しないよりは早く諦める。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// `/healthz` に接続し、0（健全）または 1（異常）で終了する。
pub fn run() -> ExitCode {
    let target = Config::health_target();
    let mut stream = match TcpStream::connect_timeout(&target, CONNECT_TIMEOUT) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("health: connect to {target} failed: {error}");
            return ExitCode::FAILURE;
        }
    };

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

    // ステータスライン（例: `HTTP/1.0 200 OK`）だけ見れば十分。
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
