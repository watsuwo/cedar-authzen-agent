//! AuthZEN 準拠の認可サイドカー（PDP: Policy Decision Point）。
//! 認可判定そのものは `cedar-local-agent` に委譲する。
//!
//! Keycloak と同一 ECS タスク内（localhost 通信）で動作し、認証フローの最中に
//! 「あるユーザー × クライアントの組み合わせに対して外部認証フェデレーションを
//! 強制すべきか」を回答する。設計の詳細は `DESIGN.md` を参照。
//!
//! サブコマンド:
//! - `authzen-sidecar`          — HTTP サーバを起動する（デフォルト）。
//! - `authzen-sidecar health`   — 稼働中サーバの `/healthz` を叩き、0/1 で終了する。
//!   シェルの無い distroless コンテナの `healthCheck` として利用する（DESIGN.md §10）。

mod authzen;
mod config;
mod convert;
mod handlers;
mod state;

use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use cedar_local_agent::public::events::core::{file_inspector_task, RefreshRate};
use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::{self, PolicySetProvider};
use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};
use cedar_local_agent::public::UpdateProviderData;
use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};

use crate::config::Config;
use crate::state::AppState;

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("health") {
        return health_check();
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

    match runtime.block_on(run_server()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!("fatal: {error}");
            eprintln!("fatal: {error}");
            ExitCode::FAILURE
        }
    }
}

/// トレーシング（認可器が発行する OCSF 認可イベントを含む）を初期化し、S3 Files
/// マウント上のポリシー/スキーマから認可器を構築し、ポリシーのホットリロード
/// タスクを起動して、SIGTERM/Ctrl-C を受け取るまで HTTP API を提供する。
async fn run_server() -> Result<(), Box<dyn Error>> {
    init_tracing();

    let cfg = Config::from_env()?;
    info!(
        "starting authzen-sidecar: bind={} policy={} schema={} refresh={:?}",
        cfg.bind, cfg.policy_path, cfg.schema_path, cfg.refresh
    );

    // cedar-policy の `Schema` をロードする（不正・欠損時は即時失敗 = fail-fast。
    // DESIGN.md §4 ⑤）。`Schema` はリクエスト・ポリシー双方を strict 検証する際の
    // 型情報そのもの。ここで一度だけ JSON からパースし、`Arc` で全ハンドラと
    // リロードタスクに共有する。
    let schema = Arc::new(Schema::from_json_file(File::open(&cfg.schema_path)?)?);

    // cedar-local-agent の `PolicySetProvider`: S3 Files マウント上のポリシー
    // ファイルを読み込み、Cedar の `PolicySet` として保持するプロバイダ。
    //
    // - `Authorizer` は評価のたびにこのプロバイダから現在のポリシー集合を取得する。
    // - `UpdateProviderData::update_provider_data()` を呼ぶとファイルを読み直し、
    //   内部の `PolicySet` をアトミックに差し替える（後述のホットリロードの実体）。
    // - 重要: このプロバイダが行う検証は「構文（パース）」のみ。Config にスキーマ
    //   項目が無く、スキーマに対する型検査は行わないため、型レベルの検証は後段の
    //   `validate_policies` で別途実施する。
    //
    // 構築時にファイルが不正・欠損ならエラー = 起動時 fail-fast。
    let provider = Arc::new(PolicySetProvider::new(
        policy_set_provider::ConfigBuilder::default()
            .policy_set_path(cfg.policy_path.clone())
            .build()
            .map_err(|e| format!("policy provider config: {e}"))?,
    )?);

    // スキーマに対して型検査に通らないポリシーは提供開始前に弾く
    // （DESIGN.md §4 ⑤, §10）。上の `PolicySetProvider` は構文しか見ないため、
    // スキーマが定義しない型・属性・アクションへの参照はこの strict 検証で初めて
    // 捕捉できる。失敗時は起動を中止する（fail-fast）。
    validate_policies(&cfg.policy_path, &schema)
        .map_err(|e| format!("startup policy schema validation failed: {e}"))?;

    // 認可器を構築する。`Authorizer` は cedar-local-agent の高レベル API で、
    // 「ポリシー供給（PolicySetProvider）＋ エンティティ供給（EntityProvider）＋
    // cedar-policy の評価エンジン」を束ねる。`is_authorized()` に AuthZEN リクエスト
    // 由来の `Request`/`Entities` を渡すと `Decision`（Allow/Deny）を返し、同時に
    // OCSF 形式の認可ログを自動発行する。
    //
    // エンティティストアは空（`EntityProvider::default()`）にする。本来 cedar-local-agent
    // の `EntityProvider` はファイルから主体・リソースの静的属性を読み込むが、本 PDP
    // では静的ストアを持たない。アイデンティティ属性はリクエストごとに AuthZEN の
    // `subject.properties` として届き、convert 層が Cedar の principal エンティティ
    // 属性として注入する（§2.1）。静的ストアを使わないことで uid 衝突が原理的に
    // 起きない（§4 ②）。
    let authorizer: Arc<state::SidecarAuthorizer> = Arc::new(Authorizer::new(
        AuthorizerConfigBuilder::default()
            .policy_set_provider(provider.clone())
            .entity_provider(Arc::new(EntityProvider::default()))
            .build()
            .map_err(|e| format!("authorizer config: {e}"))?,
    ));

    // 起動時ロードが成功したので readiness は true で開始する。以降のリロードが
    // 失敗したときだけ、リロードタスクが false に倒す（DESIGN.md §10）。
    let ready = Arc::new(AtomicBool::new(true));

    spawn_reload_task(
        provider.clone(),
        schema.clone(),
        cfg.policy_path.clone(),
        cfg.refresh,
        ready.clone(),
    );

    let state = AppState {
        authorizer,
        schema,
        ready,
    };

    let app = Router::new()
        .route("/access/v1/evaluation", post(handlers::evaluate))
        .route("/.well-known/authzen-configuration", get(handlers::metadata))
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz))
        .layer(DefaultBodyLimit::max(cfg.body_limit))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    info!("listening on http://{}", cfg.bind);
    // axum サーバを起動し、SIGTERM/Ctrl-C でグレースフルにシャットダウンする。
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// S3 Files マウント上のポリシーファイルを監視し、変更があればリロードする。
/// 成否を `ready` に記録するので、`/readyz` がリロードの健全性を反映する。
///
/// あえて cedar-local-agent の `update_provider_data_task` は使わない。あの
/// ヘルパーはリロードの成否を握り潰してしまうため、本実装では成否シグナルを
/// 取得すべく `file_inspector_task` を使った自前のループを回す（DESIGN.md §10）。
///
/// 各変更はプロバイダが差し替える *前* にスキーマ検証する。型検査に通らなく
/// なったポリシーは決して本番に出さず、直前の正常なポリシーで提供を継続しつつ
/// readiness を false に倒す（DESIGN.md §10）。
fn spawn_reload_task(
    provider: Arc<PolicySetProvider>,
    schema: Arc<Schema>,
    policy_path: String,
    refresh: Duration,
    ready: Arc<AtomicBool>,
) {
    // cedar-local-agent の `file_inspector_task`: 指定ファイルを `RefreshRate` の
    // 間隔でポーリングし、変更を検知すると `receiver` にイベントを送るバックグラウンド
    // タスクを起動する。返り値の `_inspector` ハンドルを保持している間だけ監視が続く。
    let (_inspector, mut receiver) =
        file_inspector_task(RefreshRate::Other(refresh), policy_path.clone());

    tokio::spawn(async move {
        // 監視タスクをこの spawn の生存期間中ずっと生かしておく。
        let _inspector = _inspector;
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    // 差し替え前に新ファイルをスキーマ検証する。失敗時は直前の
                    // ポリシーを維持し、不正なポリシーを提供する代わりに not-ready
                    // を報告する。
                    if let Err(error) = validate_policies(&policy_path, &schema) {
                        error!(
                            "policy reload rejected: schema validation failed \
                             ({error}); serving previous policy"
                        );
                        ready.store(false, Ordering::Relaxed);
                        continue;
                    }
                    // 検証を通過したので、プロバイダにファイルを読み直させ内部の
                    // `PolicySet` を差し替える（`UpdateProviderData` トレイト）。
                    match provider.update_provider_data().await {
                        Ok(()) => {
                            info!("policy reloaded: {event:?}");
                            ready.store(true, Ordering::Relaxed);
                        }
                        Err(error) => {
                            error!("policy reload failed (serving previous policy): {error:?}");
                            ready.store(false, Ordering::Relaxed);
                        }
                    }
                }
                Err(error) => {
                    // チャネルが閉じた = 監視タスクが終了した。ループを抜ける。
                    error!("policy reload channel closed: {error:?}");
                    break;
                }
            }
        }
    });
}

/// `policy_path` の Cedar ポリシーファイルを `schema` に対して strict に検証する。
///
/// 型検査に通らない場合（スキーマが定義しないエンティティ型・属性・アクションを
/// 参照している等）に、人間可読な要約付きで `Err` を返す。起動時（fail-fast）と
/// 各ホットリロード前（新ポリシーを却下し直前のものを維持）の両方で使う
/// （DESIGN.md §4 ⑤）。
fn validate_policies(policy_path: &str, schema: &Schema) -> Result<(), String> {
    // ファイルを読み、cedar-policy の `PolicySet` としてパースする（構文検証）。
    let src = std::fs::read_to_string(policy_path)
        .map_err(|e| format!("read `{policy_path}`: {e}"))?;
    let policy_set =
        PolicySet::from_str(&src).map_err(|e| format!("parse `{policy_path}`: {e}"))?;
    // cedar-policy の `Validator` でポリシー集合を型検査する。`ValidationMode::Strict`
    // はスキーマに厳密一致しない参照をすべて誤りとして扱う最も厳しいモード。
    let result = Validator::new(schema.clone()).validate(&policy_set, ValidationMode::Strict);
    if result.validation_passed() {
        Ok(())
    } else {
        let errors = result
            .validation_errors()
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        Err(errors)
    }
}

/// トレーシングサブスクライバを設定する。`AUTHZ_LOG_FORMAT=json` を尊重し、
/// 設定時は OCSF 認可ログを含む全ログを JSON 形式で出力する。
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if std::env::var("AUTHZ_LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt().with_env_filter(filter).json().init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

/// SIGTERM（unix）または Ctrl-C を受信したら解決する Future。グレースフル
/// シャットダウン用に `axum::serve` へ渡す。
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(error) => error!("failed to install SIGTERM handler: {error}"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    // どちらかのシグナルが先に来た時点で解決する。
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    info!("shutdown signal received");
}

/// `health` サブコマンド: 稼働中サーバの `/healthz` に接続し、0（健全）または 1 で
/// 終了する。シェルや curl の無い distroless イメージでも動くよう、ブロッキングな
/// 自前 TCP クライアントを使う（DESIGN.md §10）。
fn health_check() -> ExitCode {
    let target = Config::health_target();
    let stream = match TcpStream::connect_timeout(&target, Duration::from_secs(2)) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("health: connect to {target} failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut stream = stream;
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
