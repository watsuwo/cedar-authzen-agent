//! AuthZEN エンドポイント、ヘルスチェック、レディネスチェックの axum ハンドラ
//! 群（DESIGN.md §2, §8, §10）。
//!
//! 失敗しうるハンドラは `Result<_, ApiError>` を返す。ステータスコードと
//! JSON エラーボディへの変換は [`ApiError`] の `IntoResponse` 実装に集約
//! されているため、ここでは `?` で伝播するだけでよい。

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::Json;
use cedar_policy::Decision;
use tracing::{error, info};

use crate::authzen::{AuthzenConfiguration, EvaluationRequest, EvaluationResponse};
use crate::convert;
use crate::error::ApiError;
use crate::state::AppState;

/// `POST /access/v1/evaluation` — 単一の AuthZEN アクセスリクエストを評価する。
///
/// 成功時は `200 { "decision": <bool> }`、入力が不正なら `400`、認可器自体が
/// 失敗したら `500`。`decision: false` は `forbid` が一致したことを意味し、
/// 外部認証が強制される（DESIGN.md §2.1）。
pub async fn evaluate(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<EvaluationResponse>, ApiError> {
    // 1) リクエストボディを AuthZEN の `EvaluationRequest` にデシリアライズ。
    let request: EvaluationRequest = serde_json::from_slice(&body)?;

    // 2) スキーマ検証しつつ Cedar の `Request`/`Entities` へ変換。変換エラーは
    //    そのまま安定コード付きの 400 になる。
    let (cedar_request, entities) = convert::to_cedar(&request, &state.schema)?;

    // 3) cedar-local-agent の `Authorizer::is_authorized` で評価する。内部で
    //    現在のポリシー集合・空のエンティティプロバイダ・リクエスト時エンティティを
    //    使って判定し、OCSF 認可ログも発行される。詳細はログにのみ出し、
    //    クライアントには漏らさない。
    let response = state
        .authorizer
        .is_authorized(&cedar_request, &entities)
        .await
        .map_err(|error| {
            error!("authorizer failed: {error:?}");
            ApiError::Evaluation
        })?;

    // Cedar の `Allow` を `decision: true`（通常ログイン許可）に対応づける。
    let allowed = response.decision() == Decision::Allow;
    Ok(Json(EvaluationResponse::new(allowed)))
}

/// `GET /.well-known/authzen-configuration` — PDP のディスカバリメタデータ（§2）。
///
/// 広告するベース URL はリクエストの `Host` ヘッダから導出する。これにより
/// `policy_decision_point` の値が、この文書を取得した URL と一致する。
pub async fn metadata(headers: HeaderMap) -> Json<AuthzenConfiguration> {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost");
    let base = format!("http://{host}");
    Json(AuthzenConfiguration {
        access_evaluation_endpoint: format!("{base}/access/v1/evaluation"),
        policy_decision_point: base,
    })
}

/// `GET /healthz` — liveness（生存確認）。プロセスが動いている限り 200 を返す（§10）。
pub async fn healthz() -> StatusCode {
    StatusCode::OK
}

/// `GET /readyz` — readiness（受付可否）。準備完了なら 200、リロード失敗時は
/// 503 を返す（§10）。
pub async fn readyz(State(state): State<AppState>) -> StatusCode {
    if state.readiness.is_ready() {
        StatusCode::OK
    } else {
        info!("readiness probe: not ready (last policy reload failed)");
        StatusCode::SERVICE_UNAVAILABLE
    }
}
