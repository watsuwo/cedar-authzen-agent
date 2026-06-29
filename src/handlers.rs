//! AuthZEN エンドポイント、ヘルスチェック、レディネスチェックの axum ハンドラ
//! 群（DESIGN.md §2, §8, §10）。

use std::sync::atomic::Ordering;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cedar_policy::Decision;
use tracing::{error, info};

use crate::authzen::{AuthzenConfiguration, ErrorBody, EvaluationRequest, EvaluationResponse};
use crate::convert;
use crate::state::AppState;

/// 指定したステータス・コード・メッセージで JSON エラーレスポンスを組み立てる（§8）。
fn error_response(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (status, Json(ErrorBody::new(code, message))).into_response()
}

/// `POST /access/v1/evaluation` — 単一の AuthZEN アクセスリクエストを評価する。
///
/// 成功時は `200 { "decision": <bool> }`、入力が不正なら `400`、認可器自体が
/// 失敗したら `500`。`decision: false` は `forbid` が一致したことを意味し、
/// 外部認証が強制される（DESIGN.md §2.1）。
pub async fn evaluate(State(state): State<AppState>, body: Bytes) -> Response {
    // 1) リクエストボディを AuthZEN の `EvaluationRequest` にデシリアライズ。
    let request: EvaluationRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_json", error.to_string());
        }
    };

    // 2) スキーマ検証しつつ Cedar の `Request`/`Entities` へ変換。変換エラーは
    //    そのまま安定コード付きの 400 にする。
    let (cedar_request, entities) = match convert::to_cedar(&request, &state.schema) {
        Ok(pair) => pair,
        Err(error) => {
            return error_response(StatusCode::BAD_REQUEST, error.code(), error.to_string());
        }
    };

    // 3) cedar-local-agent の `Authorizer::is_authorized` で評価する。内部で
    //    現在のポリシー集合・空のエンティティプロバイダ・リクエスト時エンティティを
    //    使って判定し、OCSF 認可ログも発行される。
    match state.authorizer.is_authorized(&cedar_request, &entities).await {
        Ok(response) => {
            // Cedar の `Allow` を `decision: true`（通常ログイン許可）に対応づける。
            let allowed = response.decision() == Decision::Allow;
            Json(EvaluationResponse::new(allowed)).into_response()
        }
        Err(error) => {
            error!("authorizer failed: {error:?}");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "evaluation_failed",
                "authorization failed",
            )
        }
    }
}

/// `GET /.well-known/authzen-configuration` — PDP のディスカバリメタデータ（§2）。
///
/// 広告するベース URL はリクエストの `Host` ヘッダから導出する。これにより
/// `policy_decision_point` の値が、この文書を取得した URL と一致する。
pub async fn metadata(headers: HeaderMap) -> Json<AuthzenConfiguration> {
    let host = headers
        .get("host")
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
    if state.ready.load(Ordering::Relaxed) {
        StatusCode::OK
    } else {
        info!("readiness probe: not ready (last policy reload failed)");
        StatusCode::SERVICE_UNAVAILABLE
    }
}
