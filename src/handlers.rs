//! Axum handlers for the AuthZEN endpoints, health and readiness
//! (DESIGN.md §2, §8, §10).

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

/// Build a JSON error response with the given status, code and message (§8).
fn error_response(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (status, Json(ErrorBody::new(code, message))).into_response()
}

/// `POST /access/v1/evaluation` — evaluate a single AuthZEN access request.
///
/// `200 { "decision": <bool> }` on success; `400` for malformed/invalid input;
/// `500` if the authorizer itself fails. `decision: false` means a `forbid`
/// matched → external authentication is forced (DESIGN.md §2.1).
pub async fn evaluate(State(state): State<AppState>, body: Bytes) -> Response {
    let request: EvaluationRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_json", error.to_string());
        }
    };

    let (cedar_request, entities) = match convert::to_cedar(&request, &state.schema) {
        Ok(pair) => pair,
        Err(error) => {
            return error_response(StatusCode::BAD_REQUEST, error.code(), error.to_string());
        }
    };

    match state.authorizer.is_authorized(&cedar_request, &entities).await {
        Ok(response) => {
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

/// `GET /.well-known/authzen-configuration` — PDP discovery metadata (§2).
///
/// The advertised base URL is derived from the request `Host` header so the
/// `policy_decision_point` value matches the URL used to fetch this document.
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

/// `GET /healthz` — liveness. Returns 200 while the process is running (§10).
pub async fn healthz() -> StatusCode {
    StatusCode::OK
}

/// `GET /readyz` — readiness. 200 when ready, 503 when a reload has failed (§10).
pub async fn readyz(State(state): State<AppState>) -> StatusCode {
    if state.ready.load(Ordering::Relaxed) {
        StatusCode::OK
    } else {
        info!("readiness probe: not ready (last policy reload failed)");
        StatusCode::SERVICE_UNAVAILABLE
    }
}
