use std::time::Instant;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::Json;
use cedar_local_agent::public::SimplePolicySetProvider;
use cedar_policy::Decision;
use tracing::{error, info, warn};

use crate::authzen::{AuthzenConfiguration, EvaluationRequest, EvaluationResponse};
use crate::convert;
use crate::error::ApiError;
use crate::state::AppState;

pub async fn evaluate(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<EvaluationResponse>, ApiError> {
    let started = Instant::now();

    let request: EvaluationRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            warn!(
                error_code = "invalid_json",
                body_len = body.len(),
                "rejected evaluation request: malformed JSON body: {error}"
            );
            return Err(ApiError::InvalidJson(error));
        }
    };

    let subject = format!("{}::{}", request.subject.entity_type, request.subject.id);
    let resource = format!("{}::{}", request.resource.entity_type, request.resource.id);
    let action = request.action.name.clone();

    let (cedar_request, entities) = match convert::to_cedar(&request, &state.schema) {
        Ok(pair) => pair,
        Err(error) => {
            warn!(
                error_code = error.code(),
                %subject, %action, %resource,
                "rejected evaluation request: schema validation failed: {error}"
            );
            return Err(ApiError::Conversion(error));
        }
    };

    let response = match state
        .authorizer
        .is_authorized(&cedar_request, &entities)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            error!(
                %subject, %action, %resource,
                latency_ms = started.elapsed().as_millis() as u64,
                "authorizer failed: {error:?}"
            );
            return Err(ApiError::Evaluation);
        }
    };

    let allowed = response.decision() == Decision::Allow;

    let reason_ids: Vec<_> = response.diagnostics().reason().collect();
    let policy_set = state.provider.get_policy_set(&cedar_request).await.ok();

    // determining policies を可読 id（`@id`、無ければ内部 id）へ解決。ログと
    // レスポンス context の予約フィールド `reason` の両方で使う。
    // `reason()` の反復順は非決定的なので、レスポンス/ログを安定させるためソートする。
    let mut reason = reason_ids
        .iter()
        .map(|id| {
            policy_set
                .as_ref()
                .and_then(|ps| ps.policy(id))
                .map(convert::display_id)
                .unwrap_or_else(|| id.to_string())
        })
        .collect::<Vec<_>>();
    reason.sort_unstable();

    let policy_errors = response
        .diagnostics()
        .errors()
        .map(|e| e.to_string())
        .collect::<Vec<_>>();
    if !policy_errors.is_empty() {
        warn!(
            %subject, %action, %resource,
            "policy evaluation produced errors (offending policies were ignored): {}",
            policy_errors.join("; ")
        );
    }

    // アノテーション由来の context は最優先の決定ポリシー1件から生成し（@priority 昇順）、
    // そこへ cedar-local-agent 応答由来の `reason`/`errors` を予約フィールドとして付与する。
    let (context_policy, annotation_context) = match policy_set
        .as_ref()
        .and_then(|ps| convert::to_decision_context(ps, &reason_ids))
    {
        Some((policy_id, context)) => (policy_id, Some(context)),
        None => ("-".to_string(), None),
    };
    let context = convert::build_context(annotation_context, &reason, &policy_errors);

    info!(
        %subject, %action, %resource,
        decision = if allowed { "allow" } else { "deny" },
        external_auth_forced = !allowed,
        determining_policies = %reason.join(","),
        context_policy = %context_policy,
        latency_ms = started.elapsed().as_millis() as u64,
        "access evaluation completed"
    );

    Ok(Json(EvaluationResponse::new(allowed).with_context(context)))
}

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

pub async fn healthz() -> StatusCode {
    StatusCode::OK
}

pub async fn readyz(State(state): State<AppState>) -> StatusCode {
    if state.readiness.is_ready() {
        StatusCode::OK
    } else {
        info!("readiness probe: not ready (last policy reload failed)");
        StatusCode::SERVICE_UNAVAILABLE
    }
}
