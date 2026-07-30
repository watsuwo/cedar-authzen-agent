use std::time::Instant;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use cedar_local_agent::public::SimplePolicySetProvider;
use cedar_policy::{Decision, Entities, PolicyId, PolicySet, Request, Response, Schema};
use tracing::{error, info, warn};

use crate::authzen::{AuthzenConfiguration, EvaluationRequest, EvaluationResponse};
use crate::convert::{self, DecisionContext};
use crate::error::ApiError;
use crate::state::AppState;

const NO_CONTEXT_POLICY: &str = "-";

struct LogTarget {
    subject: String,
    action: String,
    resource: String,
}

impl LogTarget {
    fn new(request: &EvaluationRequest) -> Self {
        Self {
            subject: format!("{}::{}", request.subject.entity_type, request.subject.id),
            action: request.action.name.clone(),
            resource: format!("{}::{}", request.resource.entity_type, request.resource.id),
        }
    }
}

pub async fn evaluate(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<EvaluationResponse>, ApiError> {
    let started = Instant::now();

    let request = parse_request(&body)?;
    let target = LogTarget::new(&request);
    let (cedar_request, entities) = convert_request(&request, &state.schema, &target)?;

    let response = authorize(&state, &cedar_request, &entities, &target, started).await?;
    let allowed = response.decision() == Decision::Allow;

    let reason_ids: Vec<_> = response.diagnostics().reason().collect();
    let policy_set = state.provider.get_policy_set(&cedar_request).await.ok();

    let reason = resolve_reason(&reason_ids, policy_set.as_deref());
    let policy_errors = collect_policy_errors(&response, &target);

    // contextはprorityが最も高いポリシーから生成予している
    let (context_policy, annotation_context) = match policy_set
        .as_deref()
        .and_then(|ps| convert::to_decision_context(ps, &reason_ids))
    {
        Some(DecisionContext { policy_id, context }) => (Some(policy_id), Some(context)),
        None => (None, None),
    };
    let context = convert::build_response_context(annotation_context, &reason, &policy_errors);

    info!(
        subject = %target.subject, action = %target.action, resource = %target.resource,
        decision = if allowed { "allow" } else { "deny" },
        external_auth_forced = !allowed,
        determining_policies = %reason.join(","),
        context_policy = context_policy.as_deref().unwrap_or(NO_CONTEXT_POLICY),
        latency_ms = latency_ms(started),
        "access evaluation completed"
    );

    Ok(Json(EvaluationResponse::new(allowed).with_context(context)))
}

fn parse_request(body: &Bytes) -> Result<EvaluationRequest, ApiError> {
    serde_json::from_slice(body).map_err(|error| {
        warn!(
            error_code = "invalid_json",
            body_len = body.len(),
            "rejected evaluation request: malformed JSON body: {error}"
        );
        ApiError::InvalidJson(error)
    })
}

fn convert_request(
    request: &EvaluationRequest,
    schema: &Schema,
    target: &LogTarget,
) -> Result<(Request, Entities), ApiError> {
    convert::to_cedar(request, schema).map_err(|error| {
        warn!(
            error_code = error.code(),
            subject = %target.subject, action = %target.action, resource = %target.resource,
            "rejected evaluation request: schema validation failed: {error}"
        );
        ApiError::Conversion(error)
    })
}

async fn authorize(
    state: &AppState,
    request: &Request,
    entities: &Entities,
    target: &LogTarget,
    started: Instant,
) -> Result<Response, ApiError> {
    state
        .authorizer
        .is_authorized(request, entities)
        .await
        .map_err(|error| {
            error!(
                subject = %target.subject, action = %target.action, resource = %target.resource,
                latency_ms = latency_ms(started),
                "authorizer failed: {error:?}"
            );
            ApiError::Evaluation
        })
}

fn resolve_reason(reason_ids: &[&PolicyId], policy_set: Option<&PolicySet>) -> Vec<String> {
    let mut reason = reason_ids
        .iter()
        .map(|id| {
            policy_set
                .and_then(|ps| ps.policy(id))
                .map_or_else(|| id.to_string(), convert::display_id)
        })
        .collect::<Vec<_>>();
    reason.sort_unstable();
    reason
}

fn collect_policy_errors(response: &Response, target: &LogTarget) -> Vec<String> {
    let errors = response
        .diagnostics()
        .errors()
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    if !errors.is_empty() {
        warn!(
            subject = %target.subject, action = %target.action, resource = %target.resource,
            "policy evaluation produced errors (offending policies were ignored): {}",
            errors.join("; ")
        );
    }
    errors
}

fn latency_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn policy_set(src: &str) -> PolicySet {
        PolicySet::from_str(src).expect("test policy set should parse")
    }

    fn find_id<'a>(ps: &'a PolicySet, name: &str) -> &'a PolicyId {
        ps.policies()
            .find(|p| p.annotation("id") == Some(name))
            .map_or_else(
                || panic!("policy `{name}` not found"),
                cedar_policy::Policy::id,
            )
    }

    #[test]
    fn log_target_formats_the_authzen_triple() {
        let request: EvaluationRequest = serde_json::from_value(serde_json::json!({
            "subject": { "type": "User", "id": "alice" },
            "action": { "name": "login" },
            "resource": { "type": "Client", "id": "a-client" }
        }))
        .expect("test request should deserialize");

        let target = LogTarget::new(&request);
        assert_eq!(target.subject, "User::alice");
        assert_eq!(target.action, "login");
        assert_eq!(target.resource, "Client::a-client");
    }

    #[test]
    fn resolve_reason_sorts_display_ids() {
        let ps = policy_set(
            r#"
            @id("zebra")
            forbid(principal, action, resource);

            @id("alpha")
            forbid(principal, action, resource);
            "#,
        );
        let reason_ids = [find_id(&ps, "zebra"), find_id(&ps, "alpha")];

        assert_eq!(resolve_reason(&reason_ids, Some(&ps)), ["alpha", "zebra"]);
    }

    #[test]
    fn resolve_reason_falls_back_to_internal_id_for_unknown_policies() {
        let ps = policy_set(
            r#"
            @id("named")
            forbid(principal, action, resource);
            "#,
        );
        let reason_ids = [find_id(&ps, "named")];

        let resolved = resolve_reason(&reason_ids, None);
        assert_eq!(resolved, [reason_ids[0].to_string()]);
        assert_ne!(resolved, ["named"]);
    }

    #[test]
    fn resolve_reason_is_empty_without_determining_policies() {
        assert!(resolve_reason(&[], None).is_empty());
    }
}
