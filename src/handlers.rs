//! AuthZEN エンドポイント、ヘルスチェック、レディネスチェックの axum ハンドラ
//! 群（DESIGN.md §2, §8, §10）。
//!
//! 失敗しうるハンドラは `Result<_, ApiError>` を返す。ステータスコードと
//! JSON エラーボディへの変換は [`ApiError`] の `IntoResponse` 実装に集約
//! されているため、失敗パスは `ApiError` を返すだけでよい（運用ログは各分岐で
//! 文脈付きに記録する）。

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

/// `POST /access/v1/evaluation` — 単一の AuthZEN アクセスリクエストを評価する。
///
/// 成功時は `200 { "decision": <bool> }`、入力が不正なら `400`、認可器自体が
/// 失敗したら `500`。`decision: false` は `forbid` が一致したことを意味し、
/// 外部認証が強制される（DESIGN.md §2.1）。
pub async fn evaluate(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<EvaluationResponse>, ApiError> {
    // レイテンシ計測の起点（運用ログの `latency_ms` 用）。
    let started = Instant::now();

    // 1) リクエストボディを AuthZEN の `EvaluationRequest` にデシリアライズ。
    //    不正な JSON は連携元（authenticator 等）の不具合検知のため warn で残す。
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

    // 運用・監査ログ用に AuthZEN 側の識別子を文字列化する。属性値（properties）は
    // PII を含みうるため出力しない（DESIGN.md §2.1）。
    let subject = format!("{}::{}", request.subject.entity_type, request.subject.id);
    let resource = format!("{}::{}", request.resource.entity_type, request.resource.id);
    let action = request.action.name.clone();

    // 2) スキーマ検証しつつ Cedar の `Request`/`Entities` へ変換。変換エラーは
    //    そのまま安定コード付きの 400 になる。誤った連携（スキーマ外属性など）を
    //    早期発見できるよう warn で記録する。
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

    // 3) cedar-local-agent の `Authorizer::is_authorized` で評価する。内部で
    //    現在のポリシー集合・空のエンティティプロバイダ・リクエスト時エンティティを
    //    使って判定し、OCSF 認可ログも発行される。
    let response = match state.authorizer.is_authorized(&cedar_request, &entities).await {
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

    // Cedar の `Allow` を `decision: true`（通常ログイン許可）に対応づける。
    let allowed = response.decision() == Decision::Allow;

    // 判定理由となったポリシー id（どの forbid/permit が効いたかの追跡用と、
    // レスポンス `context` の組み立て用）。`reason()` は Cedar 内部 id（policy0 等）
    // を返すため、ログでは可能なら現在のポリシー集合から `@id` アノテーション
    // （例: "a-client-deny"）に解決して運用で読みやすくする。解決できなければ
    // 内部 id をそのまま使う。
    let reason_ids: Vec<_> = response.diagnostics().reason().collect();
    let policy_set = state.provider.get_policy_set(&cedar_request).await.ok();
    let determining_policies = reason_ids
        .iter()
        .map(|id| {
            policy_set
                .as_ref()
                .and_then(|ps| ps.annotation(id, "id"))
                .map(str::to_string)
                .unwrap_or_else(|| id.to_string())
        })
        .collect::<Vec<_>>()
        .join(",");

    // 評価中にエラーになったポリシーは Cedar 上は無視されるが、運用上は
    // 異常なので警告する（ポリシーの不備を見逃さないため）。
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

    // 判定を決めたポリシーの `@decision_context_<key>` アノテーションをレスポンスの
    // `context` に載せる（DESIGN.md §2.2）。該当がなければ `context` は省略。
    let context = policy_set
        .as_ref()
        .and_then(|ps| convert::to_authzen_context(ps, &reason_ids));

    // 1 リクエスト = 1 行の判定ログ。ログイン可否監査の中核。
    info!(
        %subject, %action, %resource,
        decision = if allowed { "allow" } else { "deny" },
        external_auth_forced = !allowed,
        determining_policies = %determining_policies,
        latency_ms = started.elapsed().as_millis() as u64,
        "access evaluation completed"
    );

    Ok(Json(EvaluationResponse::new(allowed).with_context(context)))
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
