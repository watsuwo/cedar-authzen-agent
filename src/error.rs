//! HTTP API のエラー型（DESIGN.md §8）。
//!
//! axum の慣例に従い、ハンドラは `Result<_, ApiError>` を返し、`ApiError` が
//! `IntoResponse` を実装することでステータスコードと JSON エラーボディへの
//! 変換を一箇所に集約する。ハンドラ側は `?` で早期リターンするだけでよい。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;

use crate::authzen::ErrorBody;
use crate::convert::ConversionError;

/// AuthZEN エンドポイントが返しうるエラー。
///
/// バリアントごとに HTTP ステータスと安定したエラーコードが決まる。
/// `#[from]` により、変換層のエラーはハンドラ内で `?` を書くだけで伝播する。
#[derive(Debug, Error)]
pub enum ApiError {
    /// リクエストボディが AuthZEN の `EvaluationRequest` として解釈できなかった。
    #[error("{0}")]
    InvalidJson(#[from] serde_json::Error),
    /// AuthZEN リクエストから Cedar 入力への変換（スキーマ検証込み）に失敗した。
    #[error("{0}")]
    Conversion(#[from] ConversionError),
    /// 認可器そのものが失敗した。詳細はログに出し、クライアントには漏らさない。
    #[error("authorization failed")]
    Evaluation,
}

impl ApiError {
    /// HTTP ステータスコードへのマッピング。
    fn status(&self) -> StatusCode {
        match self {
            Self::InvalidJson(_) | Self::Conversion(_) => StatusCode::BAD_REQUEST,
            Self::Evaluation => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// JSON エラーボディ用の安定したエラーコード（DESIGN.md §8）。
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidJson(_) => "invalid_json",
            Self::Conversion(error) => error.code(),
            Self::Evaluation => "evaluation_failed",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody::new(self.code(), self.to_string());
        (self.status(), Json(body)).into_response()
    }
}
