use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;

use crate::authzen::ErrorBody;
use crate::convert::ConversionError;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("{0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("{0}")]
    Conversion(#[from] ConversionError),
    #[error("authorization failed")]
    Evaluation,
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            Self::InvalidJson(_) | Self::Conversion(_) => StatusCode::BAD_REQUEST,
            Self::Evaluation => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

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
