use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
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

#[cfg(test)]
mod tests {
    use super::*;

    fn json_error() -> serde_json::Error {
        serde_json::from_str::<serde_json::Value>("{ not json").expect_err("must fail to parse")
    }

    #[test]
    fn client_errors_map_to_400() {
        assert_eq!(
            ApiError::InvalidJson(json_error()).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ApiError::Conversion(ConversionError::Entity(String::new())).status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn evaluation_failure_maps_to_500() {
        assert_eq!(
            ApiError::Evaluation.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(ApiError::InvalidJson(json_error()).code(), "invalid_json");
        assert_eq!(ApiError::Evaluation.code(), "evaluation_failed");
    }

    #[test]
    fn conversion_errors_delegate_their_code() {
        assert_eq!(
            ApiError::Conversion(ConversionError::Context(String::new())).code(),
            "invalid_context"
        );
    }

    #[test]
    fn evaluation_failure_hides_internal_details() {
        assert_eq!(ApiError::Evaluation.to_string(), "authorization failed");
    }
}
