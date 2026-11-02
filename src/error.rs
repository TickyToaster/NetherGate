use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("operation is not implemented")]
    NotImplemented,
    #[error("not found")]
    NotFound,
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("recovery required")]
    RecoveryRequired,
    #[error("recovery unavailable")]
    RecoveryUnavailable,
    #[error("generation fenced")]
    GenerationFenced,
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for ProviderError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::NotImplemented => (StatusCode::NOT_IMPLEMENTED, "not_implemented"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::RecoveryRequired => (StatusCode::CONFLICT, "recovery_required"),
            Self::RecoveryUnavailable => (StatusCode::FORBIDDEN, "recovery_unavailable"),
            Self::GenerationFenced => (StatusCode::CONFLICT, "generation_fenced"),
            Self::Internal(error) => {
                tracing::error!(error = %error, "internal provider error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        };

        (status, Json(json!({ "code": code }))).into_response()
    }
}

impl From<crate::store::CompleteError> for ProviderError {
    fn from(error: crate::store::CompleteError) -> Self {
        match error {
            crate::store::CompleteError::NotFound => {
                Self::InvalidRequest("unknown challenge".to_owned())
            }
            crate::store::CompleteError::AlreadyConsumed => Self::RecoveryRequired,
            crate::store::CompleteError::Internal(error) => Self::Internal(error),
        }
    }
}

impl From<crate::store::RequestError> for ProviderError {
    fn from(error: crate::store::RequestError) -> Self {
        match error {
            crate::store::RequestError::StaleGeneration => Self::GenerationFenced,
            crate::store::RequestError::Sequence => {
                Self::InvalidRequest("sequence is not newer".to_owned())
            }
            crate::store::RequestError::IdempotencyConflict => {
                Self::InvalidRequest("idempotency key reused".to_owned())
            }
            crate::store::RequestError::Internal(error) => Self::Internal(error),
        }
    }
}

impl From<crate::store::AdmissionKeyError> for ProviderError {
    fn from(error: crate::store::AdmissionKeyError) -> Self {
        match error {
            crate::store::AdmissionKeyError::UnknownKey => {
                Self::InvalidRequest("unknown admission key".to_owned())
            }
            crate::store::AdmissionKeyError::NotAckable => {
                Self::InvalidRequest("admission key cannot be acknowledged".to_owned())
            }
            crate::store::AdmissionKeyError::Internal(error) => Self::Internal(error),
        }
    }
}
