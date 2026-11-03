//! API error type and the JSON response envelope.
//!
//! Every response is `{"ok": true, "data": ...}` or
//! `{"ok": false, "error": {"code", "message", "details"?}}`.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::{Value, json};

use crate::dto::{BackendError, ValidationErrors};

/// Success envelope.
pub(crate) fn ok<T: Serialize>(data: T) -> Response {
    Json(json!({ "ok": true, "data": data })).into_response()
}

/// Machine-readable code for an HTTP status.
fn code_for(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 => "bad_request",
        401 => "unauthorized",
        403 => "forbidden",
        404 => "not_found",
        405 => "method_not_allowed",
        408 => "request_timeout",
        409 => "conflict",
        413 => "payload_too_large",
        415 => "unsupported_media_type",
        422 => "validation_failed",
        429 => "too_many_requests",
        503 => "unavailable",
        s if s >= 500 => "internal",
        _ => "error",
    }
}

/// An error that renders as the JSON error envelope.
#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    details: Option<Value>,
    retry_after: Option<u64>,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code_for(status),
            message: message.into(),
            details: None,
            retry_after: None,
        }
    }

    /// Generic error for a bare HTTP status (used for framework-generated failures).
    pub(crate) fn from_status(status: StatusCode) -> Self {
        let message = status
            .canonical_reason()
            .unwrap_or("error")
            .to_ascii_lowercase();
        Self::new(status, message)
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub(crate) fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    /// 403 with a specific code (e.g. `csrf_invalid`).
    pub(crate) fn forbidden_code(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            ..Self::new(StatusCode::FORBIDDEN, message)
        }
    }

    pub(crate) fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not found")
    }

    pub(crate) fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    pub(crate) fn too_many_requests(retry_after_secs: u64) -> Self {
        Self {
            retry_after: Some(retry_after_secs),
            ..Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too many failed attempts; try again later",
            )
        }
    }

    pub(crate) fn validation(errors: &ValidationErrors) -> Self {
        Self {
            details: serde_json::to_value(errors).ok(),
            ..Self::new(StatusCode::UNPROCESSABLE_ENTITY, "validation failed")
        }
    }

    #[cfg(test)]
    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }
}

impl From<BackendError> for ApiError {
    fn from(e: BackendError) -> Self {
        match e {
            BackendError::Unavailable(msg) => {
                // Details stay in the log; clients get a generic message.
                tracing::error!(error = %msg, "backend unavailable");
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "backend unavailable")
            }
            BackendError::Invalid(errors) => Self::validation(&errors),
            BackendError::NotFound => Self::not_found(),
            BackendError::Internal(msg) => {
                // Details stay in the log; clients get a generic message.
                tracing::error!(error = %msg, "backend internal error");
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut error = json!({ "code": self.code, "message": self.message });
        if let (Some(details), Some(obj)) = (self.details, error.as_object_mut()) {
            obj.insert("details".into(), details);
        }
        let mut response =
            (self.status, Json(json!({ "ok": false, "error": error }))).into_response();
        if let Some(secs) = self.retry_after
            && let Ok(value) = HeaderValue::from_str(&secs.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

/// Result type of all handlers.
pub(crate) type ApiResult<T = Response> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn renders_envelope_with_details_and_retry_after() {
        let resp = ApiError::validation(&ValidationErrors::single("a.b", "bad")).into_response();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "validation_failed");
        assert_eq!(v["error"]["details"]["errors"][0]["path"], "a.b");

        let resp = ApiError::too_many_requests(42).into_response();
        assert_eq!(resp.headers()[header::RETRY_AFTER], "42");
    }

    #[tokio::test]
    async fn backend_error_text_never_reaches_clients() {
        for (e, expected) in [
            (
                BackendError::Unavailable("nft: /etc/secret/path denied".into()),
                "backend unavailable",
            ),
            (
                BackendError::Internal("nft: /etc/secret/path denied".into()),
                "internal error",
            ),
        ] {
            let resp = ApiError::from(e).into_response();
            let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
            let text = String::from_utf8_lossy(&body);
            assert!(!text.contains("secret"), "{text}");
            let v: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["error"]["message"], expected);
        }
    }

    #[test]
    fn backend_error_mapping() {
        let s = |e: BackendError| ApiError::from(e).status();
        assert_eq!(
            s(BackendError::Unavailable("x".into())),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(s(BackendError::NotFound), StatusCode::NOT_FOUND);
        assert_eq!(
            s(BackendError::Internal("x".into())),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            s(BackendError::Invalid(ValidationErrors::single("p", "m"))),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
}
