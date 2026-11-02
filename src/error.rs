use std::borrow::Cow;

use rmcp::model::{ErrorCode, ErrorData};
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{message}")]
    Backend {
        status: u16,
        code: String,
        message: String,
        retryable: bool,
        details: Option<Value>,
    },
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{message}")]
    ApprovalRequired {
        message: String,
        approval_id: Option<String>,
        execution_id: Option<String>,
        expires_at: Option<String>,
    },
    #[error("{0}")]
    AuditOnly(String),
    #[error("{0}")]
    Unsupported(String),
    #[error("{0}")]
    Crypto(String),
    #[error("{0}")]
    Verification(String),
    #[error("{0}")]
    Internal(String),
}

impl AppError {
    pub fn backend(status: u16, detail: Value) -> Self {
        let code = detail
            .get("code")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| match status {
                400 => "BACKEND_BAD_REQUEST".to_owned(),
                401 => "BACKEND_UNAUTHORIZED".to_owned(),
                403 => "BACKEND_FORBIDDEN".to_owned(),
                404 => "BACKEND_NOT_FOUND".to_owned(),
                409 => "BACKEND_CONFLICT".to_owned(),
                422 => "BACKEND_UNPROCESSABLE".to_owned(),
                429 => "BACKEND_RATE_LIMITED".to_owned(),
                502..=504 => "BACKEND_UNAVAILABLE".to_owned(),
                _ => "BACKEND_ERROR".to_owned(),
            });
        let message = detail
            .get("detail")
            .or_else(|| detail.get("message"))
            .and_then(|value| match value {
                Value::String(text) => Some(text.clone()),
                Value::Object(object) => object
                    .get("message")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .or_else(|| Some(value.to_string())),
                Value::Null => None,
                other => Some(other.to_string()),
            })
            .unwrap_or_else(|| format!("backend returned HTTP {status}"));
        let retryable = status == 429 || (500..=599).contains(&status);
        let details = detail
            .get("detail")
            .filter(|value| value.is_object())
            .cloned()
            .or_else(|| detail.get("details").cloned());
        Self::Backend {
            status,
            code,
            message,
            retryable,
            details,
        }
    }

    pub fn blocklog_code(&self) -> &'static str {
        match self {
            Self::Backend { code, .. } => match code.as_str() {
                "BACKEND_UNAUTHORIZED" => "BLOCKLOG_UNAUTHORIZED",
                "BACKEND_FORBIDDEN" => "BLOCKLOG_FORBIDDEN",
                "BACKEND_NOT_FOUND" => "BLOCKLOG_NOT_FOUND",
                "BACKEND_CONFLICT" => "BLOCKLOG_CONFLICT",
                "BACKEND_RATE_LIMITED" => "BLOCKLOG_RATE_LIMITED",
                "BACKEND_UNAVAILABLE" => "BLOCKLOG_UNAVAILABLE",
                _ => "BLOCKLOG_BACKEND_ERROR",
            },
            Self::Validation(_) => "BLOCKLOG_VALIDATION_ERROR",
            Self::Unauthorized(_) => "BLOCKLOG_UNAUTHORIZED",
            Self::Forbidden(_) => "BLOCKLOG_FORBIDDEN",
            Self::NotFound(_) => "BLOCKLOG_NOT_FOUND",
            Self::Conflict(_) => "BLOCKLOG_CONFLICT",
            Self::ApprovalRequired { .. } => "BLOCKLOG_APPROVAL_REQUIRED",
            Self::AuditOnly(_) => "BLOCKLOG_AUDIT_MODE",
            Self::Unsupported(_) => "BLOCKLOG_UNSUPPORTED",
            Self::Crypto(_) | Self::Verification(_) => "BLOCKLOG_VERIFICATION_FAILED",
            Self::Internal(_) => "BLOCKLOG_INTERNAL_ERROR",
        }
    }

    pub fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Backend {
                retryable: true,
                ..
            }
        )
    }

    pub fn details(&self) -> Option<Value> {
        match self {
            Self::Backend { details, .. } => details.clone(),
            Self::ApprovalRequired {
                approval_id,
                execution_id,
                expires_at,
                ..
            } => Some(json!({
                "approval_id": approval_id,
                "execution_id": execution_id,
                "expires_at": expires_at,
            })),
            _ => None,
        }
    }

    pub fn to_error_data(&self) -> ErrorData {
        let code = match self {
            Self::Validation(_) => ErrorCode::INVALID_PARAMS,
            Self::Unauthorized(_) | Self::Forbidden(_) => ErrorCode::INVALID_REQUEST,
            Self::NotFound(_) => ErrorCode::RESOURCE_NOT_FOUND,
            Self::Backend { status: 429, .. } => ErrorCode::INVALID_REQUEST,
            Self::Backend { status, .. } if (400..500).contains(status) => {
                ErrorCode::INVALID_REQUEST
            }
            _ => ErrorCode::INTERNAL_ERROR,
        };
        let mut data = json!({
            "blocklog_code": self.blocklog_code(),
            "retryable": self.retryable(),
        });
        if let Some(details) = self.details() {
            if let Some(object) = data.as_object_mut() {
                object.insert("details".to_owned(), details);
            }
        }
        if let Self::Backend { status, code, .. } = self {
            if let Some(object) = data.as_object_mut() {
                object.insert("backend_status".to_owned(), json!(status));
                object.insert("backend_code".to_owned(), json!(code));
            }
        }
        ErrorData::new(code, Cow::Owned(self.to_string()), Some(data))
    }
}

impl From<AppError> for ErrorData {
    fn from(error: AppError) -> Self {
        error.to_error_data()
    }
}

impl From<reqwest::Error> for AppError {
    fn from(error: reqwest::Error) -> Self {
        if error.is_timeout() {
            return Self::Backend {
                status: 504,
                code: "BACKEND_TIMEOUT".to_owned(),
                message: "Blocklog backend request timed out".to_owned(),
                retryable: true,
                details: None,
            };
        }
        if error.is_connect() {
            return Self::Backend {
                status: 503,
                code: "BACKEND_UNAVAILABLE".to_owned(),
                message: "Blocklog backend is unavailable".to_owned(),
                retryable: true,
                details: None,
            };
        }
        Self::Internal(format!("HTTP client error: {error}"))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(error: serde_json::Error) -> Self {
        Self::Internal(format!("JSON serialization error: {error}"))
    }
}

pub type AppResult<T> = Result<T, AppError>;
