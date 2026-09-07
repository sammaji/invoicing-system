//! Error
//!
//! Every failure the API can produce is a variant here, and every variant
//! knows its own HTTP status and machine-readable `type`. Handlers return
//! `Result<T, AppError>` and never build an error response by hand, which is
//! what keeps the envelope actually consistent rather than mostly consistent.
//!
//! Envelope:
//! ```json
//! { "error": { "type": "invalid_state_transition", "message": "...", "status": 409,
//!              "current_state": "paid", "attempted_transition": "void" } }
//! ```

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Map, Value};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Validation(String),

    #[error("{0}")]
    Unauthorized(String),

    /// The credential is valid but does not carry the scope this route needs.
    /// The missing scope is returned so a caller can fix their key without
    /// guessing.
    #[error("missing permission {0}")]
    MissingPermission(String),

    /// The route requires a short-lived critical-tier token and got a
    /// long-lived API key.
    #[error("{0}")]
    JwtRequired(String),

    #[error("{0} not found")]
    NotFound(&'static str),

    #[error("{message}")]
    Conflict {
        error_type: &'static str,
        message: String,
    },

    /// A state transition the machine does not allow. Carries both sides so
    /// the caller can tell "someone else already paid this" from "I sent the
    /// wrong id".
    #[error("cannot {attempted} an invoice in state {current}")]
    InvalidStateTransition { current: String, attempted: String },

    /// Same idempotency key, different request body.
    #[error("{0}")]
    IdempotencyMismatch(String),

    /// The PSP gave a definitive decline. This is a 402, not a 5xx: nothing
    /// went wrong, the payment just did not happen.
    #[error("payment failed: {code}")]
    PaymentFailed {
        code: String,
        payment_attempt_id: String,
    },

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error(transparent)]
    Database(#[from] sqlx::Error),

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    pub fn conflict(error_type: &'static str, message: impl Into<String>) -> Self {
        Self::Conflict {
            error_type,
            message: message.into(),
        }
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::MissingPermission(_) | Self::JwtRequired(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict { .. } | Self::InvalidStateTransition { .. } => StatusCode::CONFLICT,
            Self::IdempotencyMismatch(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::PaymentFailed { .. } => StatusCode::PAYMENT_REQUIRED,
            Self::Upstream(_) => StatusCode::BAD_GATEWAY,
            Self::Database(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn error_type(&self) -> &str {
        match self {
            Self::Validation(_) => "invalid_request",
            Self::Unauthorized(_) => "unauthorized",
            Self::MissingPermission(_) => "missing_permission",
            Self::JwtRequired(_) => "jwt_required",
            Self::NotFound(_) => "not_found",
            Self::Conflict { error_type, .. } => error_type,
            Self::InvalidStateTransition { .. } => "invalid_state_transition",
            Self::IdempotencyMismatch(_) => "idempotency_key_reuse",
            Self::PaymentFailed { .. } => "payment_failed",
            Self::Upstream(_) => "upstream_error",
            Self::Database(_) | Self::Internal(_) => "internal_error",
        }
    }

    /// Extra machine-readable fields merged into the envelope.
    fn extra(&self) -> Map<String, Value> {
        let mut map = Map::new();
        match self {
            Self::MissingPermission(scope) => {
                map.insert("missing_permission".into(), json!(scope));
            }
            Self::InvalidStateTransition { current, attempted } => {
                map.insert("current_state".into(), json!(current));
                map.insert("attempted_transition".into(), json!(attempted));
            }
            Self::PaymentFailed {
                code,
                payment_attempt_id,
            } => {
                map.insert("code".into(), json!(code));
                map.insert("payment_attempt_id".into(), json!(payment_attempt_id));
            }
            _ => {}
        }
        map
    }

    /// The body as a value, so the payment path can persist the exact bytes a
    /// replayed idempotent request will get back.
    pub fn to_body(&self) -> Value {
        let status = self.status();
        // Internal failures are logged in full but never described to the
        // caller: a database error message is an information leak and is not
        // actionable by them anyway.
        let message = match self {
            Self::Database(_) | Self::Internal(_) => "internal server error".to_string(),
            other => other.to_string(),
        };

        let mut obj = Map::new();
        obj.insert("type".into(), json!(self.error_type()));
        obj.insert("message".into(), json!(message));
        obj.insert("status".into(), json!(status.as_u16()));
        obj.extend(self.extra());

        json!({ "error": Value::Object(obj) })
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if matches!(self, Self::Database(_) | Self::Internal(_)) {
            tracing::error!(error = %self, "unhandled internal error");
        }
        (self.status(), Json(self.to_body())).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;

/// Postgres error helpers. The payment path leans on unique-violation
/// detection heavily enough to deserve a named predicate rather than an
/// inline string match at each call site.
pub fn is_unique_violation(err: &sqlx::Error, constraint_contains: &str) -> bool {
    match err {
        sqlx::Error::Database(db) => {
            db.code().as_deref() == Some("23505")
                && db
                    .constraint()
                    .map(|c| c.contains(constraint_contains))
                    .unwrap_or(false)
        }
        _ => false,
    }
}

/// A write blocked by a row-level security policy comes back as a plain
/// "new row violates row-level security policy" error. That is the database
/// catching something the Rust scope mirror should already have caught, so it
/// is worth surfacing as its own signal rather than a generic 500.
pub fn is_rls_violation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db) => db.code().as_deref() == Some("42501"),
        _ => false,
    }
}
