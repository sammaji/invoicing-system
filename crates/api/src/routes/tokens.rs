//! `POST /auth/tokens` - trade a long-lived API key for a short-lived,
//! optionally narrower, critical-tier token.
//!
//! Two properties make this worth having rather than just letting API keys do
//! everything:
//!
//! 1. **It can only narrow.** The requested permissions must be a subset of
//!    the calling key's (see `permissions::is_subset_of`), so minting is never
//!    an escalation path. A worker that needs `api_key:create` for one
//!    provisioning call can hold a `*:*` key and mint a token that carries
//!    only that one scope for fifteen minutes.
//! 2. **It is the only way to reach the critical tier.** The routes that mint
//!    secrets require it, in the RLS policy as well as in the middleware. So a
//!    stolen API key - even `*:*` - cannot create more credentials without
//!    making this call first, and this call is one loggable, alertable,
//!    revocable event rather than a silent capability the key always had.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::{permissions, AuthContext};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[derive(Debug, Deserialize, Default)]
pub struct MintTokenRequest {
    /// A subset of the calling key's permissions. Omitted means "everything
    /// this key has", which is convenient but worth not defaulting to in a
    /// caller that knows what it needs.
    #[serde(default)]
    pub permissions: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct MintTokenResponse {
    pub token: String,
    pub token_type: &'static str,
    pub expires_at: i64,
    pub expires_in: i64,
    /// Echoed back so a caller can see what it actually got, which matters
    /// when it asked for a subset.
    pub permissions: Vec<String>,
}

pub async fn mint(
    State(state): State<AppState>,
    ctx: AuthContext,
    body: Option<Json<MintTokenRequest>>,
) -> AppResult<Json<MintTokenResponse>> {
    let requested = body
        .and_then(|Json(b)| b.permissions)
        .unwrap_or_else(|| ctx.permissions.clone());

    permissions::validate_permissions(&requested)?;

    permissions::is_subset_of(&requested, &ctx.permissions).map_err(|missing| {
        // Deliberately the same error shape as any other authorisation
        // failure: asking for more than you hold is refused for the same
        // reason as using more than you hold.
        AppError::MissingPermission(missing)
    })?;

    let (token, expires_at) =
        state
            .jwt
            .mint(ctx.business_id, requested.clone(), state.config.jwt_ttl)?;

    // Minting is logged: it is the step that precedes every secret-creating
    // action in the system, so it is the thing you would grep for after an
    // incident. The token itself is never logged.
    tracing::info!(
        business_id = %ctx.business_id,
        api_key_prefix = ctx.api_key_prefix.as_deref().unwrap_or("-"),
        permissions = ?requested,
        expires_at,
        "minted critical-tier token"
    );

    Ok(Json(MintTokenResponse {
        token,
        token_type: "Bearer",
        expires_at,
        expires_in: state.config.jwt_ttl.as_secs() as i64,
        permissions: requested,
    }))
}
