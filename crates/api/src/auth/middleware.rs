//! Authentication and authorisation middlewares.
//!
//! Runs as a `route_layer`, so it only sees requests that matched a route and
//! it can read axum's `MatchedPath` to find the route's entry in
//! [`permissions::ROUTE_SCOPES`]. Handlers therefore contain no auth logic at
//! all: by the time one runs, the caller is authenticated, the route's scope
//! requirement is satisfied, and an [`AuthContext`] is in the extensions.
//!
//! It fails closed in the case that matters most: a route present in the
//! router but missing from the scope table is rejected, not allowed. Adding an
//! endpoint and forgetting to authorise it produces a 403 in the first test
//! that touches it, rather than an open endpoint nobody notices.

use axum::extract::{MatchedPath, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::{api_key, permissions, AuthContext};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

struct RequestFacts {
    method: String,
    matched_path: String,
    credential: String,
}

pub async fn authenticate(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let facts = match extract_facts(&request) {
        Ok(facts) => facts,
        Err(err) => return err.into_response(),
    };

    match authorize(&state, facts).await {
        Ok(ctx) => {
            let mut request = request;
            request.extensions_mut().insert(ctx);
            next.run(request).await
        }
        Err(err) => err.into_response(),
    }
}

fn extract_facts(request: &Request) -> AppResult<RequestFacts> {
    let matched_path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!("auth layer ran outside of a matched route"))
        })?;

    Ok(RequestFacts {
        method: request.method().as_str().to_string(),
        matched_path,
        credential: bearer_token(request)?,
    })
}

async fn authorize(state: &AppState, facts: RequestFacts) -> AppResult<AuthContext> {
    let route = permissions::lookup(&facts.method, &facts.matched_path).ok_or_else(|| {
        tracing::error!(
            method = %facts.method,
            path = %facts.matched_path,
            "route has no declared scope requirement; refusing the request"
        );
        AppError::JwtRequired("this route has no declared authorisation policy".to_string())
    })?;

    let ctx = resolve_credential(state, &facts.credential).await?;

    if route.critical && !ctx.is_critical_tier() {
        return Err(AppError::JwtRequired(format!(
            "{} {} requires a short-lived token from POST /auth/tokens; \
             a long-lived API key cannot be used here",
            facts.method, facts.matched_path
        )));
    }
    if route.api_key_only && ctx.is_critical_tier() {
        return Err(AppError::validation(
            "this endpoint requires an API key, not a token",
        ));
    }

    if let permissions::Access::Scope { resource, action } = route.access {
        if !ctx.has_scope(resource, action) {
            return Err(AppError::MissingPermission(format!("{resource}:{action}")));
        }
    }

    Ok(ctx)
}

fn bearer_token(request: &Request) -> AppResult<String> {
    let header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;

    let (scheme, value) = header.split_once(' ').ok_or_else(|| {
        AppError::Unauthorized("expected `Authorization: Bearer <credential>`".to_string())
    })?;

    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(AppError::Unauthorized(
            "expected `Authorization: Bearer <credential>`".to_string(),
        ));
    }

    Ok(value.trim().to_string())
}

async fn resolve_credential(state: &AppState, token: &str) -> AppResult<AuthContext> {
    if api_key::looks_like_api_key(token) {
        resolve_api_key(state, token).await
    } else {
        let verified = state.jwt.verify(token)?;
        Ok(AuthContext::from_token(verified))
    }
}

async fn resolve_api_key(state: &AppState, presented: &str) -> AppResult<AuthContext> {
    let prefix = api_key::parse(presented)
        .ok_or_else(|| AppError::Unauthorized("invalid API key".to_string()))?;
    let hash = api_key::hash_key(presented);

    // `lookup_api_key` is SECURITY DEFINER: the app role has no SELECT on
    // api_keys at all, because the middleware has to identify the tenant
    // before tenant context exists. This function is the one hole in that
    // wall, and it is a narrow one - it takes the hash as an argument rather
    // than returning it, so it cannot be used to enumerate or extract.
    let row: Option<(uuid::Uuid, uuid::Uuid, Vec<String>)> =
        sqlx::query_as("SELECT id, business_id, permissions FROM lookup_api_key($1, $2)")
            .bind(prefix)
            .bind(&hash)
            .fetch_optional(&state.pool)
            .await?;

    let (id, business_id, perms) =
        row.ok_or_else(|| AppError::Unauthorized("invalid API key".to_string()))?;

    // Best-effort telemetry: a failure here must never fail the request, but
    // it should be visible, because "when was this key last used" is the first
    // question asked when deciding whether an old key is safe to revoke.
    if let Err(err) = sqlx::query("SELECT touch_api_key($1)")
        .bind(id)
        .execute(&state.pool)
        .await
    {
        tracing::warn!(error = %err, "failed to update api key last_used_at");
    }

    Ok(AuthContext::from_api_key(
        business_id,
        perms,
        id,
        prefix.to_string(),
    ))
}

/// Lets handlers take `ctx: AuthContext` as an argument.
///
/// The context is put into the extensions by the middleware above, so this
/// only ever reads it back. A handler mounted outside the auth layer would hit
/// the error path, which is why that path logs rather than silently
/// constructing an empty context.
impl<S> axum::extract::FromRequestParts<S> for AuthContext
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthContext>()
            .cloned()
            .ok_or_else(|| {
                tracing::error!("handler required an AuthContext but the auth layer did not run");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({
                        "error": {
                            "type": "internal_error",
                            "message": "internal server error",
                            "status": 500
                        }
                    })),
                )
                    .into_response()
            })
    }
}
