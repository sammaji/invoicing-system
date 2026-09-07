//! API key management.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{api_key, permissions, AuthContext};
use crate::db::tenant::begin_as_tenant;
use crate::domain::ids;
use crate::error::{AppError, AppResult};
use crate::routes::models::*;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateApiKey {
    #[serde(default)]
    pub name: Option<String>,
    pub permissions: Vec<String>,
}

pub async fn create(
    State(state): State<AppState>,
    ctx: AuthContext,
    Json(body): Json<CreateApiKey>,
) -> AppResult<(StatusCode, Json<ApiKeyResponse>)> {
    // Rejects unknown resources and actions up front, so a typo cannot become
    // a key that authenticates and then 403s on everything.
    permissions::validate_permissions(&body.permissions)?;

    // No escalation: a token can only create keys weaker than or equal to
    // itself. Without this, minting a narrow token would be pointless - the
    // holder could simply create a `*:*` key with it and carry on.
    permissions::is_subset_of(&body.permissions, &ctx.permissions)
        .map_err(AppError::MissingPermission)?;

    let generated = api_key::generate();
    let key_id = ids::new_id();
    let name = body.name.unwrap_or_default();

    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    // The RLS policy on this INSERT requires `app_tier() = 'critical'` on top
    // of `api_key:create`. The middleware already checked the tier, so reaching
    // the policy check means both layers agree - and if the middleware were
    // ever loosened by mistake, this still fails.
    let row: ApiKeyRow = sqlx::query_as(
        "INSERT INTO api_keys (id, business_id, name, key_prefix, key_hash, permissions)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, name, key_prefix, permissions, revoked_at, last_used_at, created_at",
    )
    .bind(key_id)
    .bind(ctx.business_id)
    .bind(&name)
    .bind(&generated.prefix)
    .bind(&generated.hash)
    .bind(&body.permissions)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(
        api_key_id = %key_id,
        business_id = %ctx.business_id,
        key_prefix = %generated.prefix,
        permissions = ?body.permissions,
        "api key created"
    );

    let mut response: ApiKeyResponse = row.into();
    // The only time this field is ever populated. Nothing stored can
    // regenerate it.
    response.key = Some(generated.plaintext);

    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn list(
    State(state): State<AppState>,
    ctx: AuthContext,
    Query(page): Query<Pagination>,
) -> AppResult<Json<ListResponse<ApiKeyResponse>>> {
    let limit = page.limit();
    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    let mut rows: Vec<ApiKeyRow> = sqlx::query_as(
        "SELECT id, name, key_prefix, permissions, revoked_at, last_used_at, created_at
         FROM api_keys
         WHERE business_id = $1
         ORDER BY created_at DESC, id DESC
         LIMIT $2",
    )
    .bind(ctx.business_id)
    .bind(limit + 1)
    .fetch_all(&mut *tx)
    .await?;

    tx.commit().await?;

    let has_more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);

    Ok(Json(ListResponse::new(
        rows.into_iter().map(Into::into).collect(),
        has_more,
    )))
}

pub async fn revoke(
    State(state): State<AppState>,
    ctx: AuthContext,
    Path(id): Path<String>,
) -> AppResult<Json<ApiKeyResponse>> {
    let key_id: Uuid = ids::parse_id(ids::API_KEY, &id)?;
    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    let row: Option<ApiKeyRow> = sqlx::query_as(
        "UPDATE api_keys SET revoked_at = COALESCE(revoked_at, now())
         WHERE id = $1 AND business_id = $2
         RETURNING id, name, key_prefix, permissions, revoked_at, last_used_at, created_at",
    )
    .bind(key_id)
    .bind(ctx.business_id)
    .fetch_optional(&mut *tx)
    .await?;

    tx.commit().await?;

    let row = row.ok_or(AppError::NotFound("api key"))?;

    tracing::info!(
        api_key_id = %key_id,
        key_prefix = %row.key_prefix,
        business_id = %ctx.business_id,
        "api key revoked"
    );

    Ok(Json(row.into()))
}
