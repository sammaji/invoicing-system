//! Webhook endpoint registration and delivery inspection.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{api_key, AuthContext};
use crate::db::tenant::begin_as_tenant;
use crate::domain::ids;
use crate::error::{AppError, AppResult};
use crate::routes::models::*;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateWebhookEndpoint {
    pub url: String,
}

pub async fn create(
    State(state): State<AppState>,
    ctx: AuthContext,
    Json(body): Json<CreateWebhookEndpoint>,
) -> AppResult<(StatusCode, Json<WebhookEndpointResponse>)> {
    let url = body.url.trim();
    // Deliberately minimal validation. Rejecting anything but https would be
    // right in production and wrong here, where the obvious first thing anyone
    // does is point it at a local listener. DESIGN.md notes it as a gap.
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(AppError::validation(
            "url must be an http:// or https:// address",
        ));
    }
    if url.len() > 2048 {
        return Err(AppError::validation("url is too long"));
    }

    let secret = api_key::generate_webhook_secret();
    let endpoint_id = ids::new_id();

    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    let row: WebhookEndpointRow = sqlx::query_as(
        "INSERT INTO webhook_endpoints (id, business_id, url, secret)
         VALUES ($1, $2, $3, $4)
         RETURNING id, url, disabled_at, created_at",
    )
    .bind(endpoint_id)
    .bind(ctx.business_id)
    .bind(url)
    .bind(&secret)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(endpoint_id = %endpoint_id, business_id = %ctx.business_id, %url, "webhook endpoint registered");

    let mut response: WebhookEndpointResponse = row.into();
    // Returned once. There is no rotate endpoint in v1 - registering a second
    // endpoint and disabling the first is the documented path.
    response.secret = Some(secret);

    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn list(
    State(state): State<AppState>,
    ctx: AuthContext,
    Query(page): Query<Pagination>,
) -> AppResult<Json<ListResponse<WebhookEndpointResponse>>> {
    let limit = page.limit();
    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    let mut rows: Vec<WebhookEndpointRow> = sqlx::query_as(
        "SELECT id, url, disabled_at, created_at FROM webhook_endpoints
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

/// Disable rather than delete, for the same reason keys are revoked rather
/// than deleted: the delivery rows reference it, and their history is the
/// audit trail.
pub async fn disable(
    State(state): State<AppState>,
    ctx: AuthContext,
    Path(id): Path<String>,
) -> AppResult<Json<WebhookEndpointResponse>> {
    let endpoint_id: Uuid = ids::parse_id(ids::WEBHOOK_ENDPOINT, &id)?;
    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    let row: Option<WebhookEndpointRow> = sqlx::query_as(
        "UPDATE webhook_endpoints SET disabled_at = COALESCE(disabled_at, now())
         WHERE id = $1 AND business_id = $2
         RETURNING id, url, disabled_at, created_at",
    )
    .bind(endpoint_id)
    .bind(ctx.business_id)
    .fetch_optional(&mut *tx)
    .await?;

    tx.commit().await?;

    let row = row.ok_or(AppError::NotFound("webhook endpoint"))?;
    tracing::info!(endpoint_id = %endpoint_id, "webhook endpoint disabled");

    Ok(Json(row.into()))
}

#[derive(Debug, Deserialize)]
pub struct ListDeliveries {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub event_type: Option<String>,
    #[serde(flatten)]
    pub page: Pagination,
}

/// The answer to "did that webhook arrive?".
///
/// Worth having as a first-class endpoint rather than a support ticket: an
/// integrator debugging a missed event can see the attempt count, the last
/// error and the next retry time themselves.
pub async fn list_deliveries(
    State(state): State<AppState>,
    ctx: AuthContext,
    Query(query): Query<ListDeliveries>,
) -> AppResult<Json<ListResponse<WebhookDeliveryResponse>>> {
    const VALID: [&str; 4] = ["pending", "delivering", "delivered", "exhausted"];

    if let Some(status) = &query.status {
        if !VALID.contains(&status.as_str()) {
            return Err(AppError::validation(format!(
                "unknown status `{status}`; valid statuses are {}",
                VALID.join(", ")
            )));
        }
    }

    let limit = query.page.limit();
    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    let mut rows: Vec<WebhookDeliveryRow> = sqlx::query_as(
        "SELECT id, endpoint_id, event_id, event_type, status, attempt_count,
                next_attempt_at, last_error, delivered_at, created_at
         FROM webhook_deliveries
         WHERE business_id = $1
           AND ($2::text IS NULL OR status = $2)
           AND ($3::text IS NULL OR event_type = $3)
         ORDER BY created_at DESC, id DESC
         LIMIT $4",
    )
    .bind(ctx.business_id)
    .bind(query.status.as_deref())
    .bind(query.event_type.as_deref())
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
