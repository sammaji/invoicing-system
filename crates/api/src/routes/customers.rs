use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::db::tenant::begin_as_tenant;
use crate::domain::ids;
use crate::error::{AppError, AppResult};
use crate::routes::models::*;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateCustomer {
    pub name: String,
    pub email: String,
}

pub async fn create(
    State(state): State<AppState>,
    ctx: AuthContext,
    Json(body): Json<CreateCustomer>,
) -> AppResult<(StatusCode, Json<CustomerResponse>)> {
    let name = body.name.trim();
    let email = body.email.trim();

    if name.is_empty() {
        return Err(AppError::validation("name must not be empty"));
    }
    if !email.contains('@') || email.len() < 3 {
        return Err(AppError::validation("email must be a valid email address"));
    }

    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    let row: CustomerRow = sqlx::query_as(
        "INSERT INTO customers (id, business_id, name, email)
         VALUES ($1, $2, $3, $4)
         RETURNING id, name, email, created_at",
    )
    .bind(ids::new_id())
    .bind(ctx.business_id)
    .bind(name)
    .bind(email)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(customer_id = %row.id, business_id = %ctx.business_id, "customer created");

    Ok((StatusCode::CREATED, Json(row.into())))
}

pub async fn get(
    State(state): State<AppState>,
    ctx: AuthContext,
    Path(id): Path<String>,
) -> AppResult<Json<CustomerResponse>> {
    let customer_id = ids::parse_id(ids::CUSTOMER, &id)?;
    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    let row: Option<CustomerRow> = sqlx::query_as(
        "SELECT id, name, email, created_at FROM customers
         WHERE id = $1 AND business_id = $2",
    )
    .bind(customer_id)
    .bind(ctx.business_id)
    .fetch_optional(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(row.ok_or(AppError::NotFound("customer"))?.into()))
}

pub async fn list(
    State(state): State<AppState>,
    ctx: AuthContext,
    Query(page): Query<Pagination>,
) -> AppResult<Json<ListResponse<CustomerResponse>>> {
    let cursor: Option<Uuid> = page
        .starting_after
        .as_deref()
        .map(|c| ids::parse_id(ids::CUSTOMER, c))
        .transpose()?;

    let limit = page.limit();
    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    let mut rows: Vec<CustomerRow> = sqlx::query_as(
        "SELECT id, name, email, created_at FROM customers
         WHERE business_id = $1
           AND ($2::uuid IS NULL OR (created_at, id) <
                (SELECT c.created_at, c.id FROM customers c WHERE c.id = $2))
         ORDER BY created_at DESC, id DESC
         LIMIT $3",
    )
    .bind(ctx.business_id)
    .bind(cursor)
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
