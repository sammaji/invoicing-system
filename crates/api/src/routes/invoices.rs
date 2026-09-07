use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::NaiveDate;
use serde::Deserialize;
use serde_json::json;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::db::tenant::begin_as_tenant;
use crate::domain::state_machine::{transition, InvoiceEvent, InvoiceState};
use crate::domain::{ids, money};
use crate::error::{AppError, AppResult};
use crate::events::{self, Audience};
use crate::routes::models::*;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateInvoice {
    pub customer_id: String,
    pub due_date: NaiveDate,
    pub line_items: Vec<CreateLineItem>,
    #[serde(default)]
    pub currency: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateLineItem {
    pub description: String,
    pub quantity: i32,
    pub unit_amount_cents: i64,
}

pub async fn create(
    State(state): State<AppState>,
    ctx: AuthContext,
    Json(body): Json<CreateInvoice>,
) -> AppResult<(StatusCode, Json<InvoiceResponse>)> {
    let customer_id = ids::parse_id(ids::CUSTOMER, &body.customer_id)?;

    if body.line_items.is_empty() {
        return Err(AppError::validation(
            "an invoice must have at least one line item",
        ));
    }
    if body.line_items.len() > 500 {
        return Err(AppError::validation(
            "an invoice may have at most 500 line items",
        ));
    }

    // The total is computed here from the line items and is never read from
    // the request. A client-supplied total is a client-supplied price, and
    // accepting one means a caller can invoice their customer for one amount
    // while charging their card another.
    let mut amounts = Vec::with_capacity(body.line_items.len());
    for item in &body.line_items {
        if item.description.trim().is_empty() {
            return Err(AppError::validation(
                "line item description must not be empty",
            ));
        }
        amounts.push(money::line_amount(item.quantity, item.unit_amount_cents)?);
    }
    let total_cents = money::sum_amounts(&amounts)?;

    if total_cents <= 0 {
        return Err(AppError::validation(
            "invoice total must be greater than zero",
        ));
    }

    let currency = body.currency.unwrap_or_else(|| "usd".to_string());
    if currency.len() != 3 {
        return Err(AppError::validation("currency must be a three-letter code"));
    }

    let invoice_id = ids::new_id();
    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    // Existence check inside the transaction, under RLS: another tenant's
    // customer id simply is not visible, so this is a 404 rather than a way to
    // probe for valid ids.
    let customer_exists: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM customers WHERE id = $1 AND business_id = $2")
            .bind(customer_id)
            .bind(ctx.business_id)
            .fetch_optional(&mut *tx)
            .await?;
    if customer_exists.is_none() {
        return Err(AppError::NotFound("customer"));
    }

    let invoice: InvoiceRow = sqlx::query_as(
        "INSERT INTO invoices
            (id, business_id, customer_id, state, total_cents, amount_paid_cents, currency, due_date)
         VALUES ($1, $2, $3, 'draft', $4, 0, $5, $6)
         RETURNING id, customer_id, state, total_cents, amount_paid_cents, currency,
                   due_date, sent_at, paid_at, created_at",
    )
    .bind(invoice_id)
    .bind(ctx.business_id)
    .bind(customer_id)
    .bind(total_cents)
    .bind(&currency)
    .bind(body.due_date)
    .fetch_one(&mut *tx)
    .await?;

    for (position, (item, amount)) in body.line_items.iter().zip(&amounts).enumerate() {
        sqlx::query(
            "INSERT INTO invoice_line_items
                (id, invoice_id, business_id, description, quantity, unit_amount_cents,
                 amount_cents, position)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(ids::new_id())
        .bind(invoice_id)
        .bind(ctx.business_id)
        .bind(item.description.trim())
        .bind(item.quantity)
        .bind(item.unit_amount_cents)
        .bind(amount)
        .bind(position as i32)
        .execute(&mut *tx)
        .await?;
    }

    let line_items = load_line_items(&mut tx, invoice_id).await?;
    let response = InvoiceResponse::new(invoice).with_line_items(line_items);

    events::emit(
        &mut tx,
        Audience::Tenant,
        events::INVOICE_CREATED,
        json!({ "invoice": &response }),
    )
    .await?;

    tx.commit().await?;

    tracing::info!(invoice_id = %invoice_id, total_cents, "invoice created");

    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn send(
    State(state): State<AppState>,
    ctx: AuthContext,
    Path(id): Path<String>,
) -> AppResult<Json<InvoiceResponse>> {
    let invoice_id = ids::parse_id(ids::INVOICE, &id)?;
    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    let current = load_invoice(&mut tx, invoice_id, ctx.business_id)
        .await?
        .ok_or(AppError::NotFound("invoice"))?;

    // Ask the machine first, so the error message comes from the one place
    // that knows the rules.
    transition(current.state(), InvoiceEvent::Send).map_err(|e| {
        AppError::InvalidStateTransition {
            current: e.from.to_string(),
            attempted: e.attempted.to_string(),
        }
    })?;

    let updated: Option<InvoiceRow> = sqlx::query_as(
        "UPDATE invoices SET state = 'sent', sent_at = now()
         WHERE id = $1 AND business_id = $2 AND state = 'draft'
         RETURNING id, customer_id, state, total_cents, amount_paid_cents, currency,
                   due_date, sent_at, paid_at, created_at",
    )
    .bind(invoice_id)
    .bind(ctx.business_id)
    .fetch_optional(&mut *tx)
    .await?;

    let updated = updated.ok_or(AppError::InvalidStateTransition {
        current: current.state.clone(),
        attempted: "send".to_string(),
    })?;

    let response =
        InvoiceResponse::new(updated).with_line_items(load_line_items(&mut tx, invoice_id).await?);

    events::emit(
        &mut tx,
        Audience::Tenant,
        events::INVOICE_SENT,
        json!({ "invoice": &response }),
    )
    .await?;

    tx.commit().await?;

    tracing::info!(invoice_id = %invoice_id, from = "draft", to = "sent", "invoice state changed");

    Ok(Json(response))
}

pub async fn void(
    State(state): State<AppState>,
    ctx: AuthContext,
    Path(id): Path<String>,
) -> AppResult<Json<InvoiceResponse>> {
    let invoice_id = ids::parse_id(ids::INVOICE, &id)?;
    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    let current = load_invoice(&mut tx, invoice_id, ctx.business_id)
        .await?
        .ok_or(AppError::NotFound("invoice"))?;

    transition(current.state(), InvoiceEvent::Void).map_err(|e| {
        AppError::InvalidStateTransition {
            current: e.from.to_string(),
            attempted: e.attempted.to_string(),
        }
    })?;

    let updated: Option<InvoiceRow> = sqlx::query_as(
        "UPDATE invoices SET state = 'void'
         WHERE id = $1 AND business_id = $2
           AND state IN ('draft', 'sent')
           AND amount_paid_cents = 0
         RETURNING id, customer_id, state, total_cents, amount_paid_cents, currency,
                   due_date, sent_at, paid_at, created_at",
    )
    .bind(invoice_id)
    .bind(ctx.business_id)
    .fetch_optional(&mut *tx)
    .await?;

    let updated = updated.ok_or_else(|| AppError::InvalidStateTransition {
        current: current.state.clone(),
        attempted: "void".to_string(),
    })?;

    let response =
        InvoiceResponse::new(updated).with_line_items(load_line_items(&mut tx, invoice_id).await?);

    events::emit(
        &mut tx,
        Audience::Tenant,
        events::INVOICE_VOIDED,
        json!({ "invoice": &response }),
    )
    .await?;

    tx.commit().await?;

    tracing::info!(invoice_id = %invoice_id, to = "void", "invoice state changed");

    Ok(Json(response))
}

pub async fn get(
    State(state): State<AppState>,
    ctx: AuthContext,
    Path(id): Path<String>,
) -> AppResult<Json<InvoiceResponse>> {
    let invoice_id = ids::parse_id(ids::INVOICE, &id)?;
    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    let invoice = load_invoice(&mut tx, invoice_id, ctx.business_id)
        .await?
        .ok_or(AppError::NotFound("invoice"))?;

    let line_items = load_line_items(&mut tx, invoice_id).await?;

    let attempts: Vec<PaymentAttemptRow> = sqlx::query_as(
        "SELECT id, invoice_id, status, processor, amount_cents, psp_ref, failure_code, created_at
         FROM payment_attempts
         WHERE invoice_id = $1 AND business_id = $2
         ORDER BY created_at DESC",
    )
    .bind(invoice_id)
    .bind(ctx.business_id)
    .fetch_all(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(
        InvoiceResponse::new(invoice)
            .with_line_items(line_items)
            .with_payment_attempts(attempts),
    ))
}

#[derive(Debug, Deserialize)]
pub struct ListInvoices {
    #[serde(default)]
    pub state: Option<String>,
    /// `?overdue=true` returns only invoices that are late; `?overdue=false`
    /// only those that are not. Omitted means no filter.
    #[serde(default)]
    pub overdue: Option<bool>,
    #[serde(default)]
    pub customer_id: Option<String>,
    #[serde(flatten)]
    pub page: Pagination,
}

pub async fn list(
    State(state): State<AppState>,
    ctx: AuthContext,
    Query(query): Query<ListInvoices>,
) -> AppResult<Json<ListResponse<InvoiceResponse>>> {
    let state_filter: Option<InvoiceState> = query
        .state
        .as_deref()
        .map(|s| {
            s.parse::<InvoiceState>().map_err(|_| {
                AppError::validation(format!(
                    "unknown state `{s}`; valid states are {}",
                    InvoiceState::ALL
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })
        })
        .transpose()?;

    let customer_filter: Option<Uuid> = query
        .customer_id
        .as_deref()
        .map(|c| ids::parse_id(ids::CUSTOMER, c))
        .transpose()?;

    let cursor: Option<Uuid> = query
        .page
        .starting_after
        .as_deref()
        .map(|c| ids::parse_id(ids::INVOICE, c))
        .transpose()?;

    let limit = query.page.limit();
    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    let mut rows: Vec<InvoiceRow> = sqlx::query_as(
        "SELECT id, customer_id, state, total_cents, amount_paid_cents, currency,
                due_date, sent_at, paid_at, created_at
         FROM invoices
         WHERE business_id = $1
           AND ($2::text IS NULL OR state = $2)
           AND ($3::uuid IS NULL OR customer_id = $3)
           AND ($4::boolean IS NULL
                OR (state IN ('sent', 'partially_paid') AND due_date < CURRENT_DATE) = $4)
           AND ($5::uuid IS NULL OR (created_at, id) <
                (SELECT i.created_at, i.id FROM invoices i WHERE i.id = $5))
         ORDER BY created_at DESC, id DESC
         LIMIT $6",
    )
    .bind(ctx.business_id)
    .bind(state_filter.map(|s| s.as_str()))
    .bind(customer_filter)
    .bind(query.overdue)
    .bind(cursor)
    .bind(limit + 1)
    .fetch_all(&mut *tx)
    .await?;

    tx.commit().await?;

    let has_more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);

    Ok(Json(ListResponse::new(
        rows.into_iter().map(InvoiceResponse::new).collect(),
        has_more,
    )))
}

pub async fn load_invoice(
    tx: &mut Transaction<'_, Postgres>,
    invoice_id: Uuid,
    business_id: Uuid,
) -> Result<Option<InvoiceRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, customer_id, state, total_cents, amount_paid_cents, currency,
                due_date, sent_at, paid_at, created_at
         FROM invoices WHERE id = $1 AND business_id = $2",
    )
    .bind(invoice_id)
    .bind(business_id)
    .fetch_optional(&mut **tx)
    .await
}

pub async fn load_line_items(
    tx: &mut Transaction<'_, Postgres>,
    invoice_id: Uuid,
) -> Result<Vec<LineItemRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, description, quantity, unit_amount_cents, amount_cents
         FROM invoice_line_items WHERE invoice_id = $1 ORDER BY position",
    )
    .bind(invoice_id)
    .fetch_all(&mut **tx)
    .await
}
