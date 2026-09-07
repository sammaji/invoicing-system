//! Event emission via a transactional outbox.
//!
//! Transactional outbox to ensure that a delivery row is written in the same
//! transaction as the state change that caused it. Either the invoice became
//! paid and someone will be told, or neither happened. There is no window in
//! which the database says "paid" and no notification will ever be sent, and
//! no window in which we announce a payment that then rolls back.

use serde_json::json;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::domain::ids;

pub const INVOICE_CREATED: &str = "invoice.created";
pub const INVOICE_SENT: &str = "invoice.sent";
pub const INVOICE_PAID: &str = "invoice.paid";
pub const INVOICE_PAYMENT_FAILED: &str = "invoice.payment_failed";
pub const INVOICE_VOIDED: &str = "invoice.voided";

#[derive(Clone, Copy)]
pub enum Audience {
    /// Inside a tenant-scoped transaction. Uses a SECURITY DEFINER helper that
    /// resolves the business from the request claims, because a caller's own
    /// scopes may legitimately not include `webhook:read` - a payment
    /// collector should be able to *cause* an event without being able to
    /// enumerate where events go.
    Tenant,
    /// Inside an `invoice_service` transaction, which is cross-tenant by
    /// design and so must name the business explicitly.
    Service { business_id: Uuid },
}

/// Insert one delivery row per live endpoint.
///
/// `event_id` is generated here and stays stable across every retry of this
/// event, so a receiver can deduplicate on it. That is the other half of
/// at-least-once delivery: we promise to keep trying, they get the means to
/// notice a repeat.
pub async fn emit(
    tx: &mut Transaction<'_, Postgres>,
    audience: Audience,
    event_type: &str,
    data: serde_json::Value,
) -> Result<Option<Uuid>, sqlx::Error> {
    let endpoints: Vec<(Uuid, Uuid)> = match audience {
        Audience::Tenant => {
            sqlx::query_as("SELECT id, business_id FROM active_webhook_endpoints()")
                .fetch_all(&mut **tx)
                .await?
        }
        Audience::Service { business_id } => {
            sqlx::query_as(
                "SELECT id, business_id FROM webhook_endpoints
                 WHERE business_id = $1 AND disabled_at IS NULL",
            )
            .bind(business_id)
            .fetch_all(&mut **tx)
            .await?
        }
    };

    if endpoints.is_empty() {
        // Nobody is listening. Not an error, and deliberately not a stored
        // row either - an outbox of events with no destination is just a
        // table that grows.
        return Ok(None);
    }

    let event_id = ids::new_id();
    let created_at = chrono::Utc::now();

    let payload = json!({
        "id": ids::format_id(ids::EVENT, event_id),
        "type": event_type,
        "created_at": created_at,
        "data": data,
    });

    for (endpoint_id, business_id) in endpoints {
        sqlx::query(
            "INSERT INTO webhook_deliveries
                (id, endpoint_id, business_id, event_id, event_type, payload, status, next_attempt_at)
             VALUES ($1, $2, $3, $4, $5, $6, 'pending', now())",
        )
        .bind(ids::new_id())
        .bind(endpoint_id)
        .bind(business_id)
        .bind(event_id)
        .bind(event_type)
        .bind(&payload)
        .execute(&mut **tx)
        .await?;
    }

    Ok(Some(event_id))
}
