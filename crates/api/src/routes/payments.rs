//! `POST /invoices/{id}/pay`
//!
//! # The shape of the problem
//!
//! Paying an invoice means doing two things that cannot be made atomic: taking
//! money at a third party, and recording that we took it. Any design has to
//! pick where the seam goes and what happens if the process dies on it.
//!
//! This one splits the request into three phases with **no transaction held
//! across the network call**:
//!
//! ```text
//!   phase 1 (short tx)          phase 2 (no tx)         phase 3 (short tx)
//!   ─────────────────────       ───────────────         ──────────────────────
//!   claim idempotency key       adapter.charge()        settle the attempt
//!   lock invoice FOR UPDATE      5s timeout             move the invoice
//!   insert pending attempt                              emit the event
//!   COMMIT ───────────────────▶                ────────▶ record the response
//! ```
//!
//! Holding a transaction across phase 2 would be the obvious implementation
//! and is the wrong one: a provider that hangs for 30 seconds would pin a
//! database connection and a row lock for 30 seconds each. Thirty concurrent
//! hung payments would take the whole pool down, which turns one slow vendor
//! into a total outage. The `tok_timeout` card exists to probe exactly this.
//!
//! # Mutual exclusion
//!
//! The guarantee "at most one in-flight payment per invoice" has to hold
//! across phase 2, when we hold no locks at all. So it is not a lock:
//!
//! ```sql
//! CREATE UNIQUE INDEX payment_attempts_one_pending_per_invoice
//!     ON payment_attempts (invoice_id) WHERE status = 'pending';
//! ```
//!
//! A committed row is what excludes everyone else, and it stays committed
//! while we talk to the provider, and it survives us crashing. The `FOR
//! UPDATE` in phase 1 is still there, but it does a smaller job: it serialises
//! concurrent claimants so they queue rather than collide, and it makes the
//! state check and the attempt insert see a consistent invoice.
//!
//! Considered and rejected:
//! * **Advisory locks** - released when the connection dies. If the process
//!   crashes mid-charge, the lock evaporates while the charge is still live at
//!   the provider, and the next request charges again.
//! * **SERIALIZABLE** - makes concurrent payers retry rather than fail
//!   cleanly, taxes every unrelated query on the same tables, and still does
//!   not span phase 2.
//! * **A lock held across the PSP call** - the pool exhaustion above.
//!
//! # The five failure modes
//!
//! * **(a) two simultaneous payments** - the partial unique index. One inserts,
//!   the other gets 23505 and a 409 `payment_in_progress`.
//! * **(b) the PSP times out** - the outcome is *unknown*, so the attempt stays
//!   `pending` and the caller gets **202**, not a guess. The reconciler
//!   resolves it.
//! * **(c) the PSP succeeded but we crashed before recording it** - the attempt
//!   is still `pending` after the crash, and the reconciler re-submits **the
//!   same reference** to **the same processor**. Provider-side idempotency
//!   returns the original outcome instead of charging again. This is why
//!   `reference` and `processor` are columns and not locals.
//! * **(d) the same idempotency key with a different body** - **422**. Replaying
//!   the stored response would hide a caller bug; a second charge would be
//!   worse.
//! * **(e) paying an already-paid invoice** - the `FOR UPDATE` read sees `paid`
//!   and returns 409 `invoice_already_paid` before any attempt row exists.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::db::tenant::begin_as_tenant;
use crate::domain::state_machine::{transition, InvoiceEvent, InvoiceState};
use crate::domain::{ids, money};
use crate::error::{is_unique_violation, AppError, AppResult};
use crate::events::{self, Audience};
use crate::psp::{ChargeOutcome, ChargeRequest, PspError};
use crate::routes::invoices::{load_invoice, load_line_items};
use crate::routes::models::*;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct PayRequest {
    pub card_token: String,
    /// Which provider to charge through. Defaults to `DEFAULT_PROCESSOR`.
    #[serde(default)]
    pub processor: Option<String>,
}

pub async fn pay(
    State(state): State<AppState>,
    ctx: AuthContext,
    Path(id): Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<PayRequest>,
) -> AppResult<Response> {
    let invoice_id = ids::parse_id(ids::INVOICE, &id)?;

    // Required, not optional. An idempotency key that callers may omit is one
    // that callers will omit, and the request it is protecting is the one
    // request in this API where a duplicate costs a customer real money.
    let idempotency_key = headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            AppError::validation("the Idempotency-Key header is required for this endpoint")
        })?
        .to_string();

    if idempotency_key.len() > 255 {
        return Err(AppError::validation(
            "Idempotency-Key must be at most 255 characters",
        ));
    }
    if body.card_token.trim().is_empty() {
        return Err(AppError::validation("card_token must not be empty"));
    }

    let processor_name = body
        .processor
        .clone()
        .unwrap_or_else(|| state.processors.default_name().to_string());

    let processor = state.processors.get(&processor_name).ok_or_else(|| {
        AppError::validation(format!(
            "unknown processor `{processor_name}`; available processors are {}",
            state.processors.names().join(", ")
        ))
    })?;

    let request_hash = hash_request(invoice_id, &body);

    /* ---------------------------------------------------------------- */
    /* phase 1: claim                                                    */
    /* ---------------------------------------------------------------- */

    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    // Claim the key. On conflict we look at what the previous holder did.
    let claimed: Option<(Uuid,)> = sqlx::query_as(
        "INSERT INTO idempotency_keys (id, business_id, key, request_hash)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (business_id, key) DO NOTHING
         RETURNING id",
    )
    .bind(ids::new_id())
    .bind(ctx.business_id)
    .bind(&idempotency_key)
    .bind(&request_hash)
    .fetch_optional(&mut *tx)
    .await?;

    if claimed.is_none() {
        let existing: Option<(String, Option<i32>, Option<serde_json::Value>)> = sqlx::query_as(
            "SELECT request_hash, response_status, response_body FROM idempotency_keys
             WHERE business_id = $1 AND key = $2",
        )
        .bind(ctx.business_id)
        .bind(&idempotency_key)
        .fetch_optional(&mut *tx)
        .await?;

        let (stored_hash, status, stored_body) = existing.ok_or_else(|| {
            // The conflicting row vanished between the INSERT and the SELECT -
            // the other request rolled back. Telling the caller to retry is
            // honest and safe; guessing is neither.
            AppError::conflict(
                "request_in_progress",
                "a concurrent request with this Idempotency-Key is still being processed",
            )
        })?;

        if stored_hash != request_hash {
            // Case (d). Not a 409: the caller's two requests disagree, which
            // is a bug on their side that a replayed response would conceal.
            return Err(AppError::IdempotencyMismatch(format!(
                "Idempotency-Key `{idempotency_key}` was already used with a different request body"
            )));
        }

        return match (status, stored_body) {
            // A completed request: hand back byte-identical bytes. No PSP call.
            (Some(status), Some(body)) => {
                tx.commit().await?;
                json_response(
                    StatusCode::from_u16(status as u16)
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    &body,
                )
            }
            // Claimed but not finished - the first request is still in flight.
            _ => Err(AppError::conflict(
                "request_in_progress",
                "a request with this Idempotency-Key is still being processed",
            )),
        };
    }

    // Serialise concurrent claimants on this invoice, and read the state we
    // are about to make a decision on under that lock.
    let invoice: InvoiceRow = sqlx::query_as(
        "SELECT id, customer_id, state, total_cents, amount_paid_cents, currency,
                due_date, sent_at, paid_at, created_at
         FROM invoices WHERE id = $1 AND business_id = $2
         FOR UPDATE",
    )
    .bind(invoice_id)
    .bind(ctx.business_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound("invoice"))?;

    let current_state = invoice.state();
    let amount_cents = money::remaining(invoice.total_cents, invoice.amount_paid_cents);

    // Case (e), and every other unpayable state. `paid` gets its own error
    // type because "someone already paid this" is a different operational
    // event from "you sent me a draft".
    if current_state == InvoiceState::Paid {
        return Err(AppError::conflict(
            "invoice_already_paid",
            "this invoice has already been paid in full",
        ));
    }
    transition(
        current_state,
        InvoiceEvent::PaymentSettled {
            amount_paid_cents: invoice.amount_paid_cents + amount_cents,
            total_cents: invoice.total_cents,
        },
    )
    .map_err(|e| AppError::InvalidStateTransition {
        current: e.from.to_string(),
        attempted: "pay".to_string(),
    })?;

    if amount_cents <= 0 {
        return Err(AppError::conflict(
            "nothing_to_pay",
            "this invoice has no outstanding balance",
        ));
    }

    let attempt_id = ids::new_id();

    // The mutual-exclusion point. v1 always charges the full remaining
    // balance; partial payment is a designed-but-unbuilt transition (see
    // state_machine.rs), so `amount_cents` is the whole balance by
    // construction rather than by request.
    let insert = sqlx::query(
        "INSERT INTO payment_attempts
            (id, invoice_id, business_id, status, processor, card_token, amount_cents)
         VALUES ($1, $2, $3, 'pending', $4, $5, $6)",
    )
    .bind(attempt_id)
    .bind(invoice_id)
    .bind(ctx.business_id)
    .bind(&processor_name)
    .bind(body.card_token.trim())
    .bind(amount_cents)
    .execute(&mut *tx)
    .await;

    if let Err(err) = insert {
        if is_unique_violation(&err, "one_pending_per_invoice") {
            // Case (a). Rolling back here also releases the idempotency key,
            // so the caller can retry with the same key once the in-flight
            // attempt resolves - which is what they will want to do.
            return Err(AppError::conflict(
                "payment_in_progress",
                "another payment for this invoice is already in progress",
            ));
        }
        return Err(err.into());
    }

    // Everything up to here is rolled back on any error above, deliberately:
    // a request that never reached the provider should not burn the caller's
    // idempotency key. From this commit onwards the key is spent, because from
    // here on money might move.
    tx.commit().await?;

    /* ---------------------------------------------------------------- */
    /* phase 2: charge - no transaction held                             */
    /* ---------------------------------------------------------------- */

    tracing::info!(
        %attempt_id, %invoice_id, processor = %processor_name, amount_cents,
        "charging payment attempt"
    );

    let outcome = processor
        .charge(&ChargeRequest {
            amount_cents,
            card_token: body.card_token.trim().to_string(),
            reference: attempt_id,
        })
        .await;

    /* ---------------------------------------------------------------- */
    /* phase 3: settle                                                   */
    /* ---------------------------------------------------------------- */

    let mut tx = begin_as_tenant(&state.pool, &ctx).await?;

    let (status, response_body) = settle(
        &mut tx,
        Audience::Tenant,
        ctx.business_id,
        invoice_id,
        attempt_id,
        amount_cents,
        &processor_name,
        outcome,
    )
    .await?;

    // Record the outcome so a replay is byte-identical, including for the 402
    // and 202 cases. A caller who retries a declined payment with the same key
    // must get the same decline, not a fresh attempt at the card.
    sqlx::query(
        "UPDATE idempotency_keys SET response_status = $3, response_body = $4
         WHERE business_id = $1 AND key = $2",
    )
    .bind(ctx.business_id)
    .bind(&idempotency_key)
    .bind(status.as_u16() as i32)
    .bind(&response_body)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    json_response(status, &response_body)
}

/// Turn a provider outcome into durable state.
///
/// Shared by the request path and the reconciler, which is the point: the
/// rules for "what does a succeeded charge do to an invoice" must not exist in
/// two places, or the background path will drift from the foreground one and
/// the difference will only show up under failure.
#[allow(clippy::too_many_arguments)]
pub async fn settle(
    tx: &mut Transaction<'_, Postgres>,
    audience: Audience,
    business_id: Uuid,
    invoice_id: Uuid,
    attempt_id: Uuid,
    amount_cents: i64,
    processor_name: &str,
    outcome: Result<ChargeOutcome, PspError>,
) -> AppResult<(StatusCode, serde_json::Value)> {
    match outcome {
        Ok(ChargeOutcome::Succeeded { psp_ref }) => {
            // Conditional on `status = 'pending'`: if the reconciler settled
            // this attempt while we were waiting, it is not ours to settle
            // again, and crucially not ours to add to the invoice balance a
            // second time.
            let settled = sqlx::query(
                "UPDATE payment_attempts SET status = 'succeeded', psp_ref = $2
                 WHERE id = $1 AND status = 'pending'",
            )
            .bind(attempt_id)
            .bind(&psp_ref)
            .execute(&mut **tx)
            .await?;

            if settled.rows_affected() == 0 {
                tracing::info!(%attempt_id, "attempt was already settled elsewhere; not double-applying");
                let invoice = reload_invoice(tx, invoice_id, business_id).await?;
                let attempt = reload_attempt(tx, attempt_id).await?;
                return Ok((
                    StatusCode::OK,
                    payment_result(attempt, InvoiceResponse::new(invoice)),
                ));
            }

            // The state is decided by arithmetic in SQL, on the row as it
            // exists at write time - not from the value read in phase 1, which
            // is now seconds old.
            let invoice: Option<InvoiceRow> = sqlx::query_as(
                "UPDATE invoices SET
                    amount_paid_cents = amount_paid_cents + $3,
                    state = CASE WHEN amount_paid_cents + $3 >= total_cents
                                 THEN 'paid' ELSE 'partially_paid' END,
                    paid_at = CASE WHEN amount_paid_cents + $3 >= total_cents
                                   THEN now() ELSE paid_at END
                 WHERE id = $1 AND business_id = $2
                   AND state IN ('sent', 'partially_paid')
                 RETURNING id, customer_id, state, total_cents, amount_paid_cents, currency,
                           due_date, sent_at, paid_at, created_at",
            )
            .bind(invoice_id)
            .bind(business_id)
            .bind(amount_cents)
            .fetch_optional(&mut **tx)
            .await?;

            let invoice = match invoice {
                Some(invoice) => invoice,
                None => {
                    // The charge succeeded but the invoice is no longer
                    // collectible. Money has moved and we cannot apply it,
                    // which is a human problem, not a retry problem.
                    tracing::error!(
                        %invoice_id, %attempt_id, %psp_ref, amount_cents, processor = %processor_name,
                        "MANUAL REVIEW: charge succeeded against an invoice that is no longer collectible"
                    );
                    reload_invoice(tx, invoice_id, business_id).await?
                }
            };

            let response = InvoiceResponse::new(invoice);
            events::emit(
                tx,
                audience,
                events::INVOICE_PAID,
                json!({
                    "invoice": &response,
                    "payment_attempt_id": ids::format_id(ids::PAYMENT_ATTEMPT, attempt_id),
                    "processor": processor_name,
                }),
            )
            .await?;

            tracing::info!(%attempt_id, %invoice_id, state = %response.state, "payment succeeded");

            let attempt = reload_attempt(tx, attempt_id).await?;
            Ok((StatusCode::OK, payment_result(attempt, response)))
        }

        Ok(ChargeOutcome::Failed { code }) => {
            sqlx::query(
                "UPDATE payment_attempts SET status = 'failed', failure_code = $2
                 WHERE id = $1 AND status = 'pending'",
            )
            .bind(attempt_id)
            .bind(&code)
            .execute(&mut **tx)
            .await?;

            // The invoice is untouched. A declined card is not a state change
            // for the document - it is still sent, still owed, still payable
            // with a different card.
            let invoice = reload_invoice(tx, invoice_id, business_id).await?;
            let response = InvoiceResponse::new(invoice);

            events::emit(
                tx,
                audience,
                events::INVOICE_PAYMENT_FAILED,
                json!({
                    "invoice": &response,
                    "payment_attempt_id": ids::format_id(ids::PAYMENT_ATTEMPT, attempt_id),
                    "failure_code": &code,
                    "processor": processor_name,
                }),
            )
            .await?;

            tracing::info!(%attempt_id, %invoice_id, %code, "payment declined");

            let error = AppError::PaymentFailed {
                code,
                payment_attempt_id: ids::format_id(ids::PAYMENT_ATTEMPT, attempt_id),
            };
            Ok((StatusCode::PAYMENT_REQUIRED, error.to_body()))
        }

        Err(err) => {
            // Case (b) and case (c). We do not know whether money moved, so we
            // assert nothing: the attempt stays `pending`, the invoice is
            // untouched, and 202 tells the caller the truth - this is not
            // finished yet, come back and look.
            //
            // Recording this as a failure would be the double-charge
            // trapdoor: the caller would retry, and the original charge might
            // have succeeded.
            tracing::warn!(
                %attempt_id, %invoice_id, processor = %processor_name, kind = err.kind(), error = %err,
                "payment outcome unknown; leaving attempt pending for reconciliation"
            );

            let attempt = reload_attempt(tx, attempt_id).await?;
            let invoice = reload_invoice(tx, invoice_id, business_id).await?;

            // The reconciler may have already resolved this attempt while we
            // were waiting on the timeout - it re-submits the same reference
            // and the provider replays the outcome immediately, so this is a
            // routine race rather than an exotic one. If the answer is now
            // known, say so: returning 202 "still pending" alongside a body
            // that reads `"status": "succeeded"` would be worse than useless.
            match attempt.status.as_str() {
                "succeeded" => Ok((
                    StatusCode::OK,
                    payment_result(attempt, InvoiceResponse::new(invoice)),
                )),
                "failed" => {
                    let code = attempt
                        .failure_code
                        .clone()
                        .unwrap_or_else(|| "unknown_decline".to_string());
                    Ok((
                        StatusCode::PAYMENT_REQUIRED,
                        AppError::PaymentFailed {
                            code,
                            payment_attempt_id: ids::format_id(ids::PAYMENT_ATTEMPT, attempt.id),
                        }
                        .to_body(),
                    ))
                }
                _ => {
                    let mut body = payment_result(attempt, InvoiceResponse::new(invoice));
                    body["message"] = json!(
                        "the payment processor did not return a definitive outcome; \
                         this attempt is being reconciled and will settle on its own. \
                         Poll GET /invoices/{id} for the result."
                    );
                    Ok((StatusCode::ACCEPTED, body))
                }
            }
        }
    }
}

/* -------------------------------------------------------------------------- */
/* helpers                                                                     */
/* -------------------------------------------------------------------------- */

/// Hash the *meaning* of the request rather than its bytes.
///
/// Hashing raw bytes would make a client that re-serialises its JSON with
/// different key order look like a different request and get a 422 it cannot
/// diagnose. Hashing the fields that determine what will happen catches every
/// difference that actually matters - a different card, a different processor,
/// a different invoice - and forgives the ones that do not.
fn hash_request(invoice_id: Uuid, body: &PayRequest) -> String {
    let canonical = format!(
        "invoice={invoice_id}&card_token={}&processor={}",
        body.card_token.trim(),
        body.processor.as_deref().unwrap_or("")
    );
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

fn payment_result(attempt: PaymentAttemptRow, invoice: InvoiceResponse) -> serde_json::Value {
    let attempt: PaymentAttemptResponse = attempt.into();
    let mut value = serde_json::to_value(attempt).unwrap_or_else(|_| json!({}));
    value["invoice"] = serde_json::to_value(invoice).unwrap_or_else(|_| json!(null));
    value
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> AppResult<Response> {
    let bytes = serde_json::to_vec(body)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("failed to encode response: {e}")))?;

    Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(bytes))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("failed to build response: {e}")))
}

async fn reload_invoice(
    tx: &mut Transaction<'_, Postgres>,
    invoice_id: Uuid,
    business_id: Uuid,
) -> AppResult<InvoiceRow> {
    load_invoice(tx, invoice_id, business_id)
        .await?
        .ok_or(AppError::NotFound("invoice"))
}

async fn reload_attempt(
    tx: &mut Transaction<'_, Postgres>,
    attempt_id: Uuid,
) -> AppResult<PaymentAttemptRow> {
    sqlx::query_as(
        "SELECT id, invoice_id, status, processor, amount_cents, psp_ref, failure_code, created_at
         FROM payment_attempts WHERE id = $1",
    )
    .bind(attempt_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(AppError::NotFound("payment attempt"))
}

/// Exposed for `GET /invoices/{id}` and the reconciler's logging.
pub async fn load_line_items_for(
    tx: &mut Transaction<'_, Postgres>,
    invoice_id: Uuid,
) -> Result<Vec<LineItemRow>, sqlx::Error> {
    load_line_items(tx, invoice_id).await
}
