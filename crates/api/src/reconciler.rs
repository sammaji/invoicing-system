//! The pending-attempt sweeper.
//!
//! This is the answer to the two failure modes that a request handler cannot
//! answer on its own, because in both of them the request is already over:
//!
//! * **(b) the provider timed out.** We returned 202 with an unknown outcome.
//!   Something has to go back and find out what happened.
//! * **(c) the provider succeeded and we crashed before recording it.** There
//!   is a `pending` attempt in the database, real money moved at the provider,
//!   and nothing in the request path will ever run again for that request.
//!
//! # How it resolves them safely
//!
//! It re-submits **the same reference** to **the same processor**. Both are
//! columns on `payment_attempts` for exactly this reason. The provider's
//! idempotency ledger recognises the reference and returns the original
//! outcome rather than charging again - so the retry is a *query* about what
//! happened, not a second attempt to make it happen.
//!
//! That property comes from the provider, not from us. It is the reason the
//! `reference` is part of the `PaymentProcessor` contract rather than an
//! implementation detail of one adapter: without it, there is no safe way to
//! recover from an unknown outcome at all, and the only remaining options are
//! to risk a double charge or to abandon the money.
//!
//! # Bounded, then loud
//!
//! Retries are capped (`RECONCILER_MAX_ATTEMPTS`, default 5). An attempt that
//! is still unresolved after that is marked `failed` with
//! `reconciliation_exhausted` and logged at error level. That is not a
//! resolution - it is a deliberate handoff to a human, because at that point
//! we have a payment whose fate we cannot determine automatically and the
//! correct next step is for someone to look at the provider's dashboard. A
//! system that quietly retried forever would hide that.
//!
//! # Backoff without a scheduler
//!
//! Claiming a row bumps `updated_at` (via the table's trigger), and the sweep
//! only selects rows whose `updated_at` is older than `RECONCILER_STALE_AFTER`.
//! So the claim itself is the backoff, and there is no separate `next_retry_at`
//! column to keep consistent.

use sqlx::Row;
use uuid::Uuid;

use crate::db::tenant::begin_as_service;
use crate::domain::ids;
use crate::events::Audience;
use crate::psp::ChargeRequest;
use crate::routes::payments::settle;
use crate::state::AppState;

struct StaleAttempt {
    id: Uuid,
    invoice_id: Uuid,
    business_id: Uuid,
    processor: String,
    card_token: String,
    amount_cents: i64,
    reconcile_attempts: i32,
}

pub async fn run(state: AppState) {
    let mut ticker = tokio::time::interval(state.config.reconciler_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    tracing::info!(
        interval_ms = state.config.reconciler_interval.as_millis(),
        stale_after_ms = state.config.reconciler_stale_after.as_millis(),
        max_attempts = state.config.reconciler_max_attempts,
        "payment reconciler started"
    );

    loop {
        ticker.tick().await;

        match sweep(&state).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(reconciled = n, "reconciliation sweep processed attempts"),
            Err(err) => tracing::error!(error = %err, "reconciliation sweep failed"),
        }
    }
}

async fn sweep(state: &AppState) -> anyhow::Result<usize> {
    let stale = claim(state).await?;
    if stale.is_empty() {
        return Ok(0);
    }

    let count = stale.len();
    for attempt in stale {
        if let Err(err) = reconcile_one(state, attempt).await {
            tracing::error!(error = %err, "failed to reconcile a payment attempt");
        }
    }

    Ok(count)
}

async fn claim(state: &AppState) -> anyhow::Result<Vec<StaleAttempt>> {
    let mut tx = begin_as_service(&state.pool).await?;

    // Claiming and counting in one statement. `SKIP LOCKED` keeps this correct
    // if more than one replica is running - each takes different rows.
    let rows = sqlx::query(
        "UPDATE payment_attempts
         SET reconcile_attempts = reconcile_attempts + 1
         WHERE id IN (
             SELECT id FROM payment_attempts
             WHERE status = 'pending'
               AND updated_at < now() - ($1::double precision * interval '1 second')
             ORDER BY updated_at
             LIMIT 20
             FOR UPDATE SKIP LOCKED
         )
         RETURNING id, invoice_id, business_id, processor, card_token, amount_cents,
                   reconcile_attempts",
    )
    .bind(state.config.reconciler_stale_after.as_secs_f64())
    .fetch_all(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(rows
        .into_iter()
        .map(|row| StaleAttempt {
            id: row.get("id"),
            invoice_id: row.get("invoice_id"),
            business_id: row.get("business_id"),
            processor: row.get("processor"),
            card_token: row.get("card_token"),
            amount_cents: row.get("amount_cents"),
            reconcile_attempts: row.get("reconcile_attempts"),
        })
        .collect())
}

async fn reconcile_one(state: &AppState, attempt: StaleAttempt) -> anyhow::Result<()> {
    if attempt.reconcile_attempts > state.config.reconciler_max_attempts {
        return give_up(state, &attempt).await;
    }

    let Some(processor) = state.processors.get(&attempt.processor) else {
        // The attempt names a processor this build does not have - a config
        // change or a rollback. Retrying cannot help and the money is real, so
        // this goes straight to a human.
        tracing::error!(
            attempt_id = %attempt.id,
            processor = %attempt.processor,
            "MANUAL REVIEW: pending attempt names an unknown processor"
        );
        return give_up(state, &attempt).await;
    };

    tracing::info!(
        attempt_id = %attempt.id,
        invoice_id = %attempt.invoice_id,
        processor = %attempt.processor,
        try_number = attempt.reconcile_attempts,
        "re-submitting pending attempt with its original reference"
    );

    // Same reference, same processor. The provider recognises it and replays
    // the original outcome instead of charging again.
    let outcome = processor
        .charge(&ChargeRequest {
            amount_cents: attempt.amount_cents,
            card_token: attempt.card_token.clone(),
            reference: attempt.id,
        })
        .await;

    if let Err(err) = &outcome {
        // Still unknown. Leave it pending and let the next sweep try again;
        // the attempt counter is already incremented, so this terminates.
        tracing::warn!(
            attempt_id = %attempt.id,
            kind = err.kind(),
            error = %err,
            try_number = attempt.reconcile_attempts,
            "reconciliation attempt still has no definitive outcome"
        );
        return Ok(());
    }

    let mut tx = begin_as_service(&state.pool).await?;

    // The same `settle` the request path uses. One definition of what a
    // succeeded or declined charge does to an invoice, so the background path
    // cannot drift from the foreground one.
    let (status, _body) = settle(
        &mut tx,
        Audience::Service {
            business_id: attempt.business_id,
        },
        attempt.business_id,
        attempt.invoice_id,
        attempt.id,
        attempt.amount_cents,
        &attempt.processor,
        outcome,
    )
    .await?;

    tx.commit().await?;

    tracing::info!(
        attempt_id = %attempt.id,
        invoice_id = %attempt.invoice_id,
        resolved_as = status.as_u16(),
        "reconciled a previously unknown payment outcome"
    );

    Ok(())
}

/// Stop retrying and say so, loudly.
async fn give_up(state: &AppState, attempt: &StaleAttempt) -> anyhow::Result<()> {
    let mut tx = begin_as_service(&state.pool).await?;

    sqlx::query(
        "UPDATE payment_attempts
         SET status = 'failed', failure_code = 'reconciliation_exhausted'
         WHERE id = $1 AND status = 'pending'",
    )
    .bind(attempt.id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // `failed` here does NOT mean "the card was declined". It means "we could
    // not determine what happened", and the money may well have moved. The
    // distinction is in the failure_code, and this log line is the reason the
    // code exists: it is what an alert should page on.
    tracing::error!(
        attempt_id = %ids::format_id(ids::PAYMENT_ATTEMPT, attempt.id),
        invoice_id = %ids::format_id(ids::INVOICE, attempt.invoice_id),
        business_id = %attempt.business_id,
        processor = %attempt.processor,
        amount_cents = attempt.amount_cents,
        attempts = attempt.reconcile_attempts,
        "MANUAL REVIEW REQUIRED: payment outcome could not be determined after \
         repeated reconciliation; the charge may or may not have been taken"
    );

    Ok(())
}
