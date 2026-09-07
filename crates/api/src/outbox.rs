//! The webhook dispatcher.
//!
//! Reads the outbox that `events.rs` writes and actually delivers it. Runs as
//! a background task on its own schedule, so nothing about a customer's
//! receiver - slow, down, or rate-limiting - can affect the latency of a
//! payment request.
//!
//! # Claiming
//!
//! ```sql
//! UPDATE webhook_deliveries SET status = 'delivering', ...
//! WHERE id IN (SELECT id FROM webhook_deliveries
//!              WHERE status = 'pending' AND next_attempt_at <= now()
//!              ORDER BY next_attempt_at LIMIT $1
//!              FOR UPDATE SKIP LOCKED)
//! ```
//!
//! `FOR UPDATE SKIP LOCKED` is what makes this safe to run in more than one
//! process: a second replica claims different rows instead of blocking on the
//! first one's, and no coordination service is involved. Nothing about this
//! design needs to change to scale out; the only thing that would need adding
//! is a sweep for rows stuck in `delivering` because a replica died holding
//! them (noted in DESIGN.md).
//!
//! # Signing
//!
//! Stripe-shaped, because receivers already have code for that shape:
//!
//! ```text
//! Webhook-Id:        evt_...                      (stable across retries)
//! Webhook-Timestamp: 1772035200
//! Webhook-Signature: v1=<hex HMAC-SHA256(secret, "{timestamp}.{body}")>
//! ```
//!
//! The timestamp is inside the signed string, so an attacker who captures a
//! valid request cannot replay it later against a receiver that checks the age
//! - without the secret they cannot re-sign a fresh timestamp. Receivers
//! should reject anything older than five minutes and compare signatures in
//! constant time; the recipe is in the README and `openapi.yaml`.
//!
//! # Delivery semantics
//!
//! At-least-once. Retries are 5s, 30s, 2m, 10m, 30m, 2h across 7 attempts
//! (~2.7 hours), each jittered so a receiver that just came back up does not
//! get every pending delivery in the same instant. `Webhook-Id` is stable
//! across all of them, so receivers can deduplicate.
//!
//! After the last attempt the row becomes `exhausted` and stays queryable via
//! `GET /webhook_deliveries?status=exhausted`. It is not silently dropped, and
//! it is not retried forever. Webhooks are notifications, not the source of
//! truth: a receiver that missed one reconciles from `GET /invoices`, which is
//! why an automatic redrive endpoint was a comfortable thing to cut.

use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::Row;
use uuid::Uuid;

use crate::db::tenant::begin_as_service;
use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

/// Delay after attempt N fails. Front-loaded because most failures are a
/// receiver restarting, and stretched out at the end because anything still
/// failing after ten minutes is not going to be fixed by trying harder.
const BACKOFF: [Duration; 6] = [
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(2 * 60),
    Duration::from_secs(10 * 60),
    Duration::from_secs(30 * 60),
    Duration::from_secs(2 * 60 * 60),
];

const MAX_ATTEMPTS: i32 = BACKOFF.len() as i32 + 1;

struct Claimed {
    id: Uuid,
    event_id: Uuid,
    event_type: String,
    payload: serde_json::Value,
    attempt_count: i32,
    url: String,
    secret: String,
}

pub async fn run(state: AppState) {
    let mut ticker = tokio::time::interval(state.config.webhook_poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    tracing::info!(
        interval_ms = state.config.webhook_poll_interval.as_millis(),
        "webhook dispatcher started"
    );

    loop {
        ticker.tick().await;

        match dispatch_batch(&state).await {
            Ok(0) => {}
            Ok(n) => tracing::debug!(delivered = n, "webhook batch processed"),
            // A failure here must never kill the loop: a transient database
            // blip would otherwise silently stop all webhook delivery for the
            // lifetime of the process.
            Err(err) => tracing::error!(error = %err, "webhook dispatch batch failed"),
        }
    }
}

async fn dispatch_batch(state: &AppState) -> anyhow::Result<usize> {
    let claimed = claim(state).await?;
    if claimed.is_empty() {
        return Ok(0);
    }

    let count = claimed.len();
    for delivery in claimed {
        // Sequential rather than concurrent: the batch is 10, and delivering
        // in order keeps the log readable. Making this a JoinSet is a
        // one-line change if throughput ever needs it.
        if let Err(err) = deliver(state, delivery).await {
            tracing::error!(error = %err, "webhook delivery failed to settle");
        }
    }

    Ok(count)
}

async fn claim(state: &AppState) -> anyhow::Result<Vec<Claimed>> {
    let mut tx = begin_as_service(&state.pool).await?;

    let rows = sqlx::query(
        "UPDATE webhook_deliveries d
         SET status = 'delivering', attempt_count = d.attempt_count + 1
         FROM webhook_endpoints e
         WHERE d.endpoint_id = e.id
           AND d.id IN (
               SELECT id FROM webhook_deliveries
               WHERE status = 'pending' AND next_attempt_at <= now()
               ORDER BY next_attempt_at
               LIMIT $1
               FOR UPDATE SKIP LOCKED
           )
         RETURNING d.id, d.event_id, d.event_type, d.payload, d.attempt_count, e.url, e.secret",
    )
    .bind(state.config.webhook_batch_size)
    .fetch_all(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(rows
        .into_iter()
        .map(|row| Claimed {
            id: row.get("id"),
            event_id: row.get("event_id"),
            event_type: row.get("event_type"),
            payload: row.get("payload"),
            attempt_count: row.get("attempt_count"),
            url: row.get("url"),
            secret: row.get("secret"),
        })
        .collect())
}

async fn deliver(state: &AppState, delivery: Claimed) -> anyhow::Result<()> {
    // Serialise once and sign exactly the bytes that are sent. Signing a
    // re-serialised copy is how signature mismatches happen in the field.
    let body = serde_json::to_vec(&delivery.payload)?;
    let timestamp = chrono::Utc::now().timestamp();
    let signature = sign(&delivery.secret, timestamp, &body);

    let result = state
        .http
        .post(&delivery.url)
        .timeout(state.config.webhook_delivery_timeout)
        .header("content-type", "application/json")
        .header(
            "Webhook-Id",
            crate::domain::ids::format_id(crate::domain::ids::EVENT, delivery.event_id),
        )
        .header("Webhook-Timestamp", timestamp.to_string())
        .header("Webhook-Signature", format!("v1={signature}"))
        .body(body)
        .send()
        .await;

    let outcome = match result {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) => Err(format!("receiver returned HTTP {}", response.status())),
        Err(err) => Err(err.to_string()),
    };

    let mut tx = begin_as_service(&state.pool).await?;

    match outcome {
        Ok(()) => {
            sqlx::query(
                "UPDATE webhook_deliveries
                 SET status = 'delivered', delivered_at = now(), last_error = NULL
                 WHERE id = $1",
            )
            .bind(delivery.id)
            .execute(&mut *tx)
            .await?;

            tracing::info!(
                delivery_id = %delivery.id,
                event_type = %delivery.event_type,
                attempt = delivery.attempt_count,
                "webhook delivered"
            );
        }
        Err(error) => {
            if delivery.attempt_count >= MAX_ATTEMPTS {
                sqlx::query(
                    "UPDATE webhook_deliveries SET status = 'exhausted', last_error = $2
                     WHERE id = $1",
                )
                .bind(delivery.id)
                .bind(&error)
                .execute(&mut *tx)
                .await?;

                // Loud on purpose. This is the line an alert should fire on:
                // it means a customer's integration has been silently broken
                // for nearly three hours.
                tracing::error!(
                    delivery_id = %delivery.id,
                    event_type = %delivery.event_type,
                    url = %delivery.url,
                    attempts = delivery.attempt_count,
                    error = %error,
                    "webhook delivery exhausted; no further attempts will be made"
                );
            } else {
                let delay = backoff_for(delivery.attempt_count);

                sqlx::query(
                    "UPDATE webhook_deliveries
                     SET status = 'pending',
                         last_error = $2,
                         next_attempt_at = now() + ($3::double precision * interval '1 second')
                     WHERE id = $1",
                )
                .bind(delivery.id)
                .bind(&error)
                .bind(delay.as_secs_f64())
                .execute(&mut *tx)
                .await?;

                tracing::warn!(
                    delivery_id = %delivery.id,
                    attempt = delivery.attempt_count,
                    retry_in_s = delay.as_secs(),
                    error = %error,
                    "webhook delivery failed; scheduled for retry"
                );
            }
        }
    }

    tx.commit().await?;
    Ok(())
}

/// `HMAC-SHA256(secret, "{timestamp}.{body}")`, hex.
fn sign(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Backoff with jitter in [0.5x, 1.5x].
///
/// Without jitter, every delivery queued during an outage retries at exactly
/// the same moments, and the receiver's first breath after coming back is a
/// thundering herd from every event it missed.
fn backoff_for(attempt_count: i32) -> Duration {
    let index = (attempt_count - 1).clamp(0, BACKOFF.len() as i32 - 1) as usize;
    let base = BACKOFF[index];

    let jitter: f64 = {
        use rand::Rng;
        rand::rng().random_range(0.5..1.5)
    };

    Duration::from_secs_f64(base.as_secs_f64() * jitter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_covers_both_timestamp_and_body() {
        let a = sign("whsec_test", 1_772_035_200, b"{\"id\":\"evt_1\"}");

        // Same body, different timestamp: different signature. This is what
        // stops a captured request from being replayed later.
        assert_ne!(a, sign("whsec_test", 1_772_035_201, b"{\"id\":\"evt_1\"}"));
        // Same timestamp, different body: different signature.
        assert_ne!(a, sign("whsec_test", 1_772_035_200, b"{\"id\":\"evt_2\"}"));
        // Different secret: different signature.
        assert_ne!(a, sign("whsec_other", 1_772_035_200, b"{\"id\":\"evt_1\"}"));
        // Deterministic for the same inputs, or receivers could never verify.
        assert_eq!(a, sign("whsec_test", 1_772_035_200, b"{\"id\":\"evt_1\"}"));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn signature_is_not_confusable_by_moving_the_delimiter() {
        // "1.23" + body must not equal "1" + ".23" + body. The delimiter is
        // what makes the two fields unambiguous.
        assert_ne!(sign("s", 12, b"3.x"), sign("s", 123, b"x"));
    }

    #[test]
    fn backoff_grows_and_stays_bounded() {
        for attempt in 1..=MAX_ATTEMPTS {
            let delay = backoff_for(attempt);
            assert!(delay.as_secs_f64() > 0.0);
            // Never longer than the largest step plus its jitter ceiling.
            assert!(delay.as_secs_f64() <= BACKOFF[BACKOFF.len() - 1].as_secs_f64() * 1.5);
        }

        // Out-of-range input clamps rather than panicking - a stuck row with a
        // surprising attempt_count must not take the dispatcher down.
        assert!(backoff_for(0).as_secs_f64() > 0.0);
        assert!(backoff_for(999).as_secs_f64() > 0.0);
    }

    #[test]
    fn the_advertised_retry_budget_is_what_the_table_actually_says() {
        // The docs above and DESIGN.md both claim ~2.7 hours over 7 attempts.
        let total: f64 = BACKOFF.iter().map(|d| d.as_secs_f64()).sum();
        assert_eq!(MAX_ATTEMPTS, 7);
        assert!((total / 3600.0 - 2.7).abs() < 0.1, "budget is {total}s");
    }
}
