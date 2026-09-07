//! Two mock payment providers in one binary.
//!
//! They exist to make the `PaymentProcessor` abstraction testable rather than
//! aspirational. `alphapay` implements the assignment's contract verbatim;
//! `betapay` implements a deliberately different one - different path,
//! different field names, idempotency in a header instead of the body, and
//! declines signalled by HTTP 402 rather than by a field in a 200. Both honour
//! the same magic card tokens with the same semantics, so the only thing that
//! differs between them is exactly what an adapter is supposed to absorb.
//!
//! # Magic tokens
//!
//! | token | behaviour |
//! |---|---|
//! | `tok_success` | ~100 ms, then success |
//! | `tok_insufficient_funds` | ~100 ms, then a definitive decline |
//! | `tok_card_declined` | ~100 ms, then a definitive decline |
//! | `tok_timeout` | 30 s, then success (the caller must not wait) |
//! | `tok_network_error` | connection dropped mid-response |
//!
//! # The idempotency ledger
//!
//! Charges are recorded against `(provider, reference)` before any latency is
//! simulated, and a repeat of a known reference replays the stored outcome
//! without charging again. This mirrors what real PSPs do with idempotency
//! keys, and it is the specific thing that makes the "we crashed after the
//! provider succeeded" failure mode answerable: the reconciler can re-submit
//! the same reference and find out what happened, rather than gambling.
//!
//! Recording *before* the sleep is what makes `tok_timeout` interesting. The
//! original 30-second call is still in flight when the reconciler retries, and
//! the retry returns the already-committed outcome immediately - so the
//! service learns the charge succeeded long before the original request would
//! have told it.
//!
//! The ledger is an in-memory map, so it forgets on restart. Fine for a mock;
//! a real provider's is durable, and nothing in the service depends on ours
//! being anything better.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

const NORMAL_LATENCY: Duration = Duration::from_millis(100);
const TIMEOUT_LATENCY: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum StoredOutcome {
    Succeeded { psp_ref: String },
    Failed { code: String },
}

#[derive(Clone, Debug, Serialize)]
struct ChargeRecord {
    provider: String,
    reference: String,
    card_token: String,
    amount_cents: i64,
    #[serde(flatten)]
    outcome: StoredOutcome,
}

#[derive(Default)]
struct Ledger {
    /// (provider, reference) -> the outcome that reference has already had.
    by_reference: HashMap<(String, String), ChargeRecord>,
    /// Every charge that actually happened, in order. The count is what the
    /// concurrency and idempotency tests assert on: "exactly one charge left
    /// this system" is a claim about the provider, not about our database.
    charges: Vec<ChargeRecord>,
}

#[derive(Clone, Default)]
struct AppState {
    ledger: Arc<Mutex<Ledger>>,
}

/// What a token means, before any provider-specific dressing.
enum TokenBehaviour {
    Success,
    Decline(&'static str),
    SuccessAfterLongDelay,
    DropConnection,
}

fn behaviour_for(card_token: &str) -> TokenBehaviour {
    match card_token {
        "tok_insufficient_funds" => TokenBehaviour::Decline("insufficient_funds"),
        "tok_card_declined" => TokenBehaviour::Decline("card_declined"),
        "tok_timeout" => TokenBehaviour::SuccessAfterLongDelay,
        "tok_network_error" => TokenBehaviour::DropConnection,
        // tok_success and anything else: a happy path, so a demo with a
        // realistic-looking token still works.
        _ => TokenBehaviour::Success,
    }
}

/// Resolve a charge against the ledger.
///
/// Returns the outcome plus how long to pretend it took, and whether this was
/// a replay. The ledger write happens here, under the lock, before any sleep -
/// so two concurrent requests for one reference cannot both be recorded as
/// charges.
fn settle(
    state: &AppState,
    provider: &str,
    reference: &str,
    card_token: &str,
    amount_cents: i64,
) -> (StoredOutcome, Duration, bool) {
    let key = (provider.to_string(), reference.to_string());

    {
        let ledger = state.ledger.lock().unwrap();
        if let Some(existing) = ledger.by_reference.get(&key) {
            // Replay: no new charge, no simulated latency. This is what a real
            // provider does with a repeated idempotency key, and it is why
            // reconciliation is safe.
            tracing::info!(provider, reference, "replaying known reference");
            return (existing.outcome.clone(), Duration::ZERO, true);
        }
    }

    let (outcome, latency) = match behaviour_for(card_token) {
        TokenBehaviour::Success => (
            StoredOutcome::Succeeded {
                psp_ref: format!("{provider}_ref_{}", &reference.replace('-', "")[..12]),
            },
            NORMAL_LATENCY,
        ),
        TokenBehaviour::Decline(code) => (
            StoredOutcome::Failed {
                code: code.to_string(),
            },
            NORMAL_LATENCY,
        ),
        TokenBehaviour::SuccessAfterLongDelay => (
            StoredOutcome::Succeeded {
                psp_ref: format!("{provider}_ref_{}", &reference.replace('-', "")[..12]),
            },
            TIMEOUT_LATENCY,
        ),
        TokenBehaviour::DropConnection => unreachable!("handled before reaching the ledger"),
    };

    let record = ChargeRecord {
        provider: provider.to_string(),
        reference: reference.to_string(),
        card_token: card_token.to_string(),
        amount_cents,
        outcome: outcome.clone(),
    };

    let mut ledger = state.ledger.lock().unwrap();
    // Re-check under the write lock: two requests for one reference may have
    // both missed above.
    if let Some(existing) = ledger.by_reference.get(&key) {
        return (existing.outcome.clone(), Duration::ZERO, true);
    }
    ledger.by_reference.insert(key, record.clone());
    ledger.charges.push(record);

    tracing::info!(provider, reference, card_token, ?outcome, "charged");
    (outcome, latency, false)
}

/// A response whose body starts and then the connection dies.
///
/// Emitting a truncated chunked body and then a stream error makes hyper abort
/// the response, which is what the client sees as a transport failure. That is
/// the point: the caller must experience "I don't know what happened", not a
/// tidy error object it might mistake for a decline.
fn dropped_connection() -> Response {
    let chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
        Ok(axum::body::Bytes::from_static(b"{\"status\":\"suc")),
        Err(std::io::Error::other("connection reset by peer")),
    ];

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from_stream(futures::stream::iter(chunks)))
        .expect("static response is valid")
}

/* ==========================================================================
 * alphapay - the assignment's contract, verbatim
 * ========================================================================== */

#[derive(Deserialize)]
struct AlphaPayRequest {
    amount_cents: i64,
    card_token: String,
    reference: String,
}

async fn alphapay_payments(
    State(state): State<AppState>,
    Json(body): Json<AlphaPayRequest>,
) -> Response {
    if matches!(behaviour_for(&body.card_token), TokenBehaviour::DropConnection) {
        return dropped_connection();
    }

    let (outcome, latency, _replayed) = settle(
        &state,
        "alphapay",
        &body.reference,
        &body.card_token,
        body.amount_cents,
    );
    tokio::time::sleep(latency).await;

    // Both outcomes are HTTP 200 here; the result lives in the body.
    let payload = match outcome {
        StoredOutcome::Succeeded { psp_ref } => json!({ "status": "succeeded", "psp_ref": psp_ref }),
        StoredOutcome::Failed { code } => json!({ "status": "failed", "code": code }),
    };

    (StatusCode::OK, Json(payload)).into_response()
}

/* ==========================================================================
 * betapay - deliberately a different contract
 * ========================================================================== */

#[derive(Deserialize)]
struct BetaPayRequest {
    amount: i64,
    #[allow(dead_code)]
    currency: String,
    source: String,
}

/// BetaPay's decline vocabulary. The adapter has to translate these; that
/// translation is the thing being demonstrated.
fn betapay_reason(code: &str) -> &'static str {
    match code {
        "insufficient_funds" => "DECLINED_NSF",
        _ => "DECLINED_CARD",
    }
}

async fn betapay_charges(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BetaPayRequest>,
) -> Response {
    // Idempotency reference arrives in a header, not the body.
    let reference = headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    if reference.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "reason": "MISSING_IDEMPOTENCY_KEY" } })),
        )
            .into_response();
    }

    if matches!(behaviour_for(&body.source), TokenBehaviour::DropConnection) {
        return dropped_connection();
    }

    let (outcome, latency, _replayed) =
        settle(&state, "betapay", &reference, &body.source, body.amount);
    tokio::time::sleep(latency).await;

    match outcome {
        StoredOutcome::Succeeded { psp_ref } => (
            StatusCode::OK,
            Json(json!({ "outcome": "approved", "reference": psp_ref })),
        )
            .into_response(),
        // The decline is in the status code, not the body.
        StoredOutcome::Failed { code } => (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({ "error": { "reason": betapay_reason(&code) } })),
        )
            .into_response(),
    }
}

/* ==========================================================================
 * test-only administration
 * ========================================================================== */

/// Lets tests assert "exactly one charge happened" against the *provider*
/// rather than against our own database, which is the only place that claim
/// actually means anything.
async fn admin_charges(State(state): State<AppState>) -> Json<serde_json::Value> {
    let ledger = state.ledger.lock().unwrap();
    Json(json!({
        "total_charges": ledger.charges.len(),
        "charges": ledger.charges,
    }))
}

async fn admin_charges_for_reference(
    State(state): State<AppState>,
    Path(reference): Path<String>,
) -> Json<serde_json::Value> {
    let ledger = state.ledger.lock().unwrap();
    let matching: Vec<&ChargeRecord> = ledger
        .charges
        .iter()
        .filter(|c| c.reference == reference)
        .collect();
    Json(json!({ "count": matching.len(), "charges": matching }))
}

async fn admin_reset(State(state): State<AppState>) -> StatusCode {
    let mut ledger = state.ledger.lock().unwrap();
    ledger.by_reference.clear();
    ledger.charges.clear();
    StatusCode::NO_CONTENT
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let state = AppState::default();

    let app = Router::new()
        .route("/alphapay/payments", post(alphapay_payments))
        .route("/betapay/v1/charges", post(betapay_charges))
        .route("/admin/charges", get(admin_charges))
        .route("/admin/charges/{reference}", get(admin_charges_for_reference))
        .route("/admin/reset", post(admin_reset))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state);

    let addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:9090".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "mock-psp listening (providers: alphapay, betapay)");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
