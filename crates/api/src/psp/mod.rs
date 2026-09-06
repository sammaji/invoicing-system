//! Payment service provider abstraction.
//!
//! # The one design point that matters
//!
//! A charge has **three** outcomes, not two:
//!
//! * [`ChargeOutcome::Succeeded`] - the provider took the money.
//! * [`ChargeOutcome::Failed`] - the provider definitively refused. Nothing
//!   was charged, and retrying the same card will refuse again.
//! * [`PspError`] - **we do not know**. The request timed out, the connection
//!   dropped, or the response was unparseable. The charge may have gone
//!   through. It may not have. From here the two are indistinguishable.
//!
//! Collapsing the third case into the second is the single most expensive
//! mistake available in this code. If a timeout is recorded as "failed", the
//! caller retries, and a customer is charged twice for one invoice. So
//! `charge` returns `Result<ChargeOutcome, PspError>` and adapters are
//! forbidden - in the trait contract, not just by convention - from turning a
//! transport failure into a `Failed`.
//!
//! What the service does with an unknown outcome is in `routes::payments` and
//! `reconciler`: the attempt stays `pending`, the caller gets 202, and a
//! background sweep re-submits **with the same reference** until the provider
//! tells us which of the two it was. Provider-side idempotency on that
//! reference is what makes the retry safe, which is why `reference` is part of
//! the request rather than an adapter detail.
//!
//! # Adding a provider
//!
//! One file implementing [`PaymentProcessor`], one line in [`Registry::new`].
//! Everything provider-shaped - base URL, wire format, which HTTP status means
//! "declined", what they call insufficient funds - stays inside the adapter.
//! The payment flow never sees provider JSON. Two mock providers with
//! deliberately different contracts ship in `crates/mock-psp` specifically so
//! that this claim is tested rather than asserted.

pub mod alphapay;
pub mod betapay;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use crate::config::Config;

#[derive(Debug, Clone)]
pub struct ChargeRequest {
    pub amount_cents: i64,
    pub card_token: String,
    /// Our `payment_attempts.id`. Sent to the provider as its idempotency
    /// reference, so re-submitting after an unknown outcome returns the
    /// original result instead of charging again.
    pub reference: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChargeOutcome {
    Succeeded { psp_ref: String },
    /// A definitive answer from the provider. `code` is normalised by the
    /// adapter to our vocabulary (`insufficient_funds`, `card_declined`, ...),
    /// so callers never branch on a provider's private strings.
    Failed { code: String },
}

/// Every variant means exactly one thing: **the outcome is unknown**.
#[derive(Debug, thiserror::Error)]
pub enum PspError {
    #[error("payment processor timed out")]
    Timeout,
    #[error("could not reach payment processor: {0}")]
    Network(String),
    /// The provider answered, but not in a language we understand. Treated as
    /// unknown rather than failed: a response we can't parse might well be
    /// describing a successful charge.
    #[error("unexpected response from payment processor: {0}")]
    Protocol(String),
}

impl PspError {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Network(_) => "network",
            Self::Protocol(_) => "protocol",
        }
    }
}

/// # Contract
///
/// Implementations **must** return `Err(PspError)` for any situation in which
/// the fate of the charge is not known with certainty from the provider's own
/// answer. In particular: a timeout is never `Failed`, a dropped connection is
/// never `Failed`, and a 5xx is never `Failed`. Only an explicit decline from
/// the provider is `Failed`.
#[async_trait::async_trait]
pub trait PaymentProcessor: Send + Sync {
    fn name(&self) -> &'static str;

    async fn charge(&self, request: &ChargeRequest) -> Result<ChargeOutcome, PspError>;
}

/// Maps the `processor` field on a charge request to an adapter.
///
/// Built once at startup. The name is persisted on every payment attempt,
/// because a reconciliation retry has to reach the *same* provider - a
/// reference is only idempotent at the provider that issued it.
pub struct Registry {
    processors: HashMap<String, Arc<dyn PaymentProcessor>>,
    default_name: String,
}

impl Registry {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        // One HTTP client, shared: connection pooling across attempts, and one
        // place where the timeout is set. The timeout is on the client rather
        // than wrapped around each call so it covers connect, TLS, headers and
        // body - a response that dribbles in for 30 seconds is just as much a
        // hang as one that never starts.
        let client = reqwest::Client::builder()
            .timeout(config.psp_timeout)
            .connect_timeout(Duration::from_secs(2))
            .build()?;

        let mut processors: HashMap<String, Arc<dyn PaymentProcessor>> = HashMap::new();

        let alphapay = Arc::new(alphapay::AlphaPay::new(
            client.clone(),
            config.psp_alphapay_url.clone(),
        ));
        processors.insert(alphapay.name().to_string(), alphapay);

        let betapay = Arc::new(betapay::BetaPay::new(
            client.clone(),
            config.psp_betapay_url.clone(),
        ));
        processors.insert(betapay.name().to_string(), betapay);

        if !processors.contains_key(&config.default_processor) {
            anyhow::bail!(
                "DEFAULT_PROCESSOR `{}` is not a registered processor (have: {})",
                config.default_processor,
                processors.keys().cloned().collect::<Vec<_>>().join(", ")
            );
        }

        Ok(Self {
            processors,
            default_name: config.default_processor.clone(),
        })
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn PaymentProcessor>> {
        self.processors.get(name)
    }

    pub fn default_name(&self) -> &str {
        &self.default_name
    }

    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.processors.keys().map(|k| k.as_str()).collect();
        names.sort_unstable();
        names
    }
}

/// Shared by both adapters: classify a reqwest failure without ever losing the
/// "unknown" quality of it.
pub(crate) fn classify_transport_error(err: reqwest::Error) -> PspError {
    if err.is_timeout() {
        PspError::Timeout
    } else if err.is_decode() {
        PspError::Protocol(format!("could not read response body: {err}"))
    } else {
        PspError::Network(err.to_string())
    }
}
