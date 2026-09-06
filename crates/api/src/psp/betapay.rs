//! BetaPay adapter.
//!
//! This provider exists to keep [`PaymentProcessor`] honest. Its contract
//! disagrees with AlphaPay's on every axis that a real second integration
//! disagrees on:
//!
//! | | AlphaPay | BetaPay |
//! |---|---|---|
//! | path | `/payments` | `/v1/charges` |
//! | amount field | `amount_cents` | `amount` (+ explicit `currency`) |
//! | idempotency | `reference` in body | `Idempotency-Key` header |
//! | decline signalled by | `status` in a 200 body | HTTP 402 |
//! | success shape | `{status, psp_ref}` | `{outcome, reference}` |
//! | decline codes | already ours | `DECLINED_NSF` etc., needs mapping |
//!
//! ```text
//! POST {base}/v1/charges          Idempotency-Key: <uuid>
//! { "amount": 5000, "currency": "usd", "source": "tok_success" }
//!
//! 200 { "outcome": "approved", "reference": "bp_abc123" }
//! 402 { "error": { "reason": "DECLINED_NSF" } }
//! ```
//!
//! If the abstraction were only ever exercised by one provider it would be a
//! guess. Two providers that genuinely differ turn it into a demonstrated
//! claim: the payment flow in `routes::payments` contains no `if processor ==`
//! anywhere, and adding a third would not add one.

use serde::{Deserialize, Serialize};

use super::{classify_transport_error, ChargeOutcome, ChargeRequest, PaymentProcessor, PspError};

pub struct BetaPay {
    client: reqwest::Client,
    base_url: String,
}

impl BetaPay {
    pub fn new(client: reqwest::Client, base_url: String) -> Self {
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }
}

#[derive(Serialize)]
struct BetaPayRequest<'a> {
    amount: i64,
    currency: &'a str,
    source: &'a str,
}

#[derive(Deserialize)]
struct BetaPaySuccess {
    outcome: String,
    reference: Option<String>,
}

#[derive(Deserialize)]
struct BetaPayDecline {
    error: BetaPayDeclineBody,
}

#[derive(Deserialize)]
struct BetaPayDeclineBody {
    reason: String,
}

/// Normalise BetaPay's decline vocabulary to ours.
///
/// This mapping is the adapter's whole reason for existing. Callers branch on
/// `insufficient_funds`; they must never learn that one particular provider
/// spells it `DECLINED_NSF`. Anything unrecognised maps to a generic decline
/// rather than being passed through raw - leaking a provider string into our
/// API would make it a de facto part of our contract, and then we could never
/// change providers.
fn normalise_decline(reason: &str) -> String {
    match reason {
        "DECLINED_NSF" => "insufficient_funds",
        "DECLINED_CARD" => "card_declined",
        "DECLINED_EXPIRED" => "expired_card",
        "DECLINED_FRAUD" => "fraud_suspected",
        unknown => {
            tracing::warn!(reason = %unknown, "unmapped betapay decline reason");
            "card_declined"
        }
    }
    .to_string()
}

#[async_trait::async_trait]
impl PaymentProcessor for BetaPay {
    fn name(&self) -> &'static str {
        "betapay"
    }

    async fn charge(&self, request: &ChargeRequest) -> Result<ChargeOutcome, PspError> {
        let response = self
            .client
            .post(format!("{}/v1/charges", self.base_url))
            // Same reference as AlphaPay gets in its body - the placement is
            // the provider's business, the value is ours.
            .header("Idempotency-Key", request.reference.to_string())
            .json(&BetaPayRequest {
                amount: request.amount_cents,
                currency: "usd",
                source: &request.card_token,
            })
            .send()
            .await
            .map_err(classify_transport_error)?;

        let status = response.status();

        // 402 is BetaPay's definitive decline. This is the one non-2xx status
        // that carries a real answer; everything else is unknown.
        if status == reqwest::StatusCode::PAYMENT_REQUIRED {
            let body: BetaPayDecline = response.json().await.map_err(classify_transport_error)?;
            return Ok(ChargeOutcome::Failed {
                code: normalise_decline(&body.error.reason),
            });
        }

        if !status.is_success() {
            return Err(PspError::Protocol(format!(
                "betapay returned HTTP {status}"
            )));
        }

        let body: BetaPaySuccess = response.json().await.map_err(classify_transport_error)?;

        match body.outcome.as_str() {
            "approved" => {
                let psp_ref = body.reference.ok_or_else(|| {
                    PspError::Protocol("betapay approved a charge with no reference".to_string())
                })?;
                Ok(ChargeOutcome::Succeeded { psp_ref })
            }
            other => Err(PspError::Protocol(format!(
                "betapay returned unrecognised outcome `{other}`"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decline_codes_are_translated_not_forwarded() {
        assert_eq!(normalise_decline("DECLINED_NSF"), "insufficient_funds");
        assert_eq!(normalise_decline("DECLINED_CARD"), "card_declined");
        // An unknown provider code must still come out as one of ours.
        let mapped = normalise_decline("SOME_NEW_PROVIDER_CODE");
        assert!(!mapped.contains("PROVIDER"));
        assert_eq!(mapped, "card_declined");
    }
}
