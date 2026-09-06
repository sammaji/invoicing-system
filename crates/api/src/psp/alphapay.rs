//! AlphaPay adapter.
//!
//!
//! ```text
//! POST {base}/payments
//! { "amount_cents": 5000, "card_token": "tok_success", "reference": "<uuid>" }
//!
//! 200 { "status": "succeeded", "psp_ref": "psp_abc123" }
//! 200 { "status": "failed", "code": "card_declined" }
//! ```
//!
//! Note that both outcomes are HTTP 200 - the transport succeeded either way,
//! and the payment result is in the body. Compare `betapay.rs`, which puts the
//! decline in the status code instead. Neither shape reaches the payment flow.

use serde::{Deserialize, Serialize};

use super::{classify_transport_error, ChargeOutcome, ChargeRequest, PaymentProcessor, PspError};

pub struct AlphaPay {
    client: reqwest::Client,
    base_url: String,
}

impl AlphaPay {
    pub fn new(client: reqwest::Client, base_url: String) -> Self {
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }
}

#[derive(Serialize)]
struct AlphaPayRequest<'a> {
    amount_cents: i64,
    card_token: &'a str,
    reference: String,
}

#[derive(Deserialize)]
struct AlphaPayResponse {
    status: String,
    psp_ref: Option<String>,
    code: Option<String>,
}

#[async_trait::async_trait]
impl PaymentProcessor for AlphaPay {
    fn name(&self) -> &'static str {
        "alphapay"
    }

    async fn charge(&self, request: &ChargeRequest) -> Result<ChargeOutcome, PspError> {
        let response = self
            .client
            .post(format!("{}/payments", self.base_url))
            .json(&AlphaPayRequest {
                amount_cents: request.amount_cents,
                card_token: &request.card_token,
                reference: request.reference.to_string(),
            })
            .send()
            .await
            .map_err(classify_transport_error)?;

        let status = response.status();

        // A 5xx is not a decline. The provider may have taken the money and
        // then fallen over on the way to telling us; treating this as `Failed`
        // would let the caller retry into a double charge.
        if !status.is_success() {
            return Err(PspError::Protocol(format!(
                "alphapay returned HTTP {status}"
            )));
        }

        let body: AlphaPayResponse = response.json().await.map_err(classify_transport_error)?;

        match body.status.as_str() {
            "succeeded" => {
                let psp_ref = body.psp_ref.ok_or_else(|| {
                    // Succeeded without a reference is unusable: we would have
                    // no way to reconcile or refund it. Unknown, not success.
                    PspError::Protocol("alphapay reported success with no psp_ref".to_string())
                })?;
                Ok(ChargeOutcome::Succeeded { psp_ref })
            }
            "failed" => Ok(ChargeOutcome::Failed {
                // AlphaPay already speaks our vocabulary. BetaPay does not -
                // see the mapping table there.
                code: body.code.unwrap_or_else(|| "unknown_decline".to_string()),
            }),
            other => Err(PspError::Protocol(format!(
                "alphapay returned unrecognised status `{other}`"
            ))),
        }
    }
}
