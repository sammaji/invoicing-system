//! Failure mode (a): two payment requests for the same invoice at the same
//! time.
//!
//! The assertion that matters is the last one - the *provider* recorded
//! exactly one charge. Asserting that our database has one succeeded attempt
//! would only show that we are internally consistent about a customer being
//! charged twice.

mod support;

use std::time::Duration;

use support::{TestApp, TestAppOptions, TOK_SUCCESS};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn twenty_concurrent_payments_charge_the_card_exactly_once() {
    let app = TestApp::start().await;
    let invoice_id = app.create_sent_invoice(50_000).await;

    // Twenty requests, each with its own idempotency key - so idempotency is
    // *not* what is being tested here. These are twenty genuinely distinct
    // attempts to pay the same invoice, which is the situation a retrying
    // client or a duplicated queue message actually produces.
    let mut handles = Vec::new();
    for i in 0..20 {
        let app_url = app.base_url.clone();
        let key = app.full_key.clone();
        let invoice_id = invoice_id.clone();
        let client = app.client.clone();

        handles.push(tokio::spawn(async move {
            let response = client
                .post(format!("{app_url}/invoices/{invoice_id}/pay"))
                .header("authorization", format!("Bearer {key}"))
                .header("Idempotency-Key", format!("concurrent-{i}"))
                .json(&serde_json::json!({ "card_token": TOK_SUCCESS }))
                .send()
                .await
                .expect("request failed");

            let status = response.status().as_u16();
            let body: serde_json::Value = response.json().await.unwrap_or_default();
            (status, body)
        }));
    }

    let mut successes = 0;
    let mut conflicts = 0;
    let mut others = Vec::new();

    for handle in handles {
        let (status, body) = handle.await.expect("task panicked");
        match status {
            200 => successes += 1,
            409 => {
                // The losers must lose for the right reason, and the reason
                // must be machine-readable - a client needs to tell "someone
                // else is paying this right now, back off" apart from "this
                // invoice cannot be paid at all".
                let error_type = body["error"]["type"].as_str().unwrap_or("");
                assert!(
                    error_type == "payment_in_progress" || error_type == "invoice_already_paid",
                    "unexpected 409 type: {body}"
                );
                conflicts += 1;
            }
            other => others.push((other, body)),
        }
    }

    assert!(others.is_empty(), "unexpected responses: {others:?}");
    assert_eq!(successes, 1, "exactly one request should have succeeded");
    assert_eq!(conflicts, 19);

    // Exactly one attempt reached a succeeded state.
    let statuses = app.attempt_statuses(&invoice_id).await;
    assert_eq!(
        statuses.iter().filter(|s| *s == "succeeded").count(),
        1,
        "attempt statuses were {statuses:?}"
    );
    assert_eq!(app.invoice_state(&invoice_id).await, "paid");

    // The claim that actually matters.
    assert_eq!(
        app.provider_charge_count(&invoice_id).await,
        1,
        "the provider recorded more than one charge for this invoice"
    );
}

/// The same race, but the loser arrives *after* the winner has finished rather
/// than while it is in flight. The mechanism that rejects it is different - the
/// invoice state check rather than the partial unique index - and both need to
/// hold, because which one fires depends purely on timing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paying_an_already_paid_invoice_is_rejected() {
    let app = TestApp::start().await;
    let invoice_id = app.create_sent_invoice(12_345).await;

    let (status, _) = app
        .pay(&invoice_id, &app.full_key, "first", TOK_SUCCESS)
        .await;
    assert_eq!(status, 200);

    let (status, body) = app
        .pay(&invoice_id, &app.full_key, "second", TOK_SUCCESS)
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"]["type"], "invoice_already_paid");

    assert_eq!(app.provider_charge_count(&invoice_id).await, 1);
}

/// Once a payment fails definitively the invoice is untouched and payable
/// again - a declined card is not a state change for the document. This also
/// pins that the partial unique index frees up: a failed attempt must not
/// block the retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_declined_invoice_can_be_paid_with_another_card() {
    let app = TestApp::start().await;
    let invoice_id = app.create_sent_invoice(9_900).await;

    let (status, body) = app
        .pay(
            &invoice_id,
            &app.full_key,
            "declined",
            support::TOK_CARD_DECLINED,
        )
        .await;
    assert_eq!(status, 402, "{body}");
    assert_eq!(body["error"]["code"], "card_declined");
    assert_eq!(app.invoice_state(&invoice_id).await, "sent");

    let (status, _) = app
        .pay(&invoice_id, &app.full_key, "retry", TOK_SUCCESS)
        .await;
    assert_eq!(status, 200);
    assert_eq!(app.invoice_state(&invoice_id).await, "paid");
}

/// A payment that is still in flight blocks a second one even across the
/// window where no transaction is held - which is the entire reason the
/// exclusion is an index and not a lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payment_in_flight_blocks_a_second_one() {
    let app = TestApp::start_with(TestAppOptions {
        // Long enough that the first request is still waiting on the provider
        // when the second arrives.
        psp_timeout: Duration::from_secs(10),
        ..Default::default()
    })
    .await;

    let invoice_id = app.create_sent_invoice(4_200).await;

    let slow = {
        let client = app.client.clone();
        let url = format!("{}/invoices/{invoice_id}/pay", app.base_url);
        let key = app.full_key.clone();
        tokio::spawn(async move {
            client
                .post(url)
                .header("authorization", format!("Bearer {key}"))
                .header("Idempotency-Key", "slow")
                .json(&serde_json::json!({ "card_token": support::TOK_TIMEOUT }))
                .send()
                .await
                .map(|r| r.status().as_u16())
        })
    };

    // Give the first request time to commit its pending attempt.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (status, body) = app
        .pay(&invoice_id, &app.full_key, "fast", TOK_SUCCESS)
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"]["type"], "payment_in_progress");

    let _ = slow.await;
}
