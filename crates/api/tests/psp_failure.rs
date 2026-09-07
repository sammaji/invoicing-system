//! Failure modes (b) and (c): the provider does not give us an answer.
//!
//! These are the tests that justify the tri-state `Result<ChargeOutcome,
//! PspError>` and the reconciler. The behaviour being pinned is that an
//! unknown outcome is recorded as unknown - never as a failure, because a
//! caller who retries a "failure" that actually succeeded is a double charge.

mod support;

use std::time::Duration;

use support::{TestApp, TestAppOptions, TOK_NETWORK_ERROR, TOK_SUCCESS, TOK_TIMEOUT};

/// A provider that hangs must not make us hang.
///
/// The mock sleeps 30 seconds on `tok_timeout`. Our client budget is 3, so the
/// request has to come back in about 3 - if this test ever takes 30, the
/// timeout is not being applied and one slow vendor can exhaust the connection
/// pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hanging_provider_does_not_hang_the_caller() {
    let app = TestApp::start_with(TestAppOptions {
        background_workers: false,
        psp_timeout: Duration::from_secs(3),
        ..Default::default()
    })
    .await;

    let invoice_id = app.create_sent_invoice(20_000).await;

    let started = std::time::Instant::now();
    let (status, body) = app
        .pay(&invoice_id, &app.full_key, "hang", TOK_TIMEOUT)
        .await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(8),
        "the request took {elapsed:?}; the PSP timeout is not being enforced"
    );

    // This app instance runs no reconciler, but tests share a database and the
    // reconciler is cross-tenant by design - a concurrently running test's
    // aggressive reconciler may legitimately resolve this attempt (the mock
    // records the charge before it starts sleeping) while we are still waiting
    // on the timeout. Both honest answers are pinned; a guessed failure is not.
    match status {
        // We do not know what happened, and the response says exactly that.
        // The invoice is untouched: nothing asserted about money we cannot
        // confirm.
        202 => {
            assert_eq!(body["status"], "pending", "{body}");
            assert_eq!(app.invoice_state(&invoice_id).await, "sent");
            assert_eq!(
                app.attempt_statuses(&invoice_id).await,
                vec!["pending".to_string()]
            );
        }
        // A neighbouring reconciler already learned the real outcome, and the
        // request path reported that instead of a stale "pending".
        200 => {
            assert_eq!(body["status"], "succeeded", "{body}");
            assert_eq!(app.invoice_state(&invoice_id).await, "paid");
            assert_eq!(
                app.provider_charge_count(&invoice_id).await,
                1,
                "the resolved outcome must still be a single charge"
            );
        }
        other => panic!("expected 202 (unknown) or 200 (reconciled), got {other}: {body}"),
    }
}

/// Failure mode (c), and the whole point of the reconciler.
///
/// The provider committed the charge before it started sleeping, exactly as a
/// real one would commit before responding. We gave up waiting. The attempt is
/// `pending` and there is real money on the other side of it. The reconciler
/// re-submits the same reference, the provider replays the original outcome,
/// and the invoice settles - with the customer charged once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_reconciler_resolves_an_unknown_outcome_without_charging_twice() {
    let app = TestApp::start_with(TestAppOptions {
        background_workers: true,
        reconciler_interval: Duration::from_millis(200),
        reconciler_stale_after: Duration::from_millis(200),
        psp_timeout: Duration::from_secs(2),
        ..Default::default()
    })
    .await;

    let invoice_id = app.create_sent_invoice(44_400).await;

    let (status, _) = app
        .pay(&invoice_id, &app.full_key, "reconcile-me", TOK_TIMEOUT)
        .await;
    assert!(
        status == 202 || status == 200,
        "expected an unknown or already-reconciled outcome, got {status}"
    );

    app.wait_for_attempt_status(&invoice_id, "succeeded", Duration::from_secs(20))
        .await;

    assert_eq!(app.invoice_state(&invoice_id).await, "paid");

    // The reconciliation retry reused the reference, so the provider treated
    // it as a replay. One charge, not two.
    assert_eq!(
        app.provider_charge_count(&invoice_id).await,
        1,
        "reconciliation charged the customer a second time"
    );
}

/// A dropped connection is also an unknown outcome. The response body is
/// truncated mid-JSON, which is precisely the situation where a naive adapter
/// would fall through to some default and call it a failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_connection_is_unknown_not_failed() {
    let app = TestApp::start().await;
    let invoice_id = app.create_sent_invoice(6_000).await;

    let (status, body) = app
        .pay(&invoice_id, &app.full_key, "dropped", TOK_NETWORK_ERROR)
        .await;

    assert_eq!(status, 202, "{body}");
    assert_eq!(body["status"], "pending");

    // Critically: the invoice is not corrupted, and the attempt is not marked
    // failed. Nothing has been asserted about money.
    assert_eq!(app.invoice_state(&invoice_id).await, "sent");
    assert_eq!(
        app.attempt_statuses(&invoice_id).await,
        vec!["pending".to_string()]
    );
}

/// A provider that never comes back must not be retried forever. After the cap
/// the attempt reaches a terminal state with a code that says *why* - the
/// distinction between "the card was declined" and "we never found out"
/// matters enormously to whoever picks this up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconciliation_gives_up_loudly_rather_than_retrying_forever() {
    let app = TestApp::start_with(TestAppOptions {
        background_workers: true,
        reconciler_interval: Duration::from_millis(200),
        reconciler_stale_after: Duration::from_millis(200),
        reconciler_max_attempts: 2,
        psp_timeout: Duration::from_secs(2),
        ..Default::default()
    })
    .await;

    let invoice_id = app.create_sent_invoice(3_300).await;

    let (status, _) = app
        .pay(&invoice_id, &app.full_key, "never-resolves", TOK_NETWORK_ERROR)
        .await;
    assert_eq!(status, 202);

    app.wait_for_attempt_status(&invoice_id, "failed", Duration::from_secs(30))
        .await;

    let code: Option<String> = sqlx::query_scalar(
        "SELECT failure_code FROM payment_attempts WHERE invoice_id = $1",
    )
    .bind(support::strip_prefix(&invoice_id))
    .fetch_one(&app.admin_pool)
    .await
    .unwrap();

    assert_eq!(
        code.as_deref(),
        Some("reconciliation_exhausted"),
        "an unresolvable attempt must be distinguishable from a decline"
    );

    // The invoice is still owed. We never confirmed a payment, so we never
    // claim one.
    assert_eq!(app.invoice_state(&invoice_id).await, "sent");
}

/// The abstraction claim: the same magic tokens produce the same *canonical*
/// behaviour through a provider whose wire contract differs on every axis.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_providers_behave_identically_through_their_adapters() {
    let app = TestApp::start().await;

    for processor in ["alphapay", "betapay"] {
        let invoice_id = app.create_sent_invoice(11_000).await;

        // BetaPay signals this with HTTP 402 and the code `DECLINED_NSF`;
        // AlphaPay with a 200 whose body says `insufficient_funds`. The caller
        // sees one thing.
        let response = app
            .request(
                reqwest::Method::POST,
                &format!("/invoices/{invoice_id}/pay"),
                &app.full_key,
            )
            .header("Idempotency-Key", format!("nsf-{processor}"))
            .json(&serde_json::json!({
                "card_token": support::TOK_INSUFFICIENT_FUNDS,
                "processor": processor,
            }))
            .send()
            .await
            .unwrap();

        let status = response.status().as_u16();
        let body: serde_json::Value = response.json().await.unwrap();

        assert_eq!(status, 402, "{processor}: {body}");
        assert_eq!(
            body["error"]["code"], "insufficient_funds",
            "{processor} leaked a provider-specific decline code: {body}"
        );

        // And a success through the same adapter.
        let invoice_id = app.create_sent_invoice(11_000).await;
        let response = app
            .request(
                reqwest::Method::POST,
                &format!("/invoices/{invoice_id}/pay"),
                &app.full_key,
            )
            .header("Idempotency-Key", format!("ok-{processor}"))
            .json(&serde_json::json!({ "card_token": TOK_SUCCESS, "processor": processor }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status().as_u16(), 200, "{processor}");
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["processor"], processor);
        assert_eq!(body["status"], "succeeded");
        assert_eq!(app.invoice_state(&invoice_id).await, "paid");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_processor_is_rejected_before_anything_happens() {
    let app = TestApp::start().await;
    let invoice_id = app.create_sent_invoice(1_500).await;

    let response = app
        .request(
            reqwest::Method::POST,
            &format!("/invoices/{invoice_id}/pay"),
            &app.full_key,
        )
        .header("Idempotency-Key", "bad-processor")
        .json(&serde_json::json!({ "card_token": TOK_SUCCESS, "processor": "gammapay" }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    // The error names what is available, so the caller can fix it.
    assert!(body["error"]["message"].as_str().unwrap().contains("alphapay"));

    assert!(app.attempt_statuses(&invoice_id).await.is_empty());
}
