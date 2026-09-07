//! Failure mode (d), and the ordinary retry case that motivates the whole
//! mechanism.

mod support;

use support::{TestApp, TOK_CARD_DECLINED, TOK_SUCCESS};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replaying_a_request_returns_the_original_response_without_charging_again() {
    let app = TestApp::start().await;
    let invoice_id = app.create_sent_invoice(30_000).await;

    let (first_status, first_body) = app
        .pay(&invoice_id, &app.full_key, "retry-me", TOK_SUCCESS)
        .await;
    assert_eq!(first_status, 200);

    // A client that did not see the first response - a dropped connection, a
    // restarted worker - retries. It must get the same answer, not a second
    // charge.
    let (second_status, second_body) = app
        .pay(&invoice_id, &app.full_key, "retry-me", TOK_SUCCESS)
        .await;

    assert_eq!(second_status, first_status);
    assert_eq!(
        second_body, first_body,
        "the replayed response differed from the original"
    );

    assert_eq!(app.provider_charge_count(&invoice_id).await, 1);
    assert_eq!(
        app.attempt_statuses(&invoice_id).await,
        vec!["succeeded".to_string()],
        "a replay must not create a second attempt"
    );
}

/// Declines are replayed too. This is the case people forget: if a retry of a
/// declined payment silently re-attempted the card, a client retry loop would
/// hammer a customer's card and could trip the issuer's fraud controls.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_declined_payment_replays_as_the_same_decline() {
    let app = TestApp::start().await;
    let invoice_id = app.create_sent_invoice(7_500).await;

    let (first_status, first_body) = app
        .pay(&invoice_id, &app.full_key, "decline-once", TOK_CARD_DECLINED)
        .await;
    assert_eq!(first_status, 402);

    let (second_status, second_body) = app
        .pay(&invoice_id, &app.full_key, "decline-once", TOK_CARD_DECLINED)
        .await;

    assert_eq!(second_status, 402);
    assert_eq!(second_body, first_body);
    assert_eq!(app.provider_charge_count(&invoice_id).await, 1);
}

/// Failure mode (d): same key, different body.
///
/// 422 rather than a replay, because the two requests disagree about what
/// should happen and replaying would hide a caller bug behind a success. 422
/// rather than 409, because nothing is in conflict - the request is
/// semantically wrong.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reusing_a_key_with_a_different_body_is_rejected() {
    let app = TestApp::start().await;
    let invoice_id = app.create_sent_invoice(15_000).await;

    let (status, _) = app
        .pay(&invoice_id, &app.full_key, "shared-key", TOK_SUCCESS)
        .await;
    assert_eq!(status, 200);

    let (status, body) = app
        .pay(&invoice_id, &app.full_key, "shared-key", TOK_CARD_DECLINED)
        .await;

    assert_eq!(status, 422, "{body}");
    assert_eq!(body["error"]["type"], "idempotency_key_reuse");

    // And nothing extra happened at the provider.
    assert_eq!(app.provider_charge_count(&invoice_id).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_idempotency_key_header_is_required() {
    let app = TestApp::start().await;
    let invoice_id = app.create_sent_invoice(1_000).await;

    let response = app
        .request(
            reqwest::Method::POST,
            &format!("/invoices/{invoice_id}/pay"),
            &app.full_key,
        )
        .json(&serde_json::json!({ "card_token": TOK_SUCCESS }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Idempotency-Key"),
        "{body}"
    );

    // Nothing was attempted.
    assert!(app.attempt_statuses(&invoice_id).await.is_empty());
}

/// Idempotency keys are scoped per tenant, so two businesses using the obvious
/// key ("invoice-123") never collide with each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idempotency_keys_are_scoped_to_the_tenant() {
    let app_a = TestApp::start().await;
    let app_b = TestApp::start().await;

    let invoice_a = app_a.create_sent_invoice(2_000).await;
    let invoice_b = app_b.create_sent_invoice(3_000).await;

    let (status, _) = app_a
        .pay(&invoice_a, &app_a.full_key, "same-key", TOK_SUCCESS)
        .await;
    assert_eq!(status, 200);

    // Same literal key, different business: must be treated as a brand new
    // request, not a replay of someone else's.
    let (status, body) = app_b
        .pay(&invoice_b, &app_b.full_key, "same-key", TOK_SUCCESS)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["amount_cents"], 3_000);
}

/// A conflict that happens *before* the provider is contacted rolls back the
/// idempotency claim, so the key is not burned. Otherwise a caller who hit a
/// transient 409 could never retry that request at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_is_not_consumed_by_a_request_that_never_reached_the_provider() {
    let app = TestApp::start().await;
    let invoice_id = app.create_invoice(5_000).await; // still a draft

    let (status, body) = app
        .pay(&invoice_id, &app.full_key, "reusable", TOK_SUCCESS)
        .await;
    assert_eq!(status, 409, "{body}");

    // Now make it payable and retry with the same key.
    let (status, _) = app
        .post_empty(&format!("/invoices/{invoice_id}/send"), &app.full_key)
        .await;
    assert_eq!(status, 200);

    let (status, body) = app
        .pay(&invoice_id, &app.full_key, "reusable", TOK_SUCCESS)
        .await;
    assert_eq!(status, 200, "the key should have been reusable: {body}");
}
