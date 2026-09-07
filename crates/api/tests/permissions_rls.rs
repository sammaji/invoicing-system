//! The four-action grammar, enforced end to end.
//!
//! `tests/permissions.rs` pins the two `has_scope` implementations against
//! each other. This file asks the question that agreement does not answer: do
//! the *policies* in `sql/rls.sql` and the route table actually grant the
//! right credential the right thing, through the real router and the real
//! database?
//!
//! It matters most for the distinctions `create`/`update`/`delete` exist to
//! draw, because those are the ones a single `write` verb used to blur - and
//! blurring them again would not fail any test that only checks that a `*:*`
//! key can do everything.
//!
//! Requires `docker compose up -d db mock-psp`.

mod support;

use support::{TestApp, TOK_SUCCESS};

/// Asserts a 403 that names the scope the caller lacked, rather than any 403.
/// A route accidentally requiring an unrelated scope would still be denied,
/// and the test would still pass, which is how a permission suite ends up
/// asserting nothing in particular.
fn assert_missing(body: &serde_json::Value, scope: &str, status: u16) {
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"]["type"], "missing_permission", "{body}");
    assert_eq!(body["error"]["missing_permission"], scope, "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_only_key_can_author_an_invoice_but_never_move_it() {
    let app = TestApp::start().await;
    // `customer:read` as well, because authoring an invoice resolves the
    // customer first and a scope it cannot read is a customer that does not
    // exist. Worth stating rather than working around: the finer grammar makes
    // a credential's scope list describe the *request path* it drives, not
    // just the row it ultimately writes.
    let key = app.key_with(&["invoice:create", "customer:read"]).await;

    // Authoring exercises three of the edited policies in one request: the
    // invoices INSERT, the invoice_line_items INSERT that the factory gates on
    // the same resource, and the webhook_deliveries INSERT for invoice.created
    // - which is gated on the state change that emitted it, not on a webhook
    // scope. If any of those still demanded the old `write`, this is a 500.
    let (status, body) = app
        .post(
            "/invoices",
            &key,
            serde_json::json!({
                "customer_id": app.create_customer().await,
                "currency": "usd",
                "due_date": "2030-01-01",
                "line_items": [{ "description": "consulting", "quantity": 1, "unit_amount_cents": 5_000 }],
            }),
        )
        .await;
    assert_eq!(status, 201, "invoice creation failed: {body}");
    let invoice_id = body["id"].as_str().unwrap().to_string();

    // Read comes along with it, because Postgres gives us no choice: the
    // INSERT above is a `RETURNING`, which is checked against the SELECT
    // policy too.
    let (status, body) = app.get(&format!("/invoices/{invoice_id}"), &key).await;
    assert_eq!(status, 200, "{body}");

    // ...but authoring a draft is not the power to issue it, and never the
    // power to void it. Under the old two-action grammar this key would have
    // held `invoice:write` and been able to do both.
    let (status, body) = app
        .post_empty(&format!("/invoices/{invoice_id}/send"), &key)
        .await;
    assert_missing(&body, "invoice:update", status);

    let (status, body) = app
        .post_empty(&format!("/invoices/{invoice_id}/void"), &key)
        .await;
    assert_missing(&body, "invoice:update", status);

    assert_eq!(app.invoice_state(&invoice_id).await, "draft");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_update_only_key_can_move_an_invoice_but_never_author_one() {
    let app = TestApp::start().await;
    let key = app.key_with(&["invoice:update"]).await;
    let invoice_id = app.create_invoice(12_000).await;

    // The mirror image: this key drives the state machine, and the invoices
    // UPDATE policy plus the webhook_deliveries INSERT for invoice.sent both
    // have to accept invoice:update for it to work.
    let (status, body) = app
        .post_empty(&format!("/invoices/{invoice_id}/send"), &key)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(app.invoice_state(&invoice_id).await, "sent");

    let (status, body) = app
        .post(
            "/invoices",
            &key,
            serde_json::json!({
                "customer_id": app.create_customer().await,
                "currency": "usd",
                "due_date": "2030-01-01",
                "line_items": [{ "description": "x", "quantity": 1, "unit_amount_cents": 100 }],
            }),
        )
        .await;
    assert_missing(&body, "invoice:create", status);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_collector_can_take_a_payment_and_still_nothing_else() {
    let app = TestApp::start().await;
    let invoice_id = app.create_sent_invoice(20_000).await;

    // One request across four edited policies: payment_attempts INSERT
    // (payment:create), payment_attempts UPDATE (the settle leg, which is why
    // that policy accepts payment:create at all), invoices UPDATE (accepting
    // payment:create so the balance can move), and webhook_deliveries INSERT
    // for invoice.paid. A miss on any one of them fails here rather than in
    // production.
    let (status, body) = app
        .pay(&invoice_id, &app.collector_key, "collect", TOK_SUCCESS)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(app.invoice_state(&invoice_id).await, "paid");

    // The separations the collector key exists to demonstrate. Note the last
    // one is new: taking a payment never meant the power to void the invoice,
    // but it now has a scope name that says so.
    let (status, body) = app
        .post(
            "/customers",
            &app.collector_key,
            serde_json::json!({ "name": "Nope", "email": "nope@example.com" }),
        )
        .await;
    assert_missing(&body, "customer:create", status);

    let (status, body) = app
        .post_empty(&format!("/invoices/{invoice_id}/void"), &app.collector_key)
        .await;
    assert_missing(&body, "invoice:update", status);
}

/// The headline of the change, and the reason it was worth making: issuing
/// credentials and revoking them are now separate powers.
///
/// Both routes are critical-tier, so each key mints a short-lived token first
/// - which also checks that `is_subset_of` lets a one-scope key mint its own
/// single scope, and that the api_keys policies discriminate between the two
/// halves rather than both reading "some api_key write".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn minting_and_revoking_credentials_are_separate_powers() {
    let app = TestApp::start().await;

    let minter = app.key_with(&["api_key:create"]).await;
    let revoker = app.key_with(&["api_key:delete"]).await;
    let minter_token = app.mint_token(&minter, &["api_key:create"]).await;
    let revoker_token = app.mint_token(&revoker, &["api_key:delete"]).await;

    // The minter mints. api_keys INSERT: api_key:create + critical tier.
    let (status, body) = app
        .post(
            "/api_keys",
            &minter_token,
            // Only ever its own scope: `is_subset_of` refuses to let a key
            // grant what it does not itself hold, so minting cannot widen.
            serde_json::json!({ "name": "issued by the minter", "permissions": ["api_key:create"] }),
        )
        .await;
    assert_eq!(status, 201, "{body}");
    let issued_id = body["id"].as_str().unwrap().to_string();

    // ...and cannot revoke. This is the grant that used to come free with it.
    let (status, body) = app
        .delete(&format!("/api_keys/{issued_id}"), &minter_token)
        .await;
    assert_missing(&body, "api_key:delete", status);

    // The revoker revokes. api_keys UPDATE: api_key:delete + critical tier,
    // the soft delete that keeps the audit trail.
    let (status, body) = app
        .delete(&format!("/api_keys/{issued_id}"), &revoker_token)
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["revoked_at"].is_string(), "{body}");

    // ...and cannot mint itself a successor.
    let (status, body) = app
        .post(
            "/api_keys",
            &revoker_token,
            serde_json::json!({ "name": "escalation", "permissions": ["*:*"] }),
        )
        .await;
    assert_missing(&body, "api_key:create", status);
}

/// A read-only key is still read-only, across all three mutating actions. This
/// is the direction that carries the security value, and the one the
/// read-implication rule must not have quietly loosened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_only_key_writes_nothing() {
    let app = TestApp::start().await;
    let invoice_id = app.create_sent_invoice(9_000).await;

    let (status, body) = app.get("/invoices", &app.read_key).await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = app
        .post(
            "/customers",
            &app.read_key,
            serde_json::json!({ "name": "R", "email": "r@example.com" }),
        )
        .await;
    assert_missing(&body, "customer:create", status);

    let (status, body) = app
        .post_empty(&format!("/invoices/{invoice_id}/void"), &app.read_key)
        .await;
    assert_missing(&body, "invoice:update", status);

    let (status, body) = app
        .pay(&invoice_id, &app.read_key, "denied", TOK_SUCCESS)
        .await;
    assert_missing(&body, "payment:create", status);

    assert_eq!(app.invoice_state(&invoice_id).await, "sent");
}
