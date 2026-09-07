//! Test harness.
//!
//! Every test boots the **real** router, against a **real** Postgres with the
//! real RLS policies applied, talking to the **real** mock providers over HTTP.
//! Nothing here is a stand-in for a component under test: the interesting
//! behaviour in this service lives in the interaction between a partial unique
//! index, a row-level security policy and a provider that sometimes does not
//! answer, and none of those survive being mocked out.
//!
//! Each test provisions its own business and keys, so tests share a database
//! without sharing any rows and can run concurrently.
//!
//! Requires `docker compose up -d db mock-psp`.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use api::config::Config;
use serde_json::Value;
use sqlx::PgPool;
use tokio::sync::OnceCell;
use uuid::Uuid;

pub const TOK_SUCCESS: &str = "tok_success";
pub const TOK_INSUFFICIENT_FUNDS: &str = "tok_insufficient_funds";
pub const TOK_CARD_DECLINED: &str = "tok_card_declined";
pub const TOK_TIMEOUT: &str = "tok_timeout";
pub const TOK_NETWORK_ERROR: &str = "tok_network_error";

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Migrations and the policy file, applied exactly once per test binary.
///
/// `db::migrate` re-applies `sql/rls.sql` in full on every call, and that file
/// is a stack of `CREATE OR REPLACE FUNCTION` and `CREATE POLICY` statements.
/// Two tests running it concurrently do not serialise politely - Postgres
/// fails one of them with `tuple concurrently updated`, which surfaces here as
/// "is docker compose up -d db running?" and sends you looking in the wrong
/// place entirely. The file is idempotent, so running it once and having every
/// other test await that result is both correct and faster.
static MIGRATED: OnceCell<()> = OnceCell::const_new();

pub async fn migrate_once() {
    MIGRATED
        .get_or_init(|| async {
            api::db::migrate(&admin_database_url())
                .await
                .expect("migrations failed - is `docker compose up -d db` running?");
        })
        .await;
}

/// Superuser connection, used only to provision tenants and to run assertions
/// that deliberately bypass RLS.
pub fn admin_database_url() -> String {
    env_or(
        "TEST_ADMIN_DATABASE_URL",
        "postgres://migrator:migrator_dev_password@localhost:55432/invoicing",
    )
}

/// The RLS-constrained role the service actually serves on.
pub fn app_database_url() -> String {
    env_or(
        "TEST_APP_DATABASE_URL",
        "postgres://invoice_app:invoice_app_dev_password@localhost:55432/invoicing",
    )
}

pub fn mock_psp_base() -> String {
    env_or("TEST_MOCK_PSP_URL", "http://localhost:59090")
}

/// A running instance of the service, on its own port, with its own tenant.
pub struct TestApp {
    pub base_url: String,
    pub client: reqwest::Client,
    pub admin_pool: PgPool,
    pub business_id: Uuid,
    /// `*:*`
    pub full_key: String,
    /// `*:read`
    pub read_key: String,
    /// `["invoice:read", "payment:create"]` - the least-privilege collector.
    pub collector_key: String,
}

pub struct TestAppOptions {
    /// Off by default. A test that is not about reconciliation should not be
    /// racing a sweeper; the ones that are turn it on explicitly.
    pub background_workers: bool,
    pub reconciler_interval: Duration,
    pub reconciler_stale_after: Duration,
    pub reconciler_max_attempts: i32,
    pub psp_timeout: Duration,
}

impl Default for TestAppOptions {
    fn default() -> Self {
        Self {
            background_workers: false,
            reconciler_interval: Duration::from_millis(300),
            reconciler_stale_after: Duration::from_millis(300),
            reconciler_max_attempts: 3,
            psp_timeout: Duration::from_secs(3),
        }
    }
}

impl TestApp {
    pub async fn start() -> Self {
        Self::start_with(TestAppOptions::default()).await
    }

    pub async fn start_with(options: TestAppOptions) -> Self {
        migrate_once().await;

        let admin_pool = api::db::connect(&admin_database_url(), 5)
            .await
            .expect("could not connect as the admin role");

        let business_id = Uuid::now_v7();
        sqlx::query("INSERT INTO businesses (id, name) VALUES ($1, $2)")
            .bind(business_id)
            .bind(format!("test business {business_id}"))
            .execute(&admin_pool)
            .await
            .expect("failed to provision a test business");

        let full_key = provision_key(&admin_pool, business_id, &["*:*"]).await;
        let read_key = provision_key(&admin_pool, business_id, &["*:read"]).await;
        let collector_key =
            provision_key(&admin_pool, business_id, &["invoice:read", "payment:create"]).await;

        let config = Config {
            database_url: app_database_url(),
            // Already migrated above; the app under test connects as the
            // restricted role only, exactly as it does in production.
            migrator_database_url: None,
            bind_addr: "127.0.0.1:0".to_string(),
            jwt_secret: "test-secret-not-used-anywhere-real".to_string(),
            jwt_ttl: Duration::from_secs(900),
            psp_alphapay_url: format!("{}/alphapay", mock_psp_base()),
            psp_betapay_url: format!("{}/betapay", mock_psp_base()),
            default_processor: "alphapay".to_string(),
            psp_timeout: options.psp_timeout,
            reconciler_stale_after: options.reconciler_stale_after,
            reconciler_interval: options.reconciler_interval,
            reconciler_max_attempts: options.reconciler_max_attempts,
            webhook_poll_interval: Duration::from_millis(200),
            webhook_delivery_timeout: Duration::from_secs(2),
            webhook_batch_size: 10,
            enable_background_workers: options.background_workers,
        };

        let state = api::build_state(config)
            .await
            .expect("failed to build application state");

        api::spawn_workers(&state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind an ephemeral port");
        let port = listener.local_addr().unwrap().port();

        let router = api::routes::build(state);
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("server crashed");
        });

        let app = Self {
            base_url: format!("http://127.0.0.1:{port}"),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            admin_pool,
            business_id,
            full_key,
            read_key,
            collector_key,
        };

        app.wait_until_ready().await;
        app
    }

    async fn wait_until_ready(&self) {
        for _ in 0..100 {
            if self
                .client
                .get(format!("{}/healthz", self.base_url))
                .send()
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the test server never became ready");
    }

    pub fn request(&self, method: reqwest::Method, path: &str, key: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{path}", self.base_url))
            .header("authorization", format!("Bearer {key}"))
    }

    pub async fn post(&self, path: &str, key: &str, body: Value) -> (u16, Value) {
        let response = self
            .request(reqwest::Method::POST, path, key)
            .json(&body)
            .send()
            .await
            .expect("request failed");
        read(response).await
    }

    pub async fn post_empty(&self, path: &str, key: &str) -> (u16, Value) {
        let response = self
            .request(reqwest::Method::POST, path, key)
            .send()
            .await
            .expect("request failed");
        read(response).await
    }

    pub async fn get(&self, path: &str, key: &str) -> (u16, Value) {
        let response = self
            .request(reqwest::Method::GET, path, key)
            .send()
            .await
            .expect("request failed");
        read(response).await
    }

    pub async fn delete(&self, path: &str, key: &str) -> (u16, Value) {
        let response = self
            .request(reqwest::Method::DELETE, path, key)
            .send()
            .await
            .expect("request failed");
        read(response).await
    }

    pub async fn pay(
        &self,
        invoice_id: &str,
        key: &str,
        idempotency_key: &str,
        card_token: &str,
    ) -> (u16, Value) {
        let response = self
            .request(
                reqwest::Method::POST,
                &format!("/invoices/{invoice_id}/pay"),
                key,
            )
            .header("Idempotency-Key", idempotency_key)
            .json(&serde_json::json!({ "card_token": card_token }))
            .send()
            .await
            .expect("pay request failed");
        read(response).await
    }

    /* ------------------------------------------------------------------ */
    /* fixtures                                                            */
    /* ------------------------------------------------------------------ */

    pub async fn create_customer(&self) -> String {
        let (status, body) = self
            .post(
                "/customers",
                &self.full_key,
                serde_json::json!({ "name": "Test Customer", "email": "billing@test.invalid" }),
            )
            .await;
        assert_eq!(status, 201, "customer creation failed: {body}");
        body["id"].as_str().unwrap().to_string()
    }

    /// A `draft` invoice for `total_cents`.
    pub async fn create_invoice(&self, total_cents: i64) -> String {
        let customer_id = self.create_customer().await;
        self.create_invoice_for(&customer_id, total_cents).await
    }

    pub async fn create_invoice_for(&self, customer_id: &str, total_cents: i64) -> String {
        let (status, body) = self
            .post(
                "/invoices",
                &self.full_key,
                serde_json::json!({
                    "customer_id": customer_id,
                    "due_date": "2030-01-01",
                    "line_items": [
                        { "description": "Test line", "quantity": 1, "unit_amount_cents": total_cents }
                    ]
                }),
            )
            .await;
        assert_eq!(status, 201, "invoice creation failed: {body}");
        body["id"].as_str().unwrap().to_string()
    }

    /// A `sent` invoice - the only state from which payment is accepted.
    pub async fn create_sent_invoice(&self, total_cents: i64) -> String {
        let invoice_id = self.create_invoice(total_cents).await;
        let (status, body) = self
            .post_empty(&format!("/invoices/{invoice_id}/send"), &self.full_key)
            .await;
        assert_eq!(status, 200, "send failed: {body}");
        invoice_id
    }

    /// Provision an extra key for this tenant with exactly these scopes.
    ///
    /// The three keys on `TestApp` cover the common cases; this exists for
    /// tests about the *grammar*, which need a credential holding one precise
    /// scope and nothing that implies it.
    pub async fn key_with(&self, permissions: &[&str]) -> String {
        provision_key(&self.admin_pool, self.business_id, permissions).await
    }

    pub async fn mint_token(&self, key: &str, permissions: &[&str]) -> String {
        let (status, body) = self
            .post(
                "/auth/tokens",
                key,
                serde_json::json!({ "permissions": permissions }),
            )
            .await;
        assert_eq!(status, 200, "token mint failed: {body}");
        body["token"].as_str().unwrap().to_string()
    }

    /* ------------------------------------------------------------------ */
    /* assertions against the database                                     */
    /* ------------------------------------------------------------------ */

    pub async fn invoice_state(&self, invoice_id: &str) -> String {
        let (_, body) = self
            .get(&format!("/invoices/{invoice_id}"), &self.full_key)
            .await;
        body["state"].as_str().unwrap().to_string()
    }

    /// Counts attempts by status, read as the superuser so the assertion is
    /// about what is in the table rather than about what the API chose to show.
    pub async fn attempt_statuses(&self, invoice_id: &str) -> Vec<String> {
        let uuid = strip_prefix(invoice_id);
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM payment_attempts WHERE invoice_id = $1 ORDER BY created_at",
        )
        .bind(uuid)
        .fetch_all(&self.admin_pool)
        .await
        .expect("failed to read payment attempts")
    }

    pub async fn wait_for_attempt_status(&self, invoice_id: &str, wanted: &str, timeout: Duration) {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let statuses = self.attempt_statuses(invoice_id).await;
            if statuses.iter().any(|s| s == wanted) {
                return;
            }
            if std::time::Instant::now() > deadline {
                panic!(
                    "timed out waiting for a `{wanted}` attempt on {invoice_id}; \
                     statuses were {statuses:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// How many charges the *provider* recorded for this invoice's attempts.
    ///
    /// This is the assertion that actually means "the customer was not charged
    /// twice". Counting rows in our own database would only prove that we
    /// think they were not.
    pub async fn provider_charge_count(&self, invoice_id: &str) -> usize {
        let uuid = strip_prefix(invoice_id);
        let references: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM payment_attempts WHERE invoice_id = $1")
                .bind(uuid)
                .fetch_all(&self.admin_pool)
                .await
                .expect("failed to read payment attempts");

        let mut total = 0;
        for reference in references {
            let body: Value = self
                .client
                .get(format!("{}/admin/charges/{reference}", mock_psp_base()))
                .send()
                .await
                .expect("mock-psp admin request failed")
                .json()
                .await
                .expect("mock-psp returned invalid json");
            total += body["count"].as_u64().unwrap_or(0) as usize;
        }
        total
    }
}

async fn read(response: reqwest::Response) -> (u16, Value) {
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    let body = serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({ "raw": text }));
    (status, body)
}

/// Provision a key directly, the way an operator would. Hashing goes through
/// the production code path, so a change to the key format cannot make the
/// tests pass while the seed data stops working.
async fn provision_key(pool: &PgPool, business_id: Uuid, permissions: &[&str]) -> String {
    let generated = api::auth::api_key::generate();
    let permissions: Vec<String> = permissions.iter().map(|s| s.to_string()).collect();

    sqlx::query(
        "INSERT INTO api_keys (id, business_id, name, key_prefix, key_hash, permissions)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Uuid::now_v7())
    .bind(business_id)
    .bind("test key")
    .bind(&generated.prefix)
    .bind(&generated.hash)
    .bind(&permissions)
    .execute(pool)
    .await
    .expect("failed to provision a test api key");

    generated.plaintext
}

/// `inv_0192...` -> `Uuid`.
pub fn strip_prefix(prefixed: &str) -> Uuid {
    let hex = prefixed.split_once('_').expect("prefixed id").1;
    Uuid::parse_str(hex).expect("valid uuid")
}

pub fn arc<T>(value: T) -> Arc<T> {
    Arc::new(value)
}
