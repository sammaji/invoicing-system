use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Config {
    /// Connection string for the request-handling role (`invoice_app`). This
    /// role is subject to RLS.
    pub database_url: String,
    /// Connection string for the migration role. Optional: when set, the
    /// process runs migrations at boot before serving. Kept separate from
    /// `database_url` precisely so the serving connection cannot alter schema.
    pub migrator_database_url: Option<String>,
    pub bind_addr: String,

    /// HS256 signing key for the short-lived critical-tier tokens.
    pub jwt_secret: String,
    pub jwt_ttl: Duration,

    pub psp_alphapay_url: String,
    pub psp_betapay_url: String,
    pub default_processor: String,
    /// Per-request budget for a PSP call. Must stay well below any client's
    /// own timeout: the whole point is that we decide the outcome is unknown
    /// rather than letting a caller hang. See `tok_timeout`.
    pub psp_timeout: Duration,

    /// How long a payment attempt may sit in `pending` before the reconciler
    /// picks it up. Seconds in tests, a minute in production.
    pub reconciler_stale_after: Duration,
    pub reconciler_interval: Duration,
    pub reconciler_max_attempts: i32,

    pub webhook_poll_interval: Duration,
    pub webhook_delivery_timeout: Duration,
    pub webhook_batch_size: i64,

    /// Lets the test harness run the HTTP surface without the background
    /// tasks, so a test that is not about reconciliation is not racing it.
    pub enable_background_workers: bool,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_ms(key: &str, default_ms: u64) -> Duration {
    Duration::from_millis(
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_ms),
    )
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("DATABASE_URL must be set"))?;

        Ok(Self {
            database_url,
            migrator_database_url: std::env::var("MIGRATOR_DATABASE_URL").ok(),
            bind_addr: env_or("BIND_ADDR", "0.0.0.0:8080"),

            jwt_secret: env_or("JWT_SECRET", "dev-only-insecure-jwt-secret-change-me"),
            jwt_ttl: Duration::from_secs(
                std::env::var("JWT_TTL_SECONDS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(900),
            ),

            psp_alphapay_url: env_or("PSP_ALPHAPAY_URL", "http://localhost:9090/alphapay"),
            psp_betapay_url: env_or("PSP_BETAPAY_URL", "http://localhost:9090/betapay"),
            default_processor: env_or("DEFAULT_PROCESSOR", "alphapay"),
            psp_timeout: env_ms("PSP_TIMEOUT_MS", 5_000),

            reconciler_stale_after: env_ms("RECONCILER_STALE_AFTER_MS", 60_000),
            reconciler_interval: env_ms("RECONCILER_INTERVAL_MS", 10_000),
            reconciler_max_attempts: std::env::var("RECONCILER_MAX_ATTEMPTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),

            webhook_poll_interval: env_ms("WEBHOOK_POLL_INTERVAL_MS", 1_000),
            webhook_delivery_timeout: env_ms("WEBHOOK_DELIVERY_TIMEOUT_MS", 10_000),
            webhook_batch_size: std::env::var("WEBHOOK_BATCH_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),

            enable_background_workers: env_or("ENABLE_BACKGROUND_WORKERS", "true") != "false",
        })
    }
}
