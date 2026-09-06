pub mod tenant;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;

const RLS_SQL: &str = include_str!("../../sql/rls.sql");

pub async fn connect(url: &str, max_connections: u32) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .max_lifetime(Duration::from_secs(1800))
        .connect(url)
        .await?;
    Ok(pool)
}

/// Run migrations and re-apply the security policies.
///
/// Connects as the migrator role - deliberately a different connection string
/// from the one the API serves on, so the serving role cannot alter schema
/// even in principle.
pub async fn migrate(migrator_url: &str) -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(30))
        .connect(migrator_url)
        .await?;

    tracing::info!("running migrations");
    sqlx::migrate!("../../migrations").run(&pool).await?;

    tracing::info!("applying row-level security policies");
    // Not `execute` on the pool: the file is a multi-statement script, and it
    // must be all-or-nothing. A half-applied policy file is a security hole.
    let mut tx = pool.begin().await?;
    sqlx::raw_sql(RLS_SQL).execute(&mut *tx).await?;
    tx.commit().await?;

    pool.close().await;
    Ok(())
}
