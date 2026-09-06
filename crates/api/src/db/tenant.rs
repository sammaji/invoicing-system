use sqlx::{PgPool, Postgres, Transaction};

use crate::auth::AuthContext;

/// Open a transaction scoped to the caller's tenant and scopes.
pub async fn begin_as_tenant<'a>(
    pool: &'a PgPool,
    ctx: &AuthContext,
) -> Result<Transaction<'a, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(&ctx.raw_claims)
        .execute(&mut *tx)
        .await?;

    Ok(tx)
}

/// Open a transaction for background work.
///
/// The webhook dispatcher and the payment reconciler are cross-tenant - a single
/// sweep settles attempts belonging to many businesses. Rather than giving the
/// request role that power, or running a second pool, the transaction switches
/// role for its own lifetime.
pub async fn begin_as_service(pool: &PgPool) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query("SET LOCAL ROLE invoice_service")
        .execute(&mut *tx)
        .await?;

    Ok(tx)
}
