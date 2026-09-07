//! Drift pin: the Rust permission mirror against the SQL authority.
//!
//! `auth::permissions::has_scope` exists so a doomed request is refused before
//! it opens a transaction. `has_scope(text, text)` in `sql/rls.sql` is what
//! actually protects the data, because it is embedded in every RLS policy.
//! Two implementations of one rule is a deliberate trade - a fast pre-check
//! plus an authoritative one - and it is only safe while they agree.
//!
//! So this asserts they agree, on every cell of the grid rather than on a
//! handful of examples: each permission list below is evaluated against every
//! `(resource, action)` pair by both implementations, and any disagreement
//! names the cell. A one-sided edit to either copy fails here.
//!
//! Requires `docker compose up -d db`.

mod support;

use api::auth::permissions::{self, has_scope, ACTIONS, RESOURCES, WILDCARD};
use sqlx::{PgPool, Row};

/// Schema plus an admin pool to read `has_scope` through.
///
/// The pool is per-test, not a shared static: every `#[tokio::test]` builds
/// its own runtime, and a sqlx pool is bound to the runtime that created it -
/// hand one to a second runtime and every `acquire` sits there until it times
/// out. The migration itself is shared, because that part is just a barrier.
async fn db() -> PgPool {
    support::migrate_once().await;
    api::db::connect(&support::admin_database_url(), 5)
        .await
        .expect("could not connect as the admin role")
}

/// Every scope string the grammar can express, as a single-scope credential.
/// This is the part that catches a wildcard or implication rule implemented in
/// one place and not the other.
fn every_single_scope() -> Vec<Vec<String>> {
    let mut lists = Vec::new();
    for res in RESOURCES.iter().chain(std::iter::once(&WILDCARD)) {
        for act in ACTIONS.iter().chain(std::iter::once(&WILDCARD)) {
            lists.push(vec![format!("{res}:{act}")]);
        }
    }
    lists
}

/// Lists that are more than the sum of their scopes, or that have bitten
/// before: the real seed credentials, and combinations where an implication
/// rule could plausibly leak across a resource.
fn interesting_combinations() -> Vec<Vec<String>> {
    [
        vec![],
        vec!["invoice:read", "payment:create"],
        vec!["invoice:create", "invoice:update", "invoice:delete"],
        vec!["api_key:create"],
        vec!["api_key:delete"],
        vec!["customer:*", "invoice:read"],
        vec!["*:read", "payment:create"],
        vec!["*:delete"],
        vec!["invoice:update", "customer:delete", "webhook:create"],
        // Not a valid scope, and both implementations must agree it grants
        // nothing rather than one of them treating it as a wildcard.
        vec!["invoice:write"],
        vec!["nonsense"],
    ]
    .into_iter()
    .map(|l| l.into_iter().map(String::from).collect())
    .collect()
}

/// What the SQL side thinks, for the whole grid in one round trip.
///
/// The claims document is the same shape `db/tenant.rs` sets in production -
/// this deliberately goes through `request.jwt.claims` and `app_permissions()`
/// rather than calling `has_scope` with a hand-built array, so the test covers
/// the path the policies actually take.
async fn sql_grid(pool: &PgPool, granted: &[String]) -> Vec<((String, String), bool)> {
    let claims = serde_json::json!({
        "claims": {
            "business_id": "00000000-0000-7000-8000-000000000001",
            "permissions": granted,
            "tier": "critical",
        }
    })
    .to_string();

    // Transaction-local, exactly as a request sets it.
    let mut tx = pool.begin().await.expect("failed to begin");
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(&claims)
        .execute(&mut *tx)
        .await
        .expect("failed to set claims");

    let resources: Vec<String> = RESOURCES.iter().map(|s| s.to_string()).collect();
    let actions: Vec<String> = ACTIONS.iter().map(|s| s.to_string()).collect();

    let rows = sqlx::query(
        "SELECT r.res, a.act, has_scope(r.res, a.act) AS granted
         FROM unnest($1::text[]) AS r(res), unnest($2::text[]) AS a(act)",
    )
    .bind(&resources)
    .bind(&actions)
    .fetch_all(&mut *tx)
    .await
    .expect("failed to evaluate has_scope");

    tx.rollback().await.expect("failed to roll back");

    rows.into_iter()
        .map(|row| {
            (
                (row.get::<String, _>("res"), row.get::<String, _>("act")),
                row.get::<bool, _>("granted"),
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_and_sql_has_scope_agree_across_the_whole_grid() {
    let pool = db().await;
    let pool = &pool;

    let mut checked = 0usize;

    for granted in every_single_scope().into_iter().chain(interesting_combinations()) {
        for ((resource, action), sql_says) in sql_grid(pool, &granted).await {
            let rust_says = has_scope(&granted, &resource, &action);
            assert_eq!(
                rust_says, sql_says,
                "mirror drift: holding {granted:?}, Rust says has_scope({resource}, {action}) \
                 = {rust_says} but SQL says {sql_says}. sql/rls.sql is authoritative."
            );
            checked += 1;
        }
    }

    // A grid that silently shrank to nothing would pass every assertion above.
    let expected = (RESOURCES.len() + 1) * (ACTIONS.len() + 1) + interesting_combinations().len();
    assert_eq!(checked, expected * RESOURCES.len() * ACTIONS.len());
}

/// The route table is the other half of the mirror: it decides which scope the
/// middleware demands, and `rls.sql` decides which one the policy demands. A
/// route asking for a scope no credential can be granted would 403 forever,
/// and the unit tests cannot see it because `RESOURCES`/`ACTIONS` are what
/// they check against.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_route_scope_is_grantable_and_the_db_agrees() {
    let pool = db().await;
    let pool = &pool;

    for route in permissions::ROUTE_SCOPES {
        let permissions::Access::Scope { resource, action } = route.access else {
            continue;
        };

        let exact = vec![format!("{resource}:{action}")];
        let grid = sql_grid(pool, &exact).await;
        let granted = grid
            .iter()
            .find(|((r, a), _)| r == resource && a == action)
            .map(|(_, g)| *g)
            .unwrap_or(false);

        assert!(
            granted,
            "{} {} requires {resource}:{action}, which the database grants to no one",
            route.method, route.path
        );
    }
}
