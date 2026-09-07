//! Invoice & payment service.
//!
//! The crate is a library plus a thin binary so that integration tests can
//! boot the real router, against a real database and the real mock providers,
//! rather than testing a reimplementation of it.
//!
//! Start with:
//! * [`routes::payments`] - the payment flow and the five failure modes.
//! * [`domain::state_machine`] - the invoice lifecycle and its invariants.
//! * [`auth::permissions`] - the scope grammar and the route table.
//! * `sql/rls.sql` - tenant isolation and scope enforcement in the database.

pub mod auth;
pub mod config;
pub mod db;
pub mod domain;
pub mod error;
pub mod events;
pub mod outbox;
pub mod psp;
pub mod reconciler;
pub mod routes;
pub mod state;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;

use crate::auth::jwt::JwtCodec;
use crate::config::Config;
use crate::psp::Registry;
use crate::state::AppState;

/// Build everything the service needs, without binding a port.
///
/// Split out from `serve` so tests can construct the same state and router the
/// binary does.
pub async fn build_state(config: Config) -> anyhow::Result<AppState> {
    if let Some(migrator_url) = &config.migrator_database_url {
        db::migrate(migrator_url)
            .await
            .context("failed to run migrations")?;
    }

    let pool = db::connect(&config.database_url, 20)
        .await
        .context("failed to connect to the database as the application role")?;

    let processors = Registry::new(&config)?;
    let jwt = JwtCodec::new(&config.jwt_secret);

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(5))
        .build()?;

    Ok(AppState {
        pool,
        config: Arc::new(config),
        jwt: Arc::new(jwt),
        processors: Arc::new(processors),
        http,
    })
}

/// Spawn the webhook dispatcher and payment reconciler.
///
/// Both are ordinary tokio tasks in the API process. That is a deliberate
/// scope choice, not an oversight: a queue would be the right answer at
/// volume, and both tasks are already written to be replica-safe
/// (`FOR UPDATE SKIP LOCKED`), so moving them out is a deployment change
/// rather than a rewrite. DESIGN.md says so explicitly.
pub fn spawn_workers(state: &AppState) {
    if !state.config.enable_background_workers {
        tracing::warn!("background workers disabled by configuration");
        return;
    }

    tokio::spawn(outbox::run(state.clone()));
    tokio::spawn(reconciler::run(state.clone()));
}
