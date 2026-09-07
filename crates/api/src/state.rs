use std::sync::Arc;

use sqlx::PgPool;

use crate::auth::jwt::JwtCodec;
use crate::config::Config;
use crate::psp::Registry;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub jwt: Arc<JwtCodec>,
    pub processors: Arc<Registry>,
    /// Used by the webhook dispatcher.
    pub http: reqwest::Client,
}
