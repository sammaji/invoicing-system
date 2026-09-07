pub mod api_keys;
pub mod customers;
pub mod invoices;
pub mod models;
pub mod payments;
pub mod tokens;
pub mod webhooks;

use axum::routing::{delete, get, post};
use axum::Router;

use crate::state::AppState;

async fn healthz() -> &'static str {
    "ok"
}

pub fn build(state: AppState) -> Router {
    let authenticated = Router::new()
        .route("/auth/tokens", post(tokens::mint))
        .route("/api_keys", post(api_keys::create).get(api_keys::list))
        .route("/api_keys/{id}", delete(api_keys::revoke))
        .route(
            "/webhook_endpoints",
            post(webhooks::create).get(webhooks::list),
        )
        .route("/webhook_endpoints/{id}", delete(webhooks::disable))
        .route("/webhook_deliveries", get(webhooks::list_deliveries))
        .route("/customers", post(customers::create).get(customers::list))
        .route("/customers/{id}", get(customers::get))
        .route("/invoices", post(invoices::create).get(invoices::list))
        .route("/invoices/{id}", get(invoices::get))
        .route("/invoices/{id}/send", post(invoices::send))
        .route("/invoices/{id}/void", post(invoices::void))
        .route("/invoices/{id}/pay", post(payments::pay))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::auth::middleware::authenticate,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .merge(authenticated)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}
