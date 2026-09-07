use anyhow::Context;
use api::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=warn,sqlx=warn".into()),
        )
        .with_target(true)
        .init();

    let config = Config::from_env()?;

    tracing::info!(
        bind = %config.bind_addr,
        default_processor = %config.default_processor,
        psp_timeout_ms = config.psp_timeout.as_millis(),
        "starting invoice service"
    );

    let state = api::build_state(config).await?;
    let bind_addr = state.config.bind_addr.clone();

    api::spawn_workers(&state);

    let app = api::routes::build(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;

    tracing::info!(%bind_addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    tracing::info!("shut down cleanly");
    Ok(())
}

/// In-flight requests finish before the process exits. Without this, a deploy
/// that rolls pods would cut live payment requests off mid-charge - exactly
/// the "unknown outcome" case the reconciler exists to clean up, manufactured
/// on purpose several times a day.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received SIGINT, shutting down"),
        _ = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}
