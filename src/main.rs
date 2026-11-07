use std::future::IntoFuture;
use std::io::IsTerminal;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tegata::config::Cli;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_ansi(std::io::stdout().is_terminal())
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,tegata=info")),
        )
        .init();

    let cli = Cli::parse();
    let listen = cli.listen;
    let authz_listen = cli.authz_listen;
    let crl_every = Duration::from_secs(cli.crl_refresh_minutes.max(1) * 60);
    let app = Arc::new(cli.build().await?);

    if let Err(err) = app.publish_trust().await {
        tracing::error!(error = ?err, "initial trust bundle publish failed");
    }
    tegata::spawn_background(app.clone(), crl_every);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    let authz_listener = tokio::net::TcpListener::bind(authz_listen).await?;
    tracing::info!(%listen, %authz_listen, public_url = %app.settings.public_url, "tegata listening");
    let public =
        axum::serve(listener, tegata::router(app.clone())).with_graceful_shutdown(shutdown());
    let authz =
        axum::serve(authz_listener, tegata::authz_router(app)).with_graceful_shutdown(shutdown());
    tokio::try_join!(public.into_future(), authz.into_future())?;
    Ok(())
}

/// On SIGTERM keep serving for `TEGATA_SHUTDOWN_DELAY_SECONDS` while the proxy drops this
/// endpoint; a fail-closed gateway would otherwise refuse checks routed here meanwhile.
async fn shutdown() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing the SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => return,
        _ = term.recv() => {}
    }
    let delay = std::env::var("TEGATA_SHUTDOWN_DELAY_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    tracing::info!(delay, "SIGTERM received, draining before shutdown");
    tokio::time::sleep(Duration::from_secs(delay)).await;
}
