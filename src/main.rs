use anyhow::Context;
use nxsd::api::{self, AppState};
use nxsd::config::Config;
use nxsd::store::Store;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::load()?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| config.log.clone().into()),
        )
        .init();

    let store = Store::open(&config.database_path)
        .with_context(|| format!("opening database {}", config.database_path.display()))?;
    store.migrate()?;

    let expiry_store = store.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let now = nxsd::store::now_ms();
            if let Err(error) = expiry_store.expire_leases(now) {
                tracing::warn!(%error, "failed to expire leases");
            }
            if let Err(error) = expiry_store.expire_admission_keys(now) {
                tracing::warn!(%error, "failed to retire admission keys");
            }
        }
    });

    let listen = config.listen;
    let app = api::router(AppState::new(config, store));
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;

    tracing::info!(%listen, "nxsd listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("installing Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
