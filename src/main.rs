mod plesk_api;
mod http_server;
mod settings;

use anyhow::{Context, Error};
use tracing_subscriber::FmtSubscriber;
use tracing::{info, Level};
use http_server::HttpServer;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("Loading settings.");
    let settings = settings::Settings::new().context("Failed to load settings")?;
    
    let mut http_server = HttpServer::new(&settings);
    http_server.start().await.context("Failed to start HTTP server")?;

    Ok(())
}