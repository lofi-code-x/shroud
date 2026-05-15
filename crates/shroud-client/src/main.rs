mod routing;
mod socks5;
mod tunnel;

use anyhow::{Context, Result};
use shroud_core::config::ClientConfig;
use std::fs;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "configs/client.yaml".to_string());
    let raw = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read client config: {config_path}"))?;
    let cfg: ClientConfig =
        serde_yaml::from_str(&raw).context("failed to parse client yaml config")?;

    info!(listen = %cfg.inbound.listen, "starting shroud client");
    let router = routing::Router::new(cfg.routing.clone());
    let tunnel = tunnel::TunnelClient::new(cfg.outbound.clone(), cfg.auth.clone());

    socks5::serve(cfg.inbound.listen, router, tunnel).await
}
