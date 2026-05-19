use anyhow::{Context, Result};
use shroud_client::{routing, socks5, tunnel};
use shroud_core::config::ClientConfig;
use std::fs;
use tracing::info;
use tracing_subscriber::EnvFilter;

// cargo run -p shroud-client -- configs/client.yaml
// curl --socks5-hostname 127.0.0.1:1080 https://example.com

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "configs/client.yaml".to_string());
    let raw = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read client config: {config_path}"))?;
    let cfg: ClientConfig = serde_yaml::from_str(&raw)
        .with_context(|| format!("failed to parse client yaml config: {config_path}"))?;

    info!(listen = %cfg.inbound.listen, "starting shroud client");
    let router = routing::Router::new(cfg.routing.clone());
    let tunnel = tunnel::TunnelClient::new(cfg.outbound.clone(), cfg.auth.clone());

    socks5::serve(cfg.inbound.listen, router, tunnel).await
}
