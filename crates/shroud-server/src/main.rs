mod auth;
mod relay;
mod web;

use anyhow::{Context, Result};
use shroud_core::config::ServerConfig;
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
        .unwrap_or_else(|| "configs/server.yaml".to_string());
    let raw = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read server config: {config_path}"))?;
    let cfg: ServerConfig =
        serde_yaml::from_str(&raw).context("failed to parse server yaml config")?;

    info!(listen = %cfg.listen, "starting shroud server");
    web::serve(cfg).await
}
