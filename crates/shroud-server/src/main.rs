use anyhow::{Context, Result};
use shroud_core::config::ServerConfig;
use shroud_server::web;
use std::fs;
use tracing::info;
use tracing_subscriber::EnvFilter;

// cargo run -p shroud-server -- configs/server.yaml

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

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
