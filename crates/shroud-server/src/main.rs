use anyhow::{Context, Result};
use shroud_core::config::{generate_client_credentials, load_server_config_yaml};
use shroud_server::web;
use std::fs;
use tracing::info;
use tracing_subscriber::EnvFilter;

// cargo run -p shroud-server -- configs/server.yaml
// curl -i --cacert /home/laptop/Projects/shroud/certs/ca.crt https://localhost:8443/
// curl -X POST -i --cacert /home/laptop/Projects/shroud/certs/ca.crt https://localhost:8443/api/tunnel

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let Some(config_path) = parse_cli()? else {
        return Ok(());
    };
    let raw = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read server config: {config_path}"))?;
    let cfg = load_server_config_yaml(&raw)
        .with_context(|| format!("failed to load server config: {config_path}"))?;

    info!(listen = %cfg.listen, "starting shroud server");
    web::serve(cfg).await
}

fn parse_cli() -> Result<Option<String>> {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    if matches!(
        first.as_deref(),
        Some("generate-credentials") | Some("gen-credentials")
    ) {
        let credentials = generate_client_credentials();
        println!("client_id: \"{}\"", credentials.client_id);
        println!("client_secret: \"{}\"", credentials.client_secret);
        return Ok(None);
    }

    Ok(Some(
        first.unwrap_or_else(|| "configs/server.yaml".to_string()),
    ))
}
