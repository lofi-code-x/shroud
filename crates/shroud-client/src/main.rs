use anyhow::{Context, Result};
use shroud_client::{routing, session, socks5, tun, tunnel};
use shroud_core::config::{generate_client_credentials, load_client_config_yaml};
use std::fs;
use tracing::info;
use tracing_subscriber::EnvFilter;

// cargo run -p shroud-client -- configs/client.yaml

//DNS remote resolve
// curl --socks5-hostname 127.0.0.1:1080 https://example.com

//DNS leak
//curl -v --socks5 127.0.0.1:1080 https://example.com/

//TUN TEST
// cd /home/laptop/Projects/shroud
// sudo SHROUD_SMOKE_BUILD=0 ./scripts/tun-smoke-linux.sh

//TUN TEST BUILD
// cd /home/laptop/Projects/shroud
// cargo build -p shroud-client -p shroud-server
// sudo SHROUD_SMOKE_BUILD=0 ./scripts/tun-smoke-linux.sh
#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let Some(config_path) = parse_cli()? else {
        return Ok(());
    };
    let raw = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read client config: {config_path}"))?;
    let cfg = load_client_config_yaml(&raw)
        .with_context(|| format!("failed to load client config: {config_path}"))?;

    let mut outbound = cfg.outbound.clone();
    if cfg.inbounds.tun.enabled && cfg.inbounds.tun.auto_route {
        outbound = tun::route::prepare_auto_route_outbound(outbound)?;
    }

    let router = routing::Router::try_new(cfg.routing.clone()).context("invalid routing config")?;
    let tunnel = tunnel::TunnelClient::new(outbound.clone(), cfg.auth.clone());
    let session = session::SessionCore::new(router, tunnel, cfg.dns.clone());

    if cfg.inbounds.tun.enabled {
        let device = tun::device::open(&cfg.inbounds.tun)
            .with_context(|| format!("failed to set up TUN device {}", cfg.inbounds.tun.name))?;
        info!(
            tun = device.name(),
            address = %cfg.inbounds.tun.address,
            mtu = cfg.inbounds.tun.mtu,
            auto_route = cfg.inbounds.tun.auto_route,
            "TUN device opened; starting smoltcp-backed packet engine"
        );
        let _route_guard =
            tun::route::setup_before_packet_engine(device.name(), &cfg.inbounds.tun, &outbound)?;
        let fake_dns = tun::dns::FakeDns::new();
        let fake_dns_addr = tun::dns::listen_addr(&cfg.inbounds.tun);
        info!(
            listen = %fake_dns_addr,
            "starting TUN fake DNS listener"
        );
        tokio::spawn(tun::dns::serve(fake_dns_addr, fake_dns.clone()));

        info!(tun = device.name(), "starting TUN packet engine");
        return tun::engine::TunEngine::new(device, session, fake_dns, cfg.inbounds.tun.mtu)
            .run()
            .await;
    }

    let socks = cfg
        .inbounds
        .socks
        .as_ref()
        .filter(|socks| socks.enabled)
        .context("no enabled SOCKS inbound configured")?;

    info!(listen = %socks.listen, "starting shroud client");

    socks5::serve(socks.listen, session).await
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
        first.unwrap_or_else(|| "configs/client.yaml".to_string()),
    ))
}
