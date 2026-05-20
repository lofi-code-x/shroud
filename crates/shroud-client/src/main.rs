use anyhow::{Context, Result, bail};
use shroud_client::{routing, session, socks5, tun, tunnel};
use shroud_core::config::ClientConfig;
use std::fs;
use tracing::info;
use tracing_subscriber::EnvFilter;

// cargo run -p shroud-client -- configs/client.yaml

//DNS remote resolve
// curl --socks5-hostname 127.0.0.1:1080 https://example.com

//DNS leak
//curl -v --socks5 127.0.0.1:1080 https://example.com/
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

    if cfg.inbounds.tun.enabled {
        let device = tun::device::open(&cfg.inbounds.tun)
            .with_context(|| format!("failed to set up TUN device {}", cfg.inbounds.tun.name))?;
        info!(
            tun = device.name(),
            address = %cfg.inbounds.tun.address,
            mtu = cfg.inbounds.tun.mtu,
            auto_route = cfg.inbounds.tun.auto_route,
            "TUN device opened; route setup and packet engine are not implemented yet"
        );
        tun::route::setup_before_packet_engine(device.name(), &cfg.inbounds.tun, &cfg.outbound)?;
        let fake_dns_addr = tun::dns::listen_addr(&cfg.inbounds.tun);
        info!(
            listen = %fake_dns_addr,
            "TUN fake DNS prepared; listener starts with the packet engine"
        );
        bail!("TUN inbound runtime is not implemented yet");
    }

    let socks = cfg
        .inbounds
        .socks
        .as_ref()
        .filter(|socks| socks.enabled)
        .context("no enabled SOCKS inbound configured")?;

    info!(listen = %socks.listen, "starting shroud client");
    let router = routing::Router::try_new(cfg.routing.clone()).context("invalid routing config")?;
    let tunnel = tunnel::TunnelClient::new(cfg.outbound.clone(), cfg.auth.clone());
    let session = session::SessionCore::new(router, tunnel, cfg.dns.clone());

    socks5::serve(socks.listen, session).await
}
