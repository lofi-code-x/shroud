use anyhow::{Context, Result};
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

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "configs/client.yaml".to_string());
    let raw = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read client config: {config_path}"))?;
    let cfg: ClientConfig = serde_yaml::from_str(&raw)
        .with_context(|| format!("failed to parse client yaml config: {config_path}"))?;

    let mut outbound = cfg.outbound.clone();
    if cfg.inbounds.tun.enabled && cfg.inbounds.tun.auto_route {
        if outbound.server.parse::<std::net::IpAddr>().is_err() {
            let original_server = outbound.server.clone();
            let endpoint_ip = tun::route::resolve_endpoint_ip(&outbound)?;
            outbound.server = endpoint_ip.to_string();
            if outbound.tls && outbound.tls_server_name.is_none() {
                outbound.tls_server_name = Some(original_server.clone());
            }
            info!(
                server = %original_server,
                endpoint_ip = %endpoint_ip,
                "bootstrap-resolved tunnel endpoint before enabling TUN auto-route"
            );
        }
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
