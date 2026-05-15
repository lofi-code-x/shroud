use crate::routing::Router;
use crate::tunnel::TunnelClient;
use anyhow::Result;
use shroud_core::config::RouteAction;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::{debug, info};

pub async fn serve(listen: SocketAddr, router: Router, tunnel: TunnelClient) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    info!(%listen, "SOCKS5 inbound listener started");

    loop {
        let (socket, peer) = listener.accept().await?;
        let router = router.clone();
        let tunnel = tunnel.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_connection(peer, router, tunnel).await {
                debug!(%peer, error = %err, "connection handling failed");
            }
            drop(socket);
        });
    }
}

async fn handle_connection(peer: SocketAddr, router: Router, tunnel: TunnelClient) -> Result<()> {
    let target_host = "example.com";
    let target_port = 443;
    match router.decide(target_host, target_port) {
        RouteAction::Proxy => tunnel.connect_target(target_host, target_port).await?,
        RouteAction::Direct => {
            debug!(%peer, target_host, target_port, "direct route selected (stub)");
        }
        RouteAction::Block => {
            debug!(%peer, target_host, target_port, "blocked by route rule (stub)");
        }
    }

    Ok(())
}
