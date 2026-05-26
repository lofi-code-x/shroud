use crate::routing::Router;
use crate::tunnel::{RelayStats, TunnelClient, TunnelStream, UdpTunnel};
use anyhow::{Context, Result};
use shroud_core::config::{ClientDnsConfig, RouteAction};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, warn};

const DIRECT_TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct SessionCore {
    router: Router,
    tunnel: TunnelClient,
    dns: ClientDnsConfig,
}

impl SessionCore {
    pub fn new(router: Router, tunnel: TunnelClient, dns: ClientDnsConfig) -> Self {
        Self {
            router,
            tunnel,
            dns,
        }
    }

    pub fn check_dns_policy(
        &self,
        target_host: &str,
        target_port: u16,
        context: SessionContext<'_>,
    ) -> DnsPolicyResult {
        if let Ok(target_ip) = target_host.parse::<IpAddr>() {
            if self.dns.warn_on_ip_targets {
                warn!(
                    inbound = context.inbound,
                    peer = ?context.peer,
                    %target_ip,
                    target_port,
                    remote_by_default = self.dns.remote_by_default,
                    block_ip_targets = self.dns.block_ip_targets,
                    "target is an IP address; remote DNS cannot be applied because the application likely resolved the name locally"
                );
            }

            if self.dns.block_ip_targets {
                return DnsPolicyResult::BlockedIpTarget;
            }
        } else if self.dns.remote_by_default {
            debug!(
                inbound = context.inbound,
                peer = ?context.peer,
                target_host,
                target_port,
                "target is a domain; preserving it for remote resolution"
            );
        }

        DnsPolicyResult::Allowed
    }

    pub fn decide(&self, target_host: &str, target_port: u16) -> RouteAction {
        self.router.decide(target_host, target_port)
    }

    pub async fn open_tcp(&self, target_host: &str, target_port: u16) -> Result<TcpOpenResult> {
        let action = self.decide(target_host, target_port);

        match action {
            RouteAction::Proxy => {
                let stream = self
                    .tunnel
                    .connect_target_via_tunnel(target_host, target_port)
                    .await
                    .context("proxy tunnel connect failed")?;
                Ok(TcpOpenResult::Opened(TcpOutbound {
                    action,
                    stream: TcpOutboundStream::Proxy(stream),
                }))
            }
            RouteAction::Direct => {
                let stream = timeout(
                    DIRECT_TARGET_CONNECT_TIMEOUT,
                    TcpStream::connect((target_host, target_port)),
                )
                .await
                .with_context(|| {
                    format!(
                        "timed out opening direct tcp connection to {target_host}:{target_port}"
                    )
                })?
                .with_context(|| {
                    format!("failed to open direct tcp connection to {target_host}:{target_port}")
                })?;
                Ok(TcpOpenResult::Opened(TcpOutbound {
                    action,
                    stream: TcpOutboundStream::Direct(stream),
                }))
            }
            RouteAction::Block => Ok(TcpOpenResult::Blocked),
        }
    }

    pub async fn open_udp_tunnel(&self) -> Result<UdpTunnel> {
        self.tunnel
            .open_udp_association()
            .await
            .context("proxy UDP associate failed")
    }

    pub async fn relay_tcp<S>(
        &self,
        client_stream: &mut S,
        outbound: &mut TcpOutbound,
    ) -> Result<RelayStats>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match &mut outbound.stream {
            TcpOutboundStream::Proxy(upstream) => self
                .tunnel
                .relay_over_tunnel_stream(client_stream, upstream)
                .await
                .context("proxy relay failed"),
            TcpOutboundStream::Direct(upstream) => relay_direct_tcp(client_stream, upstream)
                .await
                .context("direct relay failed"),
        }
    }
}

async fn relay_direct_tcp<S>(client_stream: &mut S, upstream: &mut TcpStream) -> Result<RelayStats>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    let client_to_upstream = async {
        let mut transferred = 0u64;
        let mut buf = [0u8; 16 * 1024];

        loop {
            let n = timeout(RELAY_IDLE_TIMEOUT, client_read.read(&mut buf))
                .await
                .context("relay idle timeout while reading from client")??;
            if n == 0 {
                timeout(RELAY_IDLE_TIMEOUT, upstream_write.shutdown())
                    .await
                    .context("relay timeout while shutting down upstream writer")??;
                break;
            }

            transferred += n as u64;
            timeout(RELAY_IDLE_TIMEOUT, upstream_write.write_all(&buf[..n]))
                .await
                .context("relay timeout while writing to upstream")??;
        }

        Ok::<u64, anyhow::Error>(transferred)
    };

    let upstream_to_client = async {
        let mut transferred = 0u64;
        let mut buf = [0u8; 16 * 1024];

        loop {
            let n = timeout(RELAY_IDLE_TIMEOUT, upstream_read.read(&mut buf))
                .await
                .context("relay idle timeout while reading from upstream")??;
            if n == 0 {
                timeout(RELAY_IDLE_TIMEOUT, client_write.shutdown())
                    .await
                    .context("relay timeout while shutting down client writer")??;
                break;
            }

            transferred += n as u64;
            timeout(RELAY_IDLE_TIMEOUT, client_write.write_all(&buf[..n]))
                .await
                .context("relay timeout while writing to client")??;
        }

        Ok::<u64, anyhow::Error>(transferred)
    };

    let (client_to_upstream_bytes, upstream_to_client_bytes) =
        tokio::try_join!(client_to_upstream, upstream_to_client)?;

    Ok(RelayStats {
        client_to_upstream_bytes,
        upstream_to_client_bytes,
    })
}

#[derive(Debug, Clone, Copy)]
pub struct SessionContext<'a> {
    pub inbound: &'a str,
    pub peer: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPolicyResult {
    Allowed,
    BlockedIpTarget,
}

pub enum TcpOpenResult {
    Opened(TcpOutbound),
    Blocked,
}

pub struct TcpOutbound {
    pub action: RouteAction,
    stream: TcpOutboundStream,
}

enum TcpOutboundStream {
    Proxy(TunnelStream),
    Direct(TcpStream),
}
