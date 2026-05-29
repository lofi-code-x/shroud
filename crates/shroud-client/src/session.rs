use crate::routing::Router;
use crate::tunnel::{RelayStats, TunnelClient, TunnelOpenTimings, TunnelStream, UdpTunnel};
use crate::tunnel_manager::{TunnelPool, TunnelStreamHandle};
use anyhow::{Context, Result};
use bytes::Bytes;
use shroud_core::config::{ClientDnsConfig, RouteAction};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
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
    tunnel_pool: Option<TunnelPool>,
    dns: ClientDnsConfig,
}

impl SessionCore {
    pub fn new(router: Router, tunnel: TunnelClient, dns: ClientDnsConfig) -> Self {
        Self {
            router,
            tunnel,
            tunnel_pool: None,
            dns,
        }
    }

    pub fn new_multiplexed(
        router: Router,
        tunnel: TunnelClient,
        tunnel_pool: TunnelPool,
        dns: ClientDnsConfig,
    ) -> Self {
        Self {
            router,
            tunnel,
            tunnel_pool: Some(tunnel_pool),
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
                if let Some(tunnel_pool) = &self.tunnel_pool {
                    let stream = tunnel_pool
                        .open_tcp_stream(target_host, target_port)
                        .await
                        .context("proxy multiplexed tunnel connect failed")?;
                    return Ok(TcpOpenResult::Opened(TcpOutbound {
                        action,
                        metrics: TcpOpenMetrics::default(),
                        stream: TcpOutboundStream::MultiplexedProxy(stream),
                    }));
                }

                let tunnel = self
                    .tunnel
                    .connect_target_via_tunnel_with_timings(target_host, target_port)
                    .await
                    .context("proxy tunnel connect failed")?;
                Ok(TcpOpenResult::Opened(TcpOutbound {
                    action,
                    metrics: TcpOpenMetrics::from(tunnel.timings),
                    stream: TcpOutboundStream::Proxy(tunnel.stream),
                }))
            }
            RouteAction::Direct => {
                let target_connect_started = Instant::now();
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
                let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());

                stream.set_nodelay(true).with_context(|| {
                    format!(
                        "failed to enable TCP_NODELAY for direct tcp connection to {target_host}:{target_port}"
                    )
                })?;

                Ok(TcpOpenResult::Opened(TcpOutbound {
                    action,
                    metrics: TcpOpenMetrics {
                        target_tcp_connect_ms,
                        ..TcpOpenMetrics::default()
                    },
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
        outbound: TcpOutbound,
    ) -> Result<RelayStats>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match outbound.stream {
            TcpOutboundStream::Proxy(mut upstream) => self
                .tunnel
                .relay_over_tunnel_stream(client_stream, &mut upstream)
                .await
                .context("proxy relay failed"),
            TcpOutboundStream::MultiplexedProxy(upstream) => {
                let stream_id = upstream.stream_id();
                relay_multiplexed_tcp(client_stream, upstream)
                    .await
                    .with_context(|| {
                        format!("multiplexed proxy relay failed for stream {stream_id}")
                    })
            }
            TcpOutboundStream::Direct(mut upstream) => {
                relay_direct_tcp(client_stream, &mut upstream)
                    .await
                    .context("direct relay failed")
            }
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
        let mut buf = [0u8; 64 * 1024];

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
        let mut buf = [0u8; 64 * 1024];

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

async fn relay_multiplexed_tcp<S>(
    client_stream: &mut S,
    stream: TunnelStreamHandle,
) -> Result<RelayStats>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream_id = stream.stream_id();
    let tunnel_id = stream.tunnel_id();
    let target_host = stream.target_host().to_owned();
    let target_port = stream.target_port();
    let opened_at = stream.opened_at();
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut tunnel_read, tunnel_write) = stream.into_split();

    let client_to_tunnel = async {
        let mut transferred = 0u64;
        let mut buf = [0u8; 64 * 1024];

        loop {
            let n = timeout(RELAY_IDLE_TIMEOUT, client_read.read(&mut buf))
                .await
                .context("relay idle timeout while reading from client")??;
            if n == 0 {
                timeout(RELAY_IDLE_TIMEOUT, tunnel_write.close())
                    .await
                    .context("relay timeout while closing multiplexed stream")??;
                break;
            }

            transferred += n as u64;
            timeout(
                RELAY_IDLE_TIMEOUT,
                tunnel_write.send_data(Bytes::copy_from_slice(&buf[..n])),
            )
            .await
            .context("relay timeout while queueing TCP_DATA to multiplexed stream")??;
        }

        Ok::<u64, anyhow::Error>(transferred)
    };

    let tunnel_to_client = async {
        let mut transferred = 0u64;

        while let Some(bytes) = timeout(RELAY_IDLE_TIMEOUT, tunnel_read.recv_data())
            .await
            .context("relay idle timeout while reading from multiplexed stream")?
        {
            transferred += bytes.len() as u64;
            timeout(RELAY_IDLE_TIMEOUT, client_write.write_all(bytes.as_ref()))
                .await
                .context("relay timeout while writing to client")??;
        }

        timeout(RELAY_IDLE_TIMEOUT, client_write.shutdown())
            .await
            .context("relay timeout while shutting down client writer")??;
        Ok::<u64, anyhow::Error>(transferred)
    };

    let result = tokio::try_join!(client_to_tunnel, tunnel_to_client);
    let active_streams = tunnel_write.cleanup_local().await;
    let relay_elapsed = opened_at.elapsed();
    match result {
        Ok((client_to_upstream_bytes, upstream_to_client_bytes)) => {
            let stats = RelayStats {
                client_to_upstream_bytes,
                upstream_to_client_bytes,
            };

            debug!(
                tunnel_id,
                stream_id,
                target_host,
                target_port,
                duration_ms = elapsed_millis(relay_elapsed),
                bytes_up = stats.client_to_upstream_bytes,
                bytes_down = stats.upstream_to_client_bytes,
                mbps = stats.mbps(relay_elapsed),
                active_streams_on_tunnel = active_streams,
                "logical TCP stream closed"
            );

            Ok(stats)
        }
        Err(err) => {
            debug!(
                tunnel_id,
                stream_id,
                target_host,
                target_port,
                duration_ms = elapsed_millis(relay_elapsed),
                active_streams_on_tunnel = active_streams,
                error = %err,
                "logical TCP stream closed with relay error"
            );

            Err(err)
        }
    }
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
    pub metrics: TcpOpenMetrics,
    stream: TcpOutboundStream,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpOpenMetrics {
    pub server_tcp_connect_ms: Option<u64>,
    pub tls_handshake_ms: Option<u64>,
    pub http_upgrade_ms: Option<u64>,
    pub target_tcp_connect_ms: u64,
}

impl From<TunnelOpenTimings> for TcpOpenMetrics {
    fn from(timings: TunnelOpenTimings) -> Self {
        Self {
            server_tcp_connect_ms: Some(timings.server_tcp_connect_ms),
            tls_handshake_ms: timings.tls_handshake_ms,
            http_upgrade_ms: Some(timings.http_upgrade_ms),
            target_tcp_connect_ms: timings.target_tcp_connect_ms,
        }
    }
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

enum TcpOutboundStream {
    Proxy(TunnelStream),
    MultiplexedProxy(TunnelStreamHandle),
    Direct(TcpStream),
}
