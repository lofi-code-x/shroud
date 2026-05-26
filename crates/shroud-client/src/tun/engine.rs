use crate::session::{DnsPolicyResult, SessionContext, SessionCore, TcpOpenResult};
use crate::tun::device::TunDevice;
use crate::tun::dns::FakeDns;
use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::{StackBuilder, TcpListener, TcpStream};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

const MAX_PACKET_SIZE: usize = 65_535;
const PACKET_CHANNEL_SIZE: usize = 256;

pub struct TunEngine {
    device: TunDevice,
    session: SessionCore,
    fake_dns: FakeDns,
    mtu: u16,
}

impl TunEngine {
    pub fn new(device: TunDevice, session: SessionCore, fake_dns: FakeDns, mtu: u16) -> Self {
        Self {
            device,
            session,
            fake_dns,
            mtu,
        }
    }

    pub async fn run(self) -> Result<()> {
        let Self {
            device,
            session,
            fake_dns,
            mtu,
        } = self;
        let tun_name = device.name().to_string();
        let file = device.into_file();
        let writer = PacketWriter::new(
            file.try_clone()
                .with_context(|| format!("failed to clone TUN file for writer: {tun_name}"))?,
        );
        let (packet_tx, mut packet_rx) = mpsc::channel(PACKET_CHANNEL_SIZE);

        let (stack, runner, _udp_socket, tcp_listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(false)
            .enable_icmp(true)
            .mtu(mtu as usize)
            .build()
            .context("failed to build smoltcp-backed TUN netstack")?;
        let tcp_listener = tcp_listener.context("TUN TCP listener was not created")?;

        if let Some(runner) = runner {
            tokio::spawn(runner);
        }

        let (mut stack_sink, mut stack_stream) = stack.split();
        tokio::task::spawn_blocking(move || read_packets(tun_name, file, packet_tx));

        let stack_to_tun = {
            let writer = writer.clone();
            tokio::spawn(async move {
                while let Some(packet) = stack_stream.next().await {
                    let packet = packet.context("TUN netstack output failed")?;
                    writer.write_packet(packet).await?;
                }
                Ok::<_, anyhow::Error>(())
            })
        };

        let tun_to_stack = tokio::spawn(async move {
            while let Some(packet) = packet_rx.recv().await {
                if let Err(err) = stack_sink.send(packet).await {
                    debug!(error = %err, "failed to send TUN packet into netstack");
                }
            }
            Ok::<_, anyhow::Error>(())
        });

        let tcp_dispatch = tokio::spawn(run_tcp_dispatcher(session, fake_dns, tcp_listener));

        tokio::select! {
            result = stack_to_tun => result.context("TUN stack-to-device task failed")??,
            result = tun_to_stack => result.context("TUN device-to-stack task failed")??,
            result = tcp_dispatch => result.context("TUN TCP dispatcher task failed")??,
        }

        Ok(())
    }
}

#[derive(Clone)]
struct PacketWriter {
    file: Arc<std::sync::Mutex<std::fs::File>>,
}

impl PacketWriter {
    fn new(file: std::fs::File) -> Self {
        Self {
            file: Arc::new(std::sync::Mutex::new(file)),
        }
    }

    async fn write_packet(&self, packet: Vec<u8>) -> Result<()> {
        let file = Arc::clone(&self.file);
        tokio::task::spawn_blocking(move || {
            let mut file = file
                .lock()
                .map_err(|_| std::io::Error::other("TUN writer mutex poisoned"))?;
            file.write_all(&packet)
        })
        .await
        .context("TUN writer task failed")?
        .context("failed to write packet to TUN")
    }
}

async fn run_tcp_dispatcher(
    session: SessionCore,
    fake_dns: FakeDns,
    mut tcp_listener: TcpListener,
) -> Result<()> {
    while let Some((stream, source, destination)) = tcp_listener.next().await {
        let session = session.clone();
        let fake_dns = fake_dns.clone();
        tokio::spawn(async move {
            if let Err(err) =
                handle_tcp_stream(session, fake_dns, stream, source, destination).await
            {
                debug!(
                    %source,
                    %destination,
                    error = %err,
                    "TUN TCP stream failed"
                );
            }
        });
    }

    Ok(())
}

async fn handle_tcp_stream(
    session: SessionCore,
    fake_dns: FakeDns,
    mut stream: TcpStream,
    source: SocketAddr,
    destination: SocketAddr,
) -> Result<()> {
    let target_host = resolve_target_host(&fake_dns, destination.ip()).await;
    let target_port = destination.port();

    if matches!(
        session.check_dns_policy(
            &target_host,
            target_port,
            SessionContext {
                inbound: "tun",
                peer: Some(source),
            },
        ),
        DnsPolicyResult::BlockedIpTarget
    ) {
        bail!("TUN TCP target blocked by DNS policy: {target_host}:{target_port}");
    }

    info!(
        %source,
        %destination,
        target_host,
        target_port,
        "accepted TUN TCP stream from smoltcp netstack"
    );

    match session.open_tcp(&target_host, target_port).await? {
        TcpOpenResult::Opened(outbound) => {
            let action = outbound.action;
            let metrics = outbound.metrics;
            let relay_started = Instant::now();
            let stats = session.relay_tcp(&mut stream, outbound).await?;
            let relay_elapsed = relay_started.elapsed();
            let total_bytes = stats.total_bytes();
            let mbps = stats.mbps(relay_elapsed);

            debug!(
                %source,
                %destination,
                target_host,
                target_port,
                route = ?action,
                server_tcp_connect_ms = metrics.server_tcp_connect_ms,
                tls_handshake_ms = metrics.tls_handshake_ms,
                http_upgrade_ms = metrics.http_upgrade_ms,
                target_tcp_connect_ms = metrics.target_tcp_connect_ms,
                client_to_upstream_bytes = stats.client_to_upstream_bytes,
                upstream_to_client_bytes = stats.upstream_to_client_bytes,
                total_bytes,
                duration_ms = elapsed_millis(relay_elapsed),
                mbps,
                "TUN TCP relay finished"
            );
        }
        TcpOpenResult::Blocked => {
            bail!("route blocked TUN TCP target {target_host}:{target_port}");
        }
    }

    Ok(())
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

async fn resolve_target_host(fake_dns: &FakeDns, ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => fake_dns
            .lookup_domain(ip)
            .await
            .unwrap_or_else(|| IpAddr::V4(ip).to_string()),
        IpAddr::V6(ip) => IpAddr::V6(ip).to_string(),
    }
}

fn read_packets(tun_name: String, mut file: std::fs::File, packet_tx: mpsc::Sender<Vec<u8>>) {
    let mut buf = vec![0u8; MAX_PACKET_SIZE];

    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => {
                debug!(tun = %tun_name, "TUN device reached EOF");
                break;
            }
            Ok(n) => n,
            Err(err) => {
                warn!(tun = %tun_name, error = %err, "failed to read from TUN device");
                break;
            }
        };

        trace!(tun = %tun_name, bytes = n, "read TUN packet");
        if packet_tx.blocking_send(buf[..n].to_vec()).is_err() {
            debug!(tun = %tun_name, "TUN packet receiver dropped");
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn resolves_fake_ip_to_domain() {
        let dns = FakeDns::new();
        let fake_ip = dns
            .resolve_or_allocate("example.com")
            .await
            .expect("fake ip");

        let host = resolve_target_host(&dns, IpAddr::V4(fake_ip)).await;

        assert_eq!(host, "example.com");
    }

    #[tokio::test]
    async fn preserves_unmapped_ip_target() {
        let dns = FakeDns::new();

        let host = resolve_target_host(&dns, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))).await;

        assert_eq!(host, "203.0.113.10");
    }
}
