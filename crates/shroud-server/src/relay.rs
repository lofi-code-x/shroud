use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use shroud_core::protocol::{
    Frame, FrameType, HEADER_LEN, MAX_FRAME_PAYLOAD_LEN, UdpDatagram, decode_tcp_connect_payload,
    decode_udp_datagram, encode_udp_associate_response_payload, encode_udp_datagram,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::debug;

const CONNECT_OK_FLAG: u16 = 0x0001;
const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn relay_tunnel<S>(mut tunnel_stream: S, peer: SocketAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let first_frame = timeout(RELAY_IDLE_TIMEOUT, read_frame(&mut tunnel_stream))
        .await
        .map_err(|_| anyhow!("timed out waiting for first tunnel frame"))??;

    match first_frame.frame_type {
        FrameType::TcpConnect => relay_tcp_tunnel(tunnel_stream, peer, first_frame).await,
        FrameType::UdpAssociateRequest => {
            relay_udp_association(tunnel_stream, peer, first_frame).await
        }
        other => {
            write_frame(
                &mut tunnel_stream,
                FrameType::ErrorFrame,
                first_frame.stream_id,
                0,
                Bytes::from_static(b"expected TCP_CONNECT or UDP_ASSOCIATE_REQUEST as first frame"),
            )
            .await?;
            bail!("first frame from peer {peer} is not a tunnel open request: {other}");
        }
    }
}

async fn relay_tcp_tunnel<S>(
    mut tunnel_stream: S,
    peer: SocketAddr,
    connect_request: Frame,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream_id = connect_request.stream_id;
    let (target_host, target_port) =
        decode_tcp_connect_payload(connect_request.payload.as_ref())
            .map_err(|err| anyhow!("invalid TCP_CONNECT payload: {err}"))?;

    let target_connect_started = Instant::now();
    let mut target_stream = match timeout(
        TARGET_CONNECT_TIMEOUT,
        TcpStream::connect((target_host.as_str(), target_port)),
    )
    .await
    {
        Err(_) => {
            let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
            let message = format!("timed out connecting target {target_host}:{target_port}");
            debug!(
                %peer,
                stream_id,
                target_host,
                target_port,
                target_tcp_connect_ms,
                "target TCP connect timed out"
            );
            write_frame(
                &mut tunnel_stream,
                FrameType::ErrorFrame,
                stream_id,
                0,
                Bytes::from(message.clone()),
            )
            .await?;
            bail!("{message}");
        }
        Ok(Ok(stream)) => {
            let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
            stream.set_nodelay(true).with_context(|| {
                format!(
                    "failed to enable TCP_NODELAY for target connection {target_host}:{target_port}"
                )
            })?;

            debug!(
                %peer,
                stream_id,
                target_host,
                target_port,
                target_tcp_connect_ms,
                "target TCP connect finished"
            );

            stream
        }
        Ok(Err(err)) => {
            let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
            let message = format!("failed to connect target {target_host}:{target_port}: {err}");
            debug!(
                %peer,
                stream_id,
                target_host,
                target_port,
                target_tcp_connect_ms,
                error = %err,
                "target TCP connect failed"
            );
            write_frame(
                &mut tunnel_stream,
                FrameType::ErrorFrame,
                stream_id,
                0,
                Bytes::from(message.clone()),
            )
            .await?;
            bail!("{message}");
        }
    };
    let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());

    write_frame(
        &mut tunnel_stream,
        FrameType::TcpConnect,
        stream_id,
        CONNECT_OK_FLAG,
        Bytes::new(),
    )
    .await?;

    let relay_started = Instant::now();
    let (mut tunnel_read, mut tunnel_write) = tokio::io::split(tunnel_stream);
    let (mut target_read, mut target_write) = target_stream.split();

    let tunnel_to_target = async {
        let mut transferred = 0u64;

        loop {
            let frame = timeout(RELAY_IDLE_TIMEOUT, read_frame(&mut tunnel_read))
                .await
                .map_err(|_| anyhow!("relay idle timeout while reading from tunnel peer"))??;
            if frame.stream_id != stream_id {
                bail!(
                    "unexpected stream id from peer {}; expected={}, got={}",
                    peer,
                    stream_id,
                    frame.stream_id
                );
            }

            match frame.frame_type {
                FrameType::TcpData => {
                    transferred += frame.payload.len() as u64;
                    timeout(
                        RELAY_IDLE_TIMEOUT,
                        target_write.write_all(frame.payload.as_ref()),
                    )
                    .await
                    .map_err(|_| anyhow!("relay timeout while writing to target"))??;
                }
                FrameType::TcpClose => {
                    timeout(RELAY_IDLE_TIMEOUT, target_write.shutdown())
                        .await
                        .map_err(|_| {
                            anyhow!("relay timeout while shutting down target writer")
                        })??;
                    break;
                }
                FrameType::ErrorFrame => {
                    let message = String::from_utf8_lossy(frame.payload.as_ref()).into_owned();
                    bail!("peer sent ERROR frame: {message}");
                }
                other => bail!("unexpected frame type from peer during relay: {other}"),
            }
        }

        Ok::<u64, anyhow::Error>(transferred)
    };

    let target_to_tunnel = async {
        let mut transferred = 0u64;
        let mut buf = [0u8; 64 * 1024];

        loop {
            let n = timeout(RELAY_IDLE_TIMEOUT, target_read.read(&mut buf))
                .await
                .map_err(|_| anyhow!("relay idle timeout while reading from target"))??;
            if n == 0 {
                timeout(
                    RELAY_IDLE_TIMEOUT,
                    write_frame(
                        &mut tunnel_write,
                        FrameType::TcpClose,
                        stream_id,
                        0,
                        Bytes::new(),
                    ),
                )
                .await
                .map_err(|_| anyhow!("relay timeout while writing TCP_CLOSE to tunnel"))??;
                timeout(RELAY_IDLE_TIMEOUT, tunnel_write.shutdown())
                    .await
                    .map_err(|_| anyhow!("relay timeout while shutting down tunnel writer"))??;
                break;
            }

            transferred += n as u64;
            timeout(
                RELAY_IDLE_TIMEOUT,
                write_frame(
                    &mut tunnel_write,
                    FrameType::TcpData,
                    stream_id,
                    0,
                    Bytes::copy_from_slice(&buf[..n]),
                ),
            )
            .await
            .map_err(|_| anyhow!("relay timeout while writing TCP_DATA to tunnel"))??;
        }

        Ok::<u64, anyhow::Error>(transferred)
    };

    let (upstream_to_target_bytes, target_to_upstream_bytes) =
        tokio::try_join!(tunnel_to_target, target_to_tunnel)?;
    let relay_elapsed = relay_started.elapsed();
    let total_bytes = upstream_to_target_bytes + target_to_upstream_bytes;
    let mbps = mbps(total_bytes, relay_elapsed);

    debug!(
        %peer,
        stream_id,
        target_host,
        target_port,
        target_tcp_connect_ms,
        upstream_to_target_bytes,
        target_to_upstream_bytes,
        total_bytes,
        duration_ms = elapsed_millis(relay_elapsed),
        mbps,
        "tunnel relay finished"
    );

    Ok(())
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

fn mbps(total_bytes: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds > 0.0 {
        (total_bytes as f64 * 8.0) / seconds / 1_000_000.0
    } else {
        0.0
    }
}

async fn relay_udp_association<S>(
    mut tunnel_stream: S,
    peer: SocketAddr,
    associate_request: Frame,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream_id = associate_request.stream_id;
    let udp_socket = match UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await {
        Ok(socket) => socket,
        Err(err) => {
            let message = format!("failed to bind remote UDP socket: {err}");
            write_frame(
                &mut tunnel_stream,
                FrameType::UdpAssociateResponse,
                stream_id,
                0,
                Bytes::from(message.clone()),
            )
            .await?;
            bail!("{message}");
        }
    };

    let bind_addr = match udp_socket.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            let message = format!("failed to inspect remote UDP bind address: {err}");
            write_frame(
                &mut tunnel_stream,
                FrameType::UdpAssociateResponse,
                stream_id,
                0,
                Bytes::from(message.clone()),
            )
            .await?;
            bail!("{message}");
        }
    };
    let response_payload =
        encode_udp_associate_response_payload(&bind_addr.ip().to_string(), bind_addr.port())
            .map_err(|err| anyhow!("failed to encode UDP associate response: {err}"))?;
    write_frame(
        &mut tunnel_stream,
        FrameType::UdpAssociateResponse,
        stream_id,
        CONNECT_OK_FLAG,
        response_payload,
    )
    .await?;

    let counters = Arc::new(UdpRelayCounters::default());
    let udp_socket = Arc::new(udp_socket);
    let (mut tunnel_read, mut tunnel_write) = tokio::io::split(tunnel_stream);

    let tunnel_to_udp_socket = Arc::clone(&udp_socket);
    let tunnel_to_udp_counters = Arc::clone(&counters);
    let tunnel_to_udp = async move {
        loop {
            let frame = timeout(RELAY_IDLE_TIMEOUT, read_frame(&mut tunnel_read))
                .await
                .map_err(|_| anyhow!("udp relay idle timeout while reading from tunnel peer"))??;
            if frame.stream_id != stream_id {
                bail!(
                    "unexpected stream id from peer {}; expected={}, got={}",
                    peer,
                    stream_id,
                    frame.stream_id
                );
            }

            match frame.frame_type {
                FrameType::UdpDatagram => {
                    let datagram = decode_udp_datagram(frame.payload.as_ref())
                        .map_err(|err| anyhow!("invalid UDP_DATAGRAM payload: {err}"))?;
                    let sent = timeout(
                        RELAY_IDLE_TIMEOUT,
                        tunnel_to_udp_socket.send_to(
                            datagram.payload.as_ref(),
                            (datagram.target_host.as_str(), datagram.target_port),
                        ),
                    )
                    .await
                    .map_err(|_| anyhow!("udp relay timeout while sending datagram"))??;
                    tunnel_to_udp_counters.record_tunnel_to_udp(sent as u64);
                }
                FrameType::ErrorFrame => {
                    let message = String::from_utf8_lossy(frame.payload.as_ref()).into_owned();
                    bail!("peer sent ERROR frame: {message}");
                }
                other => bail!("unexpected frame type from peer during udp relay: {other}"),
            }
        }

        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    let udp_to_tunnel_socket = Arc::clone(&udp_socket);
    let udp_to_tunnel_counters = Arc::clone(&counters);
    let udp_to_tunnel = async move {
        let mut buf = vec![0u8; MAX_FRAME_PAYLOAD_LEN];

        loop {
            let (n, source) = timeout(RELAY_IDLE_TIMEOUT, udp_to_tunnel_socket.recv_from(&mut buf))
                .await
                .map_err(|_| anyhow!("udp relay idle timeout while reading from udp socket"))??;
            let payload = encode_udp_datagram(&UdpDatagram {
                target_host: source.ip().to_string(),
                target_port: source.port(),
                payload: Bytes::copy_from_slice(&buf[..n]),
                association_id: None,
            })
            .map_err(|err| anyhow!("failed to encode UDP_DATAGRAM payload: {err}"))?;
            timeout(
                RELAY_IDLE_TIMEOUT,
                write_frame(
                    &mut tunnel_write,
                    FrameType::UdpDatagram,
                    stream_id,
                    0,
                    payload,
                ),
            )
            .await
            .map_err(|_| anyhow!("udp relay timeout while writing UDP_DATAGRAM to tunnel"))??;
            udp_to_tunnel_counters.record_udp_to_tunnel(n as u64);
        }

        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    let result = tokio::try_join!(tunnel_to_udp, udp_to_tunnel);
    let snapshot = counters.snapshot();
    match &result {
        Ok(_) => debug!(
            %peer,
            stream_id,
            bind_addr = %bind_addr,
            tunnel_to_udp_datagrams = snapshot.tunnel_to_udp_datagrams,
            tunnel_to_udp_bytes = snapshot.tunnel_to_udp_bytes,
            udp_to_tunnel_datagrams = snapshot.udp_to_tunnel_datagrams,
            udp_to_tunnel_bytes = snapshot.udp_to_tunnel_bytes,
            "udp tunnel relay finished"
        ),
        Err(err) => debug!(
            %peer,
            stream_id,
            bind_addr = %bind_addr,
            tunnel_to_udp_datagrams = snapshot.tunnel_to_udp_datagrams,
            tunnel_to_udp_bytes = snapshot.tunnel_to_udp_bytes,
            udp_to_tunnel_datagrams = snapshot.udp_to_tunnel_datagrams,
            udp_to_tunnel_bytes = snapshot.udp_to_tunnel_bytes,
            error = %err,
            "udp tunnel relay stopped"
        ),
    }

    result.map(|_| ())
}

async fn write_frame<W>(
    writer: &mut W,
    frame_type: FrameType,
    stream_id: u64,
    flags: u16,
    payload: Bytes,
) -> Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    if payload.len() > MAX_FRAME_PAYLOAD_LEN {
        bail!(
            "frame payload too large: max={}, got={}",
            MAX_FRAME_PAYLOAD_LEN,
            payload.len()
        );
    }

    let frame = Frame {
        frame_type,
        stream_id,
        flags,
        payload,
    };
    writer.write_all(frame.encode().as_ref()).await?;
    Ok(())
}

async fn read_frame<R>(reader: &mut R) -> Result<Frame>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;

    let payload_len = u32::from_be_bytes([header[12], header[13], header[14], header[15]]) as usize;
    if payload_len > MAX_FRAME_PAYLOAD_LEN {
        bail!(
            "frame payload too large: max={}, got={}",
            MAX_FRAME_PAYLOAD_LEN,
            payload_len
        );
    }

    let mut raw = Vec::with_capacity(HEADER_LEN + payload_len);
    raw.extend_from_slice(&header);

    if payload_len > 0 {
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;
        raw.extend_from_slice(&payload);
    }

    Frame::decode(Bytes::from(raw)).map_err(|err| anyhow!("failed to decode frame: {err}"))
}

#[derive(Default)]
struct UdpRelayCounters {
    tunnel_to_udp_datagrams: AtomicU64,
    tunnel_to_udp_bytes: AtomicU64,
    udp_to_tunnel_datagrams: AtomicU64,
    udp_to_tunnel_bytes: AtomicU64,
}

impl UdpRelayCounters {
    fn record_tunnel_to_udp(&self, bytes: u64) {
        self.tunnel_to_udp_datagrams.fetch_add(1, Ordering::Relaxed);
        self.tunnel_to_udp_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_udp_to_tunnel(&self, bytes: u64) {
        self.udp_to_tunnel_datagrams.fetch_add(1, Ordering::Relaxed);
        self.udp_to_tunnel_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn snapshot(&self) -> UdpRelayCounterSnapshot {
        UdpRelayCounterSnapshot {
            tunnel_to_udp_datagrams: self.tunnel_to_udp_datagrams.load(Ordering::Relaxed),
            tunnel_to_udp_bytes: self.tunnel_to_udp_bytes.load(Ordering::Relaxed),
            udp_to_tunnel_datagrams: self.udp_to_tunnel_datagrams.load(Ordering::Relaxed),
            udp_to_tunnel_bytes: self.udp_to_tunnel_bytes.load(Ordering::Relaxed),
        }
    }
}

struct UdpRelayCounterSnapshot {
    tunnel_to_udp_datagrams: u64,
    tunnel_to_udp_bytes: u64,
    udp_to_tunnel_datagrams: u64,
    udp_to_tunnel_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::protocol::{
        UdpDatagram, decode_udp_associate_response_payload, encode_udp_datagram,
    };
    use tokio::io::duplex;

    #[tokio::test]
    async fn udp_associate_relays_datagrams_both_directions() -> Result<()> {
        let echo_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let echo_addr = echo_socket.local_addr()?;
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (n, peer) = echo_socket.recv_from(&mut buf).await?;
            echo_socket.send_to(&buf[..n], peer).await?;
            Ok::<(), std::io::Error>(())
        });

        let (mut client_side, server_side) = duplex(128 * 1024);
        let peer = "127.0.0.1:12345".parse::<SocketAddr>()?;
        let relay_task = tokio::spawn(relay_tunnel(server_side, peer));

        write_frame(
            &mut client_side,
            FrameType::UdpAssociateRequest,
            77,
            0,
            Bytes::new(),
        )
        .await?;

        let response = timeout(Duration::from_secs(2), read_frame(&mut client_side)).await??;
        assert_eq!(response.frame_type, FrameType::UdpAssociateResponse);
        assert_eq!(response.stream_id, 77);
        assert_ne!(response.flags & CONNECT_OK_FLAG, 0);
        let (_bind_host, bind_port) =
            decode_udp_associate_response_payload(response.payload.as_ref())?;
        assert_ne!(bind_port, 0);

        let datagram_payload = encode_udp_datagram(&UdpDatagram {
            target_host: echo_addr.ip().to_string(),
            target_port: echo_addr.port(),
            payload: Bytes::from_static(b"ping"),
            association_id: None,
        })?;
        write_frame(
            &mut client_side,
            FrameType::UdpDatagram,
            77,
            0,
            datagram_payload,
        )
        .await?;

        let reply = timeout(Duration::from_secs(2), read_frame(&mut client_side)).await??;
        assert_eq!(reply.frame_type, FrameType::UdpDatagram);
        assert_eq!(reply.stream_id, 77);
        let reply = decode_udp_datagram(reply.payload.as_ref())?;
        assert_eq!(reply.target_host, echo_addr.ip().to_string());
        assert_eq!(reply.target_port, echo_addr.port());
        assert_eq!(reply.payload, Bytes::from_static(b"ping"));

        echo_task.await??;
        relay_task.abort();
        let _ = relay_task.await;
        Ok(())
    }
}
