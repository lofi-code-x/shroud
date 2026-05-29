use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use bytes::Bytes;
use shroud_core::auth::compute_auth_tag;
use shroud_core::config::{ClientAuthConfig, OutboundConfig};
use shroud_core::protocol::{
    FrameType, UdpDatagram, decode_udp_associate_response_payload, decode_udp_datagram,
    encode_tcp_connect_payload, encode_udp_datagram, read_frame, write_frame,
};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tracing::debug;

const MAX_HTTP_HEADERS: usize = 16 * 1024;
const STREAM_ID: u64 = 1;
const CONNECT_OK_FLAG: u16 = 0x0001;
const TUNNEL_ENDPOINT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_UPGRADE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_CONNECT_REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_ASSOCIATE_REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const COPY_BUF_SIZE: usize = 32 * 1024;

pub trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> TunnelIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type TunnelStream = Box<dyn TunnelIo>;

#[derive(Debug, Clone, Copy)]
pub struct RelayStats {
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
}

impl RelayStats {
    pub fn total_bytes(self) -> u64 {
        self.client_to_upstream_bytes + self.upstream_to_client_bytes
    }

    pub fn mbps(self, elapsed: Duration) -> f64 {
        let seconds = elapsed.as_secs_f64();
        if seconds > 0.0 {
            (self.total_bytes() as f64 * 8.0) / seconds / 1_000_000.0
        } else {
            0.0
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TunnelOpenTimings {
    pub server_tcp_connect_ms: u64,
    pub tls_handshake_ms: Option<u64>,
    pub http_upgrade_ms: u64,
    pub target_tcp_connect_ms: u64,
}

pub struct TcpTunnel {
    pub stream: TunnelStream,
    pub timings: TunnelOpenTimings,
}

struct TunnelTransport {
    stream: TunnelStream,
    server_tcp_connect_ms: u64,
    tls_handshake_ms: Option<u64>,
    http_upgrade_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpAssociationInfo {
    pub remote_bind_host: String,
    pub remote_bind_port: u16,
}

pub struct UdpTunnel {
    stream: TunnelStream,
    stream_id: u64,
    pub association: UdpAssociationInfo,
}

pub struct UdpTunnelReadHalf {
    reader: ReadHalf<TunnelStream>,
    stream_id: u64,
}

pub struct UdpTunnelWriteHalf {
    writer: WriteHalf<TunnelStream>,
    stream_id: u64,
}

impl UdpTunnel {
    pub fn into_split(self) -> (UdpTunnelReadHalf, UdpTunnelWriteHalf) {
        let stream_id = self.stream_id;
        let (reader, writer) = split(self.stream);
        (
            UdpTunnelReadHalf { reader, stream_id },
            UdpTunnelWriteHalf { writer, stream_id },
        )
    }
}

impl UdpTunnelReadHalf {
    pub async fn recv_datagram(&mut self) -> Result<UdpDatagram> {
        let frame = timeout(RELAY_IDLE_TIMEOUT, read_frame(&mut self.reader))
            .await
            .context("udp relay idle timeout while reading from tunnel")??;
        if frame.stream_id != self.stream_id {
            bail!(
                "unexpected stream id in UDP_DATAGRAM: expected={}, got={}",
                self.stream_id,
                frame.stream_id
            );
        }

        match frame.frame_type {
            FrameType::UdpDatagram => decode_udp_datagram(frame.payload.as_ref())
                .map_err(|err| anyhow!("invalid UDP_DATAGRAM payload: {err}")),
            FrameType::ErrorFrame => {
                let message = String::from_utf8_lossy(frame.payload.as_ref()).into_owned();
                bail!("server returned ERROR frame during UDP relay: {message}");
            }
            other => bail!("unexpected frame type from server during UDP relay: {other}"),
        }
    }
}

impl UdpTunnelWriteHalf {
    pub async fn send_datagram(&mut self, datagram: &UdpDatagram) -> Result<()> {
        let payload = encode_udp_datagram(datagram)
            .map_err(|err| anyhow!("failed to encode UDP_DATAGRAM payload: {err}"))?;
        timeout(
            RELAY_IDLE_TIMEOUT,
            write_frame(
                &mut self.writer,
                FrameType::UdpDatagram,
                self.stream_id,
                0,
                payload,
            ),
        )
        .await
        .context("udp relay timeout while writing UDP_DATAGRAM to tunnel")??;
        Ok(())
    }
}

#[derive(Clone)]
pub struct TunnelClient {
    outbound: OutboundConfig,
    auth: ClientAuthConfig,
}

impl TunnelClient {
    pub fn new(outbound: OutboundConfig, auth: ClientAuthConfig) -> Self {
        Self { outbound, auth }
    }

    pub async fn connect_target_via_tunnel(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<TunnelStream> {
        Ok(self
            .connect_target_via_tunnel_with_timings(target_host, target_port)
            .await?
            .stream)
    }

    pub async fn connect_target_via_tunnel_with_timings(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpTunnel> {
        self.open_tunnel(target_host, target_port).await
    }

    pub async fn open_udp_association(&self) -> Result<UdpTunnel> {
        let mut stream = self
            .open_tunnel_transport("<udp-associate>", 0)
            .await
            .context("failed to open tunnel transport for UDP associate")?
            .stream;

        write_frame(
            &mut stream,
            FrameType::UdpAssociateRequest,
            STREAM_ID,
            0,
            Bytes::new(),
        )
        .await?;

        let response = timeout(UDP_ASSOCIATE_REPLY_TIMEOUT, read_frame(&mut stream))
            .await
            .context("timed out waiting for UDP_ASSOCIATE response")??;
        if response.stream_id != STREAM_ID {
            bail!(
                "unexpected stream id in UDP associate response: {}",
                response.stream_id
            );
        }

        match response.frame_type {
            FrameType::UdpAssociateResponse if (response.flags & CONNECT_OK_FLAG) != 0 => {
                let (remote_bind_host, remote_bind_port) =
                    decode_udp_associate_response_payload(response.payload.as_ref())
                        .map_err(|err| anyhow!("invalid UDP_ASSOCIATE response payload: {err}"))?;
                Ok(UdpTunnel {
                    stream,
                    stream_id: STREAM_ID,
                    association: UdpAssociationInfo {
                        remote_bind_host,
                        remote_bind_port,
                    },
                })
            }
            FrameType::UdpAssociateResponse => {
                let message = String::from_utf8_lossy(response.payload.as_ref()).into_owned();
                bail!(
                    "server refused UDP_ASSOCIATE: flags={}, message={message}",
                    response.flags
                );
            }
            FrameType::ErrorFrame => {
                let message = String::from_utf8_lossy(response.payload.as_ref()).into_owned();
                bail!("server refused UDP_ASSOCIATE: {message}");
            }
            other => bail!("unexpected frame type instead of UDP associate response: {other}"),
        }
    }

    pub async fn relay_over_tunnel_stream<S>(
        &self,
        client_socket: &mut S,
        upstream: &mut TunnelStream,
    ) -> Result<RelayStats>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut client_read, mut client_write) = tokio::io::split(client_socket);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

        let client_to_upstream = async {
            let mut transferred = 0u64;
            let mut buf = [0u8; COPY_BUF_SIZE];

            loop {
                let n = timeout(RELAY_IDLE_TIMEOUT, client_read.read(&mut buf))
                    .await
                    .context("relay idle timeout while reading from SOCKS client")??;
                if n == 0 {
                    timeout(
                        RELAY_IDLE_TIMEOUT,
                        write_frame(
                            &mut upstream_write,
                            FrameType::TcpClose,
                            STREAM_ID,
                            0,
                            Bytes::new(),
                        ),
                    )
                    .await
                    .context("relay timeout while writing TCP_CLOSE to tunnel")??;
                    timeout(RELAY_IDLE_TIMEOUT, upstream_write.shutdown())
                        .await
                        .context("relay timeout while shutting down tunnel writer")??;
                    break;
                }

                transferred += n as u64;
                timeout(
                    RELAY_IDLE_TIMEOUT,
                    write_frame(
                        &mut upstream_write,
                        FrameType::TcpData,
                        STREAM_ID,
                        0,
                        Bytes::copy_from_slice(&buf[..n]),
                    ),
                )
                .await
                .context("relay timeout while writing TCP_DATA to tunnel")??;
            }

            Ok::<u64, anyhow::Error>(transferred)
        };

        let upstream_to_client = async {
            let mut transferred = 0u64;

            loop {
                let frame = timeout(RELAY_IDLE_TIMEOUT, read_frame(&mut upstream_read))
                    .await
                    .context("relay idle timeout while reading from tunnel")??;
                if frame.stream_id != STREAM_ID {
                    bail!("unexpected stream id from server: {}", frame.stream_id);
                }

                match frame.frame_type {
                    FrameType::TcpData => {
                        transferred += frame.payload.len() as u64;
                        timeout(
                            RELAY_IDLE_TIMEOUT,
                            client_write.write_all(frame.payload.as_ref()),
                        )
                        .await
                        .context("relay timeout while writing to SOCKS client")??;
                    }
                    FrameType::TcpClose => break,
                    FrameType::ErrorFrame => {
                        let message = String::from_utf8_lossy(frame.payload.as_ref()).into_owned();
                        bail!("server returned ERROR frame: {message}");
                    }
                    other => {
                        bail!("unexpected frame type from server during relay: {other}");
                    }
                }
            }

            timeout(RELAY_IDLE_TIMEOUT, client_write.shutdown())
                .await
                .context("relay timeout while shutting down SOCKS client writer")??;
            Ok::<u64, anyhow::Error>(transferred)
        };

        let (client_to_upstream_bytes, upstream_to_client_bytes) =
            tokio::try_join!(client_to_upstream, upstream_to_client)?;

        Ok(RelayStats {
            client_to_upstream_bytes,
            upstream_to_client_bytes,
        })
    }

    async fn open_tunnel(&self, target_host: &str, target_port: u16) -> Result<TcpTunnel> {
        let transport = self.open_tunnel_transport(target_host, target_port).await?;
        let TunnelTransport {
            mut stream,
            server_tcp_connect_ms,
            tls_handshake_ms,
            http_upgrade_ms,
        } = transport;

        let payload = encode_tcp_connect_payload(target_host, target_port)
            .map_err(|err| anyhow!("failed to encode tcp connect payload: {err}"))?;
        let target_connect_started = Instant::now();
        write_frame(&mut stream, FrameType::TcpConnect, STREAM_ID, 0, payload).await?;

        let connect_reply = timeout(TCP_CONNECT_REPLY_TIMEOUT, read_frame(&mut stream))
            .await
            .context("timed out waiting for TCP_CONNECT reply")??;
        let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
        if connect_reply.stream_id != STREAM_ID {
            bail!(
                "unexpected stream id in connect reply: {}",
                connect_reply.stream_id
            );
        }

        match connect_reply.frame_type {
            FrameType::TcpConnect if (connect_reply.flags & CONNECT_OK_FLAG) != 0 => {
                debug!(
                    server = %self.outbound.server,
                    target_host,
                    target_port,
                    target_tcp_connect_ms,
                    "tunnel target TCP_CONNECT finished"
                );
                Ok(TcpTunnel {
                    stream,
                    timings: TunnelOpenTimings {
                        server_tcp_connect_ms,
                        tls_handshake_ms,
                        http_upgrade_ms,
                        target_tcp_connect_ms,
                    },
                })
            }
            FrameType::ErrorFrame => {
                let message = String::from_utf8_lossy(connect_reply.payload.as_ref()).into_owned();
                bail!("server refused TCP_CONNECT: {message}");
            }
            FrameType::TcpConnect => {
                bail!(
                    "server returned TCP_CONNECT without success flag; flags={}",
                    connect_reply.flags
                );
            }
            other => bail!("unexpected frame type instead of connect reply: {other}"),
        }
    }

    pub(crate) async fn open_persistent_tunnel_transport(&self) -> Result<TunnelStream> {
        Ok(self
            .open_tunnel_transport("<multiplex>", 0)
            .await
            .context("failed to open persistent tunnel transport")?
            .stream)
    }

    async fn open_tunnel_transport(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<TunnelTransport> {
        let server_connect_started = Instant::now();
        let stream = timeout(
            TUNNEL_ENDPOINT_CONNECT_TIMEOUT,
            TcpStream::connect((self.outbound.server.as_str(), self.outbound.port)),
        )
        .await
        .with_context(|| {
            format!(
                "timed out connecting to tunnel endpoint {}:{}",
                self.outbound.server, self.outbound.port
            )
        })?
        .with_context(|| {
            format!(
                "failed to connect to tunnel endpoint {}:{}",
                self.outbound.server, self.outbound.port
            )
        })?;
        let server_tcp_connect_ms = elapsed_millis(server_connect_started.elapsed());
        debug!(
            server = %self.outbound.server,
            port = self.outbound.port,
            target_host,
            target_port,
            server_tcp_connect_ms,
            "tunnel server TCP connect finished"
        );

        stream.set_nodelay(true).with_context(|| {
            format!(
                "failed to enable TCP_NODELAY for tunnel endpoint {}:{}",
                self.outbound.server, self.outbound.port
            )
        })?;

        let mut tls_handshake_ms = None;
        let mut stream: TunnelStream = if self.outbound.tls {
            let tls_started = Instant::now();
            let connector = TlsConnector::from(Arc::new(build_tls_client_config(&self.outbound)?));
            let server_name = self
                .outbound
                .tls_server_name
                .as_deref()
                .unwrap_or(&self.outbound.server)
                .to_owned();
            let server_name = ServerName::try_from(server_name)
                .map_err(|err| anyhow!("invalid tls server name: {err}"))?;
            let tls_stream = timeout(
                TUNNEL_ENDPOINT_CONNECT_TIMEOUT,
                connector.connect(server_name, stream),
            )
            .await
            .with_context(|| {
                format!(
                    "timed out establishing tls connection to {}:{}",
                    self.outbound.server, self.outbound.port
                )
            })?
            .with_context(|| {
                format!(
                    "failed to establish tls connection to {}:{}",
                    self.outbound.server, self.outbound.port
                )
            })?;
            let elapsed_ms = elapsed_millis(tls_started.elapsed());
            tls_handshake_ms = Some(elapsed_ms);
            debug!(
                server = %self.outbound.server,
                port = self.outbound.port,
                target_host,
                target_port,
                tls_handshake_ms = elapsed_ms,
                "tunnel TLS handshake finished"
            );
            Box::new(tls_stream)
        } else {
            Box::new(stream)
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before unix epoch")?
            .as_secs() as i64;

        let nonce = uuid::Uuid::new_v4().as_bytes().to_vec();
        let auth_tag = compute_auth_tag(
            self.auth.client_secret.as_bytes(),
            &nonce,
            timestamp,
            &self.auth.client_id,
        )
        .context("failed to compute auth tag")?;

        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: Upgrade\r\nUpgrade: shroud-tunnel\r\nX-Shroud-Client-Id: {client_id}\r\nX-Shroud-Timestamp: {timestamp}\r\nX-Shroud-Nonce: {nonce}\r\nX-Shroud-Auth: {auth}\r\n\r\n",
            path = self.outbound.path,
            host = self.outbound.server,
            port = self.outbound.port,
            client_id = self.auth.client_id,
            timestamp = timestamp,
            nonce = STANDARD_NO_PAD.encode(&nonce),
            auth = auth_tag,
        );
        let http_upgrade_started = Instant::now();
        stream.write_all(request.as_bytes()).await?;

        let response = timeout(
            HTTP_UPGRADE_RESPONSE_TIMEOUT,
            read_http_headers(&mut stream),
        )
        .await
        .context("timed out waiting for HTTP upgrade response")??;
        let status = parse_status_code(&response).context("failed to parse tunnel response")?;
        let http_upgrade_ms = elapsed_millis(http_upgrade_started.elapsed());

        if status != 101 {
            bail!("tunnel endpoint rejected upgrade with HTTP status {status}");
        }

        debug!(
            server = %self.outbound.server,
            tunnel_path = %self.outbound.path,
            client_id = %self.auth.client_id,
            target_host,
            target_port,
            http_upgrade_ms,
            "tunnel upgrade accepted"
        );

        Ok(TunnelTransport {
            stream,
            server_tcp_connect_ms,
            tls_handshake_ms,
            http_upgrade_ms,
        })
    }
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

fn build_tls_client_config(outbound: &OutboundConfig) -> Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(path) = &outbound.tls_ca_cert_path {
        let certs = load_certs(path)?;
        let (_added, ignored) = root_store.add_parsable_certificates(certs);
        if ignored > 0 {
            bail!("ignored {ignored} invalid certificate(s) from tls_ca_cert_path={path}");
        }
    }

    Ok(ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth())
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("failed to open certificate file {path}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read certificates from {path}"))
}

async fn read_http_headers<R>(stream: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut data = Vec::with_capacity(512);
    let mut byte = [0u8; 1];

    while data.len() < MAX_HTTP_HEADERS {
        stream.read_exact(&mut byte).await?;
        data.push(byte[0]);
        if data.ends_with(b"\r\n\r\n") {
            return Ok(data);
        }
    }

    bail!("http headers are too large");
}

fn parse_status_code(raw_headers: &[u8]) -> Result<u16> {
    let headers = std::str::from_utf8(raw_headers).context("http headers are not valid utf-8")?;
    let status_line = headers
        .split("\r\n")
        .next()
        .ok_or_else(|| anyhow!("empty HTTP response"))?;
    let mut parts = status_line.split_whitespace();
    let _version = parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP version in response"))?;
    let code = parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP status code in response"))?;
    code.parse::<u16>()
        .context("HTTP status code is not a valid integer")
}
