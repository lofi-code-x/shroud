use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use bytes::Bytes;
use shroud_core::auth::compute_auth_tag;
use shroud_core::config::{ClientAuthConfig, OutboundConfig};
use shroud_core::protocol::{Frame, FrameType, HEADER_LEN, encode_tcp_connect_payload};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tracing::debug;

const MAX_HTTP_HEADERS: usize = 16 * 1024;
const STREAM_ID: u64 = 1;
const CONNECT_OK_FLAG: u16 = 0x0001;

pub trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> TunnelIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type TunnelStream = Box<dyn TunnelIo>;

#[derive(Debug, Clone, Copy)]
pub struct RelayStats {
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
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
        self.open_tunnel(target_host, target_port).await
    }

    pub async fn relay_over_tunnel_stream(
        &self,
        client_socket: &mut TcpStream,
        upstream: &mut TunnelStream,
    ) -> Result<RelayStats> {
        let (mut client_read, mut client_write) = client_socket.split();
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

        let client_to_upstream = async {
            let mut transferred = 0u64;
            let mut buf = [0u8; 16 * 1024];

            loop {
                let n = client_read.read(&mut buf).await?;
                if n == 0 {
                    write_frame(
                        &mut upstream_write,
                        FrameType::TcpClose,
                        STREAM_ID,
                        0,
                        Bytes::new(),
                    )
                    .await?;
                    upstream_write.shutdown().await?;
                    break;
                }

                transferred += n as u64;
                write_frame(
                    &mut upstream_write,
                    FrameType::TcpData,
                    STREAM_ID,
                    0,
                    Bytes::copy_from_slice(&buf[..n]),
                )
                .await?;
            }

            Ok::<u64, anyhow::Error>(transferred)
        };

        let upstream_to_client = async {
            let mut transferred = 0u64;

            loop {
                let frame = read_frame(&mut upstream_read).await?;
                if frame.stream_id != STREAM_ID {
                    bail!("unexpected stream id from server: {}", frame.stream_id);
                }

                match frame.frame_type {
                    FrameType::TcpData => {
                        transferred += frame.payload.len() as u64;
                        client_write.write_all(frame.payload.as_ref()).await?;
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

            client_write.shutdown().await?;
            Ok::<u64, anyhow::Error>(transferred)
        };

        let (client_to_upstream_bytes, upstream_to_client_bytes) =
            tokio::try_join!(client_to_upstream, upstream_to_client)?;

        Ok(RelayStats {
            client_to_upstream_bytes,
            upstream_to_client_bytes,
        })
    }

    /// Opens an outbound tunnel connection and requests a TCP connection to the target host.
    ///
    /// This function establishes a connection to the configured tunnel endpoint,
    /// optionally wraps it in TLS, performs an HTTP `Upgrade` handshake, authenticates
    /// the client using Shroud-specific headers, and then sends a `TcpConnect` frame
    /// asking the tunnel server to connect to the requested destination.
    ///
    /// On success, the returned `TunnelStream` is an already-upgraded tunnel stream
    /// ready for bidirectional proxied TCP traffic.
    ///
    /// # Protocol flow
    ///
    /// The function performs the following steps:
    ///
    /// 1. Opens a TCP connection to the configured outbound tunnel endpoint:
    ///
    /// ```text
    /// self.outbound.server:self.outbound.port
    /// ```
    ///
    /// 2. If TLS is enabled in the outbound configuration, upgrades the raw TCP stream
    ///    to a TLS stream.
    ///
    /// 3. Builds authentication data:
    ///
    /// - current Unix timestamp;
    /// - random UUID-based nonce;
    /// - authentication tag computed from:
    ///   - client secret;
    ///   - nonce;
    ///   - timestamp;
    ///   - client ID.
    ///
    /// 4. Sends an HTTP/1.1 upgrade request:
    ///
    /// ```text
    /// POST <path> HTTP/1.1
    /// Host: <server>:<port>
    /// Connection: Upgrade
    /// Upgrade: shroud-tunnel
    /// X-Shroud-Client-Id: <client_id>
    /// X-Shroud-Timestamp: <timestamp>
    /// X-Shroud-Nonce: <base64url_nonce>
    /// X-Shroud-Auth: <auth_tag>
    /// ```
    ///
    /// 5. Reads the HTTP response headers from the tunnel endpoint.
    ///
    /// 6. Verifies that the tunnel endpoint accepted the upgrade with:
    ///
    /// ```text
    /// HTTP status 101 Switching Protocols
    /// ```
    ///
    /// 7. Encodes the requested target address as a TCP connect payload.
    ///
    /// 8. Sends a `FrameType::TcpConnect` frame to the tunnel server.
    ///
    /// 9. Waits for a connect reply frame from the server.
    ///
    /// 10. Returns the upgraded tunnel stream if the server confirms the TCP connect
    ///     request with the `CONNECT_OK_FLAG`.
    ///
    /// # Arguments
    ///
    /// * `target_host` - Destination host that the tunnel server should connect to.
    ///   This may be a domain name, IPv4 address, or IPv6 address depending on what
    ///   `encode_tcp_connect_payload` supports.
    ///
    /// * `target_port` - Destination TCP port that the tunnel server should connect to.
    ///
    /// # Returns
    ///
    /// Returns a `TunnelStream` if:
    ///
    /// - the connection to the tunnel endpoint succeeds;
    /// - optional TLS negotiation succeeds;
    /// - the HTTP upgrade request is accepted with status `101`;
    /// - the `TcpConnect` frame is accepted by the tunnel server;
    /// - the server replies with a successful connect response.
    ///
    /// The returned stream is already upgraded from HTTP mode into the custom
    /// tunnel framing protocol and can be used for further frame-based data exchange.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - connecting to the tunnel endpoint fails;
    /// - TLS configuration cannot be built;
    /// - TLS server name is invalid;
    /// - TLS negotiation fails;
    /// - the system clock is before the Unix epoch;
    /// - authentication tag generation fails;
    /// - writing the HTTP upgrade request fails;
    /// - reading the HTTP response headers fails;
    /// - the HTTP response status cannot be parsed;
    /// - the tunnel endpoint rejects the upgrade with a status other than `101`;
    /// - encoding the TCP connect payload fails;
    /// - writing the `TcpConnect` frame fails;
    /// - reading the connect reply frame fails;
    /// - the reply uses an unexpected stream ID;
    /// - the server returns an error frame;
    /// - the server returns a `TcpConnect` frame without the success flag;
    /// - the server returns an unexpected frame type.
    ///
    /// # Authentication
    ///
    /// The upgrade request contains Shroud-specific authentication headers:
    ///
    /// ```text
    /// X-Shroud-Client-Id
    /// X-Shroud-Timestamp
    /// X-Shroud-Nonce
    /// X-Shroud-Auth
    /// ```
    ///
    /// The nonce is generated from a random UUID and encoded using base64 without
    /// padding. The authentication tag is computed from the client secret, nonce,
    /// timestamp, and client ID.
    ///
    /// This allows the server to verify that the client knows the shared secret and
    /// helps protect the upgrade request against simple replay attacks, assuming the
    /// server validates timestamp freshness and nonce uniqueness.
    ///
    /// # TLS behavior
    ///
    /// If `self.outbound.tls` is `true`, the function wraps the TCP connection with
    /// TLS before sending the HTTP upgrade request.
    ///
    /// The TLS server name is selected as follows:
    ///
    /// 1. `self.outbound.tls_server_name`, if explicitly configured.
    /// 2. `self.outbound.server`, otherwise.
    ///
    /// If `self.outbound.tls` is `false`, the HTTP upgrade request is sent directly
    /// over the raw TCP stream.
    ///
    /// # HTTP upgrade behavior
    ///
    /// The function expects the tunnel endpoint to accept the upgrade by returning
    /// HTTP status code `101`.
    ///
    /// Any other status code is treated as rejection:
    ///
    /// ```text
    /// tunnel endpoint rejected upgrade with HTTP status <status>
    /// ```
    ///
    /// After status `101`, the stream is no longer treated as normal HTTP. It is
    /// expected to switch into the custom Shroud tunnel framing protocol.
    ///
    /// # Frame behavior
    ///
    /// After the HTTP upgrade succeeds, the function sends a `TcpConnect` frame:
    ///
    /// ```text
    /// FrameType::TcpConnect
    /// stream_id = STREAM_ID
    /// flags     = 0
    /// payload   = encoded target_host + target_port
    /// ```
    ///
    /// Then it reads a reply frame and validates:
    ///
    /// - the reply belongs to the same `STREAM_ID`;
    /// - the frame type is `FrameType::TcpConnect`;
    /// - the reply has `CONNECT_OK_FLAG` set.
    ///
    /// If the server returns `FrameType::ErrorFrame`, the payload is interpreted as
    /// a UTF-8-lossy error message and returned as part of the error.
    ///
    /// # Notes
    ///
    /// This function does not itself proxy application data. It only establishes
    /// the tunnel and asks the server to open the remote TCP connection. After it
    /// returns successfully, the caller is responsible for forwarding data between
    /// the local client connection and the returned `TunnelStream`.
    async fn open_tunnel(&self, target_host: &str, target_port: u16) -> Result<TunnelStream> {
        //connect to tunnel endpoint
        let stream = TcpStream::connect((self.outbound.server.as_str(), self.outbound.port))
            .await
            .with_context(|| {
                format!(
                    "failed to connect to tunnel endpoint {}:{}",
                    self.outbound.server, self.outbound.port
                )
            })?;

        //if tls is enabled, wrap the stream in tls
        let mut stream: TunnelStream = if self.outbound.tls {
            let connector = TlsConnector::from(Arc::new(build_tls_client_config(&self.outbound)?));
            let server_name = self
                .outbound
                .tls_server_name
                .as_deref()
                .unwrap_or(&self.outbound.server)
                .to_owned();
            let server_name = ServerName::try_from(server_name)
                .map_err(|err| anyhow!("invalid tls server name: {err}"))?;
            let tls_stream = connector
                .connect(server_name, stream)
                .await
                .with_context(|| {
                    format!(
                        "failed to establish tls connection to {}:{}",
                        self.outbound.server, self.outbound.port
                    )
                })?;
            Box::new(tls_stream)
        } else {
            Box::new(stream)
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before unix epoch")?
            .as_secs() as i64;

        let nonce = uuid::Uuid::new_v4().as_bytes().to_vec();
        //hmac-sha256(client_secret, nonce, timestamp, client_id)
        let auth_tag = compute_auth_tag(
            self.auth.client_secret.as_bytes(),
            &nonce,
            timestamp,
            &self.auth.client_id,
        )
        .context("failed to compute auth tag")?;

        //http upgrade request
        //example:
        //POST /tunnel HTTP/1.1
        // Host: example.com:443
        // Connection: Upgrade
        // Upgrade: shroud-tunnel
        // X-Shroud-Client-Id: client-1
        // X-Shroud-Timestamp: 1716040000
        // X-Shroud-Nonce: 1LqY2MZtQ7m1...
        // X-Shroud-Auth: calculated-auth-tag
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
        stream.write_all(request.as_bytes()).await?;

        //upgrade response
        let response = read_http_headers(&mut stream).await?;
        let status = parse_status_code(&response).context("failed to parse tunnel response")?;

        if status != 101 {
            bail!("tunnel endpoint rejected upgrade with HTTP status {status}");
        }

        debug!(
            server = %self.outbound.server,
            tunnel_path = %self.outbound.path,
            client_id = %self.auth.client_id,
            target_host,
            target_port,
            "tunnel upgrade accepted"
        );

        //send tcp connect frame
        let payload = encode_tcp_connect_payload(target_host, target_port)
            .map_err(|err| anyhow!("failed to encode tcp connect payload: {err}"))?;
        write_frame(&mut stream, FrameType::TcpConnect, STREAM_ID, 0, payload).await?;

        //read connect reply frame
        let connect_reply = read_frame(&mut stream).await?;
        if connect_reply.stream_id != STREAM_ID {
            bail!(
                "unexpected stream id in connect reply: {}",
                connect_reply.stream_id
            );
        }

        match connect_reply.frame_type {
            FrameType::TcpConnect if (connect_reply.flags & CONNECT_OK_FLAG) != 0 => Ok(stream),
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
    let mut raw = Vec::with_capacity(HEADER_LEN + payload_len);
    raw.extend_from_slice(&header);

    if payload_len > 0 {
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;
        raw.extend_from_slice(&payload);
    }

    Frame::decode(Bytes::from(raw)).map_err(|err| anyhow!("failed to decode frame: {err}"))
}
