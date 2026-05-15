use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use bytes::Bytes;
use shroud_core::auth::compute_auth_tag;
use shroud_core::config::{ClientAuthConfig, OutboundConfig};
use shroud_core::protocol::{Frame, FrameType, HEADER_LEN, encode_tcp_connect_payload};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

const MAX_HTTP_HEADERS: usize = 16 * 1024;
const STREAM_ID: u64 = 1;
const CONNECT_OK_FLAG: u16 = 0x0001;

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
    ) -> Result<TcpStream> {
        self.open_tunnel(target_host, target_port).await
    }

    pub async fn relay_over_tunnel_stream(
        &self,
        client_socket: &mut TcpStream,
        upstream: &mut TcpStream,
    ) -> Result<RelayStats> {
        let (mut client_read, mut client_write) = client_socket.split();
        let (mut upstream_read, mut upstream_write) = upstream.split();

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

    async fn open_tunnel(&self, target_host: &str, target_port: u16) -> Result<TcpStream> {
        if self.outbound.tls {
            warn!(
                server = %self.outbound.server,
                port = self.outbound.port,
                "tls outbound requested, but tls transport is not implemented yet; using plain tcp"
            );
        }

        let mut stream = TcpStream::connect((self.outbound.server.as_str(), self.outbound.port))
            .await
            .with_context(|| {
                format!(
                    "failed to connect to tunnel endpoint {}:{}",
                    self.outbound.server, self.outbound.port
                )
            })?;

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
        stream.write_all(request.as_bytes()).await?;

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

        let payload = encode_tcp_connect_payload(target_host, target_port)
            .map_err(|err| anyhow!("failed to encode tcp connect payload: {err}"))?;
        write_frame(&mut stream, FrameType::TcpConnect, STREAM_ID, 0, payload).await?;

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

async fn read_http_headers(stream: &mut TcpStream) -> Result<Vec<u8>> {
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
    W: AsyncWrite + Unpin,
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
    R: AsyncRead + Unpin,
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
