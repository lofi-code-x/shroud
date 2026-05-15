use crate::auth::validate_auth;
use crate::relay::relay_tunnel;
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use shroud_core::config::ServerConfig;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};

const MAX_HTTP_HEADERS: usize = 16 * 1024;
const ALLOWED_TIMESTAMP_SKEW_SECS: i64 = 120;

pub async fn serve(cfg: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    info!(listen = %cfg.listen, "server listener started");

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg = cfg.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, peer, cfg).await {
                debug!(%peer, error = %err, "failed to handle incoming connection");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: std::net::SocketAddr,
    cfg: ServerConfig,
) -> Result<()> {
    let request_raw = read_http_headers(&mut stream).await?;
    let request_text =
        std::str::from_utf8(&request_raw).context("request headers are not utf-8")?;
    let parsed = parse_http_request(request_text)?;

    if parsed.method != "POST" || parsed.path != cfg.tunnel_path {
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }

    let client_id = required_header(&parsed.headers, "x-shroud-client-id")?;
    let timestamp_raw = required_header(&parsed.headers, "x-shroud-timestamp")?;
    let nonce_raw = required_header(&parsed.headers, "x-shroud-nonce")?;
    let auth_tag = required_header(&parsed.headers, "x-shroud-auth")?;

    let timestamp = timestamp_raw
        .parse::<i64>()
        .context("invalid x-shroud-timestamp header value")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs() as i64;
    if (now - timestamp).abs() > ALLOWED_TIMESTAMP_SKEW_SECS {
        stream
            .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
            .await?;
        bail!("timestamp outside allowed skew window");
    }

    let nonce = STANDARD_NO_PAD
        .decode(nonce_raw)
        .context("invalid base64 nonce in x-shroud-nonce")?;

    if !validate_auth(&cfg.clients, client_id, &nonce, timestamp, auth_tag) {
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await?;
        bail!("auth validation failed for client_id={client_id}");
    }

    stream
        .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: shroud-tunnel\r\n\r\n",
        )
        .await?;
    relay_tunnel(stream, peer).await?;
    Ok(())
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

    bail!("request headers too large")
}

struct ParsedHttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
}

fn parse_http_request(raw_request: &str) -> Result<ParsedHttpRequest> {
    let mut lines = raw_request.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("missing request line"))?;
    let mut request_line_parts = request_line.split_whitespace();
    let method = request_line_parts
        .next()
        .ok_or_else(|| anyhow!("missing method in request line"))?
        .to_string();
    let path = request_line_parts
        .next()
        .ok_or_else(|| anyhow!("missing path in request line"))?
        .to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }

        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid header line: {line}"))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    Ok(ParsedHttpRequest {
        method,
        path,
        headers,
    })
}

fn required_header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Result<&'a str> {
    headers
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("missing required header {name}"))
}
