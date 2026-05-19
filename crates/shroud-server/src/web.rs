use crate::auth::validate_auth;
use crate::relay::relay_tunnel;
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use shroud_core::config::{ServerConfig, ServerTlsConfig};
use std::collections::HashMap;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::BufReader;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig as RustlsServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, info};

const MAX_HTTP_HEADERS: usize = 16 * 1024;
const ALLOWED_TIMESTAMP_SKEW_SECS: i64 = 120;
const NONCE_LEN: usize = 16;
const NONCE_HEADER_LEN: usize = 22;
const NONCE_CACHE_TTL_SECS: u64 = (ALLOWED_TIMESTAMP_SKEW_SECS as u64) * 2;

pub async fn serve(cfg: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let tls_acceptor = build_tls_acceptor(&cfg.tls)?;
    let nonce_cache = Arc::new(NonceCache::new(Duration::from_secs(NONCE_CACHE_TTL_SECS)));
    info!(
        listen = %cfg.listen,
        tls = cfg.tls.enabled,
        "server listener started"
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg = cfg.clone();
        let tls_acceptor = tls_acceptor.clone();
        let nonce_cache = nonce_cache.clone();

        tokio::spawn(async move {
            let result = if let Some(acceptor) = tls_acceptor {
                match acceptor.accept(stream).await {
                    Ok(stream) => handle_connection(stream, peer, cfg, nonce_cache).await,
                    Err(err) => Err(anyhow!(err)).context("tls handshake failed"),
                }
            } else {
                handle_connection(stream, peer, cfg, nonce_cache).await
            };

            if let Err(err) = result {
                debug!(%peer, error = %err, "failed to handle incoming connection");
            }
        });
    }
}

async fn handle_connection<S>(
    mut stream: S,
    peer: std::net::SocketAddr,
    cfg: ServerConfig,
    nonce_cache: Arc<NonceCache>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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

    let nonce = decode_nonce(nonce_raw)?;

    if !validate_auth(&cfg.clients, client_id, &nonce, timestamp, auth_tag) {
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await?;
        bail!("auth validation failed for client_id={client_id}");
    }

    if !nonce_cache.insert_unique(client_id, &nonce).await {
        stream
            .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
            .await?;
        bail!("replayed nonce for client_id={client_id}");
    }

    stream
        .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: shroud-tunnel\r\n\r\n",
        )
        .await?;
    relay_tunnel(stream, peer).await?;
    Ok(())
}

fn decode_nonce(nonce_raw: &str) -> Result<Vec<u8>> {
    if nonce_raw.len() != NONCE_HEADER_LEN {
        bail!("invalid x-shroud-nonce length");
    }

    if !nonce_raw
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
    {
        bail!("invalid x-shroud-nonce format");
    }

    let nonce = STANDARD_NO_PAD
        .decode(nonce_raw)
        .context("invalid base64 nonce in x-shroud-nonce")?;
    if nonce.len() != NONCE_LEN {
        bail!("invalid x-shroud-nonce decoded length");
    }

    Ok(nonce)
}

#[derive(Clone, Eq)]
struct NonceKey {
    client_id: String,
    nonce: Vec<u8>,
}

impl PartialEq for NonceKey {
    fn eq(&self, other: &Self) -> bool {
        self.client_id == other.client_id && self.nonce == other.nonce
    }
}

impl Hash for NonceKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.client_id.hash(state);
        self.nonce.hash(state);
    }
}

struct NonceCache {
    ttl: Duration,
    entries: Mutex<HashMap<NonceKey, Instant>>,
}

impl NonceCache {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    async fn insert_unique(&self, client_id: &str, nonce: &[u8]) -> bool {
        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        entries.retain(|_key, expires_at| *expires_at > now);

        let key = NonceKey {
            client_id: client_id.to_string(),
            nonce: nonce.to_vec(),
        };
        if entries.contains_key(&key) {
            return false;
        }

        entries.insert(key, now + self.ttl);
        true
    }
}

fn build_tls_acceptor(tls: &ServerTlsConfig) -> Result<Option<TlsAcceptor>> {
    if !tls.enabled {
        return Ok(None);
    }

    let cert_path = tls
        .cert_path
        .as_deref()
        .ok_or_else(|| anyhow!("server tls.enabled=true requires tls.cert_path"))?;
    let key_path = tls
        .key_path
        .as_deref()
        .ok_or_else(|| anyhow!("server tls.enabled=true requires tls.key_path"))?;

    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build tls server config")?;

    Ok(Some(TlsAcceptor::from(Arc::new(config))))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("failed to open certificate file {path}"))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read certificates from {path}"))?;
    if certs.is_empty() {
        bail!("certificate file {path} does not contain certificates");
    }
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file =
        File::open(path).with_context(|| format!("failed to open private key file {path}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("failed to read private key from {path}"))?
        .ok_or_else(|| anyhow!("private key file {path} does not contain a supported key"))
}

async fn read_http_headers<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_nonce_accepts_16_byte_standard_base64_without_padding() {
        let nonce = [7u8; NONCE_LEN];
        let encoded = STANDARD_NO_PAD.encode(nonce);

        assert_eq!(decode_nonce(&encoded).expect("decode nonce"), nonce);
    }

    #[test]
    fn decode_nonce_rejects_padding() {
        let nonce = [7u8; NONCE_LEN];
        let encoded = base64::engine::general_purpose::STANDARD.encode(nonce);

        assert!(decode_nonce(&encoded).is_err());
    }

    #[test]
    fn decode_nonce_rejects_wrong_decoded_length() {
        let nonce = [7u8; NONCE_LEN - 1];
        let encoded = STANDARD_NO_PAD.encode(nonce);

        assert!(decode_nonce(&encoded).is_err());
    }

    #[test]
    fn decode_nonce_rejects_non_base64_header_chars() {
        assert!(decode_nonce("!!!!!!!!!!!!!!invalid").is_err());
    }

    #[tokio::test]
    async fn nonce_cache_rejects_reuse_for_same_client() {
        let cache = NonceCache::new(Duration::from_secs(60));

        assert!(cache.insert_unique("client-a", &[1u8; NONCE_LEN]).await);
        assert!(!cache.insert_unique("client-a", &[1u8; NONCE_LEN]).await);
    }

    #[tokio::test]
    async fn nonce_cache_allows_same_nonce_for_different_clients() {
        let cache = NonceCache::new(Duration::from_secs(60));

        assert!(cache.insert_unique("client-a", &[1u8; NONCE_LEN]).await);
        assert!(cache.insert_unique("client-b", &[1u8; NONCE_LEN]).await);
    }

    #[tokio::test]
    async fn nonce_cache_expires_entries() {
        let cache = NonceCache::new(Duration::from_millis(1));

        assert!(cache.insert_unique("client-a", &[1u8; NONCE_LEN]).await);
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(cache.insert_unique("client-a", &[1u8; NONCE_LEN]).await);
    }
}
