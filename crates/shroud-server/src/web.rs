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
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig as RustlsServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, info};

const MAX_HTTP_HEADERS: usize = 16 * 1024;
const ALLOWED_TIMESTAMP_SKEW_SECS: i64 = 120;
const NONCE_LEN: usize = 16;
const NONCE_HEADER_LEN: usize = 22;
const NONCE_CACHE_TTL_SECS: u64 = (ALLOWED_TIMESTAMP_SKEW_SECS as u64) * 2;
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn serve(cfg: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let tls_acceptor = build_tls_acceptor(&cfg.tls)?;
    let nonce_cache = Arc::new(NonceCache::new(Duration::from_secs(NONCE_CACHE_TTL_SECS)));
    let mut active = JoinSet::new();
    info!(
        listen = %cfg.listen,
        tls = cfg.tls.enabled,
        "server listener started"
    );

    loop {
        tokio::select! {
            shutdown = tokio::signal::ctrl_c() => {
                shutdown.context("failed to listen for Ctrl+C")?;
                info!(listen = %cfg.listen, active_sessions = active.len(), "server listener shutting down");
                break;
            }
            accept_result = listener.accept() => {
                let (stream, peer) = accept_result?;
                let cfg = cfg.clone();
                let tls_acceptor = tls_acceptor.clone();
                let nonce_cache = nonce_cache.clone();

                active.spawn(async move {
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
            result = active.join_next(), if !active.is_empty() => {
                if let Some(Err(err)) = result {
                    debug!(error = %err, "server connection task join failed");
                }
            }
        }
    }

    active.abort_all();
    let _ = timeout(SHUTDOWN_DRAIN_TIMEOUT, async {
        while let Some(result) = active.join_next().await {
            if let Err(err) = result {
                debug!(error = %err, "server connection task stopped during shutdown");
            }
        }
    })
    .await;

    Ok(())
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

    if parsed.method == "GET" && parsed.path == "/api/status" {
        return serve_health_status(&mut stream).await;
    }

    if parsed.method == "POST" && parsed.path == cfg.tunnel_path {
        return handle_tunnel_request(stream, peer, cfg, nonce_cache, parsed).await;
    }

    if parsed.method == "GET" || parsed.method == "HEAD" {
        return serve_static_file(
            &mut stream,
            &cfg.web_root,
            &parsed.path,
            parsed.method == "HEAD",
        )
        .await;
    }

    write_error_response(&mut stream, 404, false).await?;
    Ok(())
}

async fn serve_health_status<S>(stream: &mut S) -> Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    write_response(
        stream,
        200,
        "application/json; charset=utf-8",
        b"{\"status\":\"ok\"}\n",
        false,
    )
    .await
}

async fn handle_tunnel_request<S>(
    mut stream: S,
    peer: std::net::SocketAddr,
    cfg: ServerConfig,
    nonce_cache: Arc<NonceCache>,
    parsed: ParsedHttpRequest,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some(client_id) = optional_header(&parsed.headers, "x-shroud-client-id") else {
        write_error_response(&mut stream, 403, false).await?;
        bail!("missing required header x-shroud-client-id");
    };
    let Some(timestamp_raw) = optional_header(&parsed.headers, "x-shroud-timestamp") else {
        write_error_response(&mut stream, 403, false).await?;
        bail!("missing required header x-shroud-timestamp");
    };
    let Some(nonce_raw) = optional_header(&parsed.headers, "x-shroud-nonce") else {
        write_error_response(&mut stream, 403, false).await?;
        bail!("missing required header x-shroud-nonce");
    };
    let Some(auth_tag) = optional_header(&parsed.headers, "x-shroud-auth") else {
        write_error_response(&mut stream, 403, false).await?;
        bail!("missing required header x-shroud-auth");
    };

    let timestamp = match timestamp_raw.parse::<i64>() {
        Ok(timestamp) => timestamp,
        Err(err) => {
            write_error_response(&mut stream, 403, false).await?;
            return Err(err).context("invalid x-shroud-timestamp header value");
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs() as i64;
    if (now - timestamp).abs() > ALLOWED_TIMESTAMP_SKEW_SECS {
        write_error_response(&mut stream, 403, false).await?;
        bail!("timestamp outside allowed skew window");
    }

    let nonce = match decode_nonce(nonce_raw) {
        Ok(nonce) => nonce,
        Err(err) => {
            write_error_response(&mut stream, 403, false).await?;
            return Err(err);
        }
    };

    if !validate_auth(&cfg.clients, client_id, &nonce, timestamp, auth_tag) {
        write_error_response(&mut stream, 403, false).await?;
        bail!("auth validation failed for client_id={client_id}");
    }

    if !nonce_cache.insert_unique(client_id, &nonce).await {
        write_error_response(&mut stream, 403, false).await?;
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

async fn serve_static_file<S>(
    stream: &mut S,
    web_root: &str,
    request_path: &str,
    head_only: bool,
) -> Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    let Some(candidate) = resolve_web_path(web_root, request_path) else {
        write_error_response(stream, 404, head_only).await?;
        return Ok(());
    };

    let root = match fs::canonicalize(web_root).await {
        Ok(root) => root,
        Err(_) => {
            write_error_response(stream, 404, head_only).await?;
            return Ok(());
        }
    };

    let candidate = match fs::metadata(&candidate).await {
        Ok(metadata) if metadata.is_dir() => candidate.join("index.html"),
        Ok(_) => candidate,
        Err(_) => {
            write_error_response(stream, 404, head_only).await?;
            return Ok(());
        }
    };

    let file_path = match fs::canonicalize(&candidate).await {
        Ok(path) if path.starts_with(&root) => path,
        _ => {
            write_error_response(stream, 404, head_only).await?;
            return Ok(());
        }
    };

    let metadata = match fs::metadata(&file_path).await {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => {
            write_error_response(stream, 404, head_only).await?;
            return Ok(());
        }
    };

    let content_type = content_type_for_path(&file_path);
    if head_only {
        write_response_headers(stream, 200, content_type, metadata.len() as usize).await?;
        return Ok(());
    }

    let body = match fs::read(&file_path).await {
        Ok(body) => body,
        Err(_) => {
            write_error_response(stream, 404, false).await?;
            return Ok(());
        }
    };

    write_response(stream, 200, content_type, &body, false).await?;
    Ok(())
}

fn resolve_web_path(web_root: &str, request_path: &str) -> Option<PathBuf> {
    let relative = sanitize_request_path(request_path)?;
    let mut path = PathBuf::from(web_root);

    if relative.as_os_str().is_empty() {
        path.push("index.html");
    } else {
        path.push(relative);
    }

    Some(path)
}

fn sanitize_request_path(request_path: &str) -> Option<PathBuf> {
    if !request_path.starts_with('/') {
        return None;
    }

    let decoded = percent_decode_path(request_path)?;
    if decoded.as_bytes().contains(&0) {
        return None;
    }

    let relative = decoded.trim_start_matches('/');
    let mut out = PathBuf::new();

    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str()?;
                if part.contains('\\') {
                    return None;
                }
                out.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }

    Some(out)
}

fn percent_decode_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let high = hex_value(bytes[i + 1])?;
            let low = hex_value(bytes[i + 2])?;
            out.push((high << 4) | low);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8(out).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn content_type_for_path(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

async fn write_error_response<S>(stream: &mut S, status_code: u16, head_only: bool) -> Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    let body = match status_code {
        403 => b"<!doctype html><html><body><h1>Forbidden</h1></body></html>".as_slice(),
        404 => b"<!doctype html><html><body><h1>Not Found</h1></body></html>".as_slice(),
        _ => b"<!doctype html><html><body><h1>Error</h1></body></html>".as_slice(),
    };
    write_response(
        stream,
        status_code,
        "text/html; charset=utf-8",
        body,
        head_only,
    )
    .await
}

async fn write_response<S>(
    stream: &mut S,
    status_code: u16,
    content_type: &str,
    body: &[u8],
    head_only: bool,
) -> Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    write_response_headers(stream, status_code, content_type, body.len()).await?;
    if !head_only {
        stream.write_all(body).await?;
    }
    Ok(())
}

async fn write_response_headers<S>(
    stream: &mut S,
    status_code: u16,
    content_type: &str,
    content_len: usize,
) -> Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    let response = format!(
        "HTTP/1.1 {status_code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {content_len}\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        reason = reason_phrase(status_code),
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

fn reason_phrase(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    }
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
        .split('?')
        .next()
        .ok_or_else(|| anyhow!("missing path before query in request line"))?
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

fn optional_header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get(name).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::config::AuthorizedClient;
    use std::fs as std_fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    static TEMP_WEB_ROOT_ID: AtomicU64 = AtomicU64::new(0);

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

    #[tokio::test]
    async fn fallback_serves_index_for_root() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let response = run_request(
            &web_root,
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("Content-Type: text/html; charset=utf-8"));
        assert!(response.ends_with("fallback index"));
    }

    #[tokio::test]
    async fn fallback_serves_static_asset_with_content_type() {
        let web_root = TempWebRoot::new();
        web_root.write("assets/app.js", b"console.log('ok');");

        let response = run_request(
            &web_root,
            "GET /assets/app.js HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("Content-Type: application/javascript; charset=utf-8"));
        assert!(response.ends_with("console.log('ok');"));
    }

    #[tokio::test]
    async fn fallback_strips_query_before_file_lookup() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let response = run_request(
            &web_root,
            "GET /?v=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("fallback index"));
    }

    #[tokio::test]
    async fn health_status_returns_minimal_neutral_json() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let response = run_request(
            &web_root,
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("Content-Type: application/json; charset=utf-8"));
        assert!(response.ends_with("{\"status\":\"ok\"}\n"));
        assert!(!response.to_ascii_lowercase().contains("proxy"));
        assert!(!response.to_ascii_lowercase().contains("tunnel"));
        assert!(!response.to_ascii_lowercase().contains("auth"));
    }

    #[tokio::test]
    async fn fallback_head_returns_headers_without_body() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let response = run_request(
            &web_root,
            "HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("Content-Length: 14"));
        assert!(response.ends_with("\r\n\r\n"));
        assert!(!response.contains("fallback index"));
    }

    #[tokio::test]
    async fn fallback_missing_path_returns_neutral_404() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let response = run_request(
            &web_root,
            "GET /missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        assert!(response.contains("<h1>Not Found</h1>"));
        assert!(!response.to_ascii_lowercase().contains("proxy"));
        assert!(!response.to_ascii_lowercase().contains("shroud"));
    }

    #[tokio::test]
    async fn fallback_rejects_path_traversal() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");
        let outside = web_root.path.parent().expect("parent").join("secret.txt");
        std_fs::write(&outside, b"secret outside web root").expect("write secret");

        let response = run_request(
            &web_root,
            "GET /../secret.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        let _ = std_fs::remove_file(outside);
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        assert!(!response.contains("secret outside web root"));
    }

    #[tokio::test]
    async fn fallback_rejects_encoded_path_traversal() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let response = run_request(
            &web_root,
            "GET /%2e%2e/Cargo.toml HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        assert!(!response.contains("[workspace]"));
    }

    #[tokio::test]
    async fn tunnel_missing_auth_returns_neutral_403() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let response = run_request(
            &web_root,
            "POST /api/tunnel HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.contains("<h1>Forbidden</h1>"));
        assert!(!response.to_ascii_lowercase().contains("proxy"));
        assert!(!response.to_ascii_lowercase().contains("shroud"));
    }

    struct TempWebRoot {
        path: std::path::PathBuf,
    }

    impl TempWebRoot {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos();
            let id = TEMP_WEB_ROOT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "shroud-web-test-{}-{unique}-{id}",
                std::process::id()
            ));
            std_fs::create_dir_all(&path).expect("create temp web root");
            Self { path }
        }

        fn write(&self, relative: &str, body: &[u8]) {
            let path = self.path.join(relative);
            if let Some(parent) = path.parent() {
                std_fs::create_dir_all(parent).expect("create parent dir");
            }
            std_fs::write(path, body).expect("write fixture");
        }
    }

    impl Drop for TempWebRoot {
        fn drop(&mut self) {
            let _ = std_fs::remove_dir_all(&self.path);
        }
    }

    async fn run_request(web_root: &TempWebRoot, request: &str) -> String {
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let cfg = ServerConfig {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            tunnel_path: "/api/tunnel".to_string(),
            web_root: web_root.path.to_string_lossy().into_owned(),
            tls: ServerTlsConfig::default(),
            clients: vec![AuthorizedClient {
                client_id: "11111111-1111-1111-1111-111111111111".to_string(),
                client_secret: "test-secret".to_string(),
            }],
        };
        let nonce_cache = Arc::new(NonceCache::new(Duration::from_secs(60)));

        let handle = tokio::spawn(async move {
            handle_connection(
                server,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
                cfg,
                nonce_cache,
            )
            .await
        });

        client
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        client.shutdown().await.expect("shutdown request");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read response");

        let _ = handle.await.expect("join handler");
        String::from_utf8_lossy(&response).into_owned()
    }
}
