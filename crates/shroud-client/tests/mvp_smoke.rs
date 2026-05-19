use shroud_client::routing::Router;
use shroud_client::socks5;
use shroud_client::tunnel::TunnelClient;
use shroud_core::config::{
    AuthorizedClient, ClientAuthConfig, OutboundConfig, RouteAction, RoutingConfig, RoutingRule,
    ServerConfig, ServerTlsConfig,
};
use shroud_server::web;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep, timeout};

const CLIENT_ID: &str = "11111111-1111-1111-1111-111111111111";
const CLIENT_SECRET: &str = "integration-test-secret";
const CA_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/certs/ca.crt");
const SERVER_CERT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/certs/localhost.crt"
);
const SERVER_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/certs/localhost.key"
);

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct RunningTask {
    addr: SocketAddr,
    handle: JoinHandle<()>,
}

impl Drop for RunningTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[tokio::test]
async fn socks_tls_tunnel_relays_to_target() -> TestResult {
    let target = start_http_target("shroud proxy smoke ok").await?;
    let server = start_tunnel_server().await?;
    let client = start_socks_client(
        server.addr,
        RoutingConfig {
            default: RouteAction::Proxy,
            rules: vec![],
        },
        "/api/tunnel",
        CLIENT_SECRET,
    )
    .await?;

    let mut stream = socks_connect(client.addr, "127.0.0.1", target.addr.port()).await?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
        .await?;

    let response = read_to_end(&mut stream).await?;
    assert!(
        response.contains("shroud proxy smoke ok"),
        "unexpected HTTP response through tunnel: {response:?}"
    );

    Ok(())
}

#[tokio::test]
async fn tunnel_rejects_bad_auth() -> TestResult {
    let server = start_tunnel_server().await?;
    let tunnel = TunnelClient::new(
        outbound_config(server.addr, "/api/tunnel"),
        auth_config("wrong-secret"),
    );

    let err = match tunnel.connect_target_via_tunnel("127.0.0.1", 1).await {
        Ok(_) => panic!("tunnel unexpectedly accepted invalid auth"),
        Err(err) => err,
    };

    assert!(
        err.to_string().contains("HTTP status 403"),
        "unexpected bad-auth error: {err:#}"
    );
    Ok(())
}

#[tokio::test]
async fn tunnel_rejects_bad_path() -> TestResult {
    let server = start_tunnel_server().await?;
    let tunnel = TunnelClient::new(
        outbound_config(server.addr, "/wrong-path"),
        auth_config(CLIENT_SECRET),
    );

    let err = match tunnel.connect_target_via_tunnel("127.0.0.1", 1).await {
        Ok(_) => panic!("tunnel unexpectedly accepted invalid path"),
        Err(err) => err,
    };

    assert!(
        err.to_string().contains("HTTP status 404"),
        "unexpected bad-path error: {err:#}"
    );
    Ok(())
}

#[tokio::test]
async fn direct_route_bypasses_tunnel_and_relays_to_target() -> TestResult {
    let target = start_http_target("shroud direct route ok").await?;
    let client = start_socks_client(
        free_addr().await?,
        RoutingConfig {
            default: RouteAction::Direct,
            rules: vec![],
        },
        "/api/tunnel",
        CLIENT_SECRET,
    )
    .await?;

    let mut stream = socks_connect(client.addr, "127.0.0.1", target.addr.port()).await?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
        .await?;

    let response = read_to_end(&mut stream).await?;
    assert!(
        response.contains("shroud direct route ok"),
        "unexpected HTTP response through direct route: {response:?}"
    );

    Ok(())
}

#[tokio::test]
async fn block_route_rejects_socks_connect() -> TestResult {
    let client = start_socks_client(
        free_addr().await?,
        RoutingConfig {
            default: RouteAction::Proxy,
            rules: vec![RoutingRule {
                action: RouteAction::Block,
                domain_suffix: None,
                cidr: None,
                port: Some(80),
            }],
        },
        "/api/tunnel",
        CLIENT_SECRET,
    )
    .await?;

    let reply = socks_connect_reply_code(client.addr, "example.com", 80).await?;
    assert_eq!(reply, 0x02, "expected SOCKS connection-not-allowed reply");
    Ok(())
}

async fn start_tunnel_server() -> TestResult<RunningTask> {
    let addr = free_addr().await?;
    let cfg = ServerConfig {
        listen: addr,
        tunnel_path: "/api/tunnel".to_string(),
        web_root: "./web".to_string(),
        tls: ServerTlsConfig {
            enabled: true,
            cert_path: Some(SERVER_CERT.to_string()),
            key_path: Some(SERVER_KEY.to_string()),
        },
        clients: vec![AuthorizedClient {
            client_id: CLIENT_ID.to_string(),
            client_secret: CLIENT_SECRET.to_string(),
        }],
    };

    let handle = tokio::spawn(async move {
        let _ = web::serve(cfg).await;
    });
    wait_for_tcp(addr).await?;
    Ok(RunningTask { addr, handle })
}

async fn start_socks_client(
    tunnel_addr: SocketAddr,
    routing: RoutingConfig,
    tunnel_path: &str,
    client_secret: &str,
) -> TestResult<RunningTask> {
    let listen = free_addr().await?;
    let router = Router::new(routing);
    let tunnel = TunnelClient::new(
        outbound_config(tunnel_addr, tunnel_path),
        auth_config(client_secret),
    );

    let handle = tokio::spawn(async move {
        let _ = socks5::serve(listen, router, tunnel).await;
    });
    wait_for_tcp(listen).await?;
    Ok(RunningTask {
        addr: listen,
        handle,
    })
}

async fn start_http_target(body: &'static str) -> TestResult<RunningTask> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };

            tokio::spawn(async move {
                let _ = read_http_headers(&mut stream).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    Ok(RunningTask { addr, handle })
}

fn outbound_config(server_addr: SocketAddr, path: &str) -> OutboundConfig {
    OutboundConfig {
        server: "127.0.0.1".to_string(),
        port: server_addr.port(),
        path: path.to_string(),
        tls: true,
        tls_server_name: Some("localhost".to_string()),
        tls_ca_cert_path: Some(CA_CERT.to_string()),
    }
}

fn auth_config(client_secret: &str) -> ClientAuthConfig {
    ClientAuthConfig {
        client_id: CLIENT_ID.to_string(),
        client_secret: client_secret.to_string(),
    }
}

async fn socks_connect(proxy_addr: SocketAddr, host: &str, port: u16) -> TestResult<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut handshake = [0u8; 2];
    stream.read_exact(&mut handshake).await?;
    assert_eq!(handshake, [0x05, 0x00], "SOCKS handshake failed");

    stream
        .write_all(&build_socks_connect_request(host, port)?)
        .await?;

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x00, "SOCKS CONNECT failed: reply={reply:02x?}");
    Ok(stream)
}

async fn socks_connect_reply_code(proxy_addr: SocketAddr, host: &str, port: u16) -> TestResult<u8> {
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut handshake = [0u8; 2];
    stream.read_exact(&mut handshake).await?;
    assert_eq!(handshake, [0x05, 0x00], "SOCKS handshake failed");

    stream
        .write_all(&build_socks_connect_request(host, port)?)
        .await?;

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    Ok(reply[1])
}

fn build_socks_connect_request(host: &str, port: u16) -> TestResult<Vec<u8>> {
    let mut request = vec![0x05, 0x01, 0x00];
    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        request.push(0x01);
        request.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = host.parse::<std::net::Ipv6Addr>() {
        request.push(0x04);
        request.extend_from_slice(&ipv6.octets());
    } else {
        let host_bytes = host.as_bytes();
        if host_bytes.len() > u8::MAX as usize {
            return Err("SOCKS domain is too long".into());
        }
        request.push(0x03);
        request.push(host_bytes.len() as u8);
        request.extend_from_slice(host_bytes);
    }
    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}

async fn read_http_headers(stream: &mut TcpStream) -> TestResult<Vec<u8>> {
    let mut data = Vec::new();
    let mut byte = [0u8; 1];

    while data.len() < 16 * 1024 {
        stream.read_exact(&mut byte).await?;
        data.push(byte[0]);
        if data.ends_with(b"\r\n\r\n") {
            return Ok(data);
        }
    }

    Err("HTTP headers exceeded test limit".into())
}

async fn read_to_end(stream: &mut TcpStream) -> TestResult<String> {
    let mut data = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut data)).await??;
    Ok(String::from_utf8_lossy(&data).into_owned())
}

async fn free_addr() -> TestResult<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}

async fn wait_for_tcp(addr: SocketAddr) -> TestResult {
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(10)).await;
    }

    Err(format!("listener did not become ready at {addr}").into())
}
