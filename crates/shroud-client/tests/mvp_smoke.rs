use bytes::{BufMut, Bytes, BytesMut};
use shroud_client::routing::Router;
use shroud_client::session::SessionCore;
use shroud_client::socks5;
use shroud_client::tunnel::TunnelClient;
use shroud_core::config::{
    AuthorizedClient, ClientAuthConfig, ClientDnsConfig, OutboundConfig, RouteAction,
    RoutingConfig, RoutingRule, ServerConfig, ServerTlsConfig,
};
use shroud_core::protocol::{
    Frame, FrameType, HEADER_LEN, MAX_FRAME_PAYLOAD_LEN, PROTOCOL_VERSION,
};
use shroud_server::web;
use std::future::Future;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
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
async fn curl_socks5_hostname_smoke_relays_to_target() -> TestResult {
    let target = start_http_target("shroud curl socks5h smoke ok").await?;
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

    let output = Command::new("curl")
        .arg("-fsS")
        .arg("--max-time")
        .arg("5")
        .arg("--noproxy")
        .arg("")
        .arg("--socks5-hostname")
        .arg(format!("127.0.0.1:{}", client.addr.port()))
        .arg(format!("http://localhost:{}/", target.addr.port()))
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .await?;

    assert!(
        output.status.success(),
        "curl --socks5-hostname failed: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let body = String::from_utf8_lossy(&output.stdout);
    assert!(
        body.contains("shroud curl socks5h smoke ok"),
        "unexpected curl response through SOCKS tunnel: {body:?}"
    );

    Ok(())
}

#[tokio::test]
async fn socks_tls_tunnel_relays_large_payload() -> TestResult {
    let payload = patterned_payload(256 * 1024);
    let target = start_exact_echo_target(payload.len()).await?;
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
    stream.write_all(&payload).await?;
    stream.shutdown().await?;

    let response = read_bytes_to_end(&mut stream).await?;
    assert_eq!(
        response, payload,
        "large payload changed during tunnel relay"
    );
    Ok(())
}

#[tokio::test]
async fn socks_tls_tunnel_preserves_half_close_response() -> TestResult {
    let target = start_respond_after_eof_target(b"response after client half-close").await?;
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
    stream.write_all(b"request body before half-close").await?;
    stream.shutdown().await?;

    let response = read_bytes_to_end(&mut stream).await?;
    assert_eq!(response, b"response after client half-close");
    Ok(())
}

#[tokio::test]
async fn target_connect_failure_becomes_socks_general_failure() -> TestResult {
    let unused_target = free_addr().await?;
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

    let reply = socks_connect_reply_code(client.addr, "127.0.0.1", unused_target.port()).await?;
    assert_eq!(reply, 0x01, "expected SOCKS general failure reply");
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
async fn socks_handshake_stall_does_not_complete() -> TestResult {
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

    let mut stream = TcpStream::connect(client.addr).await?;
    let mut response = [0u8; 2];
    let result = timeout(Duration::from_millis(200), stream.read_exact(&mut response)).await;
    assert!(result.is_err(), "SOCKS handshake unexpectedly completed");
    Ok(())
}

#[tokio::test]
async fn socks_connect_request_stall_does_not_complete() -> TestResult {
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

    let mut stream = TcpStream::connect(client.addr).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut handshake = [0u8; 2];
    stream.read_exact(&mut handshake).await?;
    assert_eq!(handshake, [0x05, 0x00]);

    let mut reply = [0u8; 10];
    let result = timeout(Duration::from_millis(200), stream.read_exact(&mut reply)).await;
    assert!(
        result.is_err(),
        "SOCKS CONNECT request unexpectedly completed"
    );
    Ok(())
}

#[tokio::test]
async fn tunnel_upgrade_stall_does_not_complete() -> TestResult {
    let fake = start_fake_tunnel_server(|mut stream| async move {
        let _ = read_http_headers(&mut stream).await;
        sleep(Duration::from_secs(60)).await;
    })
    .await?;
    let tunnel = TunnelClient::new(
        outbound_config_plain(fake.addr, "/api/tunnel"),
        auth_config(CLIENT_SECRET),
    );

    let result = timeout(
        Duration::from_millis(200),
        tunnel.connect_target_via_tunnel("127.0.0.1", 80),
    )
    .await;
    assert!(result.is_err(), "tunnel upgrade unexpectedly completed");
    Ok(())
}

#[tokio::test]
async fn tunnel_connect_reply_stall_does_not_complete() -> TestResult {
    let fake = start_fake_tunnel_server(|mut stream| async move {
        if read_http_headers(&mut stream).await.is_ok() {
            let _ = write_upgrade_accepted(&mut stream).await;
            let _ = read_test_frame(&mut stream).await;
            sleep(Duration::from_secs(60)).await;
        }
    })
    .await?;
    let tunnel = TunnelClient::new(
        outbound_config_plain(fake.addr, "/api/tunnel"),
        auth_config(CLIENT_SECRET),
    );

    let result = timeout(
        Duration::from_millis(200),
        tunnel.connect_target_via_tunnel("127.0.0.1", 80),
    )
    .await;
    assert!(
        result.is_err(),
        "TCP_CONNECT reply stall unexpectedly completed"
    );
    Ok(())
}

#[tokio::test]
async fn relay_stall_does_not_complete() -> TestResult {
    let fake = start_fake_tunnel_server(|mut stream| async move {
        if read_http_headers(&mut stream).await.is_ok() {
            let _ = write_upgrade_accepted(&mut stream).await;
            if let Ok(connect) = read_test_frame(&mut stream).await {
                let _ = write_test_frame(
                    &mut stream,
                    Frame {
                        frame_type: FrameType::TcpConnect,
                        stream_id: connect.stream_id,
                        flags: 0x0001,
                        payload: Bytes::new(),
                    },
                )
                .await;
                sleep(Duration::from_secs(60)).await;
            }
        }
    })
    .await?;
    let tunnel = TunnelClient::new(
        outbound_config_plain(fake.addr, "/api/tunnel"),
        auth_config(CLIENT_SECRET),
    );
    let mut upstream = tunnel.connect_target_via_tunnel("127.0.0.1", 80).await?;
    let (_app_side, mut socks_side) = tokio::io::duplex(64);

    let result = timeout(
        Duration::from_millis(200),
        tunnel.relay_over_tunnel_stream(&mut socks_side, &mut upstream),
    )
    .await;
    assert!(result.is_err(), "idle relay unexpectedly completed");
    Ok(())
}

#[tokio::test]
async fn oversized_connect_reply_frame_is_rejected_before_payload_allocation() -> TestResult {
    let fake = start_fake_tunnel_server(|mut stream| async move {
        if read_http_headers(&mut stream).await.is_ok() {
            let _ = write_upgrade_accepted(&mut stream).await;
            let _ = read_test_frame(&mut stream).await;
            let _ = write_oversized_frame_header(&mut stream).await;
        }
    })
    .await?;
    let tunnel = TunnelClient::new(
        outbound_config_plain(fake.addr, "/api/tunnel"),
        auth_config(CLIENT_SECRET),
    );

    let err = match tunnel.connect_target_via_tunnel("127.0.0.1", 80).await {
        Ok(_) => panic!("oversized frame length must fail"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("frame payload too large"),
        "unexpected oversized-frame error: {err:#}"
    );
    Ok(())
}

#[tokio::test]
async fn truncated_connect_reply_frame_fails_cleanly() -> TestResult {
    let fake = start_fake_tunnel_server(|mut stream| async move {
        if read_http_headers(&mut stream).await.is_ok() {
            let _ = write_upgrade_accepted(&mut stream).await;
            let _ = read_test_frame(&mut stream).await;
            let _ = stream
                .write_all(&[PROTOCOL_VERSION, FrameType::TcpConnect as u8])
                .await;
            let _ = stream.shutdown().await;
        }
    })
    .await?;
    let tunnel = TunnelClient::new(
        outbound_config_plain(fake.addr, "/api/tunnel"),
        auth_config(CLIENT_SECRET),
    );

    let err = match tunnel.connect_target_via_tunnel("127.0.0.1", 80).await {
        Ok(_) => panic!("truncated frame must fail"),
        Err(err) => err,
    };
    assert!(
        !err.to_string().is_empty(),
        "truncated frame should return a usable error"
    );
    Ok(())
}

#[tokio::test]
async fn unexpected_connect_reply_stream_id_fails_cleanly() -> TestResult {
    let fake = start_fake_tunnel_server(|mut stream| async move {
        if read_http_headers(&mut stream).await.is_ok() {
            let _ = write_upgrade_accepted(&mut stream).await;
            let _ = read_test_frame(&mut stream).await;
            let _ = write_test_frame(
                &mut stream,
                Frame {
                    frame_type: FrameType::TcpConnect,
                    stream_id: 99,
                    flags: 0x0001,
                    payload: Bytes::new(),
                },
            )
            .await;
        }
    })
    .await?;
    let tunnel = TunnelClient::new(
        outbound_config_plain(fake.addr, "/api/tunnel"),
        auth_config(CLIENT_SECRET),
    );

    let err = match tunnel.connect_target_via_tunnel("127.0.0.1", 80).await {
        Ok(_) => panic!("unexpected stream id must fail"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("unexpected stream id"),
        "unexpected stream-id error: {err:#}"
    );
    Ok(())
}

#[tokio::test]
async fn error_frame_from_server_becomes_connect_failure() -> TestResult {
    let fake = start_fake_tunnel_server(|mut stream| async move {
        if read_http_headers(&mut stream).await.is_ok() {
            let _ = write_upgrade_accepted(&mut stream).await;
            if let Ok(connect) = read_test_frame(&mut stream).await {
                let _ = write_test_frame(
                    &mut stream,
                    Frame {
                        frame_type: FrameType::ErrorFrame,
                        stream_id: connect.stream_id,
                        flags: 0,
                        payload: Bytes::from_static(b"target unavailable"),
                    },
                )
                .await;
            }
        }
    })
    .await?;
    let tunnel = TunnelClient::new(
        outbound_config_plain(fake.addr, "/api/tunnel"),
        auth_config(CLIENT_SECRET),
    );

    let err = match tunnel.connect_target_via_tunnel("127.0.0.1", 80).await {
        Ok(_) => panic!("ERROR frame must fail connect"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("server refused TCP_CONNECT")
            && err.to_string().contains("target unavailable"),
        "unexpected ERROR-frame connect failure: {err:#}"
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
                domain: None,
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

#[tokio::test]
async fn dns_policy_can_block_ip_targets() -> TestResult {
    let client = start_socks_client_with_dns(
        free_addr().await?,
        RoutingConfig {
            default: RouteAction::Direct,
            rules: vec![],
        },
        "/api/tunnel",
        CLIENT_SECRET,
        ClientDnsConfig {
            remote_by_default: true,
            warn_on_ip_targets: true,
            block_ip_targets: true,
        },
    )
    .await?;

    let reply = socks_connect_reply_code(client.addr, "127.0.0.1", 80).await?;
    assert_eq!(
        reply, 0x02,
        "expected SOCKS connection-not-allowed reply for IP target blocked by DNS policy"
    );
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
    start_socks_client_with_dns(
        tunnel_addr,
        routing,
        tunnel_path,
        client_secret,
        ClientDnsConfig::default(),
    )
    .await
}

async fn start_socks_client_with_dns(
    tunnel_addr: SocketAddr,
    routing: RoutingConfig,
    tunnel_path: &str,
    client_secret: &str,
    dns: ClientDnsConfig,
) -> TestResult<RunningTask> {
    let listen = free_addr().await?;
    let router = Router::new(routing);
    let tunnel = TunnelClient::new(
        outbound_config(tunnel_addr, tunnel_path),
        auth_config(client_secret),
    );
    let session = SessionCore::new(router, tunnel, dns);

    let handle = tokio::spawn(async move {
        let _ = socks5::serve(listen, session).await;
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

async fn start_exact_echo_target(expected_len: usize) -> TestResult<RunningTask> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };

            tokio::spawn(async move {
                let mut payload = vec![0u8; expected_len];
                if stream.read_exact(&mut payload).await.is_ok() {
                    let _ = stream.write_all(&payload).await;
                }
                let _ = stream.shutdown().await;
            });
        }
    });

    Ok(RunningTask { addr, handle })
}

async fn start_respond_after_eof_target(response: &'static [u8]) -> TestResult<RunningTask> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };

            tokio::spawn(async move {
                let mut request = Vec::new();
                if stream.read_to_end(&mut request).await.is_ok() {
                    let _ = stream.write_all(response).await;
                }
                let _ = stream.shutdown().await;
            });
        }
    });

    Ok(RunningTask { addr, handle })
}

async fn start_fake_tunnel_server<F, Fut>(handler: F) -> TestResult<RunningTask>
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        if let Ok((stream, _peer)) = listener.accept().await {
            handler(stream).await;
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

fn outbound_config_plain(server_addr: SocketAddr, path: &str) -> OutboundConfig {
    OutboundConfig {
        server: "127.0.0.1".to_string(),
        port: server_addr.port(),
        path: path.to_string(),
        tls: false,
        tls_server_name: None,
        tls_ca_cert_path: None,
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

async fn write_upgrade_accepted(stream: &mut TcpStream) -> TestResult {
    stream
        .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: shroud-tunnel\r\n\r\n",
        )
        .await?;
    Ok(())
}

async fn read_test_frame(stream: &mut TcpStream) -> TestResult<Frame> {
    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let payload_len = u32::from_be_bytes([header[12], header[13], header[14], header[15]]) as usize;
    if payload_len > MAX_FRAME_PAYLOAD_LEN {
        return Err(format!(
            "frame payload too large: max={}, got={}",
            MAX_FRAME_PAYLOAD_LEN, payload_len
        )
        .into());
    }

    let mut raw = Vec::with_capacity(HEADER_LEN + payload_len);
    raw.extend_from_slice(&header);
    if payload_len > 0 {
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload).await?;
        raw.extend_from_slice(&payload);
    }

    Ok(Frame::decode(Bytes::from(raw))?)
}

async fn write_test_frame(stream: &mut TcpStream, frame: Frame) -> TestResult {
    stream.write_all(frame.encode().as_ref()).await?;
    Ok(())
}

async fn write_oversized_frame_header(stream: &mut TcpStream) -> TestResult {
    let mut encoded = BytesMut::with_capacity(HEADER_LEN);
    encoded.put_u8(PROTOCOL_VERSION);
    encoded.put_u8(FrameType::TcpData as u8);
    encoded.put_u64(1);
    encoded.put_u16(0);
    encoded.put_u32((MAX_FRAME_PAYLOAD_LEN + 1) as u32);
    stream.write_all(encoded.freeze().as_ref()).await?;
    Ok(())
}

async fn read_to_end(stream: &mut TcpStream) -> TestResult<String> {
    let mut data = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut data)).await??;
    Ok(String::from_utf8_lossy(&data).into_owned())
}

async fn read_bytes_to_end(stream: &mut TcpStream) -> TestResult<Vec<u8>> {
    let mut data = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut data)).await??;
    Ok(data)
}

fn patterned_payload(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
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
