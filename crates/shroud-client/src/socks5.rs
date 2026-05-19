use crate::routing::Router;
use crate::tunnel::TunnelClient;
use anyhow::{Context, Result, bail};
use shroud_core::config::{ClientDnsConfig, RouteAction};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

pub async fn serve(
    listen: SocketAddr,
    router: Router,
    tunnel: TunnelClient,
    dns: ClientDnsConfig,
) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    info!(%listen, "SOCKS5 inbound listener started");

    loop {
        let (socket, peer) = listener.accept().await?;
        debug!(%peer, "new connection");

        let router = router.clone();
        let tunnel = tunnel.clone();
        let dns = dns.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_connection(socket, peer, router, tunnel, dns).await {
                debug!(%peer, error = %err, "connection handling failed");
            }
        });
    }
}

/// Handles a single incoming SOCKS5 client connection.
///
/// This function processes one accepted TCP connection from a local client,
/// performs the SOCKS5 handshake, reads the client's `CONNECT` request,
/// decides how the destination should be routed, and then either proxies,
/// connects directly, or blocks the connection.
///
/// The function supports three routing outcomes:
///
/// - `RouteAction::Proxy` — connect to the target through the configured tunnel.
/// - `RouteAction::Direct` — connect to the target directly with `TcpStream`.
/// - `RouteAction::Block` — reject the connection according to routing rules.
///
/// # Protocol flow
///
/// The function performs the following steps:
///
/// 1. Performs the SOCKS5 authentication negotiation:
///
/// ```text
/// client -> local proxy: supported auth methods
/// local proxy -> client: selected auth method
/// ```
///
/// This is handled by [`handshake`].
///
/// 2. Reads the SOCKS5 `CONNECT` request:
///
/// ```text
/// client -> local proxy: connect to target_host:target_port
/// ```
///
/// This is handled by [`read_connect_request`].
///
/// 3. Extracts the target destination:
///
/// ```text
/// target_host = request.host
/// target_port = request.port
/// ```
///
/// 4. Uses the [`Router`] to decide how the connection should be handled:
///
/// ```text
/// router.decide(target_host, target_port)
/// ```
///
/// 5. Executes the selected route action:
///
/// - proxy through the tunnel;
/// - connect directly;
/// - block the request.
///
/// # Arguments
///
/// * `socket` - TCP connection accepted from the local SOCKS5 client.
/// * `peer` - Socket address of the connected client. Used for logging.
/// * `router` - Routing engine used to decide whether the target should be
///   proxied, connected directly, or blocked.
/// * `tunnel` - Tunnel client used to open proxied connections through the
///   remote tunnel server.
///
/// # Route behavior
///
/// ## `RouteAction::Proxy`
///
/// When the router returns `RouteAction::Proxy`, this function attempts to
/// connect to the requested target through the tunnel:
///
/// ```text
/// local client
///     -> local SOCKS5 proxy
///     -> tunnel client
///     -> remote tunnel server
///     -> target_host:target_port
/// ```
///
/// If the tunnel connection fails, the function sends a SOCKS5
/// `GeneralFailure` reply to the client and returns an error.
///
/// If the tunnel connection succeeds, the function sends a SOCKS5 `Succeeded`
/// reply and starts relaying data between the local client socket and the
/// tunnel stream using:
///
/// ```text
/// tunnel.relay_over_tunnel_stream(...)
/// ```
///
/// After the relay finishes, the function logs byte counters for both
/// directions.
///
/// ## `RouteAction::Direct`
///
/// When the router returns `RouteAction::Direct`, this function opens a direct
/// TCP connection to the requested target:
///
/// ```text
/// local client
///     -> local SOCKS5 proxy
///     -> target_host:target_port
/// ```
///
/// If the direct TCP connection fails, the function sends a SOCKS5
/// `GeneralFailure` reply to the client and returns an error.
///
/// If the direct connection succeeds, the function sends a SOCKS5 `Succeeded`
/// reply and starts bidirectional copying between the client socket and the
/// upstream TCP stream using [`copy_bidirectional`].
///
/// After the relay finishes, the function logs byte counters for both
/// directions.
///
/// ## `RouteAction::Block`
///
/// When the router returns `RouteAction::Block`, this function rejects the
/// request by sending a SOCKS5 `ConnectionNotAllowed` reply.
///
/// No upstream connection is opened in this case.
///
/// # SOCKS5 replies
///
/// This function writes different SOCKS5 replies depending on the result:
///
/// - `ReplyCode::Succeeded` if the upstream connection was established.
/// - `ReplyCode::GeneralFailure` if proxy/direct upstream connection failed.
/// - `ReplyCode::ConnectionNotAllowed` if the router blocked the target.
///
/// The success reply is sent only after the upstream side is actually ready.
/// This prevents the client from assuming that the connection is established
/// when the proxy failed to connect to the target.
///
/// # Returns
///
/// Returns `Ok(())` when:
///
/// - the connection was successfully proxied and relay finished normally;
/// - the connection was directly relayed and finished normally;
/// - the request was blocked by routing rules and the block reply was sent.
///
/// Returns an error when:
///
/// - SOCKS5 handshake fails;
/// - the SOCKS5 `CONNECT` request cannot be read or parsed;
/// - tunnel connection fails;
/// - direct TCP connection fails;
/// - data relay fails;
/// - writing SOCKS5 replies fails.
///
/// # Errors
///
/// This function propagates errors from:
///
/// - [`handshake`];
/// - [`read_connect_request`];
/// - [`write_reply`];
/// - `tunnel.connect_target_via_tunnel`;
/// - `tunnel.relay_over_tunnel_stream`;
/// - [`TcpStream::connect`];
/// - [`copy_bidirectional`].
///
/// Additional context is attached to some errors, for example:
///
/// - `"proxy tunnel connect failed"`
/// - `"proxy relay failed"`
/// - `"failed to open direct tcp connection to <host>:<port>"`
/// - `"relay failed for <host>:<port>"`
///
/// # Notes
///
/// This function handles one client connection only. A listener loop should call
/// it for every accepted TCP connection, usually by spawning a new asynchronous
/// task per client.
///
/// This function supports only TCP-style SOCKS5 `CONNECT` flows. UDP forwarding
/// is not handled here.
async fn handle_connection(
    mut socket: TcpStream,
    peer: SocketAddr,
    router: Router,
    tunnel: TunnelClient,
    dns: ClientDnsConfig,
) -> Result<()> {
    handshake(&mut socket).await?;
    let request = read_connect_request(&mut socket).await?;
    let target_host = request.host.as_str();
    let target_port = request.port;
    if let Some(target_ip) = target_host.parse::<IpAddr>().ok() {
        if dns.warn_on_ip_targets {
            warn!(
                %peer,
                %target_ip,
                target_port,
                remote_by_default = dns.remote_by_default,
                block_ip_targets = dns.block_ip_targets,
                "SOCKS target is an IP address; remote DNS cannot be applied because the application likely resolved the name locally"
            );
        }

        if dns.block_ip_targets {
            write_reply(&mut socket, ReplyCode::ConnectionNotAllowed).await?;
            debug!(%peer, target_host, target_port, "blocked IP target by DNS policy");
            return Ok(());
        }
    } else if dns.remote_by_default {
        debug!(
            %peer,
            target_host,
            target_port,
            "SOCKS target is a domain; preserving it for remote resolution"
        );
    }

    let action = router.decide(target_host, target_port);

    match action {
        RouteAction::Proxy => {
            //connect to the tunnel server and open a tunnel to the target
            let mut upstream = match tunnel
                .connect_target_via_tunnel(target_host, target_port)
                .await
            {
                Ok(stream) => stream,
                Err(err) => {
                    //if the tunnel connection fails, the upstream stream will be dropped
                    write_reply(&mut socket, ReplyCode::GeneralFailure).await?;
                    return Err(err).context("proxy tunnel connect failed");
                }
            };

            //if the tunnel connection succeeds, start relaying data between the local client socket and the tunnel stream
            write_reply(&mut socket, ReplyCode::Succeeded).await?;
            //relay data between client and upstream
            let stats = tunnel
                .relay_over_tunnel_stream(&mut socket, &mut upstream)
                .await
                .context("proxy relay failed")?;
            debug!(
                %peer,
                target_host,
                target_port,
                route = ?action,
                client_to_upstream_bytes = stats.client_to_upstream_bytes,
                upstream_to_client_bytes = stats.upstream_to_client_bytes,
                "connection relay finished"
            );
        }
        RouteAction::Direct => {
            let mut upstream = match TcpStream::connect((target_host, target_port)).await {
                Ok(stream) => stream,
                Err(err) => {
                    write_reply(&mut socket, ReplyCode::GeneralFailure).await?;
                    return Err(err).with_context(|| {
                        format!(
                            "failed to open direct tcp connection to {target_host}:{target_port}"
                        )
                    });
                }
            };

            write_reply(&mut socket, ReplyCode::Succeeded).await?;
            let (client_to_upstream_bytes, upstream_to_client_bytes) =
                copy_bidirectional(&mut socket, &mut upstream)
                    .await
                    .with_context(|| format!("relay failed for {target_host}:{target_port}"))?;

            debug!(
                %peer,
                target_host,
                target_port,
                route = ?action,
                client_to_upstream_bytes,
                upstream_to_client_bytes,
                "connection relay finished"
            );
        }
        RouteAction::Block => {
            write_reply(&mut socket, ReplyCode::ConnectionNotAllowed).await?;
            debug!(%peer, target_host, target_port, "blocked by route rule");
            return Ok(());
        }
    }

    Ok(())
}

#[derive(Debug)]
struct ConnectRequest {
    host: String,
    port: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum ReplyCode {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

/// Performs the initial SOCKS5 handshake with the client.
///
/// This function reads the SOCKS5 authentication negotiation request from the
/// client, validates the SOCKS version, and selects the `No Authentication`
/// method if the client supports it.
///
/// Expected client request format:
///
/// ```text
/// +-----+----------+----------+
/// | VER | NMETHODS | METHODS  |
/// +-----+----------+----------+
/// |  1  |    1     | 1..255   |
/// +-----+----------+----------+
/// ```
///
/// Where:
///
/// - `VER` must be `0x05`, meaning SOCKS5.
/// - `NMETHODS` defines the number of authentication methods sent by the client.
/// - `METHODS` contains the list of supported authentication methods.
///
/// Supported authentication methods:
///
/// - `0x00` — No Authentication Required.
///
/// If the client supports `0x00`, the server replies with:
///
/// ```text
/// 0x05 0x00
/// ```
///
/// Meaning:
///
/// - SOCKS version 5.
/// - No authentication required.
///
/// If the client does not support `0x00`, the server replies with:
///
/// ```text
/// 0x05 0xFF
/// ```
///
/// Meaning:
///
/// - SOCKS version 5.
/// - No acceptable authentication methods.
///
/// # Errors
///
/// Returns an error if:
///
/// - The socket cannot be read from or written to.
/// - The client uses an unsupported SOCKS version.
/// - The client does not provide a supported authentication method.
///
/// # Notes
///
/// This function only handles the authentication negotiation phase.
/// After this function succeeds, the client is expected to send a SOCKS5
/// request, usually a `CONNECT` request.
async fn handshake(socket: &mut TcpStream) -> Result<()> {
    let mut header = [0u8; 2];
    socket.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        bail!("unsupported socks version: {}", header[0]);
    }

    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    socket.read_exact(&mut methods).await?;

    if methods.contains(&0x00) {
        socket.write_all(&[0x05, 0x00]).await?;
        Ok(())
    } else {
        socket.write_all(&[0x05, 0xFF]).await?;
        bail!("no supported auth method from client")
    }
}

/// Reads and parses a SOCKS5 `CONNECT` request from the client.
///
/// This function is expected to be called after a successful SOCKS5 handshake.
/// It reads the client request, validates that the command is `CONNECT`,
/// extracts the destination host and port, and returns them as a
/// `ConnectRequest`.
///
/// Expected SOCKS5 request format:
///
/// ```text
/// +-----+-----+-------+------+----------+----------+
/// | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +-----+-----+-------+------+----------+----------+
/// |  1  |  1  |   1   |  1   | Variable |    2     |
/// +-----+-----+-------+------+----------+----------+
/// ```
///
/// Where:
///
/// - `VER` must be `0x05`, meaning SOCKS5.
/// - `CMD` must be `0x01`, meaning `CONNECT`.
/// - `RSV` is a reserved byte, usually `0x00`.
/// - `ATYP` defines the destination address type.
/// - `DST.ADDR` contains the destination address.
/// - `DST.PORT` contains the destination port in big-endian byte order.
///
/// Supported address types:
///
/// - `0x01` — IPv4 address, encoded as 4 bytes.
/// - `0x03` — Domain name, encoded as 1 byte length followed by domain bytes.
/// - `0x04` — IPv6 address, encoded as 16 bytes.
///
/// For example, a request to connect to `example.com:443` may look like:
///
/// ```text
/// 05 01 00 03 0B 65 78 61 6D 70 6C 65 2E 63 6F 6D 01 BB
/// ```
///
/// Decoded:
///
/// - `05` — SOCKS5.
/// - `01` — CONNECT command.
/// - `00` — reserved.
/// - `03` — domain name address type.
/// - `0B` — domain length, 11 bytes.
/// - `65 78 61 6D 70 6C 65 2E 63 6F 6D` — `example.com`.
/// - `01 BB` — port `443`.
///
/// # Returns
///
/// Returns a `ConnectRequest` containing:
///
/// - `host` — destination host as a string.
/// - `port` — destination port as `u16`.
///
/// # Errors
///
/// Returns an error if:
///
/// - The socket cannot be read from or written to.
/// - The SOCKS version is not `0x05`.
/// - The requested command is not `CONNECT`.
/// - The address type is not supported.
/// - A domain name address is not valid UTF-8.
///
/// If the command is unsupported, this function writes a SOCKS5 reply with
/// `ReplyCode::CommandNotSupported` before returning an error.
///
/// If the address type is unsupported, this function writes a SOCKS5 reply with
/// `ReplyCode::AddressTypeNotSupported` before returning an error.
///
/// # Notes
///
/// This function only parses the request. It does not establish a connection
/// to the destination host. The caller is responsible for opening the upstream
/// TCP connection or routing the request through another proxy/tunnel.
async fn read_connect_request(socket: &mut TcpStream) -> Result<ConnectRequest> {
    let mut header = [0u8; 4];
    socket.read_exact(&mut header).await?;

    if header[0] != 0x05 {
        bail!("unsupported request socks version: {}", header[0]);
    }
    if header[1] != 0x01 {
        write_reply(socket, ReplyCode::CommandNotSupported).await?;
        bail!("unsupported socks command: {}", header[1]);
    }

    let host = match header[3] {
        0x01 => {
            let mut raw = [0u8; 4];
            socket.read_exact(&mut raw).await?;
            IpAddr::V4(Ipv4Addr::from(raw)).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut raw = vec![0u8; len[0] as usize];
            socket.read_exact(&mut raw).await?;
            String::from_utf8(raw).context("invalid utf-8 domain in socks request")?
        }
        0x04 => {
            let mut raw = [0u8; 16];
            socket.read_exact(&mut raw).await?;
            IpAddr::V6(Ipv6Addr::from(raw)).to_string()
        }
        _ => {
            write_reply(socket, ReplyCode::AddressTypeNotSupported).await?;
            bail!("unsupported socks address type: {}", header[3]);
        }
    };

    let mut port_buf = [0u8; 2];
    socket.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok(ConnectRequest { host, port })
}

async fn write_reply(socket: &mut TcpStream, code: ReplyCode) -> Result<()> {
    let reply = [
        0x05, code as u8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    socket.write_all(&reply).await?;
    Ok(())
}
