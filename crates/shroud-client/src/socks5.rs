use crate::session::{DnsPolicyResult, SessionContext, SessionCore, TcpOpenResult};
use anyhow::{Context, Result, bail};
use bytes::{BufMut, Bytes, BytesMut};
use shroud_core::config::RouteAction;
use shroud_core::protocol::AddressType;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info};

const SOCKS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKS_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SOCKS_UDP_PACKET_LEN: usize = 65_536;

pub async fn serve(listen: SocketAddr, session: SessionCore) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    info!(%listen, "SOCKS5 inbound listener started");
    let mut active = JoinSet::new();

    loop {
        tokio::select! {
            shutdown = tokio::signal::ctrl_c() => {
                shutdown.context("failed to listen for Ctrl+C")?;
                info!(%listen, active_sessions = active.len(), "SOCKS5 listener shutting down");
                break;
            }
            accept_result = listener.accept() => {
                let (socket, peer) = accept_result?;
                debug!(%peer, "new connection");

                let session = session.clone();

                active.spawn(async move {
                    if let Err(err) = handle_connection(socket, peer, session).await {
                        debug!(%peer, error = %err, "connection handling failed");
                    }
                });
            }
            result = active.join_next(), if !active.is_empty() => {
                if let Some(Err(err)) = result {
                    debug!(error = %err, "SOCKS5 connection task join failed");
                }
            }
        }
    }

    active.abort_all();
    let _ = timeout(SHUTDOWN_DRAIN_TIMEOUT, async {
        while let Some(result) = active.join_next().await {
            if let Err(err) = result {
                debug!(error = %err, "SOCKS5 connection task stopped during shutdown");
            }
        }
    })
    .await;

    Ok(())
}

async fn handle_connection(
    mut socket: TcpStream,
    peer: SocketAddr,
    session: SessionCore,
) -> Result<()> {
    timeout(SOCKS_HANDSHAKE_TIMEOUT, handshake(&mut socket))
        .await
        .context("SOCKS handshake timed out")??;
    let request = timeout(SOCKS_REQUEST_TIMEOUT, read_request(&mut socket))
        .await
        .context("SOCKS request timed out")??;
    let ConnectRequest { host, port } = match request {
        SocksRequest::Connect(request) => request,
        SocksRequest::UdpAssociate(request) => {
            return handle_udp_associate(socket, peer, session, request).await;
        }
        SocksRequest::Bind(request) => {
            write_reply(&mut socket, ReplyCode::CommandNotSupported).await?;
            bail!(
                "SOCKS BIND is not supported: {}:{}",
                request.host,
                request.port
            );
        }
    };
    let target_host = host.as_str();
    let target_port = port;

    if matches!(
        session.check_dns_policy(
            target_host,
            target_port,
            SessionContext {
                inbound: "socks5",
                peer: Some(peer),
            },
        ),
        DnsPolicyResult::BlockedIpTarget
    ) {
        write_reply(&mut socket, ReplyCode::ConnectionNotAllowed).await?;
        debug!(%peer, target_host, target_port, "blocked IP target by DNS policy");
        return Ok(());
    }

    let mut outbound = match session.open_tcp(target_host, target_port).await {
        Ok(TcpOpenResult::Opened(outbound)) => outbound,
        Ok(TcpOpenResult::Blocked) => {
            write_reply(&mut socket, ReplyCode::ConnectionNotAllowed).await?;
            debug!(%peer, target_host, target_port, "blocked by route rule");
            return Ok(());
        }
        Err(err) => {
            write_reply(&mut socket, ReplyCode::GeneralFailure).await?;
            return Err(err);
        }
    };

    write_reply(&mut socket, ReplyCode::Succeeded).await?;
    let action = outbound.action;
    let stats = session
        .relay_tcp(&mut socket, &mut outbound)
        .await
        .with_context(|| format!("relay failed for {target_host}:{target_port}"))?;

    debug!(
        %peer,
        target_host,
        target_port,
        route = ?action,
        client_to_upstream_bytes = stats.client_to_upstream_bytes,
        upstream_to_client_bytes = stats.upstream_to_client_bytes,
        "connection relay finished"
    );

    Ok(())
}

async fn handle_udp_associate(
    mut control_socket: TcpStream,
    peer: SocketAddr,
    session: SessionCore,
    request: ConnectRequest,
) -> Result<()> {
    let tcp_local_addr = control_socket
        .local_addr()
        .context("failed to inspect SOCKS TCP local address")?;
    let udp_socket = match UdpSocket::bind(SocketAddr::new(tcp_local_addr.ip(), 0)).await {
        Ok(socket) => socket,
        Err(err) => {
            write_reply(&mut control_socket, ReplyCode::GeneralFailure).await?;
            return Err(err).context("failed to bind SOCKS UDP associate socket");
        }
    };
    let udp_bind_addr = udp_socket
        .local_addr()
        .context("failed to inspect SOCKS UDP associate bind address")?;

    let udp_tunnel = match session.open_udp_tunnel().await {
        Ok(tunnel) => tunnel,
        Err(err) => {
            write_reply(&mut control_socket, ReplyCode::GeneralFailure).await?;
            return Err(err);
        }
    };
    let (mut tunnel_read, mut tunnel_write) = udp_tunnel.into_split();
    let (tunnel_datagram_tx, mut tunnel_datagram_rx) = tokio::sync::mpsc::channel(64);
    let tunnel_reader = tokio::spawn(async move {
        loop {
            let datagram = tunnel_read.recv_datagram().await;
            let should_stop = datagram.is_err();
            if tunnel_datagram_tx.send(datagram).await.is_err() {
                break;
            }
            if should_stop {
                break;
            }
        }
    });

    write_reply_with_bind_addr(&mut control_socket, ReplyCode::Succeeded, udp_bind_addr).await?;
    debug!(
        %peer,
        client_declared_udp_host = %request.host,
        client_declared_udp_port = request.port,
        bind_addr = %udp_bind_addr,
        "SOCKS UDP associate established"
    );

    let mut endpoint_validator = UdpClientEndpointValidator::new(request, peer);
    let mut control_buf = [0u8; 1024];
    let mut udp_buf = vec![0u8; MAX_SOCKS_UDP_PACKET_LEN];

    loop {
        tokio::select! {
            control_result = control_socket.read(&mut control_buf) => {
                let n = control_result.context("failed to read SOCKS UDP control connection")?;
                if n == 0 {
                    debug!(%peer, bind_addr = %udp_bind_addr, "SOCKS UDP associate control connection closed");
                    break;
                }
                debug!(%peer, bytes = n, "ignoring data on SOCKS UDP associate control connection");
            }
            udp_result = udp_socket.recv_from(&mut udp_buf) => {
                let (n, source) = udp_result.context("failed to receive SOCKS UDP packet")?;
                if !endpoint_validator.allows(source) {
                    debug!(
                        %peer,
                        %source,
                        "dropping SOCKS UDP packet from unexpected endpoint"
                    );
                    continue;
                }

                let packet = match decode_udp_request_packet(&udp_buf[..n]) {
                    Ok(Some(packet)) => packet,
                    Ok(None) => {
                        debug!(%peer, %source, "dropping fragmented SOCKS UDP packet");
                        continue;
                    }
                    Err(err) => {
                        debug!(%peer, %source, error = %err, "dropping invalid SOCKS UDP packet");
                        continue;
                    }
                };
                endpoint_validator.observe(source);

                if matches!(
                    session.check_dns_policy(
                        &packet.target_host,
                        packet.target_port,
                        SessionContext {
                            inbound: "socks5-udp",
                            peer: Some(peer),
                        },
                    ),
                    DnsPolicyResult::BlockedIpTarget
                ) {
                    debug!(
                        %peer,
                        %source,
                        target_host = packet.target_host,
                        target_port = packet.target_port,
                        "blocked SOCKS UDP IP target by DNS policy"
                    );
                    continue;
                }

                match session.decide(&packet.target_host, packet.target_port) {
                    RouteAction::Proxy => {
                        let datagram = shroud_core::protocol::UdpDatagram {
                            target_host: packet.target_host,
                            target_port: packet.target_port,
                            payload: packet.payload,
                            association_id: None,
                        };
                        if let Err(err) = tunnel_write.send_datagram(&datagram).await {
                            debug!(%peer, %source, error = %err, "failed to send SOCKS UDP datagram through tunnel");
                            return Err(err);
                        }
                    }
                    RouteAction::Block => {
                        debug!(
                            %peer,
                            %source,
                            target_host = packet.target_host,
                            target_port = packet.target_port,
                            "blocked SOCKS UDP datagram by route rule"
                        );
                    }
                    RouteAction::Direct => {
                        debug!(
                            %peer,
                            %source,
                            target_host = packet.target_host,
                            target_port = packet.target_port,
                            "dropping SOCKS UDP datagram because direct UDP relay is not supported"
                        );
                    }
                }
            }
            datagram_result = tunnel_datagram_rx.recv() => {
                let Some(datagram) = datagram_result else {
                    debug!(%peer, "SOCKS UDP tunnel response reader stopped");
                    break;
                };
                let datagram = datagram?;
                let Some(client_udp_endpoint) = endpoint_validator.observed() else {
                    debug!(%peer, "dropping tunnel UDP datagram before client endpoint is known");
                    continue;
                };
                let packet = match encode_udp_response_packet(
                    &datagram.target_host,
                    datagram.target_port,
                    datagram.payload.as_ref(),
                ) {
                    Ok(packet) => packet,
                    Err(err) => {
                        debug!(%peer, error = %err, "failed to encode SOCKS UDP response packet");
                        continue;
                    }
                };
                udp_socket
                    .send_to(packet.as_ref(), client_udp_endpoint)
                    .await
                    .context("failed to send SOCKS UDP response packet to client")?;
            }
        }
    }

    tunnel_reader.abort();
    let _ = tunnel_reader.await;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectRequest {
    host: String,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SocksRequest {
    Connect(ConnectRequest),
    UdpAssociate(ConnectRequest),
    Bind(ConnectRequest),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SocksCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

struct UdpClientEndpointValidator {
    expected_ip: Option<IpAddr>,
    expected_port: u16,
    tcp_peer: SocketAddr,
    observed: Option<SocketAddr>,
}

impl UdpClientEndpointValidator {
    fn new(request: ConnectRequest, tcp_peer: SocketAddr) -> Self {
        Self {
            expected_ip: request.host.parse::<IpAddr>().ok(),
            expected_port: request.port,
            tcp_peer,
            observed: None,
        }
    }

    fn allows(&self, source: SocketAddr) -> bool {
        if let Some(observed) = self.observed {
            return source == observed;
        }

        self.source_matches_request(source)
    }

    fn observe(&mut self, source: SocketAddr) {
        debug_assert!(self.allows(source));
        self.observed = Some(source);
    }

    fn observed(&self) -> Option<SocketAddr> {
        self.observed
    }

    fn source_matches_request(&self, source: SocketAddr) -> bool {
        match self.expected_ip {
            Some(expected_ip) if !expected_ip.is_unspecified() && source.ip() != expected_ip => {
                return false;
            }
            Some(expected_ip)
                if expected_ip.is_unspecified() && source.ip() != self.tcp_peer.ip() =>
            {
                return false;
            }
            None if source.ip() != self.tcp_peer.ip() => {
                return false;
            }
            _ => {}
        }

        self.expected_port == 0 || source.port() == self.expected_port
    }
}

impl TryFrom<u8> for SocksCommand {
    type Error = u8;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::UdpAssociate),
            value => Err(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksUdpPacket {
    pub target_host: String,
    pub target_port: u16,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksUdpCodecError {
    Truncated(&'static str),
    InvalidReserved { got: [u8; 2] },
    UnknownAddressType(u8),
    DomainNotUtf8,
    DomainTooLong(usize),
}

impl fmt::Display for SocksUdpCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated(message) => write!(f, "truncated SOCKS UDP packet: {message}"),
            Self::InvalidReserved { got } => {
                write!(f, "invalid SOCKS UDP RSV bytes: {got:02x?}")
            }
            Self::UnknownAddressType(value) => {
                write!(f, "unsupported SOCKS UDP address type: {value:#04x}")
            }
            Self::DomainNotUtf8 => write!(f, "SOCKS UDP domain is not valid utf-8"),
            Self::DomainTooLong(len) => write!(f, "SOCKS UDP domain is too long: {len} bytes"),
        }
    }
}

impl Error for SocksUdpCodecError {}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum ReplyCode {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

async fn handshake<T>(socket: &mut T) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
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

async fn read_request<T>(socket: &mut T) -> Result<SocksRequest>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 4];
    socket.read_exact(&mut header).await?;

    if header[0] != 0x05 {
        bail!("unsupported request socks version: {}", header[0]);
    }
    if header[2] != 0x00 {
        write_reply(socket, ReplyCode::GeneralFailure).await?;
        bail!("invalid socks request reserved byte: {}", header[2]);
    }

    let command = match SocksCommand::try_from(header[1]) {
        Ok(command) => command,
        Err(command) => {
            skip_request_address(socket, header[3]).await?;
            write_reply(socket, ReplyCode::CommandNotSupported).await?;
            bail!("unsupported socks command: {command}");
        }
    };

    let request = read_request_address(socket, header[3]).await?;
    Ok(match command {
        SocksCommand::Connect => SocksRequest::Connect(request),
        SocksCommand::UdpAssociate => SocksRequest::UdpAssociate(request),
        SocksCommand::Bind => SocksRequest::Bind(request),
    })
}

async fn read_request_address<T>(socket: &mut T, atyp: u8) -> Result<ConnectRequest>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let host = match atyp {
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
            bail!("unsupported socks address type: {atyp}");
        }
    };

    let mut port_buf = [0u8; 2];
    socket.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok(ConnectRequest { host, port })
}

async fn skip_request_address<T>(socket: &mut T, atyp: u8) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    match atyp {
        0x01 => {
            let mut raw = [0u8; 4 + 2];
            socket.read_exact(&mut raw).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut raw = vec![0u8; len[0] as usize + 2];
            socket.read_exact(&mut raw).await?;
        }
        0x04 => {
            let mut raw = [0u8; 16 + 2];
            socket.read_exact(&mut raw).await?;
        }
        _ => {}
    }
    Ok(())
}

pub fn decode_udp_request_packet(
    packet: &[u8],
) -> std::result::Result<Option<SocksUdpPacket>, SocksUdpCodecError> {
    if packet.len() < 4 {
        return Err(SocksUdpCodecError::Truncated("missing fixed header"));
    }
    let reserved = [packet[0], packet[1]];
    if reserved != [0x00, 0x00] {
        return Err(SocksUdpCodecError::InvalidReserved { got: reserved });
    }
    if packet[2] != 0x00 {
        return Ok(None);
    }

    decode_udp_packet_body(packet)
}

pub fn encode_udp_response_packet(
    target_host: &str,
    target_port: u16,
    payload: &[u8],
) -> std::result::Result<Bytes, SocksUdpCodecError> {
    encode_udp_packet(target_host, target_port, payload)
}

fn decode_udp_packet_body(
    packet: &[u8],
) -> std::result::Result<Option<SocksUdpPacket>, SocksUdpCodecError> {
    let mut cursor = 4usize;
    let target_host = match packet[3] {
        0x01 => {
            if packet.len() < cursor + 4 + 2 {
                return Err(SocksUdpCodecError::Truncated(
                    "missing IPv4 address or port",
                ));
            }
            let mut raw = [0u8; 4];
            raw.copy_from_slice(&packet[cursor..cursor + 4]);
            cursor += 4;
            IpAddr::V4(Ipv4Addr::from(raw)).to_string()
        }
        0x03 => {
            let domain_len = *packet
                .get(cursor)
                .ok_or(SocksUdpCodecError::Truncated("missing domain length"))?
                as usize;
            cursor += 1;
            if packet.len() < cursor + domain_len + 2 {
                return Err(SocksUdpCodecError::Truncated(
                    "missing domain bytes or port",
                ));
            }
            let domain_raw = &packet[cursor..cursor + domain_len];
            cursor += domain_len;
            std::str::from_utf8(domain_raw)
                .map_err(|_| SocksUdpCodecError::DomainNotUtf8)?
                .to_string()
        }
        0x04 => {
            if packet.len() < cursor + 16 + 2 {
                return Err(SocksUdpCodecError::Truncated(
                    "missing IPv6 address or port",
                ));
            }
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&packet[cursor..cursor + 16]);
            cursor += 16;
            IpAddr::V6(Ipv6Addr::from(raw)).to_string()
        }
        value => return Err(SocksUdpCodecError::UnknownAddressType(value)),
    };

    let target_port = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
    cursor += 2;

    Ok(Some(SocksUdpPacket {
        target_host,
        target_port,
        payload: Bytes::copy_from_slice(&packet[cursor..]),
    }))
}

fn encode_udp_packet(
    target_host: &str,
    target_port: u16,
    payload: &[u8],
) -> std::result::Result<Bytes, SocksUdpCodecError> {
    let mut out = BytesMut::new();
    out.put_u16(0);
    out.put_u8(0);

    if let Ok(ip) = target_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(addr) => {
                out.put_u8(AddressType::Ipv4 as u8);
                out.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                out.put_u8(AddressType::Ipv6 as u8);
                out.extend_from_slice(&addr.octets());
            }
        }
    } else {
        let host_bytes = target_host.as_bytes();
        if host_bytes.len() > u8::MAX as usize {
            return Err(SocksUdpCodecError::DomainTooLong(host_bytes.len()));
        }
        out.put_u8(AddressType::Domain as u8);
        out.put_u8(host_bytes.len() as u8);
        out.extend_from_slice(host_bytes);
    }

    out.put_u16(target_port);
    out.extend_from_slice(payload);
    Ok(out.freeze())
}

async fn write_reply<T>(socket: &mut T, code: ReplyCode) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    let reply = [
        0x05, code as u8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    socket.write_all(&reply).await?;
    Ok(())
}

async fn write_reply_with_bind_addr<T>(
    socket: &mut T,
    code: ReplyCode,
    bind_addr: SocketAddr,
) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    let mut reply = BytesMut::with_capacity(22);
    reply.put_u8(0x05);
    reply.put_u8(code as u8);
    reply.put_u8(0x00);

    match bind_addr.ip() {
        IpAddr::V4(addr) => {
            reply.put_u8(AddressType::Ipv4 as u8);
            reply.extend_from_slice(&addr.octets());
        }
        IpAddr::V6(addr) => {
            reply.put_u8(AddressType::Ipv6 as u8);
            reply.extend_from_slice(&addr.octets());
        }
    }

    reply.put_u16(bind_addr.port());
    socket.write_all(reply.as_ref()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn parser_reads_connect_request() {
        let request = [
            0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
            b'o', b'm', 0x01, 0xbb,
        ];
        let parsed = parse_request_from_bytes(&request).await;

        assert_eq!(
            parsed,
            SocksRequest::Connect(ConnectRequest {
                host: "example.com".to_string(),
                port: 443,
            })
        );
    }

    #[tokio::test]
    async fn parser_reads_udp_associate_request() {
        let request = [0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x13, 0x88];
        let parsed = parse_request_from_bytes(&request).await;

        assert_eq!(
            parsed,
            SocksRequest::UdpAssociate(ConnectRequest {
                host: "127.0.0.1".to_string(),
                port: 5000,
            })
        );
    }

    #[tokio::test]
    async fn parser_reads_bind_as_unsupported_command_variant() {
        let request = [0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80];
        let parsed = parse_request_from_bytes(&request).await;

        assert_eq!(
            parsed,
            SocksRequest::Bind(ConnectRequest {
                host: "127.0.0.1".to_string(),
                port: 80,
            })
        );
    }

    #[test]
    fn socks_udp_decodes_ipv4_request() {
        let packet = [
            0x00, 0x00, 0x00, 0x01, 192, 0, 2, 10, 0x00, 0x35, b'd', b'n', b's',
        ];

        let decoded = decode_udp_request_packet(&packet)
            .expect("decode")
            .expect("not fragmented");

        assert_eq!(decoded.target_host, "192.0.2.10");
        assert_eq!(decoded.target_port, 53);
        assert_eq!(decoded.payload, Bytes::from_static(b"dns"));
    }

    #[test]
    fn socks_udp_decodes_domain_request() {
        let packet = [
            0x00, 0x00, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
            b'o', b'm', 0x01, 0xbb, b'x',
        ];

        let decoded = decode_udp_request_packet(&packet)
            .expect("decode")
            .expect("not fragmented");

        assert_eq!(decoded.target_host, "example.com");
        assert_eq!(decoded.target_port, 443);
        assert_eq!(decoded.payload, Bytes::from_static(b"x"));
    }

    #[test]
    fn socks_udp_encodes_ipv6_response() {
        let encoded = encode_udp_response_packet("2001:db8::1", 5353, b"reply").expect("encode");
        let decoded = decode_udp_request_packet(encoded.as_ref())
            .expect("decode")
            .expect("not fragmented");

        assert_eq!(decoded.target_host, "2001:db8::1");
        assert_eq!(decoded.target_port, 5353);
        assert_eq!(decoded.payload, Bytes::from_static(b"reply"));
    }

    #[test]
    fn socks_udp_rejects_invalid_reserved_bytes() {
        let err = decode_udp_request_packet(&[0x00, 0x01, 0x00, 0x01])
            .expect_err("invalid RSV must fail");

        assert!(matches!(
            err,
            SocksUdpCodecError::InvalidReserved { got: [0x00, 0x01] }
        ));
    }

    #[test]
    fn socks_udp_drops_fragmented_packets() {
        let packet = [0x00, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0, 53, b'x'];
        let decoded = decode_udp_request_packet(&packet).expect("fragmented packet is valid drop");

        assert_eq!(decoded, None);
    }

    #[test]
    fn socks_udp_rejects_truncated_packets() {
        let err = decode_udp_request_packet(&[0x00, 0x00, 0x00, 0x01, 127])
            .expect_err("truncated packet must fail");

        assert!(matches!(err, SocksUdpCodecError::Truncated(_)));
    }

    async fn parse_request_from_bytes(bytes: &[u8]) -> SocksRequest {
        let (mut client, mut server) = duplex(64);
        client.write_all(bytes).await.expect("write request");
        read_request(&mut server).await.expect("parse request")
    }
}
