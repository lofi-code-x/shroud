use crate::session::{DnsPolicyResult, SessionContext, SessionCore, TcpOpenResult};
use anyhow::{Context, Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info};

const SOCKS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKS_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

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
    let request = timeout(SOCKS_REQUEST_TIMEOUT, read_connect_request(&mut socket))
        .await
        .context("SOCKS CONNECT request timed out")??;
    let target_host = request.host.as_str();
    let target_port = request.port;

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
