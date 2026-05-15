use crate::routing::Router;
use crate::tunnel::TunnelClient;
use anyhow::{Context, Result, bail};
use shroud_core::config::RouteAction;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};

//Эта функция запускает асинхронный TCP-сервер и обрабатывает каждое соединение параллельно.
pub async fn serve(listen: SocketAddr, router: Router, tunnel: TunnelClient) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    info!(%listen, "SOCKS5 inbound listener started");

    loop {
        let (socket, peer) = listener.accept().await?;
        debug!(%peer, "new connection");

        let router = router.clone();
        let tunnel = tunnel.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_connection(socket, peer, router, tunnel).await {
                debug!(%peer, error = %err, "connection handling failed");
            }
        });
    }
}

//Эта функция handle_connection обрабатывает одного входящего TCP-клиента,
// вероятно в формате SOCKS-подобного CONNECT-потока, решает, как маршрутизировать соединение,
// и отправляет клиенту ответ об успехе или ошибке.

async fn handle_connection(
    mut socket: TcpStream,
    peer: SocketAddr,
    router: Router,
    tunnel: TunnelClient,
) -> Result<()> {
    //Выполняется настройка протокола:
    handshake(&mut socket).await?;
    //Выполняется настройка протокола:
    let request = read_connect_request(&mut socket).await?;

    //Из запроса извлекается информация о целевом адресе:
    let target_host = request.host.as_str();
    let target_port = request.port;

    //Функция спрашивает у роутера, что делать с этим соединением:

    //Важный момент: _stream будет сброшен в конце этой ветки match, поэтому сейчас код только проверяет возможность подключения.
    // Он не продолжает пересылать трафик между клиентом и целевым сервером.
    let action = router.decide(target_host, target_port);

    match action {
        RouteAction::Proxy => {
            dbg!(&target_host, &target_port);
            let mut upstream = match tunnel
                .connect_target_via_tunnel(target_host, target_port)
                .await
            {
                Ok(stream) => stream,
                Err(err) => {
                    write_reply(&mut socket, ReplyCode::GeneralFailure).await?;
                    return Err(err).context("proxy tunnel connect failed");
                }
            };

            write_reply(&mut socket, ReplyCode::Succeeded).await?;
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
