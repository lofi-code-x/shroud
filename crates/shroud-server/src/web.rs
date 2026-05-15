use crate::auth::validate_auth;
use crate::relay::relay_stub;
use anyhow::Result;
use shroud_core::config::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};

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
    let mut buffer = [0u8; 1024];
    let n = stream.read(&mut buffer).await?;
    let request = String::from_utf8_lossy(&buffer[..n]);

    if request.contains(&format!("POST {}", cfg.tunnel_path)) {
        if validate_auth(&cfg.clients, "stub-client", b"stub-nonce", 0, "stub-tag") {
            relay_stub(peer).await?;
            stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n").await?;
        } else {
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
        }
    } else {
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await?;
    }

    Ok(())
}
