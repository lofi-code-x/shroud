use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::debug;

#[allow(dead_code)]
pub async fn open_target(target_host: &str, target_port: u16) -> Result<TcpStream> {
    let addr = format!("{target_host}:{target_port}");
    debug!(%addr, "opening target tcp stream");
    let stream = TcpStream::connect(addr).await?;
    Ok(stream)
}

pub async fn relay_stub(peer: SocketAddr) -> Result<()> {
    debug!(%peer, "stub relay for authorized tunnel");
    Ok(())
}
