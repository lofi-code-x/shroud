use anyhow::Result;
use shroud_core::config::{ClientAuthConfig, OutboundConfig};
use tracing::debug;

#[derive(Clone)]
pub struct TunnelClient {
    outbound: OutboundConfig,
    auth: ClientAuthConfig,
}

impl TunnelClient {
    pub fn new(outbound: OutboundConfig, auth: ClientAuthConfig) -> Self {
        Self { outbound, auth }
    }

    pub async fn connect_target(&self, host: &str, port: u16) -> Result<()> {
        debug!(
            server = %self.outbound.server,
            tunnel_path = %self.outbound.path,
            client_id = %self.auth.client_id,
            host,
            port,
            "stub tunnel connect"
        );
        Ok(())
    }
}
