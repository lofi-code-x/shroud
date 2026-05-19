use serde::{Deserialize, Deserializer, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize)]
pub struct ClientConfig {
    pub inbound: SocksInboundConfig,
    pub outbound: OutboundConfig,
    pub auth: ClientAuthConfig,
    pub routing: RoutingConfig,
    pub dns: ClientDnsConfig,
}

impl<'de> Deserialize<'de> for ClientConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = ClientConfigRaw::deserialize(deserializer)?;

        let inbound = raw
            .inbound
            .or_else(|| raw.inbounds.and_then(|inbounds| inbounds.socks))
            .ok_or_else(|| {
                serde::de::Error::custom(
                    "missing inbound config: expected either `inbound.listen` or `inbounds.socks.listen`",
                )
            })?;

        let outbound = raw
            .outbound
            .or_else(|| raw.outbounds.and_then(|outbounds| outbounds.proxy))
            .ok_or_else(|| {
                serde::de::Error::custom(
                    "missing outbound config: expected either `outbound` or `outbounds.proxy`",
                )
            })?;

        let auth = raw.auth.ok_or_else(|| {
            serde::de::Error::custom(
                "missing auth config: expected `auth.client_id` and `auth.client_secret`",
            )
        })?;

        let routing = raw.routing.unwrap_or_default();
        let dns = raw.dns.unwrap_or_default();

        Ok(Self {
            inbound,
            outbound,
            auth,
            routing,
            dns,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocksInboundConfig {
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    pub server: String,
    pub port: u16,
    pub path: String,
    pub tls: bool,
    #[serde(default)]
    pub tls_server_name: Option<String>,
    #[serde(default)]
    pub tls_ca_cert_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAuthConfig {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientDnsConfig {
    #[serde(default = "default_true")]
    pub remote_by_default: bool,
    #[serde(default = "default_true")]
    pub warn_on_ip_targets: bool,
    #[serde(default)]
    pub block_ip_targets: bool,
}

impl Default for ClientDnsConfig {
    fn default() -> Self {
        Self {
            remote_by_default: true,
            warn_on_ip_targets: true,
            block_ip_targets: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingConfig {
    #[serde(default = "default_route_action")]
    pub default: RouteAction,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    #[serde(alias = "outbound")]
    pub action: RouteAction,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub domain_suffix: Option<String>,
    #[serde(default)]
    pub cidr: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    Direct,
    Proxy,
    Block,
}

fn default_route_action() -> RouteAction {
    RouteAction::Proxy
}

fn default_true() -> bool {
    true
}

impl Default for RouteAction {
    fn default() -> Self {
        default_route_action()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub tunnel_path: String,
    pub web_root: String,
    #[serde(default)]
    pub tls: ServerTlsConfig,
    pub clients: Vec<AuthorizedClient>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerTlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedClient {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Deserialize)]
struct ClientConfigRaw {
    #[serde(default)]
    inbound: Option<SocksInboundConfig>,
    #[serde(default)]
    inbounds: Option<ClientInboundsRaw>,
    #[serde(default)]
    outbound: Option<OutboundConfig>,
    #[serde(default)]
    outbounds: Option<ClientOutboundsRaw>,
    #[serde(default)]
    auth: Option<ClientAuthConfig>,
    #[serde(default)]
    routing: Option<RoutingConfig>,
    #[serde(default)]
    dns: Option<ClientDnsConfig>,
}

#[derive(Debug, Deserialize)]
struct ClientInboundsRaw {
    #[serde(default)]
    socks: Option<SocksInboundConfig>,
}

#[derive(Debug, Deserialize)]
struct ClientOutboundsRaw {
    #[serde(default)]
    proxy: Option<OutboundConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_CLIENT_CONFIG: &str = r#"
inbound:
  listen: "127.0.0.1:1080"
outbound:
  server: "127.0.0.1"
  port: 8443
  path: "/api/tunnel"
  tls: true
auth:
  client_id: "11111111-1111-1111-1111-111111111111"
  client_secret: "secret"
"#;

    #[test]
    fn client_dns_config_defaults_to_remote_dns_warning_without_blocking() {
        let cfg: ClientConfig = serde_yaml::from_str(BASE_CLIENT_CONFIG).expect("parse config");

        assert!(cfg.dns.remote_by_default);
        assert!(cfg.dns.warn_on_ip_targets);
        assert!(!cfg.dns.block_ip_targets);
    }

    #[test]
    fn client_dns_config_can_be_overridden() {
        let raw = format!(
            "{BASE_CLIENT_CONFIG}\ndns:\n  remote_by_default: false\n  warn_on_ip_targets: false\n  block_ip_targets: true\n"
        );
        let cfg: ClientConfig = serde_yaml::from_str(&raw).expect("parse config");

        assert!(!cfg.dns.remote_by_default);
        assert!(!cfg.dns.warn_on_ip_targets);
        assert!(cfg.dns.block_ip_targets);
    }
}
