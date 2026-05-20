use serde::{Deserialize, Deserializer, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Serialize)]
pub struct ClientConfig {
    pub inbound: Option<SocksInboundConfig>,
    pub inbounds: ClientInboundsConfig,
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

        let mut inbounds: ClientInboundsConfig = raw.inbounds.unwrap_or_default().into();
        if let Some(legacy_socks) = raw.inbound {
            inbounds.socks = Some(legacy_socks);
        }

        if !inbounds.has_enabled_inbound() {
            return Err(serde::de::Error::custom(
                "missing enabled inbound config: expected `inbound.listen`, enabled `inbounds.socks.listen`, or enabled `inbounds.tun`",
            ));
        }

        let inbound = inbounds.socks.clone();

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
            inbounds,
            outbound,
            auth,
            routing,
            dns,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocksInboundConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientInboundsConfig {
    #[serde(default)]
    pub socks: Option<SocksInboundConfig>,
    #[serde(default)]
    pub tun: TunInboundConfig,
}

impl ClientInboundsConfig {
    pub fn has_enabled_inbound(&self) -> bool {
        self.socks
            .as_ref()
            .map(|socks| socks.enabled)
            .unwrap_or(false)
            || self.tun.enabled
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunInboundConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_tun_name")]
    pub name: String,
    #[serde(default = "default_tun_address")]
    pub address: String,
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub auto_route: bool,
    #[serde(default)]
    pub dns: Option<IpAddr>,
}

impl Default for TunInboundConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            name: default_tun_name(),
            address: default_tun_address(),
            mtu: default_tun_mtu(),
            auto_route: false,
            dns: None,
        }
    }
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

fn default_tun_name() -> String {
    "tun0".to_string()
}

fn default_tun_address() -> String {
    "10.10.0.2/24".to_string()
}

fn default_tun_mtu() -> u16 {
    1400
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
    #[serde(default)]
    tun: TunInboundConfig,
}

impl Default for ClientInboundsRaw {
    fn default() -> Self {
        Self {
            socks: None,
            tun: TunInboundConfig::default(),
        }
    }
}

impl From<ClientInboundsRaw> for ClientInboundsConfig {
    fn from(raw: ClientInboundsRaw) -> Self {
        Self {
            socks: raw.socks,
            tun: raw.tun,
        }
    }
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

    #[test]
    fn client_config_normalizes_legacy_inbound_into_inbounds_socks() {
        let cfg: ClientConfig = serde_yaml::from_str(BASE_CLIENT_CONFIG).expect("parse config");

        let legacy = cfg.inbound.expect("legacy inbound alias");
        let socks = cfg.inbounds.socks.expect("normalized socks inbound");

        assert!(legacy.enabled);
        assert_eq!(legacy.listen.to_string(), "127.0.0.1:1080");
        assert!(socks.enabled);
        assert_eq!(socks.listen.to_string(), "127.0.0.1:1080");
        assert!(!cfg.inbounds.tun.enabled);
        assert_eq!(cfg.inbounds.tun.name, "tun0");
        assert_eq!(cfg.inbounds.tun.address, "10.10.0.2/24");
        assert_eq!(cfg.inbounds.tun.mtu, 1400);
        assert!(!cfg.inbounds.tun.auto_route);
        assert!(cfg.inbounds.tun.dns.is_none());
    }

    #[test]
    fn client_config_accepts_inbounds_socks_shape() {
        let raw = r#"
inbounds:
  socks:
    listen: "127.0.0.1:1081"
outbound:
  server: "127.0.0.1"
  port: 8443
  path: "/api/tunnel"
  tls: true
auth:
  client_id: "11111111-1111-1111-1111-111111111111"
  client_secret: "secret"
"#;

        let cfg: ClientConfig = serde_yaml::from_str(raw).expect("parse config");
        let socks = cfg.inbounds.socks.expect("socks inbound");

        assert!(socks.enabled);
        assert_eq!(socks.listen.to_string(), "127.0.0.1:1081");
        assert!(cfg.inbound.is_some());
    }

    #[test]
    fn client_config_accepts_tun_inbound_shape() {
        let raw = r#"
inbounds:
  tun:
    enabled: true
    name: "tun-test0"
    address: "10.20.0.2/24"
    mtu: 1300
    auto_route: true
    dns: "10.20.0.53"
outbound:
  server: "127.0.0.1"
  port: 8443
  path: "/api/tunnel"
  tls: true
auth:
  client_id: "11111111-1111-1111-1111-111111111111"
  client_secret: "secret"
"#;

        let cfg: ClientConfig = serde_yaml::from_str(raw).expect("parse config");

        assert!(cfg.inbound.is_none());
        assert!(cfg.inbounds.socks.is_none());
        assert!(cfg.inbounds.tun.enabled);
        assert_eq!(cfg.inbounds.tun.name, "tun-test0");
        assert_eq!(cfg.inbounds.tun.address, "10.20.0.2/24");
        assert_eq!(cfg.inbounds.tun.mtu, 1300);
        assert!(cfg.inbounds.tun.auto_route);
        assert_eq!(
            cfg.inbounds.tun.dns.expect("tun dns").to_string(),
            "10.20.0.53"
        );
    }

    #[test]
    fn client_config_rejects_missing_enabled_inbounds() {
        let raw = r#"
inbounds:
  socks:
    enabled: false
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

        assert!(serde_yaml::from_str::<ClientConfig>(raw).is_err());
    }
}
