use serde::{Deserialize, Deserializer, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize)]
pub struct ClientConfig {
    pub inbound: SocksInboundConfig,
    pub outbound: OutboundConfig,
    pub auth: ClientAuthConfig,
    pub routing: RoutingConfig,
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

        Ok(Self {
            inbound,
            outbound,
            auth,
            routing,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAuthConfig {
    pub client_id: String,
    pub client_secret: String,
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
    pub clients: Vec<AuthorizedClient>,
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
