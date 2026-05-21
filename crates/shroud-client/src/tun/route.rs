use anyhow::{Context, Result, bail};
use shroud_core::config::{OutboundConfig, TunInboundConfig};
use std::fmt;
use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCommand {
    program: String,
    args: Vec<String>,
}

impl RouteCommand {
    fn ip(args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            program: "ip".to_string(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub fn program(&self) -> &str {
        &self.program
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn run(&self) -> Result<()> {
        let output = Command::new(&self.program)
            .args(&self.args)
            .output()
            .with_context(|| format!("failed to execute route command: {self}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("route command failed: {self}: {stderr}");
        }

        Ok(())
    }
}

impl fmt::Display for RouteCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.program)?;
        for arg in &self.args {
            write!(f, " {arg}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RoutePlan {
    pub interface: Vec<RouteCommand>,
    pub loop_protection: Vec<RouteCommand>,
    pub default_route: Vec<RouteCommand>,
    pub cleanup: Vec<RouteCommand>,
}

impl RoutePlan {
    pub fn build(
        tun_name: &str,
        tun: &TunInboundConfig,
        endpoint_route: Option<EndpointRoute>,
        previous_default_routes: &[DefaultRoute],
    ) -> Result<Self> {
        validate_tun_address(&tun.address)?;

        let mut loop_protection = Vec::new();
        let mut loop_protection_cleanup = Vec::new();
        let mut cleanup = Vec::new();
        if let Some(route) = endpoint_route {
            loop_protection_cleanup.push(delete_endpoint_route_command(route.endpoint));
            loop_protection.push(route_command_for_endpoint(route));
        }

        cleanup.push(RouteCommand::ip([
            "route", "del", "default", "dev", tun_name,
        ]));
        cleanup.extend(
            previous_default_routes
                .iter()
                .map(|route| route.restore_command()),
        );
        cleanup.extend(loop_protection_cleanup);

        Ok(Self {
            interface: vec![
                RouteCommand::ip(["addr", "replace", tun.address.as_str(), "dev", tun_name]),
                RouteCommand::ip(vec![
                    "link".to_string(),
                    "set".to_string(),
                    "dev".to_string(),
                    tun_name.to_string(),
                    "mtu".to_string(),
                    tun.mtu.to_string(),
                    "up".to_string(),
                ]),
            ],
            loop_protection,
            default_route: vec![RouteCommand::ip([
                "route", "replace", "default", "dev", tun_name,
            ])],
            cleanup,
        })
    }

    pub fn apply_interface(&self) -> Result<()> {
        run_all(&self.interface)
    }

    pub fn apply_loop_protection(&self) -> Result<()> {
        run_all(&self.loop_protection)
    }

    pub fn apply_default_route(&self) -> Result<()> {
        run_all(&self.default_route)
    }

    pub fn log(&self) {
        for command in &self.interface {
            debug!(command = %command, "TUN interface setup command planned");
        }
        for command in &self.loop_protection {
            debug!(command = %command, "TUN loop-protection route command planned");
        }
        for command in &self.default_route {
            debug!(command = %command, "TUN default route command planned");
        }
    }
}

pub struct TunRouteGuard {
    cleanup: Vec<RouteCommand>,
}

impl TunRouteGuard {
    fn new(cleanup: Vec<RouteCommand>) -> Self {
        Self { cleanup }
    }
}

impl Drop for TunRouteGuard {
    fn drop(&mut self) {
        for command in &self.cleanup {
            if let Err(err) = command.run() {
                warn!(command = %command, error = %err, "failed to clean up TUN route command");
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRoute {
    pub endpoint: IpAddr,
    pub via: Option<IpAddr>,
    pub dev: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    tokens: Vec<String>,
}

impl DefaultRoute {
    fn restore_command(&self) -> RouteCommand {
        let mut args = vec!["route".to_string(), "replace".to_string()];
        args.extend(self.tokens.clone());
        RouteCommand::ip(args)
    }
}

pub fn setup_interface_only(tun_name: &str, tun: &TunInboundConfig) -> Result<()> {
    let plan = RoutePlan::build(tun_name, tun, None, &[])?;
    plan.apply_interface()
}

pub struct ResolvedEndpoint {
    pub ip: IpAddr,
    pub original_host: String,
    pub was_hostname: bool,
}

pub fn resolve_endpoint_ip(outbound: &OutboundConfig) -> Result<ResolvedEndpoint> {
    let original_host = outbound.server.clone();

    if let Ok(ip) = outbound.server.parse::<IpAddr>() {
        return Ok(ResolvedEndpoint {
            ip,
            original_host,
            was_hostname: false,
        });
    }

    let ip = (outbound.server.as_str(), outbound.port)
        .to_socket_addrs()
        .with_context(|| {
            format!(
                "failed to bootstrap-resolve tunnel endpoint {}:{} before TUN auto-route",
                outbound.server, outbound.port
            )
        })?
        .next()
        .map(|addr| addr.ip())
        .with_context(|| {
            format!(
                "bootstrap DNS returned no addresses for tunnel endpoint {}:{}",
                outbound.server, outbound.port
            )
        })?;

    Ok(ResolvedEndpoint {
        ip,
        original_host,
        was_hostname: true,
    })
}

pub fn prepare_auto_route_outbound(mut outbound: OutboundConfig) -> Result<OutboundConfig> {
    let endpoint = resolve_endpoint_ip(&outbound)?;

    outbound.server = endpoint.ip.to_string();

    if outbound.tls && outbound.tls_server_name.is_none() && endpoint.was_hostname {
        outbound.tls_server_name = Some(endpoint.original_host.clone());
    }

    info!(
        server = %endpoint.original_host,
        endpoint_ip = %endpoint.ip,
        "bootstrap-resolved tunnel endpoint before enabling TUN auto-route"
    );

    Ok(outbound)
}

pub fn resolve_endpoint_route(endpoint: IpAddr) -> Result<Option<EndpointRoute>> {
    platform::resolve_endpoint_route(endpoint)
}

pub fn setup_before_packet_engine(
    tun_name: &str,
    tun: &TunInboundConfig,
    outbound: &OutboundConfig,
) -> Result<TunRouteGuard> {
    let previous_default_routes = if tun.auto_route {
        platform::default_routes().context("failed to capture existing default routes")?
    } else {
        Vec::new()
    };
    let endpoint_route = if tun.auto_route {
        let endpoint = resolve_endpoint_ip(outbound)?.ip;
        Some(resolve_endpoint_route(endpoint)?.with_context(|| {
            format!("failed to find current route to tunnel endpoint {endpoint}")
        })?)
    } else {
        None
    };
    let plan = RoutePlan::build(tun_name, tun, endpoint_route, &previous_default_routes)?;
    plan.log();
    plan.apply_interface()
        .context("failed to configure TUN interface")?;
    let route_guard = TunRouteGuard::new(if tun.auto_route {
        plan.cleanup.clone()
    } else {
        Vec::new()
    });

    if tun.auto_route {
        if plan.loop_protection.is_empty() {
            bail!("cannot enable TUN auto_route without tunnel endpoint loop-protection route");
        }
        plan.apply_loop_protection()
            .context("failed to install tunnel endpoint loop-protection route")?;
        plan.apply_default_route()
            .context("failed to install TUN default route")?;
        info!(
            tun = tun_name,
            "installed TUN interface setup, loop-protection route, and default route"
        );
    }

    Ok(route_guard)
}

fn run_all(commands: &[RouteCommand]) -> Result<()> {
    for command in commands {
        command.run()?;
    }
    Ok(())
}

fn route_command_for_endpoint(endpoint_route: EndpointRoute) -> RouteCommand {
    let prefix = match endpoint_route.endpoint {
        IpAddr::V4(endpoint) => format!("{endpoint}/32"),
        IpAddr::V6(endpoint) => format!("{endpoint}/128"),
    };

    let mut args = vec!["route".to_string(), "replace".to_string(), prefix];
    if let Some(via) = endpoint_route.via {
        args.push("via".to_string());
        args.push(via.to_string());
    }
    args.push("dev".to_string());
    args.push(endpoint_route.dev);
    RouteCommand::ip(args)
}

fn delete_endpoint_route_command(endpoint: IpAddr) -> RouteCommand {
    let prefix = match endpoint {
        IpAddr::V4(_) => format!("{endpoint}/32"),
        IpAddr::V6(_) => format!("{endpoint}/128"),
    };
    RouteCommand::ip(["route".to_string(), "del".to_string(), prefix])
}

fn validate_tun_address(address: &str) -> Result<()> {
    let Some((ip, prefix)) = address.split_once('/') else {
        bail!("TUN address must be CIDR, got {address}");
    };
    let ip = ip
        .parse::<IpAddr>()
        .with_context(|| format!("invalid TUN address IP: {address}"))?;
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("invalid TUN address prefix: {address}"))?;

    match ip {
        IpAddr::V4(_) if prefix <= 32 => Ok(()),
        IpAddr::V6(_) if prefix <= 128 => Ok(()),
        IpAddr::V4(_) => bail!("invalid IPv4 TUN address prefix: {address}"),
        IpAddr::V6(_) => bail!("invalid IPv6 TUN address prefix: {address}"),
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{DefaultRoute, EndpointRoute};
    use anyhow::{Context, Result, bail};
    use std::net::IpAddr;
    use std::process::Command;

    pub fn resolve_endpoint_route(endpoint: IpAddr) -> Result<Option<EndpointRoute>> {
        let output = Command::new("ip")
            .args(["route", "get", &endpoint.to_string()])
            .output()
            .with_context(|| format!("failed to resolve route to tunnel endpoint {endpoint}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("failed to resolve route to tunnel endpoint {endpoint}: {stderr}");
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_ip_route_get(endpoint, &stdout)
    }

    pub fn default_routes() -> Result<Vec<DefaultRoute>> {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .context("failed to read existing default routes")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("failed to read existing default routes: {stderr}");
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_default_routes(&stdout))
    }

    fn parse_ip_route_get(endpoint: IpAddr, output: &str) -> Result<Option<EndpointRoute>> {
        let mut via = None;
        let mut dev = None;
        let mut tokens = output.split_whitespace();

        while let Some(token) = tokens.next() {
            match token {
                "via" => {
                    let Some(raw) = tokens.next() else {
                        bail!("ip route get output has `via` without gateway: {output}");
                    };
                    via = Some(raw.parse::<IpAddr>().with_context(|| {
                        format!("invalid gateway in ip route get output: {output}")
                    })?);
                }
                "dev" => {
                    let Some(raw) = tokens.next() else {
                        bail!("ip route get output has `dev` without interface: {output}");
                    };
                    dev = Some(raw.to_string());
                }
                _ => {}
            }
        }

        let Some(dev) = dev else {
            return Ok(None);
        };

        Ok(Some(EndpointRoute { endpoint, via, dev }))
    }

    fn parse_default_routes(output: &str) -> Vec<DefaultRoute> {
        output
            .lines()
            .filter_map(|line| {
                let tokens: Vec<String> = line.split_whitespace().map(str::to_string).collect();
                if tokens.first().is_some_and(|token| token == "default") {
                    Some(DefaultRoute { tokens })
                } else {
                    None
                }
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_route_get_with_gateway() {
            let route = parse_ip_route_get(
                "203.0.113.10".parse().expect("ip"),
                "203.0.113.10 via 192.168.1.1 dev wlan0 src 192.168.1.20 uid 1000\n",
            )
            .expect("parse")
            .expect("route");

            assert_eq!(route.endpoint.to_string(), "203.0.113.10");
            assert_eq!(route.via.expect("via").to_string(), "192.168.1.1");
            assert_eq!(route.dev, "wlan0");
        }

        #[test]
        fn parses_direct_route_get_without_gateway() {
            let route = parse_ip_route_get(
                "10.0.0.5".parse().expect("ip"),
                "10.0.0.5 dev eth0 src 10.0.0.2 uid 1000\n",
            )
            .expect("parse")
            .expect("route");

            assert_eq!(route.endpoint.to_string(), "10.0.0.5");
            assert!(route.via.is_none());
            assert_eq!(route.dev, "eth0");
        }

        #[test]
        fn parses_default_routes_for_restore() {
            let routes = parse_default_routes(
                "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n\
                 default dev eth0 metric 700\n",
            );

            assert_eq!(routes.len(), 2);
            assert_eq!(
                routes[0].restore_command().to_string(),
                "ip route replace default via 192.168.1.1 dev wlan0 proto dhcp metric 600"
            );
            assert_eq!(
                routes[1].restore_command().to_string(),
                "ip route replace default dev eth0 metric 700"
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::{DefaultRoute, EndpointRoute};
    use anyhow::{Result, bail};
    use std::net::IpAddr;

    pub fn resolve_endpoint_route(_endpoint: IpAddr) -> Result<Option<EndpointRoute>> {
        bail!("TUN route setup is currently implemented only on Linux")
    }

    pub fn default_routes() -> Result<Vec<DefaultRoute>> {
        bail!("TUN route setup is currently implemented only on Linux")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::config::TunInboundConfig;

    fn tun() -> TunInboundConfig {
        TunInboundConfig {
            enabled: true,
            name: "tun-test0".to_string(),
            address: "10.10.0.2/24".to_string(),
            mtu: 1400,
            auto_route: true,
            dns: None,
        }
    }

    #[test]
    fn builds_interface_and_default_route_commands() {
        let plan = RoutePlan::build("tun-test0", &tun(), None, &[]).expect("plan");

        assert_eq!(
            plan.interface[0].to_string(),
            "ip addr replace 10.10.0.2/24 dev tun-test0"
        );
        assert_eq!(
            plan.interface[1].to_string(),
            "ip link set dev tun-test0 mtu 1400 up"
        );
        assert_eq!(
            plan.default_route[0].to_string(),
            "ip route replace default dev tun-test0"
        );
        assert!(plan.loop_protection.is_empty());
    }

    #[test]
    fn builds_ipv4_loop_protection_route() {
        let endpoint_route = EndpointRoute {
            endpoint: "203.0.113.10".parse().expect("ip"),
            via: Some("192.168.1.1".parse().expect("gateway")),
            dev: "wlan0".to_string(),
        };

        let plan = RoutePlan::build("tun-test0", &tun(), Some(endpoint_route), &[]).expect("plan");

        assert_eq!(
            plan.loop_protection[0].to_string(),
            "ip route replace 203.0.113.10/32 via 192.168.1.1 dev wlan0"
        );
    }

    #[test]
    fn builds_ipv6_loop_protection_route() {
        let endpoint_route = EndpointRoute {
            endpoint: "2001:db8::10".parse().expect("ip"),
            via: None,
            dev: "eth0".to_string(),
        };

        let plan = RoutePlan::build("tun-test0", &tun(), Some(endpoint_route), &[]).expect("plan");

        assert_eq!(
            plan.loop_protection[0].to_string(),
            "ip route replace 2001:db8::10/128 dev eth0"
        );
    }

    #[test]
    fn rejects_invalid_tun_addresses() {
        assert!(validate_tun_address("10.10.0.2").is_err());
        assert!(validate_tun_address("10.10.0.2/33").is_err());
        assert!(validate_tun_address("2001:db8::2/129").is_err());
    }

    #[test]
    fn builds_cleanup_for_auto_route() {
        let previous = vec![DefaultRoute {
            tokens: vec![
                "default".to_string(),
                "via".to_string(),
                "192.168.1.1".to_string(),
                "dev".to_string(),
                "wlan0".to_string(),
            ],
        }];
        let endpoint_route = EndpointRoute {
            endpoint: "203.0.113.10".parse().expect("ip"),
            via: Some("192.168.1.1".parse().expect("gateway")),
            dev: "wlan0".to_string(),
        };
        let plan =
            RoutePlan::build("tun-test0", &tun(), Some(endpoint_route), &previous).expect("plan");

        assert_eq!(
            plan.cleanup[0].to_string(),
            "ip route del default dev tun-test0"
        );
        assert_eq!(
            plan.cleanup[1].to_string(),
            "ip route replace default via 192.168.1.1 dev wlan0"
        );
        assert_eq!(plan.cleanup[2].to_string(), "ip route del 203.0.113.10/32");
    }
}
