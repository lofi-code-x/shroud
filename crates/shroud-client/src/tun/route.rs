use anyhow::{Context, Result, bail};
use shroud_core::config::{OutboundConfig, TunInboundConfig};
use std::fmt;
use std::net::IpAddr;
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
}

impl RoutePlan {
    pub fn build(
        tun_name: &str,
        tun: &TunInboundConfig,
        outbound: &OutboundConfig,
        endpoint_route: Option<EndpointRoute>,
    ) -> Result<Self> {
        validate_tun_address(&tun.address)?;

        let mut loop_protection = Vec::new();
        if let Some(route) = endpoint_route {
            loop_protection.push(route_command_for_endpoint(outbound, route)?);
        } else if outbound.server.parse::<IpAddr>().is_err() {
            warn!(
                server = %outbound.server,
                "cannot build loop-protection route for domain tunnel endpoint before DNS resolution"
            );
        }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRoute {
    pub endpoint: IpAddr,
    pub via: Option<IpAddr>,
    pub dev: String,
}

pub fn setup_interface_only(tun_name: &str, tun: &TunInboundConfig) -> Result<()> {
    let plan = RoutePlan::build(tun_name, tun, &dummy_outbound(), None)?;
    plan.apply_interface()
}

pub fn resolve_endpoint_route(outbound: &OutboundConfig) -> Result<Option<EndpointRoute>> {
    let endpoint = match outbound.server.parse::<IpAddr>() {
        Ok(endpoint) => endpoint,
        Err(_) => return Ok(None),
    };

    platform::resolve_endpoint_route(endpoint)
}

pub fn setup_before_packet_engine(
    tun_name: &str,
    tun: &TunInboundConfig,
    outbound: &OutboundConfig,
) -> Result<()> {
    let endpoint_route = resolve_endpoint_route(outbound)?;
    let plan = RoutePlan::build(tun_name, tun, outbound, endpoint_route)?;
    plan.log();
    plan.apply_interface()
        .context("failed to configure TUN interface")?;

    if tun.auto_route {
        plan.apply_loop_protection()
            .context("failed to install tunnel endpoint loop-protection route")?;
        info!(
            tun = tun_name,
            "installed TUN interface setup and loop-protection routes"
        );
        warn!(
            tun = tun_name,
            "default route setup is deferred until TUN packet engine is implemented"
        );
    }

    Ok(())
}

fn run_all(commands: &[RouteCommand]) -> Result<()> {
    for command in commands {
        command.run()?;
    }
    Ok(())
}

fn route_command_for_endpoint(
    outbound: &OutboundConfig,
    endpoint_route: EndpointRoute,
) -> Result<RouteCommand> {
    let endpoint = outbound
        .server
        .parse::<IpAddr>()
        .context("loop-protection endpoint must be an IP address")?;
    let prefix = match endpoint {
        IpAddr::V4(_) => format!("{endpoint}/32"),
        IpAddr::V6(_) => format!("{endpoint}/128"),
    };

    let mut args = vec!["route".to_string(), "replace".to_string(), prefix];
    if let Some(via) = endpoint_route.via {
        args.push("via".to_string());
        args.push(via.to_string());
    }
    args.push("dev".to_string());
    args.push(endpoint_route.dev);
    Ok(RouteCommand::ip(args))
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

fn dummy_outbound() -> OutboundConfig {
    OutboundConfig {
        server: "127.0.0.1".to_string(),
        port: 0,
        path: "/".to_string(),
        tls: false,
        tls_server_name: None,
        tls_ca_cert_path: None,
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::EndpointRoute;
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
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::EndpointRoute;
    use anyhow::{Result, bail};
    use std::net::IpAddr;

    pub fn resolve_endpoint_route(_endpoint: IpAddr) -> Result<Option<EndpointRoute>> {
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

    fn outbound(server: &str) -> OutboundConfig {
        OutboundConfig {
            server: server.to_string(),
            port: 443,
            path: "/api/tunnel".to_string(),
            tls: true,
            tls_server_name: None,
            tls_ca_cert_path: None,
        }
    }

    #[test]
    fn builds_interface_and_default_route_commands() {
        let plan =
            RoutePlan::build("tun-test0", &tun(), &outbound("example.com"), None).expect("plan");

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

        let plan = RoutePlan::build(
            "tun-test0",
            &tun(),
            &outbound("203.0.113.10"),
            Some(endpoint_route),
        )
        .expect("plan");

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

        let plan = RoutePlan::build(
            "tun-test0",
            &tun(),
            &outbound("2001:db8::10"),
            Some(endpoint_route),
        )
        .expect("plan");

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
}
