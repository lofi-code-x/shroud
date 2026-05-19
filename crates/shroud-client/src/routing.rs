use shroud_core::config::{RouteAction, RoutingConfig, RoutingRule};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone)]
pub struct Router {
    config: RoutingConfig,
}

impl Router {
    pub fn new(config: RoutingConfig) -> Self {
        Self { config }
    }

    pub fn decide(&self, target_host: &str, target_port: u16) -> RouteAction {
        self.config
            .rules
            .iter()
            .find_map(|rule| apply_rule(rule, target_host, target_port))
            .unwrap_or(self.config.default)
    }
}

fn apply_rule(rule: &RoutingRule, target_host: &str, target_port: u16) -> Option<RouteAction> {
    if let Some(port) = rule.port {
        if port != target_port {
            return None;
        }
    }

    if let Some(suffix) = &rule.domain_suffix {
        if !target_host.ends_with(suffix) {
            return None;
        }
    }

    if let Some(cidr) = &rule.cidr {
        if !cidr_matches(cidr, target_host) {
            return None;
        }
    }

    Some(rule.action)
}

fn cidr_matches(cidr: &str, target_host: &str) -> bool {
    let Ok(target_ip) = target_host.parse::<IpAddr>() else {
        return false;
    };
    let Some((network, prefix_len)) = parse_cidr(cidr) else {
        return false;
    };

    match (network, target_ip) {
        (IpAddr::V4(network), IpAddr::V4(target)) if prefix_len <= 32 => {
            ipv4_in_cidr(network, target, prefix_len)
        }
        (IpAddr::V6(network), IpAddr::V6(target)) if prefix_len <= 128 => {
            ipv6_in_cidr(network, target, prefix_len)
        }
        _ => false,
    }
}

fn parse_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let (network, prefix_len) = cidr.split_once('/')?;
    let network = network.parse::<IpAddr>().ok()?;
    let prefix_len = prefix_len.parse::<u8>().ok()?;
    Some((network, prefix_len))
}

fn ipv4_in_cidr(network: Ipv4Addr, target: Ipv4Addr, prefix_len: u8) -> bool {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    u32::from(network) & mask == u32::from(target) & mask
}

fn ipv6_in_cidr(network: Ipv6Addr, target: Ipv6Addr, prefix_len: u8) -> bool {
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    u128::from(network) & mask == u128::from(target) & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router(default: RouteAction, rules: Vec<RoutingRule>) -> Router {
        Router::new(RoutingConfig { default, rules })
    }

    fn rule(
        action: RouteAction,
        domain_suffix: Option<&str>,
        cidr: Option<&str>,
        port: Option<u16>,
    ) -> RoutingRule {
        RoutingRule {
            action,
            domain_suffix: domain_suffix.map(str::to_string),
            cidr: cidr.map(str::to_string),
            port,
        }
    }

    #[test]
    fn uses_default_when_no_rules_match() {
        let router = router(
            RouteAction::Proxy,
            vec![rule(RouteAction::Direct, Some(".local"), None, None)],
        );

        assert!(matches!(
            router.decide("example.com", 443),
            RouteAction::Proxy
        ));
    }

    #[test]
    fn matches_domain_suffix_rule() {
        let router = router(
            RouteAction::Proxy,
            vec![rule(RouteAction::Direct, Some(".local"), None, None)],
        );

        assert!(matches!(
            router.decide("printer.local", 443),
            RouteAction::Direct
        ));
    }

    #[test]
    fn matches_port_rule() {
        let router = router(
            RouteAction::Proxy,
            vec![rule(RouteAction::Direct, None, None, Some(22))],
        );

        assert!(matches!(
            router.decide("example.com", 22),
            RouteAction::Direct
        ));
        assert!(matches!(
            router.decide("example.com", 80),
            RouteAction::Proxy
        ));
    }

    #[test]
    fn matches_ipv4_cidr_rule() {
        let router = router(
            RouteAction::Proxy,
            vec![rule(RouteAction::Direct, None, Some("10.0.0.0/8"), None)],
        );

        assert!(matches!(
            router.decide("10.20.30.40", 443),
            RouteAction::Direct
        ));
        assert!(matches!(
            router.decide("11.20.30.40", 443),
            RouteAction::Proxy
        ));
    }

    #[test]
    fn matches_ipv6_cidr_rule() {
        let router = router(
            RouteAction::Proxy,
            vec![rule(RouteAction::Block, None, Some("2001:db8::/32"), None)],
        );

        assert!(matches!(
            router.decide("2001:db8::1", 443),
            RouteAction::Block
        ));
        assert!(matches!(
            router.decide("2001:db9::1", 443),
            RouteAction::Proxy
        ));
    }

    #[test]
    fn cidr_rule_does_not_match_domain_target() {
        let router = router(
            RouteAction::Proxy,
            vec![rule(RouteAction::Direct, None, Some("10.0.0.0/8"), None)],
        );

        assert!(matches!(
            router.decide("example.com", 443),
            RouteAction::Proxy
        ));
    }

    #[test]
    fn invalid_cidr_rule_does_not_match() {
        let router = router(
            RouteAction::Proxy,
            vec![rule(RouteAction::Direct, None, Some("10.0.0.0/99"), None)],
        );

        assert!(matches!(
            router.decide("10.20.30.40", 443),
            RouteAction::Proxy
        ));
    }

    #[test]
    fn rule_conditions_are_combined() {
        let router = router(
            RouteAction::Proxy,
            vec![rule(
                RouteAction::Direct,
                None,
                Some("192.168.0.0/16"),
                Some(8080),
            )],
        );

        assert!(matches!(
            router.decide("192.168.1.10", 8080),
            RouteAction::Direct
        ));
        assert!(matches!(
            router.decide("192.168.1.10", 443),
            RouteAction::Proxy
        ));
    }

    #[test]
    fn rules_are_evaluated_in_order() {
        let router = router(
            RouteAction::Proxy,
            vec![
                rule(RouteAction::Block, None, Some("10.0.0.0/8"), None),
                rule(RouteAction::Direct, None, Some("10.20.0.0/16"), None),
            ],
        );

        assert!(matches!(
            router.decide("10.20.30.40", 443),
            RouteAction::Block
        ));
    }
}
