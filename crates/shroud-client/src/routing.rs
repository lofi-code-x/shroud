use shroud_core::config::{RouteAction, RoutingConfig, RoutingRule};

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

    if rule.cidr.is_some() {
        return None;
    }

    Some(rule.action)
}
