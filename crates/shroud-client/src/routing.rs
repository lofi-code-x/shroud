use shroud_core::config::{RouteAction, RoutingConfig, RoutingRule};

/*
Router — это локальный движок принятия решения, куда отправлять конкретное соединение: direct, proxy или block.

Его задача:
1. Получить target_host и target_port от SOCKS5 слоя.
2. Пройти список правил сверху вниз (rules).
3. Вернуть действие первого подошедшего правила.
4. Если ничего не подошло — вернуть default.
Это делает метод decide(...) (routing.rs).

Зачем он нужен:
• Отделяет политику маршрутизации от сетевого кода SOCKS/tunnel.
• Позволяет задавать поведение через конфиг, а не хардкод.
• Это база для split tunneling (часть трафика напрямую, часть через сервер, часть блокировать).

Сейчас реализация упрощённая:
• Работают проверки по port и domain_suffix.
• cidr в правилах пока не реализован (ветка-заглушка в routing.rs).
 */

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
