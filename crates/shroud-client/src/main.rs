mod routing;
mod socks5;
mod tunnel;

use anyhow::{Context, Result};
use shroud_core::config::ClientConfig;
use std::fs;
use tracing::info;
use tracing_subscriber::EnvFilter;

// cargo run -p shroud-client -- configs/client.yaml
// curl --socks5-hostname 127.0.0.1:1080 https://example.com

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "configs/client.yaml".to_string());
    let raw = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read client config: {config_path}"))?;
    let cfg: ClientConfig = serde_yaml::from_str(&raw)
        .with_context(|| format!("failed to parse client yaml config: {config_path}"))?;

    info!(listen = %cfg.inbound.listen, "starting shroud client");
    let router = routing::Router::new(cfg.routing.clone());
    let tunnel = tunnel::TunnelClient::new(cfg.outbound.clone(), cfg.auth.clone());

    socks5::serve(cfg.inbound.listen, router, tunnel).await
}


/*
Готово. Реализовал следующий шаг: proxy теперь работает через реальный клиент↔сервер tunnel
 transport с auth + frame relay, а не через direct-stub.
Что сделано:
• В клиентском SOCKS-слое Proxy-ветка теперь:
i) поднимает tunnel до сервера,
ii) отправляет TCP_CONNECT,
iii) только после успешного ответа отправляет SOCKS Succeeded,
iv) релеит трафик через TCP_DATA/TCP_CLOSE. См. socks5.rs
•
Добавлен полноценный TunnelClient transport:
◦ HTTP upgrade request с X-Shroud-* заголовками,
◦ HMAC auth (compute_auth_tag),
◦ frame I/O (FrameType::TcpConnect/TcpData/TcpClose/ErrorFrame),
◦ двунаправленный relay с подсчётом байт. См. tunnel.rs
•
На сервере:
◦ web.rs теперь реально парсит HTTP headers, проверяет path, auth headers, timestamp window, nonce(base64),
 и передаёт соединение в relay. См. web.rs
◦ relay.rs теперь реализует tunnel session:
▪ ожидает первый TCP_CONNECT,
▪ открывает target-сокет,
▪ отправляет CONNECT_OK (TcpConnect + flag),
▪ релеит TCP_DATA в обе стороны,
▪ обрабатывает TCP_CLOSE/ErrorFrame. См. relay.rs
• В shroud-core добавил общий encode/decode payload для TCP_CONNECT + тесты. См. protocol.rs
• Добавлены зависимости в client/server: base64, bytes; в client ещё uuid для nonce.
 См. crates/shroud-client/Cargo.toml, crates/shroud-server/Cargo.toml
Проверка:
• cargo check -p shroud-client -p shroud-server — OK
• cargo test -p shroud-core — OK (3/3)
Важно:
• outbound.tls: true пока не реализует TLS transport; сейчас есть явный warn и
 используется plain TCP fallback (dev-режим), чтобы пайплайн уже работал end-to-end.
 */
