# Проектирование собственного VLESS-like proxy/VPN протокола

## 1. Цель проекта

Идея: реализовать собственный протокол по типу VLESS, где:

- локальный клиент забирает трафик через **SOCKS5** или **TUN**;
- клиент передаёт трафик на удалённый сервер через собственный протокол;
- сервер работает как proxy/VPN endpoint;
- сервер может менять внешний IP / egress route;
- соединение снаружи выглядит как обычное HTTPS-соединение к сайту;
- факт использования proxy не должен быть очевиден как при открытом SOCKS/VPN-порте.

Базовая схема:

```text
Приложения / система
        ↓
локальный inbound: SOCKS5 или TUN
        ↓
локальный клиент
        ↓
твой протокол поверх TLS / HTTP/2 / HTTP/3 / QUIC
        ↓
удалённый сервер
        ↓
target site / service
```

Важно: лучше не пытаться «подделываться» под чужой сайт. Практичнее и чище поднять обычный HTTPS-сервис на своём домене с валидным TLS-сертификатом, нормальным SNI/ALPN и fallback-поведением.

---

## 2. Общая архитектура

### 2.1. Клиент

```text
myclient
├── inbound
│   ├── socks5: 127.0.0.1:1080
│   └── tun: tun0
│
├── routing engine
│   ├── domain rules
│   ├── CIDR rules
│   ├── port rules
│   ├── app/process rules, optional
│   └── direct / proxy / block
│
├── DNS module
│   ├── remote DNS
│   ├── fake-ip, optional
│   └── leak protection
│
├── session manager
│   ├── TCP streams
│   ├── UDP sessions
│   └── multiplexing, optional
│
└── outbound
    └── custom protocol over TLS / HTTP/2 / HTTP/3 / QUIC
```

### 2.2. Сервер

```text
myserver
├── TLS/HTTP listener: 443
├── auth layer
├── protocol decoder
├── TCP relay
├── UDP relay
├── DNS resolver
├── egress manager
│   ├── default outbound IP
│   ├── multiple egress IPs
│   └── per-rule egress selection
└── fallback web service
```

---

## 3. Режимы inbound на клиенте

В терминологии Xray/V2Ray **inbound** — это входящая точка, через которую трафик попадает в клиент или сервер.

На локальном клиенте inbound может быть:

- SOCKS5 proxy;
- HTTP proxy;
- TUN interface;
- transparent proxy;
- dokodemo-door-like inbound.

На сервере inbound может быть уже твоим собственным протоколом, VLESS-like listener, Trojan-like listener и т.д.

---

## 4. SOCKS5 inbound

SOCKS5 inbound — лучший вариант для первого прототипа.

Схема:

```text
Browser / curl / proxychains
        ↓
SOCKS5 127.0.0.1:1080
        ↓
myclient
        ↓
custom protocol
        ↓
myserver
        ↓
target
```

Плюсы:

- проще реализовать;
- легко отлаживать;
- поддерживается браузерами, `curl`, `proxychains`;
- не требует root-прав;
- хорошо подходит для per-app proxy.

Минусы:

- приложения нужно явно направлять в SOCKS;
- не весь системный трафик автоматически пойдёт через прокси.

Пример использования:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

В Firefox желательно включать remote DNS:

```text
network.proxy.socks_remote_dns = true
```

---

## 5. TUN inbound

TUN нужен для VPN-like режима.

Схема:

```text
System traffic
        ↓
tun0
        ↓
myclient
        ↓
custom protocol
        ↓
myserver
        ↓
Internet
```

Но не стоит начинать с полноценной L3 VPN-реализации. Практичнее сделать так:

```text
TUN → tun2socks-like module → internal SOCKS/session engine → custom protocol
```

То есть TUN-режим внутри клиента превращает IP-пакеты в TCP/UDP-сессии, а дальше использует ту же логику, что и SOCKS.

Плюсы:

- можно захватывать весь системный трафик;
- удобно для VPN-mode;
- можно делать split tunneling.

Минусы:

- нужны root-права или `CAP_NET_ADMIN`;
- сложнее DNS;
- сложнее UDP;
- важен MTU;
- можно получить routing loop;
- больше сетевых edge cases.

---

## 6. Transparent proxy mode

Отдельный вариант — transparent proxy через `iptables`/`nftables`.

Схема:

```text
App
 ↓
iptables/nftables redirect
 ↓
local transparent inbound
 ↓
myclient
 ↓
custom protocol
 ↓
myserver
```

Проблема: после redirect локальный клиент должен узнать исходный destination. В Linux для этого используют `SO_ORIGINAL_DST`.

Также нужно исключать из перенаправления трафик самого proxy-клиента, иначе будет loop.

Пример концепции:

```bash
sudo iptables -t nat -A OUTPUT \
  -p tcp \
  -m owner ! --uid-owner myproxy \
  -j REDIRECT --to-ports 12345
```

---

## 7. Собственный протокол

Протокол лучше разделить на два уровня:

```text
Transport layer: TLS / HTTP/2 / HTTP/3 / QUIC
Application protocol: CONNECT / UDP / PING / CLOSE / DATA frames
```

Не стоит писать своё шифрование. Лучше использовать стандартный защищённый транспорт, а внутри передавать собственные сообщения.

---

## 8. Минимальные команды протокола

```text
AUTH        — авторизация клиента
CONNECT     — открыть TCP-соединение до target
UDP_OPEN    — создать UDP-сессию
DATA        — передать данные
CLOSE       — закрыть stream/session
PING/PONG   — keepalive
ERROR       — ошибка
```

---

## 9. Пример бинарного фрейма

```text
+---------+----------+-----------+---------+----------+----------+
| VERSION | FRAME_T  | STREAM_ID | FLAGS   | LENGTH   | PAYLOAD  |
| 1 byte  | 1 byte   | 8 bytes   | 2 bytes | 4 bytes  | N bytes  |
+---------+----------+-----------+---------+----------+----------+
```

Поля:

```text
VERSION    = версия протокола
FRAME_T    = тип фрейма: AUTH, CONNECT, DATA, CLOSE...
STREAM_ID  = идентификатор логического соединения
FLAGS      = дополнительные признаки
LENGTH     = размер payload
PAYLOAD    = данные фрейма
```

---

## 10. CONNECT payload

```text
+------+----------+-------------+------+
| CMD  | ADDR_TYP | ADDRESS     | PORT |
+------+----------+-------------+------+
```

Пример:

```text
CMD      = 0x01 TCP_CONNECT
ADDR_TYP = 0x03 DOMAIN
ADDRESS  = example.com
PORT     = 443
```

Смысл:

```text
Клиент → сервер:
открой TCP-соединение до example.com:443
```

Сервер отвечает:

```text
CONNECT_OK stream_id=123
```

После этого обе стороны передают `DATA`-фреймы с этим `stream_id`.

---

## 11. Address types

Нужно поддержать минимум:

```text
0x01 — IPv4
0x03 — DOMAIN
0x04 — IPv6
```

Это похоже на подход SOCKS5.

---

## 12. Авторизация

Минимальная модель:

```text
client_id     = UUID
client_secret = random 32 bytes
```

Но секрет нельзя отправлять напрямую.

Нормальная схема:

```text
1. Клиент подключается по TLS.
2. Сервер присылает nonce.
3. Клиент считает HMAC(client_secret, nonce + timestamp + client_id).
4. Сервер проверяет HMAC.
5. Если всё хорошо — принимает CONNECT/UDP.
```

AUTH payload:

```text
client_id
timestamp
nonce
hmac
capabilities
```

Защита от replay:

```text
timestamp window: например ±60 секунд
nonce cache на сервере
HMAC-SHA256 или BLAKE3 keyed hash
```

Более сильные варианты:

- mTLS;
- Ed25519 challenge-response;
- Noise Protocol;
- TLS client certificates.

Для первого прототипа достаточно:

```text
TLS + UUID + HMAC challenge-response
```

---

## 13. Как сделать соединение похожим на обычный HTTPS

Самый практичный вариант:

```text
custom protocol over HTTP/2 или HTTP/3
```

Например:

```text
Client → https://your-domain.com/api/connect
```

Снаружи это выглядит как обычное TLS-соединение к твоему домену на `443`.

---

## 14. Варианты транспорта

### 14.1. Raw TLS + custom protocol

```text
TCP 443
 ↓
TLS
 ↓
custom binary protocol
```

Плюсы:

- быстро;
- меньше overhead;
- проще, чем HTTP/2.

Минусы:

- может выглядеть нестандартно;
- custom ALPN может fingerprint-иться.

---

### 14.2. WebSocket over TLS

```text
HTTPS
 ↓
WebSocket upgrade
 ↓
custom binary frames
```

Плюсы:

- просто реализовать;
- легко прокидывать через reverse proxy;
- похоже на обычное web-приложение;
- поддерживается Nginx/Caddy.

Минусы:

- больше overhead;
- хуже для высокой скорости;
- WebSocket-трафик можно отличать по поведению.

---

### 14.3. HTTP/2 stream

```text
TLS
 ↓
HTTP/2
 ↓
long-lived POST /api/tunnel
 ↓
binary frames
```

Плюсы:

- похоже на современный HTTPS API;
- есть multiplexing;
- можно использовать стандартный HTTP/2 stack.

Минусы:

- сложнее реализация;
- важно не сломать flow control.

---

### 14.4. HTTP/3 / QUIC

```text
UDP 443
 ↓
QUIC/TLS 1.3
 ↓
HTTP/3
 ↓
custom frames
```

Плюсы:

- хорошо для multiplexing;
- нет TCP-over-TCP проблемы;
- лучше для UDP;
- современный транспорт.

Минусы:

- сложнее;
- UDP 443 не везде стабилен;
- больше нюансов с firewall/NAT.

---

## 15. Практический выбор транспорта

Для MVP:

```text
SOCKS5 inbound
+
custom protocol over WebSocket/TLS
```

Для производительности:

```text
SOCKS5/TUN inbound
+
custom protocol over HTTP/2 or QUIC
```

---

## 16. Fallback web service

Чтобы сервер не выглядел как голый proxy-порт, на домене должен быть нормальный HTTPS-сайт или API.

Пример:

```text
https://your-domain.com/
→ обычная страница

https://your-domain.com/assets/app.js
→ обычный JS

https://your-domain.com/api/status
→ обычный JSON

https://your-domain.com/api/tunnel
→ tunnel endpoint только для авторизованных клиентов
```

Если запрос невалидный:

```text
обычный 404
обычный 403
обычный HTML/JSON-ответ
без proxy-specific ошибок
```

Не стоит делать ответы вида:

```text
ERR invalid proxy auth
VLESS auth failed
bad tunnel request
```

Лучше:

```text
HTTP/1.1 404 Not Found
или
HTTP/1.1 403 Forbidden
```

---

## 17. Routing engine

Пример конфигурации:

```yaml
inbounds:
  socks:
    listen: "127.0.0.1:1080"

  tun:
    enabled: false
    name: "tun0"
    address: "10.10.0.2/24"
    mtu: 1400

outbounds:
  proxy:
    type: "custom"
    server: "your-domain.com"
    port: 443
    transport: "h2"
    tls: true
    path: "/api/tunnel"

  direct:
    type: "direct"

  block:
    type: "block"

routing:
  rules:
    - domain_suffix: ".local"
      outbound: "direct"

    - cidr: "10.0.0.0/8"
      outbound: "direct"

    - cidr: "192.168.0.0/16"
      outbound: "direct"

    - port: 22
      outbound: "direct"

    - domain_suffix: ".example.org"
      outbound: "proxy"

    - default: true
      outbound: "proxy"
```

Логика:

```text
1. Клиент получает target host/IP/port.
2. Проверяет правила сверху вниз.
3. direct → подключается напрямую.
4. proxy → отправляет CONNECT на сервер.
5. block → закрывает соединение.
```

---

## 18. DNS

DNS нужно продумать отдельно, иначе будут DNS leaks.

### 18.1. SOCKS mode

Для SOCKS нужно поддерживать remote DNS.

Правильно:

```text
приложение передаёт домен в SOCKS5
клиент передаёт домен серверу
сервер сам резолвит target
```

Например:

```text
CONNECT example.com:443
```

Нежелательный вариант:

```text
локальный DNS → IP
CONNECT 93.184.216.34:443
```

В `curl`:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

А не:

```bash
curl --socks5 127.0.0.1:1080 https://example.com
```

---

### 18.2. TUN mode

В TUN-режиме можно сделать:

```text
1. Поднять локальный DNS listener: 127.0.0.1:5353 или fake DNS.
2. Перехватывать DNS-запросы.
3. Резолвить через remote DNS на сервере.
4. Сохранять mapping domain → fake IP.
5. Когда трафик идёт на fake IP, восстанавливать original domain.
```

Упрощённый вариант:

```text
TUN mode → весь DNS тоже через tunnel
```

---

## 19. Сервер как proxy/VPN и смена IP

Сервер может менять внешний IP несколькими способами.

---

### 19.1. Несколько серверов

```text
client
 ├── server-1: Germany
 ├── server-2: Netherlands
 ├── server-3: Finland
 └── server-4: USA
```

Клиент выбирает outbound node по правилам.

Пример:

```yaml
routing:
  rules:
    - domain_suffix: ".de"
      outbound: "proxy_de"

    - domain_suffix: ".nl"
      outbound: "proxy_nl"

    - default: true
      outbound: "proxy_fi"
```

---

### 19.2. Один сервер с несколькими egress IP

На сервере может быть несколько IP-адресов:

```text
eth0: 203.0.113.10
eth0: 203.0.113.11
eth0: 203.0.113.12
```

Сервер при исходящем подключении выбирает source IP.

В Linux это можно делать через:

- policy routing;
- `SO_BINDTODEVICE`;
- `bind()` к конкретному source IP;
- `iptables`/`nftables` SNAT.

---

### 19.3. Egress pool

```text
myserver
 ├── direct egress
 ├── upstream proxy 1
 ├── upstream proxy 2
 └── upstream WireGuard tunnel
```

Сервер принимает твой протокол, а дальше выбирает, куда выпустить трафик.

---

## 20. UDP

TCP проще. UDP сложнее.

Для UDP нужен session mapping:

```text
client UDP socket/app
        ↓
client creates UDP session_id
        ↓
UDP_DATA frame
        ↓
server sends UDP packet to target
        ↓
server receives response
        ↓
UDP_DATA frame back
        ↓
client returns packet to app
```

UDP frame:

```text
SESSION_ID
TARGET_ADDR
TARGET_PORT
PAYLOAD
```

Для QUIC-based транспорта UDP реализуется естественнее.

Для WebSocket/TCP-транспорта UDP будет работать, но это будет UDP-over-TCP, что может плохо влиять на latency.

---

## 21. Multiplexing

Можно сделать одно соединение client → server и внутри него много stream'ов:

```text
TLS connection
 ├── stream_id=1 → example.com:443
 ├── stream_id=2 → api.site.com:443
 ├── stream_id=3 → 1.1.1.1:53 UDP
 └── stream_id=4 → ssh.example.com:22
```

Плюсы:

- меньше TLS handshakes;
- быстрее открытие новых соединений;
- удобно для HTTP/2/QUIC.

Минусы:

- сложнее flow control;
- один плохой stream может влиять на другие;
- в TCP-транспорте возможен head-of-line blocking.

Для MVP можно начать без multiplexing:

```text
1 local connection = 1 remote tunnel connection
```

Потом добавить multiplexing.

---

## 22. Потери скорости от локального SOCKS inbound

Локальный SOCKS inbound может добавить небольшой overhead:

```text
1. SOCKS handshake
2. локальное TCP-соединение application → proxy client
3. парсинг адреса назначения
4. relay данных между двумя socket'ами
```

Но это происходит через `127.0.0.1`, поэтому overhead обычно минимальный.

Основные потери скорости чаще возникают из-за:

- удалённого сервера;
- маршрута до сервера;
- транспорта: WebSocket/gRPC/TLS/REALITY-like;
- шифрования;
- MTU;
- DNS/CDN;
- количества соединений;
- UDP-over-TCP;
- плохой реализации relay.

TUN не обязательно быстрее SOCKS. TUN нужен скорее для системного захвата трафика, split tunneling и VPN-like поведения.

---

## 23. Рекомендуемый roadmap

### Этап 1 — MVP TCP proxy

Клиент:

```text
SOCKS5 inbound
CONNECT parsing
custom CONNECT to server
```

Сервер:

```text
auth
TCP connect to target
relay
```

Transport:

```text
TLS + WebSocket
```

Почему WebSocket:

- быстро собрать;
- легко тестировать;
- можно посадить за Caddy/Nginx;
- удобно сделать fallback на обычный сайт.

---

### Этап 2 — routing + DNS

Добавить:

```text
domain rules
CIDR rules
port rules
remote DNS
direct/proxy/block
```

---

### Этап 3 — HTTP/2 или QUIC transport

После MVP можно заменить WebSocket на:

```text
HTTP/2 long-lived stream
или
HTTP/3/QUIC
```

---

### Этап 4 — TUN mode

Не писать TUN сразу с нуля. Лучше:

```text
TUN → tun2socks-like engine → existing SOCKS/session core
```

Так можно переиспользовать уже работающую proxy-логику.

---

### Этап 5 — UDP

Добавить:

```text
UDP ASSOCIATE для SOCKS5
UDP sessions
remote UDP relay
DNS over tunnel
```

---

### Этап 6 — egress IP selection

На сервере:

```text
per-user egress
per-domain egress
random egress
sticky session egress
```

Для авторизованных сайтов лучше использовать sticky egress, иначе смена IP может ломать сессии.

---

## 24. Рекомендуемый стек

### 24.1. Rust

Хороший выбор, если нужна производительность и контроль.

Библиотеки:

```text
tokio                 — async runtime
rustls                — TLS
hyper                 — HTTP/1.1 / HTTP/2
h2                    — low-level HTTP/2
tokio-tungstenite     — WebSocket
quinn                 — QUIC
tun                   — TUN interface
hickory-dns           — DNS
bytes                 — byte buffers
serde / serde_yaml    — config
tracing               — logging
```

### 24.2. Go

Проще для сетевых прототипов.

Библиотеки / пакеты:

```text
net
net/http
x/net/http2
nhooyr/websocket или gorilla/websocket
quic-go
water для TUN
miekg/dns
zap / zerolog
```

Если цель — быстро получить рабочую версию, Go проще.  
Если цель — долгосрочная производительность, безопасность памяти и контроль, Rust хорош, но разработка будет дольше.

---

## 25. Минимальный протокол v1

Рекомендуемый v1:

```text
Transport:
  TLS + WebSocket или HTTP/2

Auth:
  client_id + HMAC challenge-response

Commands:
  TCP_CONNECT
  TCP_DATA
  TCP_CLOSE
  UDP_OPEN
  UDP_DATA
  PING
  ERROR

Address types:
  IPv4
  IPv6
  DOMAIN

Routing:
  на клиенте

DNS:
  remote DNS by default
```

---

## 26. Логика TCP-соединения

```text
1. App подключается к SOCKS5 127.0.0.1:1080.
2. Client получает target: example.com:443.
3. Routing решает: proxy.
4. Client открывает TLS/WebSocket до your-domain.com/api/tunnel.
5. Client проходит AUTH.
6. Client отправляет TCP_CONNECT example.com:443.
7. Server подключается к example.com:443.
8. Server отвечает CONNECT_OK.
9. Client и server гоняют DATA-фреймы.
10. При закрытии отправляется CLOSE.
```

---

## 27. Ограничения маскировки

Нельзя гарантированно скрыть факт прокси от всех наблюдателей. Даже если транспорт выглядит как HTTPS, остаются косвенные признаки:

- длинные постоянные соединения;
- объём трафика;
- паттерны packet size/timing;
- отсутствие обычного поведения браузера;
- TLS fingerprint клиента;
- SNI/ALPN;
- репутация IP сервера;
- поведение endpoint'а при active probing;
- необычные ответы сервера;
- слишком стабильные long-lived туннели.

Более реалистичная цель:

```text
не открытый SOCKS/VPN-порт,
а обычный TLS/HTTPS-сервис с авторизованным tunnel endpoint'ом
```

---

## 28. Финальная рекомендуемая реализация

MVP:

```text
Client:
  - SOCKS5 inbound 127.0.0.1:1080
  - routing engine
  - remote DNS
  - custom binary protocol over WebSocket/TLS

Server:
  - HTTPS 443
  - normal web fallback
  - /api/tunnel endpoint
  - HMAC auth
  - TCP relay
  - logs/metrics
```

Следующие этапы:

```text
- HTTP/2 transport
- UDP relay
- TUN mode через tun2socks-like engine
- multiple egress IPs
- QUIC transport
- multiplexing
```

Финальная схема:

```text
Browser / App / System
        ↓
SOCKS5 or TUN inbound
        ↓
myclient routing engine
        ↓
custom protocol over HTTPS / HTTP/2 / QUIC
        ↓
myserver on 443
        ↓
selected egress IP
        ↓
target site
```

Самая здравая первая версия:

```text
SOCKS5 inbound → custom CONNECT protocol → WebSocket/TLS → server TCP relay
```

После того как это стабильно работает, можно добавлять:

```text
TUN
UDP
QUIC
multiplexing
egress IP selection
advanced DNS
```

---

## 29. Краткое сравнение с VLESS и SOCKS5

### SOCKS5

```text
Application → SOCKS5 proxy → Target
```

SOCKS5 — это локальный/прикладной proxy-протокол. Приложение говорит прокси:

```text
подключи меня к host:port
```

### VLESS-like подход

```text
Application
 ↓
local SOCKS/TUN inbound
 ↓
client routing
 ↓
VLESS-like outbound protocol
 ↓
remote server
 ↓
Target
```

VLESS-like протокол — это протокол между локальным proxy-клиентом и удалённым proxy-сервером.

Практичная архитектура:

```text
локально — SOCKS5/TUN для совместимости и захвата трафика
между клиентом и сервером — свой VLESS-like протокол
снаружи — TLS/HTTP2/QUIC/WebSocket transport
```
