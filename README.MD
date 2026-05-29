# Shroud

Shroud is an experimental Rust client/server tunneling project.

The current implementation provides local client inbounds, an authenticated tunnel transport to a remote server, and server-side TCP/UDP relay to the requested target. The main stable path is **SOCKS5 TCP CONNECT over an HTTP/1.1 Upgrade tunnel**, optionally protected by TLS. SOCKS TCP can run either as one tunnel connection per TCP stream or through an experimental persistent multiplexed tunnel. SOCKS5 `UDP ASSOCIATE` is implemented for proxied UDP datagrams on the non-multiplexed tunnel path.

The project also contains an early Linux **TUN mode** backed by `netstack-smoltcp`. TUN currently targets controlled beta/smoke-test scenarios and is not yet a full VPN replacement.

## Current status

### Implemented

- Rust workspace with three crates:
  - `shroud-core` — shared config, auth and frame protocol code;
  - `shroud-client` — local SOCKS5/TUN client and tunnel outbound;
  - `shroud-server` — HTTP/TLS listener, auth validation, static fallback and TCP/UDP relay.
- SOCKS5 inbound:
  - no-auth SOCKS5 handshake;
  - `CONNECT` command;
  - `UDP ASSOCIATE` command;
  - IPv4, IPv6 and domain targets;
  - TCP relay;
  - UDP datagram relay through the tunnel for `proxy` routes;
  - UDP endpoint validation against the TCP control connection and the client's declared UDP endpoint;
  - fragmented SOCKS UDP packets are dropped.
- Tunnel transport:
  - HTTP/1.1 `Upgrade: shroud-tunnel`;
  - optional TLS;
  - custom framed protocol;
  - max frame payload size: `64 KiB`;
  - oversized frame rejection before payload allocation;
  - TCP stream frames;
  - UDP association and UDP datagram frames.
- TCP multiplexing:
  - optional client-side `outbound.multiplex`;
  - optional server-side `multiplex.enabled`;
  - configurable pool of persistent physical tunnels via `outbound.multiplex_tunnels`;
  - per-tunnel stream soft limit via `outbound.max_streams_per_tunnel`;
  - logical TCP streams use odd client-allocated `stream_id` values;
  - per-stream `TcpConnect`, `TcpData`, `TcpClose` and `ErrorFrame` dispatch;
  - client waits for server `TcpConnect` success before completing SOCKS `CONNECT`;
  - server-side stream state tracks client/target close direction and ignores late `TcpData` for closing streams;
  - separate control/data writer queues prioritize connect, close, error and keepalive frames over data frames;
  - pressure-aware tunnel selection uses active stream count plus recent writer wait;
  - client keepalive `Ping` / server `Pong` and reconnect of broken persistent tunnels;
  - active-stream, target, tunnel, close-reason and writer-queue pressure logging.
- Authentication:
  - `client_id` / `client_secret` based auth header;
  - timestamp validation;
  - nonce replay protection;
  - credential generation command.
- Routing:
  - `proxy`, `direct`, `block` actions;
  - exact domain rules;
  - domain suffix rules;
  - CIDR rules for IP targets;
  - port rules;
  - first matching rule wins.
- DNS policy checks:
  - domain targets are preserved for remote resolution when possible;
  - IP targets can be warned about or blocked;
  - useful for detecting local DNS resolution / DNS leak risk in SOCKS usage.
- Server web behavior:
  - `GET /api/status` health endpoint;
  - static fallback from `web_root`;
  - minimal diagnostic exposure.
- Server relay:
  - TCP connect and relay to requested targets;
  - UDP association bind;
  - UDP datagram send/receive with source address preserved in response datagrams.
- TUN mode:
  - Linux TUN device creation through `/dev/net/tun`;
  - no packet information header (`IFF_NO_PI`);
  - interface setup and optional route setup;
  - TCP packet handling through `netstack-smoltcp`;
  - Fake DNS listener for A records;
  - fake IPv4 mapping from `198.18.0.0/15`;
  - fake IP back-mapping to the original domain for observed TCP connections;
  - Linux namespace smoke test script.
- Tests:
  - protocol encode/decode tests;
  - routing unit tests;
  - config validation tests;
  - SOCKS/TLS tunnel integration tests;
  - SOCKS UDP ASSOCIATE integration test;
  - server-side UDP relay integration test;
  - multiplexed tunnel unit tests and an ignored multi-stream socket test;
  - large payload relay test;
  - half-close behavior test;
  - timeout/error-path tests;
  - ignored Linux TUN smoke test.

### Not implemented yet

- Direct UDP routing from the SOCKS inbound.
- TUN UDP forwarding.
- Browser DoH/DoT interception.
- Multiplexed UDP associations.
- Per-stream multiplex flow control.
- Benchmark-driven multiplex frame-size tuning.
- WebSocket transport.
- HTTP/2 transport.
- QUIC / HTTP/3 transport.
- Server-side egress IP selection.
- Automatic system DNS switching for TUN mode.

## Architecture

```text
Application / curl / browser
        |
        | SOCKS5 or TUN
        v
shroud-client
        |
        | HTTP/1.1 Upgrade + Shroud frames
        | optional TLS
        | optional TCP multiplexing
        v
shroud-server
        |
        | TCP connect / relay
        | UDP send / receive
        v
Target host
```

Workspace layout:

```text
.
├── Cargo.toml
├── configs/
│   ├── client.yaml
│   └── server.yaml
├── crates/
│   ├── shroud-core/
│   ├── shroud-client/
│   └── shroud-server/
├── scripts/
│   └── tun-smoke-linux.sh
└── web/
    └── index.html
```

## Requirements

- Rust toolchain compatible with edition `2024`.
- `cargo`.
- `curl` for manual smoke checks.
- Linux for TUN mode.
- Root privileges for TUN smoke tests.
- Linux tools for TUN smoke tests:
  - `ip`;
  - `python3`;
  - `/dev/net/tun`.

## Configuration

Example client config:

```yaml
inbounds:
  socks:
    enabled: true
    listen: "127.0.0.1:1080"

  tun:
    enabled: false
    name: "shroud0"
    address: "10.10.0.2/24"
    mtu: 1400
    auto_route: false
    dns: "127.0.0.1"

outbound:
  server: "127.0.0.1"
  port: 8443
  path: "/api/tunnel"
  tls: true
  tls_server_name: "localhost"
  tls_ca_cert_path: "certs/ca.crt"
  multiplex: true
  multiplex_tunnels: 4
  max_streams_per_tunnel: 16
  keepalive_interval_secs: 20
  keepalive_timeout_secs: 10

auth:
  client_id: "11111111-1111-1111-1111-111111111111"
  client_secret: "replace-with-random-secret"

dns:
  remote_by_default: true
  warn_on_ip_targets: true
  block_ip_targets: false

routing:
  default: "proxy"
  rules:
    - action: "direct"
      domain: "localhost"
    - action: "direct"
      domain_suffix: ".local"
    - action: "direct"
      cidr: "127.0.0.0/8"
    - action: "direct"
      port: 22
```

Example server config:

```yaml
listen: "0.0.0.0:8443"
tunnel_path: "/api/tunnel"
web_root: "./web"
tls:
  enabled: true
  cert_path: "certs/localhost.crt"
  key_path: "certs/localhost.key"
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "replace-with-random-secret"
multiplex:
  enabled: true
```

The checked-in example configs expect certificate files under `certs/` relative to the workspace root. If that directory is absent, either create/copy development certificates there or change the paths in `configs/client.yaml` and `configs/server.yaml`.

`outbound.multiplex` and `multiplex.enabled` must be configured consistently for the intended tunnel mode. The checked-in configs enable the experimental TCP multiplexed mode.

## Generate client credentials

```bash
cargo run -p shroud-server -- generate-credentials
```

or:

```bash
cargo run -p shroud-client -- generate-credentials
```

The command prints:

```yaml
client_id: "..."
client_secret: "..."
```

Put the same pair into:

- `auth.client_id` / `auth.client_secret` in the client config;
- `clients[].client_id` / `clients[].client_secret` in the server config.

## Run

Start the server:

```bash
cargo run -p shroud-server -- configs/server.yaml
```

Start the server with Docker Compose:

```bash
docker compose up --build shroud-server
```

The compose service mounts these host paths read-only into the container:

- `configs/server.yaml` -> `/app/configs/server.yaml`;
- `certs/` -> `/app/certs/`;
- `web/` -> `/app/web/`.

The default server config uses relative paths under `/app`, so `tls.cert_path: "certs/localhost.crt"`,
`tls.key_path: "certs/localhost.key"` and `web_root: "./web"` work unchanged in the container.
Generate or copy the TLS files described in `certs/README.md` before starting the service.

Start the client:

```bash
cargo run -p shroud-client -- configs/client.yaml
```

By default, both binaries use the default config path when no config argument is provided:

```bash
cargo run -p shroud-server
cargo run -p shroud-client
```

## Health check

For TLS with a development CA:

```bash
curl --cacert certs/ca.crt https://localhost:8443/api/status
```

Expected response:

```json
{"status":"ok"}
```

For local testing with certificate verification disabled:

```bash
curl -k https://localhost:8443/api/status
```

## SOCKS5 smoke test

Make sure SOCKS is enabled and TUN is disabled in the client config:

```yaml
inbounds:
  socks:
    enabled: true
    listen: "127.0.0.1:1080"
  tun:
    enabled: false
```

Run server and client, then test:

```bash
curl -v --socks5-hostname 127.0.0.1:1080 https://example.com/
```

Use `--socks5-hostname`, not `--socks5`, when you want the domain name to be sent through the tunnel and resolved remotely by the server side.

This is the primary MVP scenario.

### SOCKS5 TCP multiplexing

TCP multiplexing is available for SOCKS5 `CONNECT` proxy routes. When enabled, the client opens a pool of persistent physical HTTP Upgrade tunnels and sends logical TCP streams over them using distinct `stream_id` values per tunnel.

Enable it on the client:

```yaml
outbound:
  multiplex: true
  multiplex_tunnels: 4
  max_streams_per_tunnel: 16
  keepalive_interval_secs: 20
  keepalive_timeout_secs: 10
```

Enable the matching server relay mode:

```yaml
multiplex:
  enabled: true
```

Current behavior:

- applies to proxied SOCKS TCP connections;
- uses `outbound.multiplex_tunnels` persistent physical tunnels per client process, defaulting to 4;
- chooses a connected tunnel by pressure score: active streams plus recent writer wait, with `outbound.max_streams_per_tunnel` defaulting to 16 before fallback to the least-pressured connected tunnel;
- creates logical streams with odd client-side `stream_id` values;
- dispatches `TcpConnect`, `TcpData`, `TcpClose` and `ErrorFrame` per logical stream;
- uses separate control/data writer queues so control frames are preferred over `TcpData`, with periodic control checks after bounded data bursts;
- sends client keepalive `Ping` frames and reconnects a broken persistent tunnel while excluding disconnected tunnels from new stream selection;
- logs active stream counts and writer-channel send waits when the writer queue is under pressure.

Current limitations:

- no multiplexed UDP associations;
- no per-stream flow control yet.

Because the server chooses either the multiplexed relay or the non-multiplexed relay for the tunnel path, SOCKS5 `UDP ASSOCIATE` currently requires the non-multiplexed server mode. Disable both `outbound.multiplex` and `multiplex.enabled` when testing UDP ASSOCIATE.

### SOCKS5 UDP ASSOCIATE

SOCKS5 `UDP ASSOCIATE` is supported for UDP clients that use the SOCKS5 UDP request header format.

Behavior:

- Shroud binds a local UDP socket and returns its address in `BND.ADDR` / `BND.PORT`;
- the TCP SOCKS control connection stays open for the lifetime of the UDP association;
- UDP packets are accepted only from the expected client UDP endpoint;
- SOCKS UDP headers are decoded locally and encoded again for responses;
- `proxy` routes are sent through the tunnel as `UdpDatagram` frames;
- `block` routes are dropped;
- `direct` routes are currently dropped because direct UDP relay is not implemented yet.

This is covered by the `socks_udp_associate_relays_datagrams_through_tunnel` integration test.

## DNS leak notes

For SOCKS usage:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

preserves `example.com` and sends the domain through the tunnel.

This form:

```bash
curl --socks5 127.0.0.1:1080 https://example.com/
```

may resolve the domain locally before sending an IP target to the SOCKS proxy. In that case Shroud can warn about an IP target and can optionally block it with:

```yaml
dns:
  block_ip_targets: true
```

For TUN usage, Fake DNS only works when the system resolver actually sends DNS queries to the Shroud Fake DNS listener. The current implementation does not automatically switch the system DNS server.

DoH/DoT configured inside a browser is not intercepted by the current Fake DNS listener.

## TUN mode

TUN mode is Linux-only and currently beta-level.

Enable it in the client config:

```yaml
inbounds:
  socks:
    enabled: false
  tun:
    enabled: true
    name: "shroud0"
    address: "10.10.0.2/24"
    mtu: 1400
    auto_route: false
    dns: "127.0.0.1"
```

With `auto_route: false`, Shroud opens and configures the TUN interface, but system traffic will not automatically use it.

With `auto_route: true`, Shroud attempts to move the default route through the TUN interface and adds loop-protection for the tunnel server endpoint. Use this only in controlled test environments until the TUN mode is more mature.

### Fake DNS with TUN

Fake DNS is started only when TUN mode is enabled. It listens on UDP port `53` at `inbounds.tun.dns`. If `dns` is omitted, the listener defaults to `127.0.0.1:53`.

`inbounds.tun.dns` does not install DNS into the operating system. It only chooses the address Shroud binds for the Fake DNS listener. The system resolver must be pointed at that address manually while the client is running.

Current Fake DNS behavior:

- handles only UDP DNS `A` queries;
- returns fake IPv4 addresses from `198.18.0.0/15`;
- keeps an in-memory mapping from domain to fake IP;
- when the TUN TCP stack later observes a connection to that fake IP, Shroud maps it back to the original domain and sends the domain through the tunnel;
- if the destination IP was not allocated by Fake DNS, Shroud treats it as a plain IP target.

Recommended local beta setup:

```yaml
inbounds:
  tun:
    enabled: true
    name: "shroud0"
    address: "10.10.0.2/24"
    mtu: 1400
    auto_route: true
    dns: "127.0.0.1"
```

Then manually point the host resolver to `127.0.0.1` for the test session. The exact command depends on the Linux resolver stack. For `systemd-resolved`, one temporary per-link option is:

```bash
sudo resolvectl dns shroud0 127.0.0.1
sudo resolvectl domain shroud0 '~.'
```

For systems that use `/etc/resolv.conf` directly, the equivalent test change is:

```text
nameserver 127.0.0.1
```

Restore the previous DNS settings after stopping Shroud. Shroud currently does not save, replace, or restore system DNS configuration.

If you configure `inbounds.tun.dns` to a non-loopback address, that address must be local and bindable by the client process before the Fake DNS task starts. For example, using `10.10.0.53` requires you to arrange that address yourself; Shroud does not add it automatically. Binding to an address that is not present on the host can make the Fake DNS listener fail to start.

Current TUN limitations:

- TCP only;
- no UDP forwarding;
- no automatic system DNS switching;
- Fake DNS only works if the system resolver is pointed at the Fake DNS listen address;
- browser DoH/DoT bypasses Fake DNS;
- QUIC/HTTP3 traffic is not supported through TUN yet.

## TUN smoke test

The Linux TUN smoke test creates isolated network namespaces, starts a local server/client pair and verifies that `curl` reaches a target through the TUN path.

Run:

```bash
sudo ./scripts/tun-smoke-linux.sh
```

If binaries are already built:

```bash
cargo build -p shroud-client -p shroud-server
sudo SHROUD_SMOKE_BUILD=0 ./scripts/tun-smoke-linux.sh
```

Expected success message:

```text
PASS: curl reached 198.51.100.10:18080 through shroudsm0 and Shroud tunnel
```

The script requires:

- root privileges;
- `curl`;
- `ip`;
- `python3`;
- `/dev/net/tun`.

## Tests

Run the regular test suite:

```bash
cargo test --workspace
```

Run the ignored Linux TUN smoke test through Cargo:

```bash
sudo cargo test -p shroud-client --test tun_smoke_linux -- --ignored
```

The TUN smoke test is ignored by default because it requires Linux root privileges and modifies network namespaces/routes.

## Protocol summary

In non-multiplexed mode, each tunnel connection carries either one TCP stream or one UDP association.

In multiplexed mode, each persistent tunnel connection carries multiple logical TCP streams. The client can open a pool of persistent tunnels and schedules new streams across connected tunnels. UDP associations are not multiplexed yet.

Frame header:

```text
version:   u8
kind:      u8
stream_id: u64
flags:     u16
length:    u32
payload:   [u8; length]
```

Important frame types:

- `TcpConnect` — request or acknowledge a target TCP connection;
- `TcpData` — relay TCP payload;
- `TcpClose` — half-close / close notification;
- `UdpAssociateRequest` — request a remote UDP association;
- `UdpAssociateResponse` — acknowledge the UDP association and return the remote UDP bind address;
- `UdpDatagram` — relay one UDP datagram with target/source address metadata;
- `ErrorFrame` — report tunnel or target connection failure;
- `Ping` / `Pong` — keepalive frames for persistent multiplexed tunnels; the client sends `Ping`, the server responds with `Pong`, and the client reconnects a tunnel when keepalive fails.

Current hard limit:

```text
MAX_FRAME_PAYLOAD_LEN = 64 KiB
```

## Security notes

- Use TLS in production.
- Use a valid public CA certificate or configure `tls_ca_cert_path` for a private CA.
- Treat `client_secret` as a password.
- Do not commit real secrets.
- Restrict permissions on config files containing secrets.
- Keep `GET /api/status` minimal; it intentionally does not expose routing, auth or client details.
- Do not expose tunnel internals through fallback pages or error responses.

## Roadmap

### MVP stabilization

- Keep SOCKS5 TCP CONNECT as the main stable path.
- Keep SOCKS5 UDP ASSOCIATE covered by integration tests and harden edge cases.
- Continue stabilizing TCP multiplexing under browser/video workloads:
  - benchmark `multiplex_tunnels=1/2/4/6` and tune defaults from measured writer waits;
  - track late/unknown `TcpData` frequency under load;
  - add per-stream or per-host throughput summaries where useful.
- Keep HTTP/1.1 Upgrade transport until the TCP MVP is fully stable.
- Continue hardening timeouts, frame validation and relay edge cases.
- Keep `cargo test --workspace` as the default quality gate.

### TUN usable beta

- Validate `auto_route` in Linux namespaces.
- Add startup diagnostics for:
  - TUN interface name/address;
  - `auto_route` status;
  - Fake DNS listen address;
  - detected system DNS;
  - DNS leak risk.
- Decide DNS behavior:
  - either automatic system DNS switch when `tun.auto_route = true`;
  - or explicit manual setup documented as the supported beta behavior.
- Clearly keep TUN marked as TCP-only until UDP forwarding exists.

### Post-MVP

- WebSocket over TLS transport.
- Direct UDP routing from the SOCKS inbound.
- TUN UDP forwarding.
- HTTP/2 transport.
- QUIC / HTTP/3 transport.
- Multiplex per-stream flow control and deeper fairness tuning.
- Multiplexed UDP associations.
- Egress IP / exit selection.
- Better operational observability.

## Development notes

Useful commands:

```bash
cargo fmt
cargo clippy --workspace --all-targets
cargo test --workspace
cargo build -p shroud-client -p shroud-server
```

For verbose logs:

```bash
RUST_LOG=debug cargo run -p shroud-client -- configs/client.yaml
RUST_LOG=debug cargo run -p shroud-server -- configs/server.yaml
```
