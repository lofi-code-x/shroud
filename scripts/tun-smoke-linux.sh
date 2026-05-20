#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CLIENT_NS="shroud-smoke-client-$$"
SERVER_NS="shroud-smoke-server-$$"
CLIENT_VETH="shc$$"
SERVER_VETH="shs$$"
CLIENT_IP="10.250.0.2"
SERVER_IP="10.250.0.1"
TARGET_IP="198.51.100.10"
SERVER_PORT="18443"
TARGET_PORT="18080"
TUN_NAME="shroudsm0"
TUN_ADDR="10.10.0.2/24"
EXPECTED_BODY="shroud tun smoke ok"
TMP_DIR="$(mktemp -d /tmp/shroud-tun-smoke.XXXXXX)"

SERVER_PID=""
TARGET_PID=""
CLIENT_PID=""

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

cleanup() {
    set +e
    for pid in "$CLIENT_PID" "$SERVER_PID" "$TARGET_PID"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" >/dev/null 2>&1
            wait "$pid" >/dev/null 2>&1
        fi
    done
    ip netns del "$CLIENT_NS" >/dev/null 2>&1
    ip netns del "$SERVER_NS" >/dev/null 2>&1
    rm -rf "$TMP_DIR"
}

on_exit() {
    local status=$?
    if [[ "$status" -ne 0 ]]; then
        dump_logs
    fi
    cleanup
    exit "$status"
}

wait_for_url() {
    local ns="$1"
    local url="$2"
    local curl_args=("--noproxy" "*" "-fsS" "--max-time" "1")
    if [[ "$url" == https://* ]]; then
        curl_args+=("-k")
    fi

    for _ in $(seq 1 100); do
        if ip netns exec "$ns" curl "${curl_args[@]}" "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done

    echo "timed out waiting for $url in namespace $ns" >&2
    return 1
}

wait_for_tun() {
    for _ in $(seq 1 100); do
        if ip -n "$CLIENT_NS" link show "$TUN_NAME" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done

    echo "timed out waiting for TUN interface $TUN_NAME" >&2
    return 1
}

wait_for_tun_route() {
    for _ in $(seq 1 100); do
        if ip -n "$CLIENT_NS" route show default 2>/dev/null | grep -q "dev ${TUN_NAME}"; then
            return 0
        fi
        sleep 0.1
    done

    echo "timed out waiting for default route through $TUN_NAME" >&2
    return 1
}

dump_logs() {
    echo "----- client routes -----" >&2
    ip -n "$CLIENT_NS" addr show >&2 || true
    ip -n "$CLIENT_NS" route show >&2 || true
    echo "----- server.log -----" >&2
    sed -n '1,200p' "$TMP_DIR/server.log" >&2 || true
    echo "----- target.log -----" >&2
    sed -n '1,200p' "$TMP_DIR/target.log" >&2 || true
    echo "----- client.log -----" >&2
    sed -n '1,240p' "$TMP_DIR/client.log" >&2 || true
}

if [[ "${EUID}" -ne 0 ]]; then
    echo "this smoke test must run as root because it creates network namespaces and TUN devices" >&2
    exit 1
fi

require_cmd curl
require_cmd ip
require_cmd python3

if [[ ! -e /dev/net/tun ]]; then
    echo "/dev/net/tun is missing; load the tun module or enable TUN support first" >&2
    exit 1
fi

trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "${SHROUD_SMOKE_BUILD:-1}" == "1" ]]; then
    require_cmd cargo
    cargo build -p shroud-client -p shroud-server
fi

SERVER_BIN="$ROOT_DIR/target/debug/shroud-server"
CLIENT_BIN="$ROOT_DIR/target/debug/shroud-client"
if [[ ! -x "$SERVER_BIN" || ! -x "$CLIENT_BIN" ]]; then
    echo "expected built binaries at target/debug/shroud-server and target/debug/shroud-client" >&2
    exit 1
fi

mkdir -p "$TMP_DIR/target"
printf '%s\n' "$EXPECTED_BODY" > "$TMP_DIR/target/index.html"

SERVER_CFG="$TMP_DIR/server.yaml"
CLIENT_CFG="$TMP_DIR/client.yaml"

cat > "$SERVER_CFG" <<YAML
listen: "0.0.0.0:${SERVER_PORT}"
tunnel_path: "/api/tunnel"
web_root: "${ROOT_DIR}/web"
tls:
  enabled: true
  cert_path: "${ROOT_DIR}/certs/localhost.crt"
  key_path: "${ROOT_DIR}/certs/localhost.key"
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "replace-with-random-secret"
YAML

cat > "$CLIENT_CFG" <<YAML
inbounds:
  tun:
    enabled: true
    name: "${TUN_NAME}"
    address: "${TUN_ADDR}"
    mtu: 1400
    auto_route: true
    dns: "127.0.0.1"

outbound:
  server: "${SERVER_IP}"
  port: ${SERVER_PORT}
  path: "/api/tunnel"
  tls: true
  tls_server_name: "localhost"
  tls_ca_cert_path: "${ROOT_DIR}/certs/ca.crt"

auth:
  client_id: "11111111-1111-1111-1111-111111111111"
  client_secret: "replace-with-random-secret"

dns:
  remote_by_default: true
  warn_on_ip_targets: true
  block_ip_targets: false

routing:
  default: "proxy"
  rules: []
YAML

ip netns add "$CLIENT_NS"
ip netns add "$SERVER_NS"
ip link add "$CLIENT_VETH" type veth peer name "$SERVER_VETH"
ip link set "$CLIENT_VETH" netns "$CLIENT_NS"
ip link set "$SERVER_VETH" netns "$SERVER_NS"

ip -n "$CLIENT_NS" link set lo up
ip -n "$SERVER_NS" link set lo up
ip -n "$CLIENT_NS" addr add "${CLIENT_IP}/24" dev "$CLIENT_VETH"
ip -n "$SERVER_NS" addr add "${SERVER_IP}/24" dev "$SERVER_VETH"
ip -n "$SERVER_NS" addr add "${TARGET_IP}/32" dev lo
ip -n "$CLIENT_NS" link set "$CLIENT_VETH" up
ip -n "$SERVER_NS" link set "$SERVER_VETH" up

ip netns exec "$SERVER_NS" "$SERVER_BIN" "$SERVER_CFG" > "$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

ip netns exec "$SERVER_NS" \
    python3 -m http.server "$TARGET_PORT" --bind "$TARGET_IP" --directory "$TMP_DIR/target" \
    > "$TMP_DIR/target.log" 2>&1 &
TARGET_PID=$!

wait_for_url "$CLIENT_NS" "https://${SERVER_IP}:${SERVER_PORT}/"
wait_for_url "$SERVER_NS" "http://${TARGET_IP}:${TARGET_PORT}/"

RUST_LOG="${RUST_LOG:-info}" ip netns exec "$CLIENT_NS" "$CLIENT_BIN" "$CLIENT_CFG" \
    > "$TMP_DIR/client.log" 2>&1 &
CLIENT_PID=$!

wait_for_tun
wait_for_tun_route

RESPONSE="$(
    ip netns exec "$CLIENT_NS" \
        curl --noproxy "*" -fsS --max-time 10 "http://${TARGET_IP}:${TARGET_PORT}/"
)"

if [[ "$RESPONSE" != *"$EXPECTED_BODY"* ]]; then
    echo "unexpected target response through TUN:" >&2
    printf '%s\n' "$RESPONSE" >&2
    exit 1
fi

sleep 0.2
if ! grep -q "accepted TUN TCP stream from smoltcp netstack" "$TMP_DIR/client.log"; then
    echo "curl succeeded, but client log does not show the smoltcp-backed TUN TCP path" >&2
    exit 1
fi

echo "PASS: curl reached ${TARGET_IP}:${TARGET_PORT} through ${TUN_NAME} and Shroud tunnel"
