#!/usr/bin/env bash
#
# public-infra-smoke.sh -- prove rendezvous, STUN, optional TURN allocation,
# and end-to-end PQC relay fallback against a QuantumLink edge.
#
# Local mode starts qlinkctl rendezvous/relay/STUN on loopback. Public mode
# points at an already deployed edge and leaves those services untouched.
#
# Examples:
#   scripts/public-infra-smoke.sh --local --build
#   scripts/public-infra-smoke.sh --rendezvous qlink.example.com:9471 \
#     --relay qlink.example.com:9472 --stun qlink.example.com:3478 --build
#   scripts/public-infra-smoke.sh --rendezvous qlink.example.com:9471 \
#     --relay qlink.example.com:9472 --stun qlink.example.com:3478 \
#     --turn qlink.example.com:3478 --turn-username qlink --turn-password "$TURN_PASSWORD" --build
#   scripts/public-infra-smoke.sh --local --admission-token local-edge-secret --build
#   scripts/public-infra-smoke.sh --local --prove-turn-relay --admission-token local-edge-secret --build
#   scripts/public-infra-smoke.sh --local --control-tls --admission-token local-edge-secret --build

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="public"
MESH_ID="${QLINK_MESH_ID:-public-infra-smoke}"
RENDEZVOUS=""
RELAY=""
STUN=""
TURN=""
TURN_USERNAME="${QLINK_TURN_USERNAME:-}"
TURN_PASSWORD="${QLINK_TURN_PASSWORD:-}"
TURN_REALM="${QLINK_TURN_REALM:-}"
TURN_PERMIT_PEER_IP="${QLINK_TURN_PERMIT_PEER_IP:-}"
RENDEZVOUS_AUTH_TOKEN="${QLINK_RENDEZVOUS_AUTH_TOKEN:-}"
RELAY_AUTH_TOKEN="${QLINK_RELAY_AUTH_TOKEN:-}"
RENDEZVOUS_RATE_LIMIT_PER_WINDOW="${QLINK_RENDEZVOUS_RATE_LIMIT_PER_WINDOW:-0}"
RELAY_RATE_LIMIT_PER_WINDOW="${QLINK_RELAY_RATE_LIMIT_PER_WINDOW:-0}"
ADMISSION_RATE_LIMIT_WINDOW_SECONDS="${QLINK_ADMISSION_RATE_LIMIT_WINDOW_SECONDS:-60}"
RENDEZVOUS_METRICS_ADDR="${QLINK_RENDEZVOUS_METRICS_ADDR:-}"
RELAY_METRICS_ADDR="${QLINK_RELAY_METRICS_ADDR:-}"
MAX_REQUEST_LINE_BYTES="${QLINK_MAX_REQUEST_LINE_BYTES:-131072}"
MAX_CONCURRENT_CONNECTIONS="${QLINK_MAX_CONCURRENT_CONNECTIONS:-1024}"
IDLE_TIMEOUT_SECONDS="${QLINK_IDLE_TIMEOUT_SECONDS:-300}"
RELAY_MAX_PAYLOAD_BYTES="${QLINK_RELAY_MAX_PAYLOAD_BYTES:-65536}"
RELAY_MAX_PEER_ID_BYTES="${QLINK_RELAY_MAX_PEER_ID_BYTES:-256}"
RELAY_MAX_REGISTERED_PEERS="${QLINK_RELAY_MAX_REGISTERED_PEERS:-2048}"
CONTROL_TLS="${QLINK_CONTROL_TLS:-0}"
CONTROL_TLS_CA="${QLINK_CONTROL_TLS_CA:-}"
CONTROL_TLS_CERT="${QLINK_CONTROL_TLS_CERT:-}"
CONTROL_TLS_KEY="${QLINK_CONTROL_TLS_KEY:-}"
BIN="${QLINK_BIN:-$ROOT/target/release/qlinkctl}"
BUILD=0
PROVE_TURN_RELAY=0
LOCAL_HOST="${QLINK_PUBLIC_INFRA_LOCAL_HOST:-127.0.0.1}"
BASE_PORT="${QLINK_PUBLIC_INFRA_BASE_PORT:-19710}"
RESPONDER_BIND="${QLINK_PUBLIC_INFRA_RESPONDER_BIND:-0.0.0.0:0}"
ADVERTISE_ADDR="${QLINK_PUBLIC_INFRA_ADVERTISE_ADDR:-127.0.0.1:1}"
TIMEOUT_MS="${QLINK_PUBLIC_INFRA_TIMEOUT_MS:-10000}"
DIRECT_PROBE_TIMEOUT_MS="${QLINK_PUBLIC_INFRA_DIRECT_PROBE_TIMEOUT_MS:-300}"
COUNT="${QLINK_PUBLIC_INFRA_COUNT:-3}"
INTERVAL_MS="${QLINK_PUBLIC_INFRA_INTERVAL_MS:-10}"
RUN_DIR="${QLINK_PUBLIC_INFRA_RUN_DIR:-}"

usage() {
  grep '^#' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local) MODE="local"; shift ;;
    --mesh-id) MESH_ID="$2"; shift 2 ;;
    --rendezvous) RENDEZVOUS="$2"; shift 2 ;;
    --relay) RELAY="$2"; shift 2 ;;
    --stun) STUN="$2"; shift 2 ;;
    --turn) TURN="$2"; shift 2 ;;
    --turn-username) TURN_USERNAME="$2"; shift 2 ;;
    --turn-password) TURN_PASSWORD="$2"; shift 2 ;;
    --turn-realm) TURN_REALM="$2"; shift 2 ;;
    --turn-permit-peer-ip) TURN_PERMIT_PEER_IP="$2"; shift 2 ;;
    --rendezvous-auth-token) RENDEZVOUS_AUTH_TOKEN="$2"; shift 2 ;;
    --relay-auth-token) RELAY_AUTH_TOKEN="$2"; shift 2 ;;
    --admission-token)
      RENDEZVOUS_AUTH_TOKEN="$2"
      RELAY_AUTH_TOKEN="$2"
      shift 2
      ;;
    --rendezvous-rate-limit-per-window) RENDEZVOUS_RATE_LIMIT_PER_WINDOW="$2"; shift 2 ;;
    --relay-rate-limit-per-window) RELAY_RATE_LIMIT_PER_WINDOW="$2"; shift 2 ;;
    --admission-rate-limit-window-seconds) ADMISSION_RATE_LIMIT_WINDOW_SECONDS="$2"; shift 2 ;;
    --rendezvous-metrics-addr) RENDEZVOUS_METRICS_ADDR="$2"; shift 2 ;;
    --relay-metrics-addr) RELAY_METRICS_ADDR="$2"; shift 2 ;;
    --max-request-line-bytes) MAX_REQUEST_LINE_BYTES="$2"; shift 2 ;;
    --max-concurrent-connections) MAX_CONCURRENT_CONNECTIONS="$2"; shift 2 ;;
    --idle-timeout-seconds) IDLE_TIMEOUT_SECONDS="$2"; shift 2 ;;
    --relay-max-payload-bytes) RELAY_MAX_PAYLOAD_BYTES="$2"; shift 2 ;;
    --relay-max-peer-id-bytes) RELAY_MAX_PEER_ID_BYTES="$2"; shift 2 ;;
    --relay-max-registered-peers) RELAY_MAX_REGISTERED_PEERS="$2"; shift 2 ;;
    --control-tls) CONTROL_TLS=1; shift ;;
    --control-tls-ca) CONTROL_TLS_CA="$2"; shift 2 ;;
    --control-tls-cert) CONTROL_TLS_CERT="$2"; shift 2 ;;
    --control-tls-key) CONTROL_TLS_KEY="$2"; shift 2 ;;
    --base-port) BASE_PORT="$2"; shift 2 ;;
    --responder-bind) RESPONDER_BIND="$2"; shift 2 ;;
    --advertise-addr) ADVERTISE_ADDR="$2"; shift 2 ;;
    --timeout-ms) TIMEOUT_MS="$2"; shift 2 ;;
    --direct-probe-timeout-ms) DIRECT_PROBE_TIMEOUT_MS="$2"; shift 2 ;;
    --count) COUNT="$2"; shift 2 ;;
    --interval-ms) INTERVAL_MS="$2"; shift 2 ;;
    --run-dir) RUN_DIR="$2"; shift 2 ;;
    --build) BUILD=1; shift ;;
    --prove-turn-relay) PROVE_TURN_RELAY=1; shift ;;
    --qlink-bin) BIN="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$RUN_DIR" ]]; then
  RUN_DIR="$ROOT/build/public-infra-smoke/$timestamp"
fi
mkdir -p "$RUN_DIR"

PIDS=()
cleanup() {
  if [[ -n "${rendezvous_auth_token_file:-}" && -e "${rendezvous_auth_token_file:-}" ]]; then
    rm "$rendezvous_auth_token_file"
  fi
  if [[ -n "${relay_auth_token_file:-}" && -e "${relay_auth_token_file:-}" ]]; then
    rm "$relay_auth_token_file"
  fi
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { echo "error: $*" >&2; exit 1; }

wait_tcp() {
  local host_port="$1"
  local host="${host_port%:*}"
  local port="${host_port##*:}"
  for _ in {1..50}; do
    if nc -z -G 1 "$host" "$port" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_peer_id() {
  local file="$1"
  for _ in {1..100}; do
    local peer
    peer="$(sed -n 's/^local_peer_id=//p' "$file" | head -1)"
    if [[ -n "$peer" ]]; then
      echo "$peer"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_log_pattern() {
  local file="$1"
  local pattern="$2"
  for _ in {1..100}; do
    if grep -Eq "$pattern" "$file" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

require_endpoint() {
  local value="$1"
  local name="$2"
  local endpoint
  endpoint="$(control_host_port "$value")"
  [[ "$endpoint" == *:* ]] || die "$name must be host:port, tcp://host:port, or tls://host:port"
}

control_host_port() {
  local value="$1"
  value="${value#tcp://}"
  value="${value#tls://}"
  echo "$value"
}

endpoint_is_tls() {
  [[ "$1" == tls://* ]]
}

generate_local_control_tls() {
  [[ "$CONTROL_TLS" == "1" ]] || return 0
  if [[ -z "$CONTROL_TLS_CERT" ]]; then
    CONTROL_TLS_CERT="$RUN_DIR/control-tls.crt"
  fi
  if [[ -z "$CONTROL_TLS_KEY" ]]; then
    CONTROL_TLS_KEY="$RUN_DIR/control-tls.key"
  fi
  if [[ -z "$CONTROL_TLS_CA" ]]; then
    CONTROL_TLS_CA="$CONTROL_TLS_CERT"
  fi
  if [[ -f "$CONTROL_TLS_CERT" && -f "$CONTROL_TLS_KEY" ]]; then
    return 0
  fi
  command -v openssl >/dev/null 2>&1 || die "--control-tls local mode requires openssl to generate a local test certificate"
  local openssl_conf="$RUN_DIR/control-tls-openssl.cnf"
  cat > "$openssl_conf" <<EOF
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_req

[dn]
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$CONTROL_TLS_KEY" \
    -out "$CONTROL_TLS_CERT" \
    -config "$openssl_conf" \
    > "$RUN_DIR/openssl-control-tls.log" 2>&1 \
    || die "failed to generate local control TLS certificate; see $RUN_DIR/openssl-control-tls.log"
  chmod 600 "$CONTROL_TLS_KEY"
}

write_secret_file() {
  local path="$1"
  local value="$2"
  umask 077
  printf '%s\n' "$value" > "$path"
}

bool_for_nonempty() {
  if [[ -n "$1" ]]; then
    echo true
  else
    echo false
  fi
}

scrape_metrics() {
  local addr="$1"
  local out="$2"
  ruby -rsocket -rtimeout -e '
    Timeout.timeout(2) do
      addr = ARGV.fetch(0)
      out = ARGV.fetch(1)
      host, port = addr.rpartition(":").values_at(0, 2)
      socket = TCPSocket.new(host, Integer(port))
      socket.write("GET /metrics HTTP/1.1\r\nHost: quantumlink-metrics\r\nConnection: close\r\n\r\n")
      response = socket.read
      body = response.to_s.split("\r\n\r\n", 2).last.to_s
      File.write(out, body)
    end
  ' "$addr" "$out"
}

metric_value() {
  local file="$1"
  local name="$2"
  awk -v name="$name" '$1 == name {print int($2); found=1; exit} END {if (!found) print 0}' "$file" 2>/dev/null
}

probe_oversized_line() {
  local endpoint="$1"
  local max_bytes="$2"
  local args=(control-oversize-smoke --server "$endpoint" --max-request-line-bytes "$max_bytes")
  if [[ -n "$CONTROL_TLS_CA" ]]; then
    args+=(--control-tls-ca "$CONTROL_TLS_CA")
  fi
  "$BIN" "${args[@]}" > "$RUN_DIR/control-oversize-$(basename "$endpoint" | tr -c 'A-Za-z0-9' '_').log" 2>&1
}

probe_relay_payload_limit() {
  local endpoint="$1"
  local max_payload_bytes="$2"
  local args=(relay-quota-smoke --server "$endpoint" --peer-id qlink-quota-probe --max-payload-bytes "$max_payload_bytes")
  if [[ -n "$RELAY_AUTH_TOKEN" ]]; then
    args+=(--auth-token "$RELAY_AUTH_TOKEN")
  fi
  if [[ -n "$CONTROL_TLS_CA" ]]; then
    args+=(--control-tls-ca "$CONTROL_TLS_CA")
  fi
  "$BIN" "${args[@]}" > "$RUN_DIR/relay-quota-smoke.log" 2>&1
}

if [[ "$BUILD" -eq 1 ]]; then
  features="dev-quic-carrier"
  if [[ "$PROVE_TURN_RELAY" -eq 1 ]]; then
    features="turn-relay"
  elif [[ -n "$TURN" ]]; then
    features="dev-quic-carrier,turn-relay"
  fi
  if [[ "$CONTROL_TLS" == "1" || "$RENDEZVOUS" == tls://* || "$RELAY" == tls://* ]]; then
    features="$features,public-edge-tls"
  fi
  log "building qlinkctl release binary with features=$features"
  cargo build -p qlink-core --release --bin qlinkctl --features "$features" \
    > "$RUN_DIR/build.log" 2>&1
fi

[[ -x "$BIN" ]] || die "qlinkctl not executable at $BIN; use --build or --qlink-bin"

if [[ "$MODE" == "local" ]]; then
  if [[ "$CONTROL_TLS" == "1" ]]; then
    RENDEZVOUS="${RENDEZVOUS:-tls://$LOCAL_HOST:$BASE_PORT}"
    RELAY="${RELAY:-tls://$LOCAL_HOST:$((BASE_PORT + 1))}"
    generate_local_control_tls
  else
    RENDEZVOUS="${RENDEZVOUS:-$LOCAL_HOST:$BASE_PORT}"
    RELAY="${RELAY:-$LOCAL_HOST:$((BASE_PORT + 1))}"
  fi
  STUN="${STUN:-$LOCAL_HOST:$((BASE_PORT + 2))}"
  RENDEZVOUS_METRICS_ADDR="${RENDEZVOUS_METRICS_ADDR:-127.0.0.1:$((BASE_PORT + 4))}"
  RELAY_METRICS_ADDR="${RELAY_METRICS_ADDR:-127.0.0.1:$((BASE_PORT + 5))}"
  if [[ "$PROVE_TURN_RELAY" -eq 1 ]]; then
    TURN="${TURN:-$LOCAL_HOST:$((BASE_PORT + 3))}"
    TURN_PERMIT_PEER_IP="${TURN_PERMIT_PEER_IP:-$LOCAL_HOST}"
  fi

  log "starting local rendezvous at $RENDEZVOUS"
  rendezvous_listen="$(control_host_port "$RENDEZVOUS")"
  relay_listen="$(control_host_port "$RELAY")"
  rendezvous_args=(
    rendezvous
    --listen "$rendezvous_listen"
    --max-request-line-bytes "$MAX_REQUEST_LINE_BYTES"
    --max-concurrent-connections "$MAX_CONCURRENT_CONNECTIONS"
    --idle-timeout-seconds "$IDLE_TIMEOUT_SECONDS"
  )
  if [[ -n "$RENDEZVOUS_AUTH_TOKEN" ]]; then
    rendezvous_auth_token_file="$RUN_DIR/rendezvous-auth-token"
    write_secret_file "$rendezvous_auth_token_file" "$RENDEZVOUS_AUTH_TOKEN"
    rendezvous_args+=(--auth-token-file "$rendezvous_auth_token_file")
  fi
  if endpoint_is_tls "$RENDEZVOUS"; then
    [[ -n "$CONTROL_TLS_CERT" && -n "$CONTROL_TLS_KEY" ]] \
      || die "local TLS rendezvous requires --control-tls-cert/--control-tls-key or --control-tls"
    rendezvous_args+=(--tls-cert "$CONTROL_TLS_CERT" --tls-key "$CONTROL_TLS_KEY")
  fi
  if [[ "$RENDEZVOUS_RATE_LIMIT_PER_WINDOW" -gt 0 ]]; then
    rendezvous_args+=(
      --rate-limit-per-window "$RENDEZVOUS_RATE_LIMIT_PER_WINDOW"
      --rate-limit-window-seconds "$ADMISSION_RATE_LIMIT_WINDOW_SECONDS"
    )
  fi
  if [[ -n "$RENDEZVOUS_METRICS_ADDR" ]]; then
    rendezvous_args+=(--metrics-addr "$RENDEZVOUS_METRICS_ADDR")
  fi
  "$BIN" "${rendezvous_args[@]}" > "$RUN_DIR/rendezvous.log" 2>&1 &
  PIDS+=("$!")
  log "starting local relay at $RELAY"
  relay_args=(
    relay
    --listen "$relay_listen"
    --max-request-line-bytes "$MAX_REQUEST_LINE_BYTES"
    --max-concurrent-connections "$MAX_CONCURRENT_CONNECTIONS"
    --idle-timeout-seconds "$IDLE_TIMEOUT_SECONDS"
    --max-relay-payload-bytes "$RELAY_MAX_PAYLOAD_BYTES"
    --max-relay-peer-id-bytes "$RELAY_MAX_PEER_ID_BYTES"
    --max-relay-registered-peers "$RELAY_MAX_REGISTERED_PEERS"
  )
  if [[ -n "$RELAY_AUTH_TOKEN" ]]; then
    relay_auth_token_file="$RUN_DIR/relay-auth-token"
    write_secret_file "$relay_auth_token_file" "$RELAY_AUTH_TOKEN"
    relay_args+=(--auth-token-file "$relay_auth_token_file")
  fi
  if endpoint_is_tls "$RELAY"; then
    [[ -n "$CONTROL_TLS_CERT" && -n "$CONTROL_TLS_KEY" ]] \
      || die "local TLS relay requires --control-tls-cert/--control-tls-key or --control-tls"
    relay_args+=(--tls-cert "$CONTROL_TLS_CERT" --tls-key "$CONTROL_TLS_KEY")
  fi
  if [[ "$RELAY_RATE_LIMIT_PER_WINDOW" -gt 0 ]]; then
    relay_args+=(
      --rate-limit-per-window "$RELAY_RATE_LIMIT_PER_WINDOW"
      --rate-limit-window-seconds "$ADMISSION_RATE_LIMIT_WINDOW_SECONDS"
    )
  fi
  if [[ -n "$RELAY_METRICS_ADDR" ]]; then
    relay_args+=(--metrics-addr "$RELAY_METRICS_ADDR")
  fi
  "$BIN" "${relay_args[@]}" > "$RUN_DIR/relay.log" 2>&1 &
  PIDS+=("$!")
  log "starting local STUN at $STUN"
  "$BIN" stun --listen "$STUN" > "$RUN_DIR/stun.log" 2>&1 &
  PIDS+=("$!")
  if [[ "$PROVE_TURN_RELAY" -eq 1 ]]; then
    log "starting local TURN dev server at $TURN"
    "$BIN" turn-dev --listen "$TURN" > "$RUN_DIR/turn-dev.log" 2>&1 &
    PIDS+=("$!")
  fi
fi

require_endpoint "$RENDEZVOUS" "--rendezvous"
require_endpoint "$RELAY" "--relay"
require_endpoint "$STUN" "--stun"
[[ -z "$TURN" ]] || require_endpoint "$TURN" "--turn"
if [[ "$PROVE_TURN_RELAY" -eq 1 ]]; then
  [[ -n "$TURN" ]] || die "--prove-turn-relay requires --turn or --local"
  if [[ -z "$TURN_PERMIT_PEER_IP" ]]; then
    die "--prove-turn-relay requires --turn-permit-peer-ip outside --local"
  fi
fi

log "waiting for rendezvous=$RENDEZVOUS and relay=$RELAY"
wait_tcp "$(control_host_port "$RENDEZVOUS")" || die "rendezvous did not accept TCP connections"
wait_tcp "$(control_host_port "$RELAY")" || die "relay did not accept TCP connections"

log "proving rendezvous publish/lookup"
rendezvous_smoke_args=(rendezvous-smoke --server "$RENDEZVOUS")
if [[ -n "$RENDEZVOUS_AUTH_TOKEN" ]]; then
  rendezvous_smoke_args+=(--auth-token "$RENDEZVOUS_AUTH_TOKEN")
fi
if [[ -n "$CONTROL_TLS_CA" ]]; then
  rendezvous_smoke_args+=(--control-tls-ca "$CONTROL_TLS_CA")
fi
"$BIN" "${rendezvous_smoke_args[@]}" > "$RUN_DIR/rendezvous-smoke.log" 2>&1
grep -q '^record_verified=true$' "$RUN_DIR/rendezvous-smoke.log" \
  || die "rendezvous smoke did not verify the published record"

rendezvous_auth_verified=false
if [[ -n "$RENDEZVOUS_AUTH_TOKEN" ]]; then
  unauth_rendezvous_args=(rendezvous-smoke --server "$RENDEZVOUS")
  if [[ -n "$CONTROL_TLS_CA" ]]; then
    unauth_rendezvous_args+=(--control-tls-ca "$CONTROL_TLS_CA")
  fi
  if "$BIN" "${unauth_rendezvous_args[@]}" > "$RUN_DIR/rendezvous-unauth.log" 2>&1; then
    die "rendezvous accepted unauthenticated publish/lookup"
  fi
  grep -qi 'authentication failed' "$RUN_DIR/rendezvous-unauth.log" \
    || die "rendezvous unauthenticated probe failed for an unexpected reason"
  rendezvous_auth_verified=true
fi

relay_auth_verified=false
if [[ -n "$RELAY_AUTH_TOKEN" ]]; then
  unauth_relay_args=(relay-admission-smoke --server "$RELAY" --peer-id qlink-unauth-probe)
  if [[ -n "$CONTROL_TLS_CA" ]]; then
    unauth_relay_args+=(--control-tls-ca "$CONTROL_TLS_CA")
  fi
  if "$BIN" "${unauth_relay_args[@]}" > "$RUN_DIR/relay-unauth.log" 2>&1; then
    die "relay accepted unauthenticated registration"
  fi
  grep -qi 'authentication failed' "$RUN_DIR/relay-unauth.log" \
    || die "relay unauthenticated probe failed for an unexpected reason"
  relay_auth_args=(relay-admission-smoke --server "$RELAY" --peer-id qlink-auth-probe --auth-token "$RELAY_AUTH_TOKEN")
  if [[ -n "$CONTROL_TLS_CA" ]]; then
    relay_auth_args+=(--control-tls-ca "$CONTROL_TLS_CA")
  fi
  "$BIN" "${relay_auth_args[@]}" > "$RUN_DIR/relay-admission.log" 2>&1
  grep -q '^relay_registration_accepted=true$' "$RUN_DIR/relay-admission.log" \
    || die "relay authenticated admission probe did not register"
  relay_auth_verified=true
fi

bounds_verified=false
relay_payload_limit_verified=false
log "proving rendezvous and relay request-line bounds"
probe_oversized_line "$RENDEZVOUS" "$MAX_REQUEST_LINE_BYTES" \
  || die "rendezvous oversized-line probe failed"
probe_oversized_line "$RELAY" "$MAX_REQUEST_LINE_BYTES" \
  || die "relay oversized-line probe failed"
bounds_verified=true

log "proving relay payload-size quota"
probe_relay_payload_limit "$RELAY" "$RELAY_MAX_PAYLOAD_BYTES" \
  || die "relay payload quota probe failed"
relay_payload_limit_verified=true

log "proving STUN reflexive candidate"
"$BIN" stun-gather --server "$STUN" --bind-addr 0.0.0.0:0 \
  > "$RUN_DIR/stun-gather.log" 2>&1
grep -q '^candidate_type=ServerReflexive$' "$RUN_DIR/stun-gather.log" \
  || die "STUN gather did not return a server-reflexive candidate"

if [[ -n "$TURN" ]]; then
  log "proving TURN relay candidate allocation"
  turn_args=(turn-gather --server "$TURN" --bind-addr 0.0.0.0:0)
  if [[ -n "$TURN_USERNAME" || -n "$TURN_PASSWORD" ]]; then
    [[ -n "$TURN_USERNAME" && -n "$TURN_PASSWORD" ]] \
      || die "TURN auth requires both --turn-username and --turn-password"
    turn_args+=(--username "$TURN_USERNAME" --password "$TURN_PASSWORD")
  fi
  if [[ -n "$TURN_REALM" ]]; then
    turn_args+=(--realm "$TURN_REALM")
  fi
  "$BIN" "${turn_args[@]}" > "$RUN_DIR/turn-gather.log" 2>&1
  grep -q '^candidate_type=Relay$' "$RUN_DIR/turn-gather.log" \
    || die "TURN gather did not return a relay candidate"
fi

if [[ "$PROVE_TURN_RELAY" -eq 1 ]]; then
  log "starting responder with resident TURN allocation"
else
  log "starting responder registered with public relay"
fi
RESPONDER_LOG="$RUN_DIR/responder.log"
RESPONDER_KEY="$RUN_DIR/responder.seed"
if [[ "$PROVE_TURN_RELAY" -eq 1 ]]; then
  publish_args=(turn-relay-responder
    --rendezvous "$RENDEZVOUS"
    --mesh-id "$MESH_ID"
    --turn "$TURN"
    --bind-addr "$RESPONDER_BIND"
    --permit-peer-ip "$TURN_PERMIT_PEER_IP"
    --ttl-seconds 60
    --keyfile "$RESPONDER_KEY"
    --max-frames "$COUNT")
  if [[ -n "$RENDEZVOUS_AUTH_TOKEN" ]]; then
    publish_args+=(--rendezvous-auth-token "$RENDEZVOUS_AUTH_TOKEN")
  fi
  if [[ -n "$TURN_USERNAME" || -n "$TURN_PASSWORD" ]]; then
    publish_args+=(--turn-username "$TURN_USERNAME" --turn-password "$TURN_PASSWORD")
  fi
  if [[ -n "$TURN_REALM" ]]; then
    publish_args+=(--turn-realm "$TURN_REALM")
  fi
  if [[ -n "$CONTROL_TLS_CA" ]]; then
    publish_args+=(--control-tls-ca "$CONTROL_TLS_CA")
  fi
else
  publish_args=(publish-self
    --rendezvous "$RENDEZVOUS"
    --mesh-id "$MESH_ID"
    --bind-addr "$RESPONDER_BIND"
    --advertise-addr "$ADVERTISE_ADDR"
    --relay "$RELAY"
    --ttl-seconds 60
    --keyfile "$RESPONDER_KEY"
    --stun "$STUN")
  if [[ -n "$RENDEZVOUS_AUTH_TOKEN" ]]; then
    publish_args+=(--rendezvous-auth-token "$RENDEZVOUS_AUTH_TOKEN")
  fi
  if [[ -n "$RELAY_AUTH_TOKEN" ]]; then
    publish_args+=(--relay-auth-token "$RELAY_AUTH_TOKEN")
  fi
  if [[ -n "$CONTROL_TLS_CA" ]]; then
    publish_args+=(--control-tls-ca "$CONTROL_TLS_CA")
  fi
  if [[ -n "$TURN" ]]; then
    publish_args+=(--turn "$TURN")
    if [[ -n "$TURN_USERNAME" || -n "$TURN_PASSWORD" ]]; then
      publish_args+=(--turn-username "$TURN_USERNAME" --turn-password "$TURN_PASSWORD")
    fi
    if [[ -n "$TURN_REALM" ]]; then
      publish_args+=(--turn-realm "$TURN_REALM")
    fi
  fi
fi
"$BIN" "${publish_args[@]}" > "$RESPONDER_LOG" 2>&1 &
PIDS+=("$!")
REMOTE_PEER="$(wait_peer_id "$RESPONDER_LOG")" \
  || die "responder did not print a local_peer_id"
if [[ "$PROVE_TURN_RELAY" -eq 1 ]]; then
  wait_log_pattern "$RESPONDER_LOG" '^turn_responder_ready=true$' \
    || die "TURN relay responder did not become ready"
  wait_log_pattern "$RESPONDER_LOG" '^published_candidate\[[0-9]+\]_type=Relay$' \
    || die "published record did not include a resident TURN relay candidate"
else
  wait_log_pattern "$RESPONDER_LOG" '^published_candidate\[[0-9]+\]_type=ServerReflexive$' \
    || die "published record did not include a server-reflexive candidate"
  wait_log_pattern "$RESPONDER_LOG" '^published_candidate\[[0-9]+\]_type=QuantumLinkRelay$' \
    || die "published record did not include a QuantumLink relay candidate"
  if [[ -n "$TURN" ]]; then
    wait_log_pattern "$RESPONDER_LOG" '^published_candidate\[[0-9]+\]_type=Relay$' \
      || die "published record did not include a TURN relay candidate"
  fi
fi

expected_path="relay"
if [[ "$PROVE_TURN_RELAY" -eq 1 ]]; then
  expected_path="turn-relay"
fi

log "forcing published $expected_path fallback to peer $REMOTE_PEER"
direct_send_args=(direct-send
  --rendezvous "$RENDEZVOUS"
  --mesh-id "$MESH_ID"
  --remote-peer-id "$REMOTE_PEER"
  --relay "$RELAY"
  --bind-addr 0.0.0.0:0
  --payload public-infra-smoke
  --count "$COUNT"
  --interval-ms "$INTERVAL_MS"
  --timeout-ms "$TIMEOUT_MS"
  --direct-probe-timeout-ms "$DIRECT_PROBE_TIMEOUT_MS")
if [[ -n "$RENDEZVOUS_AUTH_TOKEN" ]]; then
  direct_send_args+=(--rendezvous-auth-token "$RENDEZVOUS_AUTH_TOKEN")
fi
if [[ -n "$RELAY_AUTH_TOKEN" ]]; then
  direct_send_args+=(--relay-auth-token "$RELAY_AUTH_TOKEN")
fi
if [[ -n "$CONTROL_TLS_CA" ]]; then
  direct_send_args+=(--control-tls-ca "$CONTROL_TLS_CA")
fi
"$BIN" "${direct_send_args[@]}" > "$RUN_DIR/direct-send.log" 2>&1

selected_path="$(sed -n 's/^selected_path=//p' "$RUN_DIR/direct-send.log" | tail -1)"
frames_sent="$(sed -n 's/^frames_sent=//p' "$RUN_DIR/direct-send.log" | tail -1)"
total_elapsed_ms="$(sed -n 's/^total_elapsed_ms=//p' "$RUN_DIR/direct-send.log" | tail -1)"
[[ "$selected_path" == "$expected_path" ]] \
  || die "direct-send selected_path=$selected_path; expected $expected_path"
[[ "$frames_sent" == "$COUNT" ]] \
  || die "direct-send frames_sent=$frames_sent; expected $COUNT"

stun_addr="$(sed -n 's/^reflexive_address=//p' "$RUN_DIR/stun-gather.log" | tail -1)"
stun_port="$(sed -n 's/^reflexive_port=//p' "$RUN_DIR/stun-gather.log" | tail -1)"
turn_addr=""
turn_port=""
if [[ -f "$RUN_DIR/turn-gather.log" ]]; then
  turn_addr="$(sed -n 's/^relayed_address=//p' "$RUN_DIR/turn-gather.log" | tail -1)"
  turn_port="$(sed -n 's/^relayed_port=//p' "$RUN_DIR/turn-gather.log" | tail -1)"
fi
published_candidate_count="$(sed -n 's/^published_candidate_count=//p' "$RESPONDER_LOG" | head -1)"
published_candidate_types="$(
  awk -F= '/^published_candidate\[[0-9]+\]_type=/ {print $2}' "$RESPONDER_LOG" \
    | paste -sd, -
)"
self_publish_stun_failures="$(sed -n 's/^stun_failure_count=//p' "$RESPONDER_LOG" | head -1)"
self_publish_turn_failures="$(sed -n 's/^turn_failure_count=//p' "$RESPONDER_LOG" | head -1)"
turn_responder_addr="$(sed -n 's/^turn_relayed_address=//p' "$RESPONDER_LOG" | tail -1)"
turn_responder_port="$(sed -n 's/^turn_relayed_port=//p' "$RESPONDER_LOG" | tail -1)"

rendezvous_metrics_scraped=false
relay_metrics_scraped=false
rendezvous_auth_failures_total=0
relay_auth_failures_total=0
rendezvous_requests_succeeded_total=0
relay_forwarded_datagrams_total=0
relay_unknown_destination_drops_total=0
rendezvous_request_too_large_total=0
relay_request_too_large_total=0
relay_payload_too_large_total=0
relay_duplicate_registration_rejections_total=0
if [[ -n "$RENDEZVOUS_METRICS_ADDR" ]]; then
  log "scraping rendezvous metrics at $RENDEZVOUS_METRICS_ADDR"
  scrape_metrics "$RENDEZVOUS_METRICS_ADDR" "$RUN_DIR/rendezvous.metrics" \
    || die "failed to scrape rendezvous metrics at $RENDEZVOUS_METRICS_ADDR"
  rendezvous_metrics_scraped=true
  rendezvous_auth_failures_total="$(metric_value "$RUN_DIR/rendezvous.metrics" quantumlink_rendezvous_auth_failures_total)"
  rendezvous_requests_succeeded_total="$(metric_value "$RUN_DIR/rendezvous.metrics" quantumlink_rendezvous_requests_succeeded_total)"
  rendezvous_request_too_large_total="$(metric_value "$RUN_DIR/rendezvous.metrics" quantumlink_rendezvous_request_too_large_total)"
  if [[ -n "$RENDEZVOUS_AUTH_TOKEN" && "$rendezvous_auth_failures_total" -lt 1 ]]; then
    die "rendezvous metrics did not record the negative auth probe"
  fi
  if [[ "$rendezvous_request_too_large_total" -lt 1 ]]; then
    die "rendezvous metrics did not record the oversized-line probe"
  fi
fi
if [[ -n "$RELAY_METRICS_ADDR" ]]; then
  log "scraping relay metrics at $RELAY_METRICS_ADDR"
  scrape_metrics "$RELAY_METRICS_ADDR" "$RUN_DIR/relay.metrics" \
    || die "failed to scrape relay metrics at $RELAY_METRICS_ADDR"
  relay_metrics_scraped=true
  relay_auth_failures_total="$(metric_value "$RUN_DIR/relay.metrics" quantumlink_relay_auth_failures_total)"
  relay_forwarded_datagrams_total="$(metric_value "$RUN_DIR/relay.metrics" quantumlink_relay_forwarded_datagrams_total)"
  relay_unknown_destination_drops_total="$(metric_value "$RUN_DIR/relay.metrics" quantumlink_relay_unknown_destination_drops_total)"
  relay_request_too_large_total="$(metric_value "$RUN_DIR/relay.metrics" quantumlink_relay_request_too_large_total)"
  relay_payload_too_large_total="$(metric_value "$RUN_DIR/relay.metrics" quantumlink_relay_payload_too_large_total)"
  relay_duplicate_registration_rejections_total="$(metric_value "$RUN_DIR/relay.metrics" quantumlink_relay_duplicate_registration_rejections_total)"
  if [[ -n "$RELAY_AUTH_TOKEN" && "$relay_auth_failures_total" -lt 1 ]]; then
    die "relay metrics did not record the negative auth probe"
  fi
  if [[ "$relay_request_too_large_total" -lt 1 ]]; then
    die "relay metrics did not record the oversized-line probe"
  fi
  if [[ "$relay_payload_too_large_total" -lt 1 ]]; then
    die "relay metrics did not record the payload quota probe"
  fi
  if [[ "$expected_path" == "relay" && "$relay_forwarded_datagrams_total" -lt "$COUNT" ]]; then
    die "relay metrics forwarded_datagrams_total=$relay_forwarded_datagrams_total; expected at least $COUNT"
  fi
fi

git_sha="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
EVIDENCE="$RUN_DIR/evidence.json"
cat > "$EVIDENCE" <<EOF
{
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "git_sha": "$git_sha",
  "mode": "$MODE",
  "mesh_id": "$MESH_ID",
  "rendezvous": "$RENDEZVOUS",
  "relay": "$RELAY",
  "stun": "$STUN",
  "turn": "$TURN",
  "control_tls_ca_configured": $(bool_for_nonempty "$CONTROL_TLS_CA"),
  "rendezvous_tls_enabled": $(endpoint_is_tls "$RENDEZVOUS" && echo true || echo false),
  "relay_tls_enabled": $(endpoint_is_tls "$RELAY" && echo true || echo false),
  "rendezvous_auth_required": $(bool_for_nonempty "$RENDEZVOUS_AUTH_TOKEN"),
  "relay_auth_required": $(bool_for_nonempty "$RELAY_AUTH_TOKEN"),
  "rendezvous_auth_verified": $rendezvous_auth_verified,
  "relay_auth_verified": $relay_auth_verified,
  "rendezvous_rate_limit_per_window": $RENDEZVOUS_RATE_LIMIT_PER_WINDOW,
  "relay_rate_limit_per_window": $RELAY_RATE_LIMIT_PER_WINDOW,
  "admission_rate_limit_window_seconds": $ADMISSION_RATE_LIMIT_WINDOW_SECONDS,
  "rendezvous_metrics_addr": "$RENDEZVOUS_METRICS_ADDR",
  "relay_metrics_addr": "$RELAY_METRICS_ADDR",
  "rendezvous_metrics_scraped": $rendezvous_metrics_scraped,
  "relay_metrics_scraped": $relay_metrics_scraped,
  "bounds_verified": $bounds_verified,
  "relay_payload_limit_verified": $relay_payload_limit_verified,
  "max_request_line_bytes": $MAX_REQUEST_LINE_BYTES,
  "max_concurrent_connections": $MAX_CONCURRENT_CONNECTIONS,
  "idle_timeout_seconds": $IDLE_TIMEOUT_SECONDS,
  "relay_max_payload_bytes": $RELAY_MAX_PAYLOAD_BYTES,
  "relay_max_peer_id_bytes": $RELAY_MAX_PEER_ID_BYTES,
  "relay_max_registered_peers": $RELAY_MAX_REGISTERED_PEERS,
  "rendezvous_auth_failures_total": $rendezvous_auth_failures_total,
  "relay_auth_failures_total": $relay_auth_failures_total,
  "rendezvous_requests_succeeded_total": $rendezvous_requests_succeeded_total,
  "relay_forwarded_datagrams_total": $relay_forwarded_datagrams_total,
  "relay_unknown_destination_drops_total": $relay_unknown_destination_drops_total,
  "rendezvous_request_too_large_total": $rendezvous_request_too_large_total,
  "relay_request_too_large_total": $relay_request_too_large_total,
  "relay_payload_too_large_total": $relay_payload_too_large_total,
  "relay_duplicate_registration_rejections_total": $relay_duplicate_registration_rejections_total,
  "prove_turn_relay": $([[ "$PROVE_TURN_RELAY" -eq 1 ]] && echo true || echo false),
  "remote_peer_id": "$REMOTE_PEER",
  "advertise_addr": "$ADVERTISE_ADDR",
  "turn_permit_peer_ip": "$TURN_PERMIT_PEER_IP",
  "direct_probe_timeout_ms": $DIRECT_PROBE_TIMEOUT_MS,
  "stun_reflexive": "$stun_addr:$stun_port",
  "turn_relayed": "$turn_addr:$turn_port",
  "turn_responder_relayed": "$turn_responder_addr:$turn_responder_port",
  "published_candidate_count": ${published_candidate_count:-0},
  "published_candidate_types": "$published_candidate_types",
  "self_publish_stun_failures": ${self_publish_stun_failures:-0},
  "self_publish_turn_failures": ${self_publish_turn_failures:-0},
  "selected_path": "$selected_path",
  "frames_sent": $frames_sent,
  "total_elapsed_ms": ${total_elapsed_ms:-0}
}
EOF

rm -f "${rendezvous_auth_token_file:-}" "${relay_auth_token_file:-}"

log "PASS public infra smoke"
echo "evidence=$EVIDENCE"
echo "selected_path=$selected_path"
echo "frames_sent=$frames_sent"
echo "total_elapsed_ms=${total_elapsed_ms:-0}"
