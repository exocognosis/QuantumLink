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
BIN="${QLINK_BIN:-$ROOT/target/release/qlinkctl}"
BUILD=0
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
    --base-port) BASE_PORT="$2"; shift 2 ;;
    --responder-bind) RESPONDER_BIND="$2"; shift 2 ;;
    --advertise-addr) ADVERTISE_ADDR="$2"; shift 2 ;;
    --timeout-ms) TIMEOUT_MS="$2"; shift 2 ;;
    --direct-probe-timeout-ms) DIRECT_PROBE_TIMEOUT_MS="$2"; shift 2 ;;
    --count) COUNT="$2"; shift 2 ;;
    --interval-ms) INTERVAL_MS="$2"; shift 2 ;;
    --run-dir) RUN_DIR="$2"; shift 2 ;;
    --build) BUILD=1; shift ;;
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
  [[ "$value" == *:* ]] || die "$name must be host:port"
}

if [[ "$BUILD" -eq 1 ]]; then
  features="dev-quic-carrier"
  if [[ -n "$TURN" ]]; then
    features="dev-quic-carrier,turn-relay"
  fi
  log "building qlinkctl release binary with features=$features"
  cargo build -p qlink-core --release --bin qlinkctl --features "$features" \
    > "$RUN_DIR/build.log" 2>&1
fi

[[ -x "$BIN" ]] || die "qlinkctl not executable at $BIN; use --build or --qlink-bin"

if [[ "$MODE" == "local" ]]; then
  RENDEZVOUS="${RENDEZVOUS:-$LOCAL_HOST:$BASE_PORT}"
  RELAY="${RELAY:-$LOCAL_HOST:$((BASE_PORT + 1))}"
  STUN="${STUN:-$LOCAL_HOST:$((BASE_PORT + 2))}"

  log "starting local rendezvous at $RENDEZVOUS"
  "$BIN" rendezvous --listen "$RENDEZVOUS" > "$RUN_DIR/rendezvous.log" 2>&1 &
  PIDS+=("$!")
  log "starting local relay at $RELAY"
  "$BIN" relay --listen "$RELAY" > "$RUN_DIR/relay.log" 2>&1 &
  PIDS+=("$!")
  log "starting local STUN at $STUN"
  "$BIN" stun --listen "$STUN" > "$RUN_DIR/stun.log" 2>&1 &
  PIDS+=("$!")
fi

require_endpoint "$RENDEZVOUS" "--rendezvous"
require_endpoint "$RELAY" "--relay"
require_endpoint "$STUN" "--stun"
[[ -z "$TURN" ]] || require_endpoint "$TURN" "--turn"

log "waiting for rendezvous=$RENDEZVOUS and relay=$RELAY"
wait_tcp "$RENDEZVOUS" || die "rendezvous did not accept TCP connections"
wait_tcp "$RELAY" || die "relay did not accept TCP connections"

log "proving rendezvous publish/lookup"
"$BIN" rendezvous-smoke --server "$RENDEZVOUS" > "$RUN_DIR/rendezvous-smoke.log" 2>&1
grep -q '^record_verified=true$' "$RUN_DIR/rendezvous-smoke.log" \
  || die "rendezvous smoke did not verify the published record"

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

log "starting responder registered with public relay"
RESPONDER_LOG="$RUN_DIR/responder.log"
RESPONDER_KEY="$RUN_DIR/responder.seed"
publish_args=(publish-self
  --rendezvous "$RENDEZVOUS" \
  --mesh-id "$MESH_ID" \
  --bind-addr "$RESPONDER_BIND" \
  --advertise-addr "$ADVERTISE_ADDR" \
  --relay "$RELAY" \
  --ttl-seconds 60 \
  --keyfile "$RESPONDER_KEY" \
  --stun "$STUN")
if [[ -n "$TURN" ]]; then
  publish_args+=(--turn "$TURN")
  if [[ -n "$TURN_USERNAME" || -n "$TURN_PASSWORD" ]]; then
    publish_args+=(--turn-username "$TURN_USERNAME" --turn-password "$TURN_PASSWORD")
  fi
  if [[ -n "$TURN_REALM" ]]; then
    publish_args+=(--turn-realm "$TURN_REALM")
  fi
fi
"$BIN" "${publish_args[@]}" > "$RESPONDER_LOG" 2>&1 &
PIDS+=("$!")
REMOTE_PEER="$(wait_peer_id "$RESPONDER_LOG")" \
  || die "responder did not print a local_peer_id"
wait_log_pattern "$RESPONDER_LOG" '^published_candidate\[[0-9]+\]_type=ServerReflexive$' \
  || die "published record did not include a server-reflexive candidate"
if [[ -n "$TURN" ]]; then
  wait_log_pattern "$RESPONDER_LOG" '^published_candidate\[[0-9]+\]_type=Relay$' \
    || die "published record did not include a TURN relay candidate"
fi

log "forcing relay fallback to peer $REMOTE_PEER"
"$BIN" direct-send \
  --rendezvous "$RENDEZVOUS" \
  --mesh-id "$MESH_ID" \
  --remote-peer-id "$REMOTE_PEER" \
  --relay "$RELAY" \
  --bind-addr 0.0.0.0:0 \
  --payload public-infra-smoke \
  --count "$COUNT" \
  --interval-ms "$INTERVAL_MS" \
  --timeout-ms "$TIMEOUT_MS" \
  --direct-probe-timeout-ms "$DIRECT_PROBE_TIMEOUT_MS" \
  > "$RUN_DIR/direct-send.log" 2>&1

selected_path="$(sed -n 's/^selected_path=//p' "$RUN_DIR/direct-send.log" | tail -1)"
frames_sent="$(sed -n 's/^frames_sent=//p' "$RUN_DIR/direct-send.log" | tail -1)"
total_elapsed_ms="$(sed -n 's/^total_elapsed_ms=//p' "$RUN_DIR/direct-send.log" | tail -1)"
[[ "$selected_path" == "relay" ]] \
  || die "direct-send selected_path=$selected_path; expected relay"
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
  "remote_peer_id": "$REMOTE_PEER",
  "advertise_addr": "$ADVERTISE_ADDR",
  "direct_probe_timeout_ms": $DIRECT_PROBE_TIMEOUT_MS,
  "stun_reflexive": "$stun_addr:$stun_port",
  "turn_relayed": "$turn_addr:$turn_port",
  "published_candidate_count": ${published_candidate_count:-0},
  "published_candidate_types": "$published_candidate_types",
  "self_publish_stun_failures": ${self_publish_stun_failures:-0},
  "self_publish_turn_failures": ${self_publish_turn_failures:-0},
  "selected_path": "$selected_path",
  "frames_sent": $frames_sent,
  "total_elapsed_ms": ${total_elapsed_ms:-0}
}
EOF

log "PASS public infra smoke"
echo "evidence=$EVIDENCE"
echo "selected_path=$selected_path"
echo "frames_sent=$frames_sent"
echo "total_elapsed_ms=${total_elapsed_ms:-0}"
