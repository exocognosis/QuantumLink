#!/usr/bin/env bash
#
# nat-holepunch-test.sh — two-NATed-peer connectivity test over a public relay.
#
# TWO-MACHINE TEST. Run role A on one NATed host (e.g. a laptop on a phone
# hotspot) and role B on another NATed host (e.g. this Mac on home Wi-Fi). Both
# use a public server (the Hetzner testbed) as rendezvous + STUN + relay.
#
# What it proves:
#   1. Each peer's NAT mapping type (via STUN to two ports) — cone vs symmetric.
#   2. Whether the two real NATs connect DIRECT (hole-punch) or via RELAY.
#
# Honest scope: the connector uses a one-directional dial (no ICE
# simultaneous-open yet), so two NATed peers will land on the RELAY path —
# which is the correct, secure fallback and the realistic path for symmetric
# NATs. Direct cross-NAT hole-punching needs ICE on the shared data socket
# (a separate, larger feature). This driver measures reality and names the gap.
#
# Usage:
#   # on the resident peer (A):
#   scripts/nat-holepunch-test.sh --role A \
#     --server <PUBLIC_IP> [--rendezvous-port 9471] [--relay-port 9472] \
#     [--stun-port 3478] [--stun2-port 3479]
#   # prints A's peer_id; paste it into B:
#
#   # on the connecting peer (B):
#   scripts/nat-holepunch-test.sh --role B --server <PUBLIC_IP> \
#     --remote-peer <A_PEER_ID>
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ROLE=""
SERVER=""
REND_PORT=9471
RELAY_PORT=9472
STUN_PORT=3478
STUN2_PORT=3479
REMOTE_PEER=""
MESH_ID="${QLINK_MESH_ID:-nat-holepunch}"
BIN="${QLINK_BIN:-$ROOT/target/release/qlinkctl}"
BIND_PORT=9520

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --role) ROLE="$2"; shift 2 ;;
    --server) SERVER="$2"; shift 2 ;;
    --rendezvous-port) REND_PORT="$2"; shift 2 ;;
    --relay-port) RELAY_PORT="$2"; shift 2 ;;
    --stun-port) STUN_PORT="$2"; shift 2 ;;
    --stun2-port) STUN2_PORT="$2"; shift 2 ;;
    --remote-peer) REMOTE_PEER="$2"; shift 2 ;;
    --mesh-id) MESH_ID="$2"; shift 2 ;;
    --bin) BIN="$2"; shift 2 ;;
    --bind-port) BIND_PORT="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 2 ;;
  esac
done

[[ -n "$SERVER" ]] || { echo "error: --server <PUBLIC_IP> required" >&2; exit 2; }
[[ -x "$BIN" ]] || { echo "error: qlinkctl not at $BIN (build it or pass --bin)" >&2; exit 2; }

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# Classify this host's NAT mapping using the two STUN ports on the same server.
diagnose_nat() {
  log "[nat] classifying via STUN ${SERVER}:${STUN_PORT} and :${STUN2_PORT}"
  local p1 p2
  p1=$("$BIN" stun-gather --server "${SERVER}:${STUN_PORT}"  --bind-addr 0.0.0.0:0 2>/dev/null | sed -n 's/^reflexive_port=//p')
  local pub; pub=$("$BIN" stun-gather --server "${SERVER}:${STUN_PORT}" --bind-addr 0.0.0.0:0 2>/dev/null | sed -n 's/^reflexive_address=//p')
  p2=$("$BIN" stun-gather --server "${SERVER}:${STUN2_PORT}" --bind-addr 0.0.0.0:0 2>/dev/null | sed -n 's/^reflexive_port=//p')
  log "[nat] public_ip=${pub:-?}  reflexive_ports: :${STUN_PORT}->${p1:-?} :${STUN2_PORT}->${p2:-?}"
  # NOTE: separate sockets per gather, so this is a coarse indicator; a fixed
  # source port that yields different external ports strongly implies symmetric.
  if [[ -n "$p1" && -n "$p2" ]]; then
    log "[nat] mapping: ports differ across destinations => leans SYMMETRIC (relay-bound); same => cone-ish"
  else
    log "[nat] STUN unreachable — check the server's UDP ${STUN_PORT}/${STUN2_PORT}"
  fi
}

case "$ROLE" in
  A)
    diagnose_nat
    KEY="$ROOT/build/nat-peerA.seed"; mkdir -p "$ROOT/build"
    log "[A] starting resident relay peer (bind 0.0.0.0:${BIND_PORT}, relay ${SERVER}:${RELAY_PORT})"
    log "[A] ---> share this peer_id with peer B:"
    exec "$BIN" publish-self \
      --rendezvous "${SERVER}:${REND_PORT}" \
      --mesh-id "$MESH_ID" \
      --bind-addr "0.0.0.0:${BIND_PORT}" \
      --relay "${SERVER}:${RELAY_PORT}" \
      --ttl-seconds 120 \
      --keyfile "$KEY"
    ;;
  B)
    [[ -n "$REMOTE_PEER" ]] || { echo "error: role B needs --remote-peer <A_PEER_ID>" >&2; exit 2; }
    diagnose_nat
    log "[B] connecting to $REMOTE_PEER via rendezvous ${SERVER}:${REND_PORT}, relay ${SERVER}:${RELAY_PORT}"
    out=$("$BIN" direct-send \
      --rendezvous "${SERVER}:${REND_PORT}" \
      --mesh-id "$MESH_ID" \
      --remote-peer-id "$REMOTE_PEER" \
      --relay "${SERVER}:${RELAY_PORT}" \
      --bind-addr "0.0.0.0:0" \
      --payload "nat-holepunch-probe" \
      --count 5 --interval-ms 20 \
      --timeout-ms 15000 2>&1) || { echo "$out" >&2; exit 1; }
    path=$(printf '%s\n' "$out" | sed -n 's/^selected_path=//p')
    ms=$(printf '%s\n' "$out" | sed -n 's/^total_elapsed_ms=//p')
    printf '%s\n' "$out" | grep -E 'selected_path|selected_remote_addr|frames_sent|total_elapsed_ms'
    echo
    log "[verdict] two NATed peers connected via '${path:-?}' in ${ms:-?}ms"
    if [[ "$path" == "direct" ]]; then
      log "[verdict] DIRECT hole-punch succeeded across NATs"
    else
      log "[verdict] fell back to RELAY (expected when a peer is symmetric / no ICE)"
    fi
    ;;
  *)
    echo "error: --role must be A or B" >&2; usage 2 ;;
esac
