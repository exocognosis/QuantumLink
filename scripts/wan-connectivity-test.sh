#!/usr/bin/env bash
#
# wan-connectivity-test.sh — exercise DIRECT and MESH (relay-fallback) against a
# live remote QuantumLink node over the real internet, from this workstation.
#
# Prerequisites (on the remote box, e.g. the Hetzner testbed):
#   rendezvous + relay running, plus two resident nodes published under $MESH_ID:
#     * a DIRECT node  — advertises a reachable public candidate + --relay
#     * a MESH node    — advertises an unreachable candidate + --relay
#   (see scripts/hetzner-testbed.sh; nodes started with `publish-self --relay`).
#
# This runs the Mac/connector side and prints a PASS/FAIL matrix.
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

HOST=""; MESH_ID="hetzner-testbed"; DIRECT_PEER=""; RELAY_PEER=""
RENDEZVOUS_PORT=9471; RELAY_PORT=9472; COUNT=10; TIMEOUT_MS=9000
BIN="${QLINK_BIN:-$ROOT/target/release/qlinkctl}"

usage() { cat <<EOF
Usage: scripts/wan-connectivity-test.sh --host IP --direct-peer ID --relay-peer ID [opts]
  --host IP           remote box public IP (required)
  --direct-peer ID    peer_id of the direct-capable node (required)
  --relay-peer ID     peer_id of the relay-only node (required)
  --mesh-id ID        mesh id (default: $MESH_ID)
  --count N           frames to stream per test (default: $COUNT)
  --timeout-ms N      connect budget (default: $TIMEOUT_MS)
EOF
}
while [[ $# -gt 0 ]]; do case "$1" in
  --host) HOST="$2"; shift 2;; --direct-peer) DIRECT_PEER="$2"; shift 2;;
  --relay-peer) RELAY_PEER="$2"; shift 2;; --mesh-id) MESH_ID="$2"; shift 2;;
  --count) COUNT="$2"; shift 2;; --timeout-ms) TIMEOUT_MS="$2"; shift 2;;
  --help) usage; exit 0;; *) echo "unknown arg: $1" >&2; usage >&2; exit 2;;
esac; done
[[ -n "$HOST" && -n "$DIRECT_PEER" && -n "$RELAY_PEER" ]] || { usage >&2; exit 2; }
[[ -x "$BIN" ]] || { echo "qlinkctl not found at $BIN (build with --features dev-quic-carrier)" >&2; exit 1; }

# run <label> <peer> <expected-path>
run_case() {
  local label="$1" peer="$2" expected="$3"
  local out path sent total
  out="$("$BIN" direct-send --rendezvous "$HOST:$RENDEZVOUS_PORT" --relay "$HOST:$RELAY_PORT" \
    --mesh-id "$MESH_ID" --remote-peer-id "$peer" --bind-addr 0.0.0.0:0 \
    --payload "wan-$label-canary" --count "$COUNT" --interval-ms 20 --timeout-ms "$TIMEOUT_MS" 2>&1)" || true
  path="$(sed -n 's/^selected_path=//p' <<<"$out" | head -1)"
  sent="$(sed -n 's/^frames_sent=//p' <<<"$out" | head -1)"
  total="$(sed -n 's/^total_elapsed_ms=//p' <<<"$out" | head -1)"
  local verdict="FAIL"
  [[ "$path" == "$expected" && "$sent" == "$COUNT" ]] && verdict="PASS"
  printf '| %-6s | %-6s | %-6s | %s/%s | %sms | %s |\n' \
    "$label" "$expected" "${path:-none}" "${sent:-0}" "$COUNT" "${total:-?}" "$verdict"
  [[ "$verdict" == "PASS" ]]
}

echo "# QuantumLink WAN connectivity — $HOST (mesh_id=$MESH_ID)"
echo
echo "| Mode   | Expect | Path   | Sent | Connect | Verdict |"
echo "|--------|--------|--------|------|---------|---------|"
ok=0; total=0
run_case direct "$DIRECT_PEER" direct && ok=$((ok+1)); total=$((total+1))
run_case mesh   "$RELAY_PEER"  relay  && ok=$((ok+1)); total=$((total+1))
echo
echo "result: $ok/$total passed"
[[ "$ok" -eq "$total" ]]
