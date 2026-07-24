#!/usr/bin/env bash
#
# remote-channel-probe.sh — from THIS machine, direct-connect to a remote
# QuantumLink responder (see scripts/hetzner-testbed.sh) and stream an encrypted
# packet burst over the real network. Reports stream throughput and, with
# --pcap, captures the wire to confirm the channel is opaque (no plaintext).
#
# Example:
#   scripts/remote-channel-probe.sh --host 5.6.7.8 --mesh-id hetzner-testbed \
#     --responder-peer qlink_XXXX --count 500 --interval-ms 5 --pcap
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

HOST=""
RENDEZVOUS_PORT="9471"
MESH_ID="hetzner-testbed"
PEER=""
COUNT="500"
INTERVAL_MS="5"
PAYLOAD="qlink-channel-probe"
BIN="${QLINK_BIN:-$ROOT/target/release/qlinkctl}"
PCAP=0
BUILD=0

usage() {
  cat <<EOF
Usage: scripts/remote-channel-probe.sh --host IP --responder-peer PEER [options]

  --host IP             Remote server public IP (required)
  --responder-peer P    Responder peer_id from 'hetzner-testbed.sh info' (required)
  --mesh-id ID          Mesh id (default: $MESH_ID)
  --rendezvous-port N   Remote rendezvous TCP port (default: $RENDEZVOUS_PORT)
  --count N             Frames to stream (default: $COUNT)
  --interval-ms N       Delay between frames (default: $INTERVAL_MS)
  --payload S           Frame payload (default: $PAYLOAD)
  --pcap                Capture the wire (tcpdump, needs sudo) + scan for plaintext
  --build               Build qlinkctl first (release, dev-quic-carrier)
  --qlink-bin PATH      Use an existing qlinkctl
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --responder-peer) PEER="$2"; shift 2 ;;
    --mesh-id) MESH_ID="$2"; shift 2 ;;
    --rendezvous-port) RENDEZVOUS_PORT="$2"; shift 2 ;;
    --count) COUNT="$2"; shift 2 ;;
    --interval-ms) INTERVAL_MS="$2"; shift 2 ;;
    --payload) PAYLOAD="$2"; shift 2 ;;
    --pcap) PCAP=1; shift ;;
    --build) BUILD=1; shift ;;
    --qlink-bin) BIN="$2"; shift 2 ;;
    --help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$HOST" ]] || { echo "--host is required" >&2; usage >&2; exit 2; }
[[ -n "$PEER" ]] || { echo "--responder-peer is required" >&2; usage >&2; exit 2; }

if [[ "$BUILD" -eq 1 ]]; then
  echo "building qlinkctl (release, --features dev-quic-carrier)"
  cargo build --release --bin qlinkctl --features dev-quic-carrier
fi
[[ -x "$BIN" ]] || { echo "qlinkctl not found at $BIN (use --build or --qlink-bin)" >&2; exit 1; }

PCAP_FILE=""
PCAP_PID=""
cleanup() { [[ -n "$PCAP_PID" ]] && sudo kill "$PCAP_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

if [[ "$PCAP" -eq 1 ]]; then
  PCAP_FILE="$(mktemp -t qlink-channel-XXXX).pcap"
  echo "capturing wire to $PCAP_FILE (udp host $HOST) — sudo required"
  sudo tcpdump -i any -w "$PCAP_FILE" "udp and host $HOST" >/dev/null 2>&1 &
  PCAP_PID=$!
  sleep 1
fi

echo "=== streaming $COUNT frames -> $HOST:$RENDEZVOUS_PORT (peer $PEER) ==="
"$BIN" direct-send \
  --rendezvous "$HOST:$RENDEZVOUS_PORT" \
  --mesh-id "$MESH_ID" \
  --remote-peer-id "$PEER" \
  --bind-addr "0.0.0.0:0" \
  --payload "$PAYLOAD" \
  --count "$COUNT" \
  --interval-ms "$INTERVAL_MS" \
  2>&1 | grep -E 'selected_path|selected_remote_addr|frames_sent|stream_elapsed_ms|frames_per_sec|stream_bytes|total_elapsed_ms'

if [[ "$PCAP" -eq 1 ]]; then
  sleep 1; sudo kill "$PCAP_PID" 2>/dev/null || true; PCAP_PID=""
  PKTS="$(sudo tcpdump -r "$PCAP_FILE" 2>/dev/null | wc -l | tr -d ' ')"
  echo "=== wire capture: $PKTS packets in $PCAP_FILE ==="
  # Confidentiality check: the cleartext payload must NOT appear on the wire.
  if sudo tcpdump -r "$PCAP_FILE" -A 2>/dev/null | grep -qF "$PAYLOAD"; then
    echo "  LEAK: cleartext payload found on the wire!"
  else
    echo "  OK: cleartext payload '$PAYLOAD' not present on the wire (channel opaque)"
  fi
fi
