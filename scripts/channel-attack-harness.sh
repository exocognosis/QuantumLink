#!/usr/bin/env bash
#
# channel-attack-harness.sh — run the QuantumLink channel-attack battery and
# render a PASS/FAIL matrix. Exercises the REAL PQC channel:
#   * app-layer tamper / replay / downgrade / key-isolation on frames derived
#     from a live ML-KEM-768 handshake, and
#   * a LIVE malicious-relay MITM that tampers or duplicates PQC frames in
#     flight, asserting the channel fails closed end-to-end.
#
# Runs on-machine, no signing, no remote host required.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SCENARIO="all"
BIN="${QLINK_BIN:-$ROOT/target/release/qlinkctl}"
BUILD=0
LOG_ROOT="$ROOT/build/channel-attack"

usage() {
  cat <<EOF
Usage: scripts/channel-attack-harness.sh [options]
  --scenario S   all (default) | crypto | relay-baseline | relay-tamper | relay-replay
  --build        Build qlinkctl first (release, --features dev-quic-carrier)
  --qlink-bin P  Use an existing qlinkctl
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scenario) SCENARIO="$2"; shift 2 ;;
    --build) BUILD=1; shift ;;
    --qlink-bin) BIN="$2"; shift 2 ;;
    --help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$BUILD" -eq 1 ]]; then
  echo "building qlinkctl (release, --features dev-quic-carrier)"
  cargo build --release --bin qlinkctl --features dev-quic-carrier
fi
[[ -x "$BIN" ]] || { echo "qlinkctl not found at $BIN (use --build)" >&2; exit 1; }

RUN_ID="chan-$(date -u +%Y%m%d-%H%M%S)"
RUN_DIR="$LOG_ROOT/$RUN_ID"
mkdir -p "$RUN_DIR"
RAW="$RUN_DIR/raw.log"

echo "running channel-attack --scenario $SCENARIO"
set +e
"$BIN" channel-attack --scenario "$SCENARIO" >"$RAW" 2>&1
STATUS=$?
set -e

{
  echo "# QuantumLink Channel-Attack Matrix"
  echo
  echo "- run: \`$RUN_ID\`  scenario: \`$SCENARIO\`"
  echo "- target: the real PQC channel (live ML-KEM-768 handshake keys + a live malicious-relay MITM)"
  echo
  echo "| Attack | Layer | Expected | Observed | Verdict |"
  echo "|---|---|---|---|---|"
  grep '^attack=' "$RAW" | while IFS= read -r line; do
    name=$(sed -n 's/.*attack=\([^ ]*\).*/\1/p' <<<"$line")
    layer=$(sed -n 's/.*layer=\([^ ]*\).*/\1/p' <<<"$line")
    expected=$(sed -n 's/.*expected=\([^ ]*\).*/\1/p' <<<"$line")
    verdict=$(sed -n 's/.*verdict=\([^ ]*\).*/\1/p' <<<"$line")
    observed=$(sed -n 's/.*observed=\(.*\) verdict=.*/\1/p' <<<"$line")
    printf '| %s | %s | %s | %s | %s |\n' "$name" "$layer" "$expected" "$observed" "$verdict"
  done
  echo
  grep -E '^channel_attack_(passed|total|result)=' "$RAW" | sed 's/^/- /'
} | tee "$RUN_DIR/summary.md"

echo
echo "raw: $RAW"
exit $STATUS
