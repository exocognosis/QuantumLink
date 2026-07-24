#!/usr/bin/env bash
#
# connectivity-test-harness.sh
#
# Runnable, on-machine connectivity matrix for QuantumLink's three deployment
# modes: Direct, Mesh (direct + relay fallback), and Local VPN (full tunnel).
#
# It exercises the real PQC transport engine on loopback using virtual test
# components -- a virtual control plane (rendezvous + relay on loopback ports),
# virtual nodes (distinct loopback ports), overlay virtual IPs (100.127.0.x in
# the signed peer records), and black-hole virtual IPs (RFC 5737 TEST-NET-1 /
# 127.0.0.1:1) to force relay fallback. No code signing or second machine is
# required for Layers 1-2; Layer 3 (the macOS Network Extension tunnel) stays
# gated on a signed build and is reported as such.
#
# Layers
#   L1  Rust transport engine (loopback)      -- always runs, gates the verdict
#   L2  Swift FFI full-tunnel packet round-trip -- runs if swift + dylib present
#   L3  macOS NEPacketTunnelProvider           -- reported only (needs signing)
#
# Output: a metrics matrix (stdout + summary.md) and machine-readable
# metrics.json under build/connectivity-harness/<run-id>/.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ---- configuration -------------------------------------------------------
ITERATIONS=10          # timed samples per scenario (percentiles)
PEERS=3                # resident virtual peers for the LAN direct sweep
BASE_PORT=19600        # first loopback port (rendezvous); +1 relay; +10.. peers
LISTEN_HOST="127.0.0.1"
MESH_ID="conn-harness-$(date -u +%Y%m%d%H%M%S)"
FEATURES="dev-quic-carrier"
QLINK_BIN="${QLINK_BIN:-$ROOT/target/release/qlinkctl}"
DYLIB="${QLINK_CORE_DYLIB:-$ROOT/target/release/libqlink_core.dylib}"
LOG_ROOT="$ROOT/build/connectivity-harness"
BUILD=1
RUN_FFI=1              # Layer 2 Swift FFI smoke
RUN_WAN=0             # synthetic-WAN bench sweep (slow: cargo bench)
LOOPBACK_ALIAS=0     # add lo0 alias virtual host IPs (needs sudo)

# SLO targets (ms) from docs/perf-baseline.md
SLO_DIRECT_MS=300
SLO_RELAY_MS=2000

usage() {
  cat <<EOF
Usage: scripts/connectivity-test-harness.sh [options]

  --iterations N   Timed samples per scenario (default: $ITERATIONS)
  --peers N        Resident virtual peers for the LAN sweep (default: $PEERS)
  --base-port N    First loopback port (default: $BASE_PORT)
  --qlink-bin PATH Use an existing qlinkctl (skips the cargo build)
  --skip-build     Do not cargo build qlinkctl before running
  --no-ffi         Skip the Layer-2 Swift FFI packet round-trip
  --wan            Also run the synthetic-WAN bench sweep (slow)
  --loopback-alias Add lo0 alias virtual host IPs 127.0.0.2.. (needs sudo)
  --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --peers) PEERS="$2"; shift 2 ;;
    --base-port) BASE_PORT="$2"; shift 2 ;;
    --qlink-bin) QLINK_BIN="$2"; BUILD=0; shift 2 ;;
    --skip-build) BUILD=0; shift ;;
    --no-ffi) RUN_FFI=0; shift ;;
    --wan) RUN_WAN=1; shift ;;
    --loopback-alias) LOOPBACK_ALIAS=1; shift ;;
    --help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

RUN_ID="conn-$(date -u +%Y%m%d-%H%M%S)"
RUN_DIR="$LOG_ROOT/$RUN_ID"
mkdir -p "$RUN_DIR"
SUMMARY_MD="$RUN_DIR/summary.md"
METRICS_JSON="$RUN_DIR/metrics.json"
RENDEZVOUS_PORT="$BASE_PORT"
RELAY_PORT=$((BASE_PORT + 1))

PIDS=""
ALIAS_IPS=""
cleanup() {
  for pid in $PIDS; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  for ip in $ALIAS_IPS; do
    sudo ifconfig lo0 -alias "$ip" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT INT TERM

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# Rows for the final matrix: "config|component|assert|samples|p50|p90|max|slo|verdict"
MATRIX_ROWS=""
add_row() { MATRIX_ROWS="${MATRIX_ROWS}$1"$'\n'; }

# percentiles from a file of integers -> sets P50 P90 PMAX (blank if empty)
percentiles() {
  local file="$1"
  P50=""; P90=""; PMAX=""
  [[ -s "$file" ]] || return 0
  read -r P50 P90 PMAX < <(sort -n "$file" | awk '
    function pick(p,   i){ i=int((p/100.0)*(NR-1))+1; if(i<1)i=1; if(i>NR)i=NR; return v[i] }
    {v[NR]=$1}
    END{ if(NR==0) exit; printf "%d %d %d\n", pick(50), pick(90), v[NR] }')
}

verdict_for() {  # $1 p50, $2 slo -> PASS/FAIL/-
  [[ -z "$1" ]] && { echo "-"; return; }
  if [[ "$1" -le "$2" ]]; then echo "PASS"; else echo "FAIL"; fi
}

wait_tcp_port() {
  local port="$1" attempts=0
  while [[ "$attempts" -lt 60 ]]; do
    if nc -z -G 1 "$LISTEN_HOST" "$port" >/dev/null 2>&1; then return 0; fi
    attempts=$((attempts + 1)); sleep 0.1
  done
  return 1
}

# ---- preflight -----------------------------------------------------------
log "run_dir=$RUN_DIR"
log "mesh_id=$MESH_ID iterations=$ITERATIONS peers=$PEERS base_port=$BASE_PORT"

if [[ "$BUILD" -eq 1 ]]; then
  log "building qlinkctl (release, --features $FEATURES)"
  cargo build --release --bin qlinkctl --features "$FEATURES" >"$RUN_DIR/build.log" 2>&1
fi
if [[ ! -x "$QLINK_BIN" ]]; then
  echo "qlinkctl not executable: $QLINK_BIN" >&2; exit 1
fi
log "qlink_bin=$QLINK_BIN"

if [[ "$LOOPBACK_ALIAS" -eq 1 ]]; then
  for n in 2 3 4; do
    ip="127.0.0.$n"
    if sudo ifconfig lo0 alias "$ip" up >/dev/null 2>&1; then
      ALIAS_IPS="$ALIAS_IPS $ip"; log "loopback_alias_added=$ip"
    fi
  done
fi

# ---- L1.0 PQC handshake sanity ------------------------------------------
log "[handshake] simulate-handshake"
HS_LOG="$RUN_DIR/handshake.log"
"$QLINK_BIN" simulate-handshake >"$HS_LOG" 2>&1 || true
HS_SUITE="$(sed -n 's/^suite=//p' "$HS_LOG" | head -1)"
HS_TXRX="$(sed -n 's/^initiator_tx_matches_responder_rx=//p' "$HS_LOG" | head -1)"
HS_RXTX="$(sed -n 's/^initiator_rx_matches_responder_tx=//p' "$HS_LOG" | head -1)"
if [[ "$HS_TXRX" == "true" && "$HS_RXTX" == "true" ]]; then HS_VERDICT="PASS"; else HS_VERDICT="FAIL"; fi
log "[handshake] suite=$HS_SUITE keys_agree=$HS_TXRX/$HS_RXTX -> $HS_VERDICT"
add_row "handshake|ML-KEM-768 + ML-DSA-65|keys_agree|1|-|-|-|-|$HS_VERDICT"

# ---- L1.1 DIRECT (self-contained scenario) ------------------------------
log "[direct/self] mesh-connect --scenario direct x$ITERATIONS"
DS_SELF="$RUN_DIR/direct-self.samples"; : >"$DS_SELF"
ds_self_bad=0
for i in $(seq 1 "$ITERATIONS"); do
  out="$("$QLINK_BIN" mesh-connect --scenario direct 2>>"$RUN_DIR/direct-self.log")" || true
  path="$(printf '%s\n' "$out" | sed -n 's/^selected_path=//p' | head -1)"
  ms="$(printf '%s\n' "$out" | sed -n 's/^total_elapsed_ms=//p' | head -1)"
  [[ "$path" == "direct" ]] || ds_self_bad=$((ds_self_bad+1))
  [[ -n "$ms" ]] && printf '%s\n' "$ms" >>"$DS_SELF"
done
percentiles "$DS_SELF"
DS_SELF_V="$(verdict_for "$P50" "$SLO_DIRECT_MS")"
[[ "$ds_self_bad" -ne 0 ]] && DS_SELF_V="FAIL"
log "[direct/self] p50=${P50}ms p90=${P90}ms max=${PMAX}ms wrong_path=$ds_self_bad -> $DS_SELF_V"
add_row "direct|self-contained (real QUIC responder)|selected_path=direct|$ITERATIONS|$P50|$P90|$PMAX|$SLO_DIRECT_MS|$DS_SELF_V"

# ---- L1.2 DIRECT (virtual-node LAN via rendezvous + publish-self) -------
log "[direct/lan] standing up virtual control plane + $PEERS resident peers"
"$QLINK_BIN" rendezvous --listen "$LISTEN_HOST:$RENDEZVOUS_PORT" >"$RUN_DIR/rendezvous.log" 2>&1 &
PIDS="$PIDS $!"; wait_tcp_port "$RENDEZVOUS_PORT" || { echo "rendezvous down" >&2; exit 1; }
"$QLINK_BIN" relay --listen "$LISTEN_HOST:$RELAY_PORT" >"$RUN_DIR/relay.log" 2>&1 &
PIDS="$PIDS $!"; wait_tcp_port "$RELAY_PORT" || { echo "relay down" >&2; exit 1; }
log "[direct/lan] virtual control plane: rendezvous=$LISTEN_HOST:$RENDEZVOUS_PORT relay=$LISTEN_HOST:$RELAY_PORT"

: >"$RUN_DIR/peers.tsv"
for idx in $(seq 1 "$PEERS"); do
  port=$((BASE_PORT + 10 + idx))
  keyfile="$RUN_DIR/peer-$idx.seed"
  plog="$RUN_DIR/peer-$idx.log"; : >"$plog"
  "$QLINK_BIN" publish-self --rendezvous "$LISTEN_HOST:$RENDEZVOUS_PORT" --mesh-id "$MESH_ID" \
    --bind-addr "$LISTEN_HOST:$port" --ttl-seconds 120 --keyfile "$keyfile" >"$plog" 2>&1 &
  PIDS="$PIDS $!"
  pid_line=""
  for _ in $(seq 1 60); do
    pid_line="$(sed -n 's/^local_peer_id=//p' "$plog" | head -1)"
    [[ -n "$pid_line" ]] && break; sleep 0.1
  done
  [[ -n "$pid_line" ]] || { echo "peer $idx never published" >&2; exit 1; }
  printf '%s:%s\n' "$idx" "$pid_line" >>"$RUN_DIR/peers.tsv"
  log "[direct/lan] virtual node $idx: port=$port peer_id=$pid_line"
done

DS_LAN="$RUN_DIR/direct-lan.samples"; : >"$DS_LAN"
DS_LAN_QC="$RUN_DIR/direct-lan.quicconnect"; : >"$DS_LAN_QC"
ds_lan_bad=0; ds_lan_ok=0
for round in $(seq 1 "$ITERATIONS"); do
  while IFS=: read -r idx peer_id; do
    out="$("$QLINK_BIN" direct-send --rendezvous "$LISTEN_HOST:$RENDEZVOUS_PORT" --mesh-id "$MESH_ID" \
        --remote-peer-id "$peer_id" --bind-addr "$LISTEN_HOST:0" \
        --payload "vip-probe-r${round}-p${idx}" 2>>"$RUN_DIR/direct-lan.log")" || true
    path="$(printf '%s\n' "$out" | sed -n 's/^selected_path=//p' | head -1)"
    ms="$(printf '%s\n' "$out" | sed -n 's/^total_elapsed_ms=//p' | head -1)"
    qc="$(printf '%s\n' "$out" | sed -n 's/.*"quic_connect_ms":\([0-9]*\).*/\1/p' | head -1)"
    if [[ "$path" == "direct" && -n "$ms" ]]; then
      ds_lan_ok=$((ds_lan_ok+1)); printf '%s\n' "$ms" >>"$DS_LAN"
      [[ -n "$qc" ]] && printf '%s\n' "$qc" >>"$DS_LAN_QC"
    else
      ds_lan_bad=$((ds_lan_bad+1))
    fi
  done < "$RUN_DIR/peers.tsv"
done
percentiles "$DS_LAN"
DS_LAN_V="$(verdict_for "$P50" "$SLO_DIRECT_MS")"
[[ "$ds_lan_bad" -ne 0 ]] && DS_LAN_V="FAIL"
DS_LAN_P50="$P50"; DS_LAN_P90="$P90"; DS_LAN_MAX="$PMAX"
percentiles "$DS_LAN_QC"; DS_LAN_QC_P50="$P50"
log "[direct/lan] ok=$ds_lan_ok fail=$ds_lan_bad p50=${DS_LAN_P50}ms p90=${DS_LAN_P90}ms max=${DS_LAN_MAX}ms quic_connect_p50=${DS_LAN_QC_P50}ms -> $DS_LAN_V"
add_row "direct|virtual-node LAN ($PEERS peers, overlay IPs)|selected_path=direct|$((PEERS*ITERATIONS))|$DS_LAN_P50|$DS_LAN_P90|$DS_LAN_MAX|$SLO_DIRECT_MS|$DS_LAN_V"

# ---- L1.3 MESH (relay fallback via black-hole virtual IP) ---------------
log "[mesh/relay] mesh-connect --scenario relay-fallback x$ITERATIONS"
MS_RELAY="$RUN_DIR/mesh-relay.samples"; : >"$MS_RELAY"
ms_relay_bad=0
for i in $(seq 1 "$ITERATIONS"); do
  out="$("$QLINK_BIN" mesh-connect --scenario relay-fallback 2>>"$RUN_DIR/mesh-relay.log")" || true
  path="$(printf '%s\n' "$out" | sed -n 's/^selected_path=//p' | head -1)"
  ms="$(printf '%s\n' "$out" | sed -n 's/^total_elapsed_ms=//p' | head -1)"
  [[ "$path" == "relay" ]] || ms_relay_bad=$((ms_relay_bad+1))
  [[ -n "$ms" ]] && printf '%s\n' "$ms" >>"$MS_RELAY"
done
percentiles "$MS_RELAY"
MS_RELAY_V="$(verdict_for "$P50" "$SLO_RELAY_MS")"
[[ "$ms_relay_bad" -ne 0 ]] && MS_RELAY_V="FAIL"
log "[mesh/relay] p50=${P50}ms p90=${P90}ms max=${PMAX}ms wrong_path=$ms_relay_bad -> $MS_RELAY_V"
add_row "mesh|relay fallback (black-hole 127.0.0.1:1)|selected_path=relay|$ITERATIONS|$P50|$P90|$PMAX|$SLO_RELAY_MS|$MS_RELAY_V"

# paced scenario (non-gating: known-flaky demo -- no relay responder on fallback)
log "[mesh/paced] mesh-connect --scenario paced (non-gating)"
paced_out="$("$QLINK_BIN" mesh-connect --scenario paced 2>&1)" || true
paced_path="$(printf '%s\n' "$paced_out" | sed -n 's/^selected_path=//p' | head -1)"
if [[ "$paced_path" == "direct" ]]; then PACED_V="PASS(direct)"; else PACED_V="FLAKY(${paced_path:-error})"; fi
log "[mesh/paced] -> $PACED_V"
add_row "mesh|paced probe (TEST-NET-1 black hole)|selected_path=direct|1|-|-|-|-|$PACED_V (non-gating)"

# ---- L2 LOCAL VPN (Swift FFI full-tunnel packet round-trip) --------------
FFI_V="SKIPPED"
if [[ "$RUN_FFI" -eq 1 ]]; then
  if command -v swift >/dev/null 2>&1 && [[ -f "$DYLIB" ]]; then
    log "[localvpn/ffi] swift full-tunnel packet round-trip (dylib=$DYLIB)"
    if QLINK_CORE_DYLIB="$DYLIB" swift test \
        --filter 'TunnelTransportTests/testTransportSmokeRunnerWhenDylibIsConfigured' \
        >"$RUN_DIR/ffi-smoke.log" 2>&1; then
      FFI_V="PASS"
    else
      FFI_V="FAIL"
    fi
    log "[localvpn/ffi] -> $FFI_V"
  else
    log "[localvpn/ffi] skipped (swift or dylib missing)"
  fi
fi
add_row "localVPN|FFI full-tunnel packet round-trip (100.127.0.10)|packetRoundTrip=true|1|-|-|-|-|$FFI_V"
add_row "localVPN|OS tunnel (NEPacketTunnelProvider, 0.0.0.0/0)|route+DNS+killswitch|-|-|-|-|-|GATED (needs signing)"

# ---- WAN sweep (optional) ------------------------------------------------
if [[ "$RUN_WAN" -eq 1 ]]; then
  log "[wan] cargo bench --bench slos_wan (LAN/CABLE/MOBILE_3G) -- this is slow"
  # slos_wan passes a QUIC endpoint to MeshConnector::new, which only exists in
  # the dev-quic-carrier variant, so the bench needs the feature to compile.
  cargo bench -p qlink-core --bench slos_wan --features dev-quic-carrier >"$RUN_DIR/wan.log" 2>&1 || true
  while IFS= read -r line; do
    scen="$(printf '%s\n' "$line" | awk '{print $1}')"
    p50="$(printf '%s\n' "$line" | sed -n 's/.*p50=\([0-9.]*\)ms.*/\1/p')"
    [[ -n "$p50" ]] && add_row "wan|${scen}|synthetic WAN|-|$p50|-|-|-|INFO"
  done < <(grep -E '^slo\.' "$RUN_DIR/wan.log" 2>/dev/null || true)
fi

# ---- summary matrix ------------------------------------------------------
{
  echo "# QuantumLink Connectivity Test Matrix"
  echo
  echo "- run: \`$RUN_ID\`  mesh_id: \`$MESH_ID\`  iterations: $ITERATIONS  peers: $PEERS"
  echo "- host: on-machine loopback  |  virtual control plane: rendezvous \`$LISTEN_HOST:$RENDEZVOUS_PORT\`, relay \`$LISTEN_HOST:$RELAY_PORT\`"
  echo "- SLOs: direct < ${SLO_DIRECT_MS}ms, relay fallback < ${SLO_RELAY_MS}ms (docs/perf-baseline.md)"
  echo
  echo "| Config | Component | Assertion | Samples | p50 ms | p90 ms | max ms | SLO ms | Verdict |"
  echo "|---|---|---|--:|--:|--:|--:|--:|---|"
  printf '%s' "$MATRIX_ROWS" | while IFS='|' read -r c comp a s p50 p90 pmax slo v; do
    [[ -z "$c" ]] && continue
    printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
      "$c" "$comp" "$a" "${s:--}" "${p50:--}" "${p90:--}" "${pmax:--}" "${slo:--}" "$v"
  done
} | tee "$SUMMARY_MD"

# machine-readable
{
  echo "{"
  echo "  \"run_id\": \"$RUN_ID\","
  echo "  \"mesh_id\": \"$MESH_ID\","
  echo "  \"iterations\": $ITERATIONS,"
  echo "  \"peers\": $PEERS,"
  echo "  \"slo_direct_ms\": $SLO_DIRECT_MS,"
  echo "  \"slo_relay_ms\": $SLO_RELAY_MS,"
  echo "  \"rows\": ["
  printf '%s' "$MATRIX_ROWS" | awk -F'|' 'NF>=9{
    if(started)printf ",\n"; started=1
    printf "    {\"config\":\"%s\",\"component\":\"%s\",\"assert\":\"%s\",\"samples\":\"%s\",\"p50\":\"%s\",\"p90\":\"%s\",\"max\":\"%s\",\"slo\":\"%s\",\"verdict\":\"%s\"}",$1,$2,$3,$4,$5,$6,$7,$8,$9
  } END{print ""}'
  echo "  ]"
  echo "}"
} >"$METRICS_JSON"

log "wrote $SUMMARY_MD"
log "wrote $METRICS_JSON"

# overall verdict: any gating FAIL fails the run
if printf '%s' "$MATRIX_ROWS" | grep -qE '\|FAIL$'; then
  log "result=FAILED (a gating scenario did not meet its assertion/SLO)"
  exit 1
fi
log "result=PASSED"
