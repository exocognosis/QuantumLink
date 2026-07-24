#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PEERS=5
ROUNDS=20
PEER_SCALES="10,25,50"
DIRECT_CONCURRENCY=8
RELAY_FALLBACK_ROUNDS=20
BASE_PORT=9800
LISTEN_HOST="127.0.0.1"
MESH_ID="lan-sim-$(date -u +%Y%m%d%H%M%S)"
LOG_ROOT="$ROOT/build/security-harness"
QLINK_BIN="${QLINK_BIN:-$ROOT/target/release/qlinkctl}"
BUILD=1

usage() {
  cat <<EOF
Usage: scripts/lan-stress-harness.sh [options]

Options:
  --peers N          Number of local published peers (default: $PEERS)
  --peer-scales CSV  Run separate harness passes for each scale (default: $PEER_SCALES)
  --rounds N         Direct-send rounds per peer (default: $ROUNDS)
  --direct-concurrency N
                     Parallel direct-send workers per stress batch (default: $DIRECT_CONCURRENCY)
  --relay-fallback-rounds N
                     Local relay-fallback stress iterations (default: $RELAY_FALLBACK_ROUNDS)
  --base-port N      First local port for rendezvous/relay/peers (default: $BASE_PORT)
  --mesh-id ID       Mesh id for this LAN simulation (default: generated)
  --listen-host IP   Local bind address (default: $LISTEN_HOST)
  --log-root DIR     Directory for run logs (default: build/security-harness)
  --qlink-bin PATH   Existing qlinkctl binary to use
  --skip-build       Do not run cargo build before starting
  --help             Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --peers) PEERS="$2"; PEER_SCALES=""; shift 2 ;;
    --peer-scales) PEER_SCALES="$2"; shift 2 ;;
    --rounds) ROUNDS="$2"; shift 2 ;;
    --direct-concurrency) DIRECT_CONCURRENCY="$2"; shift 2 ;;
    --relay-fallback-rounds) RELAY_FALLBACK_ROUNDS="$2"; shift 2 ;;
    --base-port) BASE_PORT="$2"; shift 2 ;;
    --mesh-id) MESH_ID="$2"; shift 2 ;;
    --listen-host) LISTEN_HOST="$2"; shift 2 ;;
    --log-root) LOG_ROOT="$2"; shift 2 ;;
    --qlink-bin) QLINK_BIN="$2"; BUILD=0; shift 2 ;;
    --skip-build) BUILD=0; shift ;;
    --help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -n "$PEER_SCALES" ]]; then
  first=1
  IFS=',' read -r -a scales <<< "$PEER_SCALES"
  for scale in "${scales[@]}"; do
    scale="${scale//[[:space:]]/}"
    if [[ -z "$scale" ]]; then
      continue
    fi
    args=(
      --peers "$scale"
      --rounds "$ROUNDS"
      --base-port "$BASE_PORT"
      --mesh-id "$MESH_ID-scale-$scale"
      --listen-host "$LISTEN_HOST"
      --log-root "$LOG_ROOT"
      --direct-concurrency "$DIRECT_CONCURRENCY"
      --relay-fallback-rounds "$RELAY_FALLBACK_ROUNDS"
    )
    if [[ "$BUILD" -eq 0 || "$first" -eq 0 ]]; then
      args+=(--skip-build)
    fi
    if [[ "$QLINK_BIN" != "$ROOT/target/release/qlinkctl" ]]; then
      args+=(--qlink-bin "$QLINK_BIN")
    fi
    "$0" "${args[@]}"
    first=0
    BASE_PORT=$((BASE_PORT + 1000))
  done
  exit 0
fi

case "$PEERS:$ROUNDS:$BASE_PORT:$DIRECT_CONCURRENCY:$RELAY_FALLBACK_ROUNDS" in
  *[!0-9:]*|"::"*) echo "--peers, --rounds, and --base-port must be positive integers" >&2; exit 2 ;;
esac
if [[ "$PEERS" -lt 1 || "$ROUNDS" -lt 1 || "$DIRECT_CONCURRENCY" -lt 1 || "$RELAY_FALLBACK_ROUNDS" -lt 0 ]]; then
  echo "--peers, --rounds, and --direct-concurrency must be positive; --relay-fallback-rounds must be non-negative" >&2
  exit 2
fi

RUN_ID="lan-sim-$(date -u +%Y%m%d-%H%M%S)"
RUN_DIR="$LOG_ROOT/$RUN_ID"
mkdir -p "$RUN_DIR"
SUMMARY="$RUN_DIR/summary.log"
PID_FILE="$RUN_DIR/pids.tsv"
RESOURCE_CSV="$RUN_DIR/resource-usage.csv"
SAMPLER_STOP="$RUN_DIR/resource-sampler.stop"
SAMPLER_PID=""

PIDS=""
cleanup() {
  if [[ -n "$SAMPLER_PID" ]]; then
    : > "$SAMPLER_STOP"
    wait "$SAMPLER_PID" >/dev/null 2>&1 || true
  fi
  for pid in $PIDS; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup EXIT INT TERM

log() {
  printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$SUMMARY"
}

track_pid() {
  role="$1"
  pid="$2"
  printf '%s\t%s\n' "$pid" "$role" >> "$PID_FILE"
}

count_sockets() {
  pid="$1"
  lsof -Pan -p "$pid" -i 2>/dev/null | awk 'NR > 1 {count++} END {print count + 0}'
}

count_fds() {
  pid="$1"
  lsof -Pan -p "$pid" 2>/dev/null | awk 'NR > 1 {count++} END {print count + 0}'
}

start_resource_sampler() {
  printf 'timestamp_utc,pid,role,cpu_percent,rss_kb,fds,sockets\n' > "$RESOURCE_CSV"
  (
    while [[ ! -e "$SAMPLER_STOP" ]]; do
      ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      if [[ -f "$PID_FILE" ]]; then
        while IFS=$'\t' read -r pid role; do
          [[ -z "$pid" ]] && continue
          if kill -0 "$pid" >/dev/null 2>&1; then
            read -r cpu rss <<< "$(ps -p "$pid" -o %cpu= -o rss= 2>/dev/null | awk '{print $1, $2}')"
            fds="$(count_fds "$pid")"
            sockets="$(count_sockets "$pid")"
            printf '%s,%s,%s,%s,%s,%s,%s\n' "$ts" "$pid" "$role" "${cpu:-0}" "${rss:-0}" "$fds" "$sockets" >> "$RESOURCE_CSV"
          fi
        done < "$PID_FILE"
      fi
      sleep 1
    done
  ) &
  SAMPLER_PID="$!"
}

wait_tcp_port() {
  port="$1"
  attempts=0
  while [[ "$attempts" -lt 60 ]]; do
    if nc -z -G 1 "$LISTEN_HOST" "$port" >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 0.1
  done
  return 1
}

wait_peer_id() {
  log_file="$1"
  attempts=0
  while [[ "$attempts" -lt 80 ]]; do
    peer_id="$(sed -n 's/^local_peer_id=//p' "$log_file" | head -1)"
    if [[ -n "$peer_id" ]]; then
      printf '%s\n' "$peer_id"
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 0.1
  done
  return 1
}

start_peer() {
  index="$1"
  port=$((BASE_PORT + 10 + index))
  keyfile="$RUN_DIR/peer-$index.seed"
  log_file="$RUN_DIR/peer-$index.log"
  : > "$log_file"
  "$QLINK_BIN" publish-self \
    --rendezvous "$LISTEN_HOST:$RENDEZVOUS_PORT" \
    --mesh-id "$MESH_ID" \
    --bind-addr "$LISTEN_HOST:$port" \
    --ttl-seconds 120 \
    --keyfile "$keyfile" \
    > "$log_file" 2>&1 &
  pid=$!
  PIDS="$PIDS $pid"
  track_pid "peer-$index" "$pid"
  peer_id="$(wait_peer_id "$log_file")"
  log "peer[$index] pid=$pid peer_id=$peer_id responder=$LISTEN_HOST:$port"
  printf '%s:%s:%s\n' "$index" "$pid" "$peer_id" >> "$RUN_DIR/peers.tsv"
}

run_parallel_direct_sends() {
  name="$1"
  rounds="$2"
  log_file="$RUN_DIR/$name.log"
  results_file="$RUN_DIR/$name.results"
  : > "$log_file"
  : > "$results_file"

  active=0
  batch_pids=""
  for round in $(seq 1 "$rounds"); do
    while IFS=: read -r index pid peer_id; do
      (
        if direct_send "$peer_id" "$name-round-$round-peer-$index" >> "$log_file" 2>&1; then
          printf 'ok\n' >> "$results_file"
        else
          printf 'fail\n' >> "$results_file"
        fi
      ) &
      batch_pids="$batch_pids $!"
      active=$((active + 1))
      if [[ "$active" -ge "$DIRECT_CONCURRENCY" ]]; then
        for child in $batch_pids; do
          wait "$child"
        done
        active=0
        batch_pids=""
      fi
    done < "$RUN_DIR/peers.tsv"
  done
  if [[ "$active" -gt 0 ]]; then
    for child in $batch_pids; do
      wait "$child"
    done
  fi

  ok="$(grep -c '^ok$' "$results_file" || true)"
  fail="$(grep -c '^fail$' "$results_file" || true)"
  log "${name}_success=$ok ${name}_fail=$fail"
}

direct_send() {
  peer_id="$1"
  payload="$2"
  "$QLINK_BIN" direct-send \
    --rendezvous "$LISTEN_HOST:$RENDEZVOUS_PORT" \
    --mesh-id "$MESH_ID" \
    --remote-peer-id "$peer_id" \
    --payload "$payload"
}

if [[ "$BUILD" -eq 1 ]]; then
  log "building qlinkctl release binary"
  # dev-quic-carrier is required: without it direct-send / mesh-connect hit the
  # "native UDP live mesh carrier is not wired yet" error in mesh_transport.rs.
  cargo build -p qlink-core --bin qlinkctl --release --features dev-quic-carrier >> "$RUN_DIR/build.log" 2>&1
fi

if [[ ! -x "$QLINK_BIN" ]]; then
  echo "qlinkctl binary is not executable: $QLINK_BIN" >&2
  exit 1
fi

RENDEZVOUS_PORT="$BASE_PORT"
RELAY_PORT=$((BASE_PORT + 1))
: > "$RUN_DIR/rendezvous.log"
: > "$RUN_DIR/relay.log"
: > "$RUN_DIR/peers.tsv"
: > "$PID_FILE"
start_resource_sampler

log "run_dir=$RUN_DIR"
log "mesh_id=$MESH_ID peers=$PEERS rounds=$ROUNDS direct_concurrency=$DIRECT_CONCURRENCY base_port=$BASE_PORT"

"$QLINK_BIN" rendezvous --listen "$LISTEN_HOST:$RENDEZVOUS_PORT" > "$RUN_DIR/rendezvous.log" 2>&1 &
PIDS="$PIDS $!"
track_pid "rendezvous" "$!"
wait_tcp_port "$RENDEZVOUS_PORT"
log "rendezvous=$LISTEN_HOST:$RENDEZVOUS_PORT"

"$QLINK_BIN" relay --listen "$LISTEN_HOST:$RELAY_PORT" > "$RUN_DIR/relay.log" 2>&1 &
PIDS="$PIDS $!"
track_pid "relay" "$!"
wait_tcp_port "$RELAY_PORT"
log "relay=$LISTEN_HOST:$RELAY_PORT"

for i in $(seq 1 "$PEERS"); do
  start_peer "$i"
done

log "baseline direct sends"
ok=0
fail=0
while IFS=: read -r index pid peer_id; do
  if direct_send "$peer_id" "baseline-peer-$index" >> "$RUN_DIR/direct-baseline.log" 2>&1; then
    ok=$((ok + 1))
  else
    fail=$((fail + 1))
  fi
done < "$RUN_DIR/peers.tsv"
log "baseline_success=$ok baseline_fail=$fail"

log "malformed control-plane probes"
{
  printf 'not-json\n' | nc -w 2 "$LISTEN_HOST" "$RENDEZVOUS_PORT" || true
  printf '{"type":"lookup","mesh_id":"%s"}\n' "$MESH_ID" | nc -w 2 "$LISTEN_HOST" "$RENDEZVOUS_PORT" || true
  printf 'not-json\n' | nc -w 2 "$LISTEN_HOST" "$RELAY_PORT" || true
  { printf '%s\n' '{"type":"register","peer_id":"lan-probe"}'; sleep 0.1; printf '%s\n' '{"type":"datagram","source":"lan-probe","destination":"missing-peer","payload_base64":"%%%"}'; } | nc -w 2 "$LISTEN_HOST" "$RELAY_PORT" || true
} > "$RUN_DIR/malformed-probes.log" 2>&1

log "negative lookup probes"
if direct_send "qlink_missing_peer" "missing-peer" >> "$RUN_DIR/negative.log" 2>&1; then
  log "missing_peer_result=unexpected_success"
else
  log "missing_peer_result=expected_failure"
fi

log "bounded udp noise to responders"
while IFS=: read -r index pid peer_id; do
  port=$((BASE_PORT + 10 + index))
  for n in $(seq 1 3); do
    printf 'lan-noise-%s-%s' "$index" "$n" | nc -u -w 1 "$LISTEN_HOST" "$port" || true
  done
done < "$RUN_DIR/peers.tsv"

log "direct-send stress rounds"
run_parallel_direct_sends "direct-stress" "$ROUNDS"

log "relay-fallback stress rounds"
relay_ok=0
relay_fail=0
for round in $(seq 1 "$RELAY_FALLBACK_ROUNDS"); do
  if "$QLINK_BIN" mesh-connect --scenario relay-fallback >> "$RUN_DIR/relay-fallback-stress.log" 2>&1; then
    relay_ok=$((relay_ok + 1))
  else
    relay_fail=$((relay_fail + 1))
  fi
done
log "relay_fallback_success=$relay_ok relay_fallback_fail=$relay_fail"

log "restart peer[1] and verify recovery"
first_pid="$(awk -F: 'NR==1 {print $2}' "$RUN_DIR/peers.tsv")"
if [[ -n "$first_pid" ]]; then
  kill "$first_pid" >/dev/null 2>&1 || true
  sleep 0.5
  grep -v '^1:' "$RUN_DIR/peers.tsv" > "$RUN_DIR/peers.tsv.next"
  mv "$RUN_DIR/peers.tsv.next" "$RUN_DIR/peers.tsv"
  start_peer 1
fi

ok=0
fail=0
while IFS=: read -r index pid peer_id; do
  if direct_send "$peer_id" "post-restart-peer-$index" >> "$RUN_DIR/direct-post-restart.log" 2>&1; then
    ok=$((ok + 1))
  else
    fail=$((fail + 1))
  fi
done < "$RUN_DIR/peers.tsv"
log "post_restart_success=$ok post_restart_fail=$fail"

log "final service checks"
if ! wait_tcp_port "$RENDEZVOUS_PORT"; then
  log "rendezvous_final=down"
  exit 1
fi
if ! wait_tcp_port "$RELAY_PORT"; then
  log "relay_final=down"
  exit 1
fi

total_expected=$((PEERS * ROUNDS))
if [[ "$fail" -ne 0 ]]; then
  log "result=failed post-restart direct sends failed"
  exit 1
fi
if ! grep -q "direct-stress_success=$total_expected direct-stress_fail=0" "$SUMMARY"; then
  log "result=failed direct stress did not reach expected success count"
  exit 1
fi
if ! grep -q "relay_fallback_success=$RELAY_FALLBACK_ROUNDS relay_fallback_fail=0" "$SUMMARY"; then
  log "result=failed relay fallback stress did not reach expected success count"
  exit 1
fi

log "result=passed"
