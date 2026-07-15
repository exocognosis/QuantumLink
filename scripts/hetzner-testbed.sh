#!/usr/bin/env bash
#
# hetzner-testbed.sh — isolated QuantumLink channel-test rig for a server YOU own.
#
# Stands up a self-contained "silo" (one directory, purgeable) running the
# QuantumLink control plane + a resident PQC responder that absorbs a streamed
# encrypted channel and exposes received-frame metrics. A client (see
# scripts/remote-channel-probe.sh) then direct-connects over the real network,
# streams packets, and you monitor / attack the channel.
#
# Nothing here touches the rest of the box: all state lives under the silo dir,
# services run as the invoking user on high ports, and `purge` removes it all.
#
# THIS RUNS ON THE SERVER. Copy the repo (or at least rust/ + scripts/) to the
# box first, e.g.:  rsync -az --exclude target ./ user@HOST:~/QuantumLinkOS/
# then on the box:  cd ~/QuantumLinkOS && QLINK_SRC=$PWD scripts/hetzner-testbed.sh build && scripts/hetzner-testbed.sh start
#
# Subcommands: deps | build | start | status | stop | purge | info | firewall
#
set -euo pipefail

SILO="${QLINK_TESTBED_DIR:-$HOME/qlink-testbed}"
SRC="${QLINK_SRC:-}"                       # repo checkout root, for `build`
MESH_ID="${QLINK_MESH_ID:-hetzner-testbed}"
RENDEZVOUS_PORT="${QLINK_RENDEZVOUS_PORT:-9471}"   # TCP
RELAY_PORT="${QLINK_RELAY_PORT:-9472}"             # TCP
RESPONDER_PORT="${QLINK_RESPONDER_PORT:-9510}"     # UDP (QUIC)
METRICS_PORT="${QLINK_METRICS_PORT:-9600}"         # TCP (bound to localhost)
PUBLIC_IP="${QLINK_PUBLIC_IP:-}"
BIN="$SILO/qlinkctl"
KEYFILE="$SILO/responder.seed"
PIDS_DIR="$SILO/pids"
LOGS_DIR="$SILO/logs"

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { echo "error: $*" >&2; exit 1; }

detect_public_ip() {
  [[ -n "$PUBLIC_IP" ]] && { echo "$PUBLIC_IP"; return; }
  local ip
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1)"
  [[ -z "$ip" ]] && ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -z "$ip" ]] && ip="$(curl -fsS --max-time 5 ifconfig.me 2>/dev/null || true)"
  [[ -z "$ip" ]] && die "could not detect public IP; set QLINK_PUBLIC_IP"
  echo "$ip"
}

ensure_dirs() { mkdir -p "$SILO" "$PIDS_DIR" "$LOGS_DIR"; }

cmd_deps() {
  if command -v cargo >/dev/null 2>&1; then log "cargo present: $(cargo --version)"; return; fi
  log "installing rustup (per-user, into ~/.rustup and ~/.cargo)"
  curl -fsS --proto '=https' --tlsv1.2 https://sh.rustup.rs | sh -s -- -y --profile minimal
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
  log "cargo installed: $(cargo --version)"
}

cmd_build() {
  ensure_dirs
  [[ -n "$SRC" ]] || die "set QLINK_SRC to the repo checkout root (the dir with Cargo.toml + Cargo.lock)"
  [[ -f "$SRC/Cargo.lock" ]] || die "no Cargo.lock under QLINK_SRC=$SRC — copy the repo-root Cargo.toml + Cargo.lock and both workspace members"
  command -v cargo >/dev/null 2>&1 || { source "$HOME/.cargo/env" 2>/dev/null || die "cargo not found; run: $0 deps"; }
  log "building qlinkctl (release, --features dev-quic-carrier, --locked) from $SRC"
  # Build from the workspace root with --locked so the box resolves the SAME
  # dependency versions as the developer's Cargo.lock. Several crypto deps are
  # pre-1.0 release candidates (ml-dsa, ml-kem, slh-dsa) whose APIs change
  # between rc's — a fresh resolve picks a newer rc and fails to compile.
  ( cd "$SRC" && cargo build --release --bin qlinkctl --features dev-quic-carrier --locked )
  cp -f "$SRC/target/release/qlinkctl" "$BIN"
  chmod +x "$BIN"
  log "installed $BIN"
}

is_running() { local f="$1"; [[ -f "$f" ]] && kill -0 "$(cat "$f")" 2>/dev/null; }

start_one() {
  local name="$1"; shift
  local pidf="$PIDS_DIR/$name.pid"
  if is_running "$pidf"; then log "$name already running (pid $(cat "$pidf"))"; return; fi
  "$@" >"$LOGS_DIR/$name.log" 2>&1 &
  echo $! >"$pidf"
  log "$name started (pid $!)"
}

cmd_start() {
  ensure_dirs
  [[ -x "$BIN" ]] || die "no qlinkctl at $BIN; run: $0 build"
  local ip; ip="$(detect_public_ip)"
  log "public_ip=$ip mesh_id=$MESH_ID"

  start_one rendezvous "$BIN" rendezvous --listen "0.0.0.0:$RENDEZVOUS_PORT"
  start_one relay      "$BIN" relay      --listen "0.0.0.0:$RELAY_PORT"
  sleep 1
  # Responder binds the PUBLIC IP so the peer record advertises a routable
  # candidate (ICE gathering is off). Metrics stay on localhost — scrape via
  # an SSH tunnel, never expose them publicly.
  start_one responder "$BIN" publish-self \
    --rendezvous "127.0.0.1:$RENDEZVOUS_PORT" \
    --mesh-id "$MESH_ID" \
    --bind-addr "$ip:$RESPONDER_PORT" \
    --ttl-seconds 120 \
    --keyfile "$KEYFILE" \
    --metrics-addr "127.0.0.1:$METRICS_PORT"
  sleep 1
  cmd_info
}

cmd_status() {
  for name in rendezvous relay responder; do
    local pidf="$PIDS_DIR/$name.pid"
    if is_running "$pidf"; then printf '  %-11s RUNNING (pid %s)\n' "$name" "$(cat "$pidf")";
    else printf '  %-11s stopped\n' "$name"; fi
  done
  echo "  --- responder metrics (localhost) ---"
  curl -fsS --max-time 3 "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null \
    | grep -E 'frames_received_total|bytes_received_total|_peers ' | grep -v '^#' | sed 's/^/  /' \
    || echo "  (metrics endpoint not reachable)"
}

cmd_stop() {
  for name in responder relay rendezvous; do
    local pidf="$PIDS_DIR/$name.pid"
    if is_running "$pidf"; then kill "$(cat "$pidf")" 2>/dev/null || true; log "$name stopped"; fi
    rm -f "$pidf"
  done
}

cmd_purge() { cmd_stop; log "removing silo $SILO"; rm -rf "$SILO"; }

cmd_info() {
  local ip peer; ip="$(detect_public_ip)"
  peer="$(sed -n 's/^local_peer_id=//p' "$LOGS_DIR/responder.log" 2>/dev/null | head -1)"
  cat <<EOF

=== QuantumLink testbed — client connection parameters ===
  public_ip        : $ip
  mesh_id          : $MESH_ID
  responder_peer   : ${peer:-<not up yet — check: $0 status>}
  rendezvous       : $ip:$RENDEZVOUS_PORT   (TCP)
  relay            : $ip:$RELAY_PORT   (TCP)
  responder (QUIC) : $ip:$RESPONDER_PORT   (UDP)
  metrics          : 127.0.0.1:$METRICS_PORT   (TCP, localhost only — SSH-tunnel to scrape)

From your workstation:
  scripts/remote-channel-probe.sh --host $ip --mesh-id $MESH_ID \\
    --responder-peer ${peer:-<peer_id>} --count 500 --interval-ms 5
EOF
}

cmd_firewall() {
  local ip; ip="$(detect_public_ip)"
  cat <<EOF
Open these on the Hetzner Cloud firewall AND host firewall (do NOT expose metrics):
  TCP $RENDEZVOUS_PORT   rendezvous
  TCP $RELAY_PORT   relay
  UDP $RESPONDER_PORT   responder (QUIC)
  (metrics TCP $METRICS_PORT stays on 127.0.0.1 — reach it with:
     ssh -L $METRICS_PORT:127.0.0.1:$METRICS_PORT user@$ip )

ufw example:
  sudo ufw allow $RENDEZVOUS_PORT/tcp && sudo ufw allow $RELAY_PORT/tcp && sudo ufw allow $RESPONDER_PORT/udp
EOF
}

case "${1:-}" in
  deps) cmd_deps ;;
  build) cmd_build ;;
  start) cmd_start ;;
  status) cmd_status ;;
  stop) cmd_stop ;;
  purge) cmd_purge ;;
  info) cmd_info ;;
  firewall) cmd_firewall ;;
  *) echo "usage: $0 {deps|build|start|status|stop|purge|info|firewall}" >&2; exit 2 ;;
esac
