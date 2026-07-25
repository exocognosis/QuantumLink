#!/usr/bin/env bash
#
# public-edge-live-evidence.sh -- run both off-host public-edge evidence modes
# and verify that the resulting smoke files are deployable public evidence.
#
# The script is intended to run from a tester machine outside the edge host.
# It consumes exported variables or an env file shaped like
# infra/public-edge/public-edge.env.example plus the public endpoint host.
#
# Required inputs:
#   QLINK_PUBLIC_EDGE_HOST or explicit --rendezvous/--relay/--stun/--turn
#   QLINK_CONTROL_TLS_CA
#   QLINK_RENDEZVOUS_AUTH_TOKEN or QLINK_RENDEZVOUS_AUTH_TOKEN_FILE
#   QLINK_RELAY_AUTH_TOKEN or QLINK_RELAY_AUTH_TOKEN_FILE
#   QLINK_TURN_USERNAME
#   QLINK_TURN_PASSWORD or QLINK_TURN_PASSWORD_FILE
#   QLINK_TURN_REALM
#   QLINK_TURN_PERMIT_PEER_IP
#   QLINK_RENDEZVOUS_METRICS_ADDR and QLINK_RELAY_METRICS_ADDR
#     (usually SSH-forwarded loopback metrics endpoints)
#   QLINK_MAX_REQUEST_LINE_BYTES, QLINK_MAX_CONCURRENT_CONNECTIONS,
#     QLINK_IDLE_TIMEOUT_SECONDS, and relay quota envs
#
# Example:
#   scripts/public-edge-live-evidence.sh --env-file ./edge.env --build

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_FILE=""
EDGE_HOST="${QLINK_PUBLIC_EDGE_HOST:-${QLINK_EDGE_HOST:-}}"
RENDEZVOUS="${QLINK_PUBLIC_RENDEZVOUS_ENDPOINT:-${QLINK_RENDEZVOUS_ENDPOINT:-}}"
RELAY="${QLINK_PUBLIC_RELAY_ENDPOINT:-${QLINK_RELAY_ENDPOINT:-}}"
STUN="${QLINK_PUBLIC_STUN_ENDPOINT:-${QLINK_STUN_ENDPOINT:-}}"
TURN="${QLINK_PUBLIC_TURN_ENDPOINT:-${QLINK_TURN_ENDPOINT:-}}"
CONTROL_TLS_CA="${QLINK_CONTROL_TLS_CA:-}"
RENDEZVOUS_AUTH_TOKEN="${QLINK_RENDEZVOUS_AUTH_TOKEN:-}"
RELAY_AUTH_TOKEN="${QLINK_RELAY_AUTH_TOKEN:-}"
RENDEZVOUS_AUTH_TOKEN_FILE="${QLINK_RENDEZVOUS_AUTH_TOKEN_FILE:-}"
RELAY_AUTH_TOKEN_FILE="${QLINK_RELAY_AUTH_TOKEN_FILE:-}"
TURN_USERNAME="${QLINK_TURN_USERNAME:-}"
TURN_PASSWORD="${QLINK_TURN_PASSWORD:-}"
TURN_PASSWORD_FILE="${QLINK_TURN_PASSWORD_FILE:-}"
TURN_REALM="${QLINK_TURN_REALM:-}"
TURN_PERMIT_PEER_IP="${QLINK_TURN_PERMIT_PEER_IP:-}"
RUN_DIR="${QLINK_PUBLIC_EDGE_EVIDENCE_RUN_DIR:-}"
BIN="${QLINK_BIN:-}"
BUILD=1
COUNT="${QLINK_PUBLIC_INFRA_COUNT:-3}"
TIMEOUT_MS="${QLINK_PUBLIC_INFRA_TIMEOUT_MS:-10000}"
DIRECT_PROBE_TIMEOUT_MS="${QLINK_PUBLIC_INFRA_DIRECT_PROBE_TIMEOUT_MS:-300}"
MESH_ID="${QLINK_MESH_ID:-public-edge-live-evidence}"
RENDEZVOUS_RATE_LIMIT_PER_WINDOW="${QLINK_RENDEZVOUS_RATE_LIMIT_PER_WINDOW:-120}"
RELAY_RATE_LIMIT_PER_WINDOW="${QLINK_RELAY_RATE_LIMIT_PER_WINDOW:-240}"
ADMISSION_RATE_LIMIT_WINDOW_SECONDS="${QLINK_ADMISSION_RATE_LIMIT_WINDOW_SECONDS:-60}"
RENDEZVOUS_METRICS_ADDR="${QLINK_RENDEZVOUS_METRICS_ADDR:-}"
RELAY_METRICS_ADDR="${QLINK_RELAY_METRICS_ADDR:-}"
MAX_REQUEST_LINE_BYTES="${QLINK_MAX_REQUEST_LINE_BYTES:-131072}"
MAX_CONCURRENT_CONNECTIONS="${QLINK_MAX_CONCURRENT_CONNECTIONS:-1024}"
IDLE_TIMEOUT_SECONDS="${QLINK_IDLE_TIMEOUT_SECONDS:-300}"
RELAY_MAX_PAYLOAD_BYTES="${QLINK_RELAY_MAX_PAYLOAD_BYTES:-65536}"
RELAY_MAX_PEER_ID_BYTES="${QLINK_RELAY_MAX_PEER_ID_BYTES:-256}"
RELAY_MAX_REGISTERED_PEERS="${QLINK_RELAY_MAX_REGISTERED_PEERS:-2048}"
RELAY_MAX_PEER_DATAGRAMS_PER_WINDOW="${QLINK_RELAY_MAX_PEER_DATAGRAMS_PER_WINDOW:-120}"
RELAY_PEER_DATAGRAM_WINDOW_SECONDS="${QLINK_RELAY_PEER_DATAGRAM_WINDOW_SECONDS:-60}"

usage() {
  grep '^#' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file) ENV_FILE="$2"; shift 2 ;;
    --edge-host) EDGE_HOST="$2"; shift 2 ;;
    --rendezvous) RENDEZVOUS="$2"; shift 2 ;;
    --relay) RELAY="$2"; shift 2 ;;
    --stun) STUN="$2"; shift 2 ;;
    --turn) TURN="$2"; shift 2 ;;
    --control-tls-ca) CONTROL_TLS_CA="$2"; shift 2 ;;
    --rendezvous-auth-token-file) RENDEZVOUS_AUTH_TOKEN_FILE="$2"; shift 2 ;;
    --relay-auth-token-file) RELAY_AUTH_TOKEN_FILE="$2"; shift 2 ;;
    --turn-password-file) TURN_PASSWORD_FILE="$2"; shift 2 ;;
    --turn-username) TURN_USERNAME="$2"; shift 2 ;;
    --turn-realm) TURN_REALM="$2"; shift 2 ;;
    --turn-permit-peer-ip) TURN_PERMIT_PEER_IP="$2"; shift 2 ;;
    --rendezvous-metrics-addr) RENDEZVOUS_METRICS_ADDR="$2"; shift 2 ;;
    --relay-metrics-addr) RELAY_METRICS_ADDR="$2"; shift 2 ;;
    --max-request-line-bytes) MAX_REQUEST_LINE_BYTES="$2"; shift 2 ;;
    --max-concurrent-connections) MAX_CONCURRENT_CONNECTIONS="$2"; shift 2 ;;
    --idle-timeout-seconds) IDLE_TIMEOUT_SECONDS="$2"; shift 2 ;;
    --relay-max-payload-bytes) RELAY_MAX_PAYLOAD_BYTES="$2"; shift 2 ;;
    --relay-max-peer-id-bytes) RELAY_MAX_PEER_ID_BYTES="$2"; shift 2 ;;
    --relay-max-registered-peers) RELAY_MAX_REGISTERED_PEERS="$2"; shift 2 ;;
    --relay-max-peer-datagrams-per-window) RELAY_MAX_PEER_DATAGRAMS_PER_WINDOW="$2"; shift 2 ;;
    --relay-peer-datagram-window-seconds) RELAY_PEER_DATAGRAM_WINDOW_SECONDS="$2"; shift 2 ;;
    --run-dir) RUN_DIR="$2"; shift 2 ;;
    --mesh-id) MESH_ID="$2"; shift 2 ;;
    --count) COUNT="$2"; shift 2 ;;
    --timeout-ms) TIMEOUT_MS="$2"; shift 2 ;;
    --direct-probe-timeout-ms) DIRECT_PROBE_TIMEOUT_MS="$2"; shift 2 ;;
    --build) BUILD=1; shift ;;
    --no-build) BUILD=0; shift ;;
    --qlink-bin) BIN="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -n "$ENV_FILE" ]]; then
  [[ -f "$ENV_FILE" ]] || { echo "env file does not exist: $ENV_FILE" >&2; exit 1; }
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
  EDGE_HOST="${QLINK_PUBLIC_EDGE_HOST:-${QLINK_EDGE_HOST:-$EDGE_HOST}}"
  RENDEZVOUS="${QLINK_PUBLIC_RENDEZVOUS_ENDPOINT:-${QLINK_RENDEZVOUS_ENDPOINT:-$RENDEZVOUS}}"
  RELAY="${QLINK_PUBLIC_RELAY_ENDPOINT:-${QLINK_RELAY_ENDPOINT:-$RELAY}}"
  STUN="${QLINK_PUBLIC_STUN_ENDPOINT:-${QLINK_STUN_ENDPOINT:-$STUN}}"
  TURN="${QLINK_PUBLIC_TURN_ENDPOINT:-${QLINK_TURN_ENDPOINT:-$TURN}}"
  CONTROL_TLS_CA="${QLINK_CONTROL_TLS_CA:-$CONTROL_TLS_CA}"
  RENDEZVOUS_AUTH_TOKEN="${QLINK_RENDEZVOUS_AUTH_TOKEN:-$RENDEZVOUS_AUTH_TOKEN}"
  RELAY_AUTH_TOKEN="${QLINK_RELAY_AUTH_TOKEN:-$RELAY_AUTH_TOKEN}"
  RENDEZVOUS_AUTH_TOKEN_FILE="${QLINK_RENDEZVOUS_AUTH_TOKEN_FILE:-$RENDEZVOUS_AUTH_TOKEN_FILE}"
  RELAY_AUTH_TOKEN_FILE="${QLINK_RELAY_AUTH_TOKEN_FILE:-$RELAY_AUTH_TOKEN_FILE}"
  TURN_USERNAME="${QLINK_TURN_USERNAME:-$TURN_USERNAME}"
  TURN_PASSWORD="${QLINK_TURN_PASSWORD:-$TURN_PASSWORD}"
  TURN_PASSWORD_FILE="${QLINK_TURN_PASSWORD_FILE:-$TURN_PASSWORD_FILE}"
  TURN_REALM="${QLINK_TURN_REALM:-$TURN_REALM}"
  TURN_PERMIT_PEER_IP="${QLINK_TURN_PERMIT_PEER_IP:-$TURN_PERMIT_PEER_IP}"
  RENDEZVOUS_METRICS_ADDR="${QLINK_RENDEZVOUS_METRICS_ADDR:-$RENDEZVOUS_METRICS_ADDR}"
  RELAY_METRICS_ADDR="${QLINK_RELAY_METRICS_ADDR:-$RELAY_METRICS_ADDR}"
  MAX_REQUEST_LINE_BYTES="${QLINK_MAX_REQUEST_LINE_BYTES:-$MAX_REQUEST_LINE_BYTES}"
  MAX_CONCURRENT_CONNECTIONS="${QLINK_MAX_CONCURRENT_CONNECTIONS:-$MAX_CONCURRENT_CONNECTIONS}"
  IDLE_TIMEOUT_SECONDS="${QLINK_IDLE_TIMEOUT_SECONDS:-$IDLE_TIMEOUT_SECONDS}"
  RELAY_MAX_PAYLOAD_BYTES="${QLINK_RELAY_MAX_PAYLOAD_BYTES:-$RELAY_MAX_PAYLOAD_BYTES}"
  RELAY_MAX_PEER_ID_BYTES="${QLINK_RELAY_MAX_PEER_ID_BYTES:-$RELAY_MAX_PEER_ID_BYTES}"
  RELAY_MAX_REGISTERED_PEERS="${QLINK_RELAY_MAX_REGISTERED_PEERS:-$RELAY_MAX_REGISTERED_PEERS}"
  RELAY_MAX_PEER_DATAGRAMS_PER_WINDOW="${QLINK_RELAY_MAX_PEER_DATAGRAMS_PER_WINDOW:-$RELAY_MAX_PEER_DATAGRAMS_PER_WINDOW}"
  RELAY_PEER_DATAGRAM_WINDOW_SECONDS="${QLINK_RELAY_PEER_DATAGRAM_WINDOW_SECONDS:-$RELAY_PEER_DATAGRAM_WINDOW_SECONDS}"
  BIN="${QLINK_BIN:-$BIN}"
fi

die() { echo "error: $*" >&2; exit 1; }
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }

read_secret_file() {
  local path="$1"
  [[ -f "$path" ]] || die "secret file does not exist: $path"
  tr -d '\r\n' < "$path"
}

if [[ -n "$RENDEZVOUS_AUTH_TOKEN_FILE" ]]; then
  RENDEZVOUS_AUTH_TOKEN="$(read_secret_file "$RENDEZVOUS_AUTH_TOKEN_FILE")"
fi
if [[ -n "$RELAY_AUTH_TOKEN_FILE" ]]; then
  RELAY_AUTH_TOKEN="$(read_secret_file "$RELAY_AUTH_TOKEN_FILE")"
fi
if [[ -n "$TURN_PASSWORD_FILE" ]]; then
  TURN_PASSWORD="$(read_secret_file "$TURN_PASSWORD_FILE")"
fi

if [[ -n "$EDGE_HOST" ]]; then
  RENDEZVOUS="${RENDEZVOUS:-tls://$EDGE_HOST:9471}"
  RELAY="${RELAY:-tls://$EDGE_HOST:9472}"
  STUN="${STUN:-$EDGE_HOST:3478}"
  TURN="${TURN:-$EDGE_HOST:3478}"
fi

[[ -n "$RENDEZVOUS" ]] || die "missing rendezvous endpoint"
[[ -n "$RELAY" ]] || die "missing relay endpoint"
[[ -n "$STUN" ]] || die "missing STUN endpoint"
[[ -n "$TURN" ]] || die "missing TURN endpoint"
[[ "$RENDEZVOUS" == tls://* ]] || die "rendezvous endpoint must use tls://"
[[ "$RELAY" == tls://* ]] || die "relay endpoint must use tls://"
[[ -n "$CONTROL_TLS_CA" ]] || die "missing QLINK_CONTROL_TLS_CA or --control-tls-ca"
[[ -f "$CONTROL_TLS_CA" ]] || die "control TLS CA file does not exist: $CONTROL_TLS_CA"
[[ -n "$RENDEZVOUS_AUTH_TOKEN" ]] || die "missing rendezvous auth token or token file"
[[ -n "$RELAY_AUTH_TOKEN" ]] || die "missing relay auth token or token file"
[[ -n "$TURN_USERNAME" ]] || die "missing TURN username"
[[ -n "$TURN_PASSWORD" ]] || die "missing TURN password"
[[ -n "$TURN_REALM" ]] || die "missing TURN realm"
[[ -n "$TURN_PERMIT_PEER_IP" ]] || die "missing TURN permit peer IP for resident TURN proof"
[[ -n "$RENDEZVOUS_METRICS_ADDR" ]] || die "missing QLINK_RENDEZVOUS_METRICS_ADDR or --rendezvous-metrics-addr"
[[ -n "$RELAY_METRICS_ADDR" ]] || die "missing QLINK_RELAY_METRICS_ADDR or --relay-metrics-addr"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$RUN_DIR" ]]; then
  RUN_DIR="$ROOT/build/public-edge-live-evidence/$timestamp"
fi
mkdir -p "$RUN_DIR/app-relay" "$RUN_DIR/turn-relay"

git_sha="$(git rev-parse HEAD)"
smoke_common=(
  scripts/public-infra-smoke.sh
  --rendezvous "$RENDEZVOUS"
  --relay "$RELAY"
  --stun "$STUN"
  --turn "$TURN"
  --turn-username "$TURN_USERNAME"
  --turn-realm "$TURN_REALM"
  --mesh-id "$MESH_ID"
  --count "$COUNT"
  --timeout-ms "$TIMEOUT_MS"
  --direct-probe-timeout-ms "$DIRECT_PROBE_TIMEOUT_MS"
  --rendezvous-rate-limit-per-window "$RENDEZVOUS_RATE_LIMIT_PER_WINDOW"
  --relay-rate-limit-per-window "$RELAY_RATE_LIMIT_PER_WINDOW"
  --admission-rate-limit-window-seconds "$ADMISSION_RATE_LIMIT_WINDOW_SECONDS"
  --rendezvous-metrics-addr "$RENDEZVOUS_METRICS_ADDR"
  --relay-metrics-addr "$RELAY_METRICS_ADDR"
  --max-request-line-bytes "$MAX_REQUEST_LINE_BYTES"
  --max-concurrent-connections "$MAX_CONCURRENT_CONNECTIONS"
  --idle-timeout-seconds "$IDLE_TIMEOUT_SECONDS"
  --relay-max-payload-bytes "$RELAY_MAX_PAYLOAD_BYTES"
  --relay-max-peer-id-bytes "$RELAY_MAX_PEER_ID_BYTES"
  --relay-max-registered-peers "$RELAY_MAX_REGISTERED_PEERS"
  --relay-max-peer-datagrams-per-window "$RELAY_MAX_PEER_DATAGRAMS_PER_WINDOW"
  --relay-peer-datagram-window-seconds "$RELAY_PEER_DATAGRAM_WINDOW_SECONDS"
)
if [[ "$BUILD" -eq 1 ]]; then
  smoke_common+=(--build)
fi
if [[ -n "$BIN" ]]; then
  smoke_common+=(--qlink-bin "$BIN")
fi

export QLINK_CONTROL_TLS_CA="$CONTROL_TLS_CA"
export QLINK_RENDEZVOUS_AUTH_TOKEN="$RENDEZVOUS_AUTH_TOKEN"
export QLINK_RELAY_AUTH_TOKEN="$RELAY_AUTH_TOKEN"
export QLINK_TURN_PASSWORD="$TURN_PASSWORD"

log "running public app-relay evidence"
"${smoke_common[@]}" --run-dir "$RUN_DIR/app-relay" > "$RUN_DIR/app-relay.log" 2>&1
app_evidence="$RUN_DIR/app-relay/evidence.json"
ruby scripts/verify-public-infra-evidence.rb \
  --require-public \
  --expected-sha "$git_sha" \
  --report "$RUN_DIR/app-relay-verification.json" \
  "$app_evidence" > "$RUN_DIR/app-relay-verification.stdout.json"

log "running public TURN relay evidence"
"${smoke_common[@]}" \
  --prove-turn-relay \
  --turn-permit-peer-ip "$TURN_PERMIT_PEER_IP" \
  --run-dir "$RUN_DIR/turn-relay" > "$RUN_DIR/turn-relay.log" 2>&1
turn_evidence="$RUN_DIR/turn-relay/evidence.json"
ruby scripts/verify-public-infra-evidence.rb \
  --require-public \
  --require-turn-relay \
  --expected-sha "$git_sha" \
  --report "$RUN_DIR/turn-relay-verification.json" \
  "$turn_evidence" > "$RUN_DIR/turn-relay-verification.stdout.json"

credential_source() {
  local file="$1"
  if [[ -n "$file" ]]; then
    echo "file"
  else
    echo "environment"
  fi
}

manifest="$RUN_DIR/manifest.json"
export QLINK_LIVE_EVIDENCE_GIT_SHA="$git_sha"
export QLINK_LIVE_EVIDENCE_RENDEZVOUS_AUTH_SOURCE="$(credential_source "$RENDEZVOUS_AUTH_TOKEN_FILE")"
export QLINK_LIVE_EVIDENCE_RELAY_AUTH_SOURCE="$(credential_source "$RELAY_AUTH_TOKEN_FILE")"
export QLINK_LIVE_EVIDENCE_TURN_PASSWORD_SOURCE="$(credential_source "$TURN_PASSWORD_FILE")"
ruby -rjson -rtime -e '
  manifest_path = ARGV.fetch(0)
  app_evidence_path = ARGV.fetch(1)
  app_verification_path = ARGV.fetch(2)
  turn_evidence_path = ARGV.fetch(3)
  turn_verification_path = ARGV.fetch(4)
  app = JSON.parse(File.read(app_evidence_path))
  app_verification = JSON.parse(File.read(app_verification_path))
  turn = JSON.parse(File.read(turn_evidence_path))
  turn_verification = JSON.parse(File.read(turn_verification_path))
  manifest = {
    "schemaVersion" => 1,
    "evidenceKind" => "quantumLinkPublicEdgeLiveEvidence",
    "generatedAt" => Time.now.utc.iso8601,
    "gitSha" => ENV.fetch("QLINK_LIVE_EVIDENCE_GIT_SHA"),
    "mode" => "public",
    "status" => (app_verification.fetch("publicInfraReady") && turn_verification.fetch("publicInfraReady") ? "pass" : "blocked"),
    "endpoints" => {
      "rendezvous" => app.fetch("rendezvous"),
      "relay" => app.fetch("relay"),
      "stun" => app.fetch("stun"),
      "turn" => app.fetch("turn")
    },
    "credentialSources" => {
      "controlTlsCa" => "file",
      "rendezvousAuth" => ENV.fetch("QLINK_LIVE_EVIDENCE_RENDEZVOUS_AUTH_SOURCE"),
      "relayAuth" => ENV.fetch("QLINK_LIVE_EVIDENCE_RELAY_AUTH_SOURCE"),
      "turnPassword" => ENV.fetch("QLINK_LIVE_EVIDENCE_TURN_PASSWORD_SOURCE")
    },
    "proofs" => {
      "appRelay" => {
        "evidence" => app_evidence_path,
        "verification" => app_verification_path,
        "selectedPath" => app.fetch("selected_path"),
        "framesSent" => app.fetch("frames_sent"),
        "rendezvousMetricsScraped" => app.fetch("rendezvous_metrics_scraped"),
        "relayMetricsScraped" => app.fetch("relay_metrics_scraped"),
        "boundsVerified" => app.fetch("bounds_verified"),
        "relayPayloadLimitVerified" => app.fetch("relay_payload_limit_verified"),
        "relaySaturationLimitVerified" => app.fetch("relay_saturation_limit_verified"),
        "rendezvousAuthFailuresTotal" => app.fetch("rendezvous_auth_failures_total"),
        "relayAuthFailuresTotal" => app.fetch("relay_auth_failures_total"),
        "rendezvousRequestTooLargeTotal" => app.fetch("rendezvous_request_too_large_total"),
        "relayRequestTooLargeTotal" => app.fetch("relay_request_too_large_total"),
        "relayPayloadTooLargeTotal" => app.fetch("relay_payload_too_large_total"),
        "relayPeerRateLimitedTotal" => app.fetch("relay_peer_rate_limited_total"),
        "relayForwardedDatagramsTotal" => app.fetch("relay_forwarded_datagrams_total"),
        "publicInfraReady" => app_verification.fetch("publicInfraReady")
      },
      "turnRelay" => {
        "evidence" => turn_evidence_path,
        "verification" => turn_verification_path,
        "selectedPath" => turn.fetch("selected_path"),
        "framesSent" => turn.fetch("frames_sent"),
        "rendezvousMetricsScraped" => turn.fetch("rendezvous_metrics_scraped"),
        "relayMetricsScraped" => turn.fetch("relay_metrics_scraped"),
        "boundsVerified" => turn.fetch("bounds_verified"),
        "relayPayloadLimitVerified" => turn.fetch("relay_payload_limit_verified"),
        "relaySaturationLimitVerified" => turn.fetch("relay_saturation_limit_verified"),
        "rendezvousAuthFailuresTotal" => turn.fetch("rendezvous_auth_failures_total"),
        "relayAuthFailuresTotal" => turn.fetch("relay_auth_failures_total"),
        "rendezvousRequestTooLargeTotal" => turn.fetch("rendezvous_request_too_large_total"),
        "relayRequestTooLargeTotal" => turn.fetch("relay_request_too_large_total"),
        "relayPayloadTooLargeTotal" => turn.fetch("relay_payload_too_large_total"),
        "relayPeerRateLimitedTotal" => turn.fetch("relay_peer_rate_limited_total"),
        "publicInfraReady" => turn_verification.fetch("publicInfraReady")
      }
    }
  }
  File.write(manifest_path, "#{JSON.pretty_generate(manifest)}\n")
' "$manifest" "$app_evidence" "$RUN_DIR/app-relay-verification.json" "$turn_evidence" "$RUN_DIR/turn-relay-verification.json"

log "PASS public edge live evidence"
echo "manifest=$manifest"
echo "app_relay_evidence=$app_evidence"
echo "turn_relay_evidence=$turn_evidence"
