#!/usr/bin/env bash
#
# public-edge-service-token-revocation.sh -- run a live public-edge service
# token revocation and replacement drill without writing raw tokens to evidence.
#
# The drill should run from a secured operator shell that can reach the public
# rendezvous/relay endpoints, scrape loopback metrics through SSH forwarding or
# local access, and write the live token/digest files.
#
# Example:
#   scripts/public-edge-service-token-revocation.sh \
#     --env-file ./edge-public.env \
#     --rendezvous-replacement-auth-token-file ./rendezvous-auth-token.next \
#     --relay-replacement-auth-token-file ./relay-auth-token.next \
#     --append-revocation-digests \
#     --install-replacement-tokens

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_FILE=""
EDGE_HOST="${QLINK_PUBLIC_EDGE_HOST:-${QLINK_EDGE_HOST:-}}"
RENDEZVOUS="${QLINK_PUBLIC_RENDEZVOUS_ENDPOINT:-${QLINK_RENDEZVOUS_ENDPOINT:-}}"
RELAY="${QLINK_PUBLIC_RELAY_ENDPOINT:-${QLINK_RELAY_ENDPOINT:-}}"
CONTROL_TLS_CA="${QLINK_CONTROL_TLS_CA:-}"
RENDEZVOUS_AUTH_TOKEN_FILE="${QLINK_RENDEZVOUS_AUTH_TOKEN_FILE:-}"
RELAY_AUTH_TOKEN_FILE="${QLINK_RELAY_AUTH_TOKEN_FILE:-}"
RENDEZVOUS_REPLACEMENT_AUTH_TOKEN_FILE="${QLINK_RENDEZVOUS_REPLACEMENT_AUTH_TOKEN_FILE:-}"
RELAY_REPLACEMENT_AUTH_TOKEN_FILE="${QLINK_RELAY_REPLACEMENT_AUTH_TOKEN_FILE:-}"
RENDEZVOUS_REVOKED_AUTH_TOKEN_DIGEST_FILE="${QLINK_RENDEZVOUS_REVOKED_AUTH_TOKEN_DIGEST_FILE:-${QLINK_REVOKED_SERVICE_TOKEN_DIGESTS:-}}"
RELAY_REVOKED_AUTH_TOKEN_DIGEST_FILE="${QLINK_RELAY_REVOKED_AUTH_TOKEN_DIGEST_FILE:-${QLINK_REVOKED_SERVICE_TOKEN_DIGESTS:-}}"
RENDEZVOUS_METRICS_ADDR="${QLINK_RENDEZVOUS_METRICS_ADDR:-}"
RELAY_METRICS_ADDR="${QLINK_RELAY_METRICS_ADDR:-}"
RUN_DIR="${QLINK_SERVICE_TOKEN_REVOCATION_RUN_DIR:-}"
BIN="${QLINK_BIN:-$ROOT/target/release/qlinkctl}"
APPEND_REVOCATION_DIGESTS=0
INSTALL_REPLACEMENT_TOKENS=0

usage() {
  grep '^#' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file) ENV_FILE="$2"; shift 2 ;;
    --edge-host) EDGE_HOST="$2"; shift 2 ;;
    --rendezvous) RENDEZVOUS="$2"; shift 2 ;;
    --relay) RELAY="$2"; shift 2 ;;
    --control-tls-ca) CONTROL_TLS_CA="$2"; shift 2 ;;
    --rendezvous-auth-token-file) RENDEZVOUS_AUTH_TOKEN_FILE="$2"; shift 2 ;;
    --relay-auth-token-file) RELAY_AUTH_TOKEN_FILE="$2"; shift 2 ;;
    --rendezvous-replacement-auth-token-file) RENDEZVOUS_REPLACEMENT_AUTH_TOKEN_FILE="$2"; shift 2 ;;
    --relay-replacement-auth-token-file) RELAY_REPLACEMENT_AUTH_TOKEN_FILE="$2"; shift 2 ;;
    --rendezvous-revoked-auth-token-digest-file) RENDEZVOUS_REVOKED_AUTH_TOKEN_DIGEST_FILE="$2"; shift 2 ;;
    --relay-revoked-auth-token-digest-file) RELAY_REVOKED_AUTH_TOKEN_DIGEST_FILE="$2"; shift 2 ;;
    --rendezvous-metrics-addr) RENDEZVOUS_METRICS_ADDR="$2"; shift 2 ;;
    --relay-metrics-addr) RELAY_METRICS_ADDR="$2"; shift 2 ;;
    --run-dir) RUN_DIR="$2"; shift 2 ;;
    --qlink-bin) BIN="$2"; shift 2 ;;
    --append-revocation-digests) APPEND_REVOCATION_DIGESTS=1; shift ;;
    --install-replacement-tokens) INSTALL_REPLACEMENT_TOKENS=1; shift ;;
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
  CONTROL_TLS_CA="${QLINK_CONTROL_TLS_CA:-$CONTROL_TLS_CA}"
  RENDEZVOUS_AUTH_TOKEN_FILE="${QLINK_RENDEZVOUS_AUTH_TOKEN_FILE:-$RENDEZVOUS_AUTH_TOKEN_FILE}"
  RELAY_AUTH_TOKEN_FILE="${QLINK_RELAY_AUTH_TOKEN_FILE:-$RELAY_AUTH_TOKEN_FILE}"
  RENDEZVOUS_REPLACEMENT_AUTH_TOKEN_FILE="${QLINK_RENDEZVOUS_REPLACEMENT_AUTH_TOKEN_FILE:-$RENDEZVOUS_REPLACEMENT_AUTH_TOKEN_FILE}"
  RELAY_REPLACEMENT_AUTH_TOKEN_FILE="${QLINK_RELAY_REPLACEMENT_AUTH_TOKEN_FILE:-$RELAY_REPLACEMENT_AUTH_TOKEN_FILE}"
  RENDEZVOUS_REVOKED_AUTH_TOKEN_DIGEST_FILE="${QLINK_RENDEZVOUS_REVOKED_AUTH_TOKEN_DIGEST_FILE:-${QLINK_REVOKED_SERVICE_TOKEN_DIGESTS:-$RENDEZVOUS_REVOKED_AUTH_TOKEN_DIGEST_FILE}}"
  RELAY_REVOKED_AUTH_TOKEN_DIGEST_FILE="${QLINK_RELAY_REVOKED_AUTH_TOKEN_DIGEST_FILE:-${QLINK_REVOKED_SERVICE_TOKEN_DIGESTS:-$RELAY_REVOKED_AUTH_TOKEN_DIGEST_FILE}}"
  RENDEZVOUS_METRICS_ADDR="${QLINK_RENDEZVOUS_METRICS_ADDR:-$RENDEZVOUS_METRICS_ADDR}"
  RELAY_METRICS_ADDR="${QLINK_RELAY_METRICS_ADDR:-$RELAY_METRICS_ADDR}"
  BIN="${QLINK_BIN:-$BIN}"
fi

die() { echo "error: $*" >&2; exit 1; }
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }

read_secret_file() {
  local path="$1"
  [[ -f "$path" ]] || die "secret file does not exist: $path"
  tr -d '\r\n' < "$path"
}

file_sha256() {
  local path="$1"
  if [[ -z "$path" || ! -f "$path" ]]; then
    echo ""
    return 0
  fi
  shasum -a 256 "$path" | awk '{print $1}'
}

service_token_digest_for_file() {
  local path="$1"
  "$BIN" service-token-digest --auth-token-file "$path" \
    | sed -n 's/^service_token_digest=//p' \
    | tail -1
}

probe_rendezvous_success() {
  local token="$1"
  local out="$2"
  local args=(rendezvous-smoke --server "$RENDEZVOUS" --auth-token "$token")
  if [[ -n "$CONTROL_TLS_CA" ]]; then
    args+=(--control-tls-ca "$CONTROL_TLS_CA")
  fi
  "$BIN" "${args[@]}" > "$out" 2>&1
  grep -q '^record_verified=true$' "$out"
}

probe_rendezvous_auth_failure() {
  local token="$1"
  local out="$2"
  local args=(rendezvous-smoke --server "$RENDEZVOUS" --auth-token "$token")
  if [[ -n "$CONTROL_TLS_CA" ]]; then
    args+=(--control-tls-ca "$CONTROL_TLS_CA")
  fi
  if "$BIN" "${args[@]}" > "$out" 2>&1; then
    return 1
  fi
  grep -qi 'authentication failed' "$out"
}

probe_relay_success() {
  local token="$1"
  local peer="$2"
  local out="$3"
  local args=(relay-admission-smoke --server "$RELAY" --peer-id "$peer" --auth-token "$token")
  if [[ -n "$CONTROL_TLS_CA" ]]; then
    args+=(--control-tls-ca "$CONTROL_TLS_CA")
  fi
  "$BIN" "${args[@]}" > "$out" 2>&1
  grep -q '^relay_registration_accepted=true$' "$out"
}

probe_relay_auth_failure() {
  local token="$1"
  local peer="$2"
  local out="$3"
  local args=(relay-admission-smoke --server "$RELAY" --peer-id "$peer" --auth-token "$token")
  if [[ -n "$CONTROL_TLS_CA" ]]; then
    args+=(--control-tls-ca "$CONTROL_TLS_CA")
  fi
  if "$BIN" "${args[@]}" > "$out" 2>&1; then
    return 1
  fi
  grep -qi 'authentication failed' "$out"
}

append_digest_once() {
  local digest="$1"
  local path="$2"
  [[ -n "$digest" ]] || die "empty service-token digest"
  [[ -e "$path" ]] || : > "$path"
  [[ -f "$path" ]] || die "revocation digest path is not a file: $path"
  [[ -w "$path" ]] || die "revocation digest path is not writable: $path"
  if ! awk '{print $1}' "$path" | grep -Fxq "$digest"; then
    printf '%s # public edge service-token revocation drill %s\n' "$digest" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$path"
  fi
}

install_replacement_token() {
  local source="$1"
  local target="$2"
  [[ -f "$source" ]] || die "replacement token file does not exist: $source"
  [[ -f "$target" ]] || die "active token file does not exist: $target"
  local tmp="${target}.next.$$"
  umask 077
  tr -d '\r\n' < "$source" > "$tmp"
  chown --reference="$target" "$tmp" 2>/dev/null || true
  chmod --reference="$target" "$tmp" 2>/dev/null || chmod 0640 "$tmp"
  mv "$tmp" "$target"
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

if [[ -n "$EDGE_HOST" ]]; then
  RENDEZVOUS="${RENDEZVOUS:-tls://$EDGE_HOST:9471}"
  RELAY="${RELAY:-tls://$EDGE_HOST:9472}"
fi

[[ -n "$RENDEZVOUS" ]] || die "missing rendezvous endpoint"
[[ -n "$RELAY" ]] || die "missing relay endpoint"
[[ "$RENDEZVOUS" == tls://* ]] || die "rendezvous endpoint must use tls://"
[[ "$RELAY" == tls://* ]] || die "relay endpoint must use tls://"
[[ -n "$CONTROL_TLS_CA" ]] || die "missing QLINK_CONTROL_TLS_CA or --control-tls-ca"
[[ -f "$CONTROL_TLS_CA" ]] || die "control TLS CA file does not exist: $CONTROL_TLS_CA"
[[ -n "$RENDEZVOUS_AUTH_TOKEN_FILE" ]] || die "missing rendezvous active token file"
[[ -n "$RELAY_AUTH_TOKEN_FILE" ]] || die "missing relay active token file"
[[ -n "$RENDEZVOUS_REPLACEMENT_AUTH_TOKEN_FILE" ]] || die "missing rendezvous replacement token file"
[[ -n "$RELAY_REPLACEMENT_AUTH_TOKEN_FILE" ]] || die "missing relay replacement token file"
[[ -n "$RENDEZVOUS_REVOKED_AUTH_TOKEN_DIGEST_FILE" ]] || die "missing rendezvous revoked digest file"
[[ -n "$RELAY_REVOKED_AUTH_TOKEN_DIGEST_FILE" ]] || die "missing relay revoked digest file"
[[ -n "$RENDEZVOUS_METRICS_ADDR" ]] || die "missing rendezvous metrics address"
[[ -n "$RELAY_METRICS_ADDR" ]] || die "missing relay metrics address"
[[ -x "$BIN" ]] || die "qlinkctl not executable at $BIN"
[[ "$APPEND_REVOCATION_DIGESTS" -eq 1 ]] || die "refusing to mutate revocation files without --append-revocation-digests"
[[ "$INSTALL_REPLACEMENT_TOKENS" -eq 1 ]] || die "refusing to rotate active token files without --install-replacement-tokens"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$RUN_DIR" ]]; then
  RUN_DIR="$ROOT/build/public-edge-service-token-revocation/$timestamp"
fi
mkdir -p "$RUN_DIR"

old_rendezvous_token="$(read_secret_file "$RENDEZVOUS_AUTH_TOKEN_FILE")"
old_relay_token="$(read_secret_file "$RELAY_AUTH_TOKEN_FILE")"
replacement_rendezvous_token="$(read_secret_file "$RENDEZVOUS_REPLACEMENT_AUTH_TOKEN_FILE")"
replacement_relay_token="$(read_secret_file "$RELAY_REPLACEMENT_AUTH_TOKEN_FILE")"

log "proving current rendezvous and relay tokens are accepted before revocation"
probe_rendezvous_success "$old_rendezvous_token" "$RUN_DIR/rendezvous-before-revocation.log" \
  || die "rendezvous active token was not accepted before revocation"
probe_relay_success "$old_relay_token" qlink-revocation-before "$RUN_DIR/relay-before-revocation.log" \
  || die "relay active token was not accepted before revocation"

rendezvous_digest="$(service_token_digest_for_file "$RENDEZVOUS_AUTH_TOKEN_FILE")"
relay_digest="$(service_token_digest_for_file "$RELAY_AUTH_TOKEN_FILE")"

log "appending revoked-token digests"
append_digest_once "$rendezvous_digest" "$RENDEZVOUS_REVOKED_AUTH_TOKEN_DIGEST_FILE"
append_digest_once "$relay_digest" "$RELAY_REVOKED_AUTH_TOKEN_DIGEST_FILE"

log "installing replacement token files"
install_replacement_token "$RENDEZVOUS_REPLACEMENT_AUTH_TOKEN_FILE" "$RENDEZVOUS_AUTH_TOKEN_FILE"
install_replacement_token "$RELAY_REPLACEMENT_AUTH_TOKEN_FILE" "$RELAY_AUTH_TOKEN_FILE"

log "proving revoked tokens are rejected"
probe_rendezvous_auth_failure "$old_rendezvous_token" "$RUN_DIR/rendezvous-revoked-token.log" \
  || die "rendezvous did not reject the revoked token"
probe_relay_auth_failure "$old_relay_token" qlink-revocation-revoked "$RUN_DIR/relay-revoked-token.log" \
  || die "relay did not reject the revoked token"

log "proving replacement tokens are accepted"
probe_rendezvous_success "$replacement_rendezvous_token" "$RUN_DIR/rendezvous-replacement-token.log" \
  || die "rendezvous did not accept the replacement token"
probe_relay_success "$replacement_relay_token" qlink-revocation-replacement "$RUN_DIR/relay-replacement-token.log" \
  || die "relay did not accept the replacement token"

log "scraping auth revocation counters"
scrape_metrics "$RENDEZVOUS_METRICS_ADDR" "$RUN_DIR/rendezvous.metrics" \
  || die "failed to scrape rendezvous metrics at $RENDEZVOUS_METRICS_ADDR"
scrape_metrics "$RELAY_METRICS_ADDR" "$RUN_DIR/relay.metrics" \
  || die "failed to scrape relay metrics at $RELAY_METRICS_ADDR"
rendezvous_auth_revocations_total="$(metric_value "$RUN_DIR/rendezvous.metrics" quantumlink_rendezvous_auth_revocations_total)"
relay_auth_revocations_total="$(metric_value "$RUN_DIR/relay.metrics" quantumlink_relay_auth_revocations_total)"
[[ "$rendezvous_auth_revocations_total" -gt 0 ]] \
  || die "rendezvous auth revocation counter did not increase"
[[ "$relay_auth_revocations_total" -gt 0 ]] \
  || die "relay auth revocation counter did not increase"

rendezvous_revocation_list_sha256="$(file_sha256 "$RENDEZVOUS_REVOKED_AUTH_TOKEN_DIGEST_FILE")"
relay_revocation_list_sha256="$(file_sha256 "$RELAY_REVOKED_AUTH_TOKEN_DIGEST_FILE")"
revocation_list_sha256="${rendezvous_revocation_list_sha256}:${relay_revocation_list_sha256}"
git_sha="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
evidence="$RUN_DIR/service-token-revocation.json"
exports_file="$RUN_DIR/service-token-revocation.env"

export QLINK_REVOCATION_EVIDENCE_PATH="$evidence"
export QLINK_REVOCATION_GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export QLINK_REVOCATION_GIT_SHA="$git_sha"
export QLINK_REVOCATION_RENDEZVOUS="$RENDEZVOUS"
export QLINK_REVOCATION_RELAY="$RELAY"
export QLINK_REVOCATION_RENDEZVOUS_DIGEST_FILE_CONFIGURED=true
export QLINK_REVOCATION_RELAY_DIGEST_FILE_CONFIGURED=true
export QLINK_REVOCATION_RENDEZVOUS_OLD_ACCEPTED=true
export QLINK_REVOCATION_RELAY_OLD_ACCEPTED=true
export QLINK_REVOCATION_RENDEZVOUS_REVOKED_REJECTED=true
export QLINK_REVOCATION_RELAY_REVOKED_REJECTED=true
export QLINK_REVOCATION_RENDEZVOUS_REPLACEMENT_ACCEPTED=true
export QLINK_REVOCATION_RELAY_REPLACEMENT_ACCEPTED=true
export QLINK_REVOCATION_RENDEZVOUS_REVOCATIONS="$rendezvous_auth_revocations_total"
export QLINK_REVOCATION_RELAY_REVOCATIONS="$relay_auth_revocations_total"
export QLINK_REVOCATION_RENDEZVOUS_LIST_SHA="$rendezvous_revocation_list_sha256"
export QLINK_REVOCATION_RELAY_LIST_SHA="$relay_revocation_list_sha256"
export QLINK_REVOCATION_LIST_SHA="$revocation_list_sha256"
ruby -rjson -e '
  out = ARGV.fetch(0)
  evidence = {
    "evidence_kind" => "quantumLinkPublicEdgeServiceTokenRevocation",
    "generated_at" => ENV.fetch("QLINK_REVOCATION_GENERATED_AT"),
    "git_sha" => ENV.fetch("QLINK_REVOCATION_GIT_SHA"),
    "rendezvous" => ENV.fetch("QLINK_REVOCATION_RENDEZVOUS"),
    "relay" => ENV.fetch("QLINK_REVOCATION_RELAY"),
    "revoked_token_digest_file_configured" => true,
    "service_token_revocation_verified" => true,
    "rendezvous_old_token_accepted_before_revocation" => true,
    "relay_old_token_accepted_before_revocation" => true,
    "rendezvous_revoked_token_rejected" => true,
    "relay_revoked_token_rejected" => true,
    "rendezvous_replacement_token_accepted" => true,
    "relay_replacement_token_accepted" => true,
    "rendezvous_auth_revocations_total" => Integer(ENV.fetch("QLINK_REVOCATION_RENDEZVOUS_REVOCATIONS")),
    "relay_auth_revocations_total" => Integer(ENV.fetch("QLINK_REVOCATION_RELAY_REVOCATIONS")),
    "rendezvous_revocation_list_sha256" => ENV.fetch("QLINK_REVOCATION_RENDEZVOUS_LIST_SHA"),
    "relay_revocation_list_sha256" => ENV.fetch("QLINK_REVOCATION_RELAY_LIST_SHA"),
    "revocation_list_sha256" => ENV.fetch("QLINK_REVOCATION_LIST_SHA")
  }
  File.write(out, "#{JSON.pretty_generate(evidence)}\n")
' "$evidence"

cat > "$exports_file" <<EOF
QLINK_SERVICE_TOKEN_REVOCATION_VERIFIED=true
QLINK_RENDEZVOUS_REVOKED_TOKEN_REJECTED=true
QLINK_RELAY_REVOKED_TOKEN_REJECTED=true
QLINK_RENDEZVOUS_REPLACEMENT_TOKEN_ACCEPTED=true
QLINK_RELAY_REPLACEMENT_TOKEN_ACCEPTED=true
EOF
chmod 0600 "$exports_file"

log "PASS service-token revocation drill"
echo "evidence=$evidence"
echo "exports=$exports_file"
