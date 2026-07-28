#!/usr/bin/env bash
#
# public-edge-incident-rollback.sh -- capture a public-edge rollback drill and
# verify the post-rollback live evidence manifest.
#
# The default path runs scripts/public-edge-live-evidence.sh after exporting the
# rollback metadata required by the public evidence gate. Pass
# --post-rollback-live-manifest to verify a manifest that was already produced.
#
# Example:
#   scripts/public-edge-incident-rollback.sh \
#     --env-file ./edge-public.env \
#     --incident-id public-edge-drill-YYYYMMDD \
#     --from-release-id "$CURRENT_RELEASE" \
#     --to-release-id "$PREVIOUS_RELEASE" \
#     --rollback-manifest ./rollback-manifest.json \
#     --rollback-duration-seconds 42 \
#     --build

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_FILE=""
INCIDENT_ID="${QLINK_INCIDENT_ID:-}"
ROLLBACK_FROM_RELEASE_ID="${QLINK_ROLLBACK_FROM_RELEASE_ID:-${QLINK_PUBLIC_EDGE_RELEASE_ID:-}}"
ROLLBACK_TO_RELEASE_ID="${QLINK_ROLLBACK_TO_RELEASE_ID:-${QLINK_PREVIOUS_RELEASE_ID:-}}"
ROLLBACK_MANIFEST="${QLINK_ROLLBACK_MANIFEST:-}"
ROLLBACK_DURATION_SECONDS="${QLINK_ROLLBACK_DURATION_SECONDS:-0}"
POST_ROLLBACK_LIVE_MANIFEST="${QLINK_POST_ROLLBACK_LIVE_MANIFEST:-}"
RUN_DIR="${QLINK_INCIDENT_ROLLBACK_RUN_DIR:-}"
BUILD=1
BIN="${QLINK_BIN:-}"

usage() {
  grep '^#' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file) ENV_FILE="$2"; shift 2 ;;
    --incident-id) INCIDENT_ID="$2"; shift 2 ;;
    --from-release-id) ROLLBACK_FROM_RELEASE_ID="$2"; shift 2 ;;
    --to-release-id) ROLLBACK_TO_RELEASE_ID="$2"; shift 2 ;;
    --rollback-manifest) ROLLBACK_MANIFEST="$2"; shift 2 ;;
    --rollback-duration-seconds) ROLLBACK_DURATION_SECONDS="$2"; shift 2 ;;
    --post-rollback-live-manifest) POST_ROLLBACK_LIVE_MANIFEST="$2"; shift 2 ;;
    --run-dir) RUN_DIR="$2"; shift 2 ;;
    --build) BUILD=1; shift ;;
    --no-build) BUILD=0; shift ;;
    --qlink-bin) BIN="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }

file_sha256() {
  local path="$1"
  [[ -f "$path" ]] || die "file does not exist: $path"
  shasum -a 256 "$path" | awk '{print $1}'
}

[[ -n "$INCIDENT_ID" ]] || die "missing incident id"
[[ -n "$ROLLBACK_FROM_RELEASE_ID" ]] || die "missing rollback source release id"
[[ -n "$ROLLBACK_TO_RELEASE_ID" ]] || die "missing rollback target release id"
[[ -n "$ROLLBACK_MANIFEST" ]] || die "missing rollback manifest path"
[[ -f "$ROLLBACK_MANIFEST" ]] || die "rollback manifest does not exist: $ROLLBACK_MANIFEST"
[[ "$ROLLBACK_DURATION_SECONDS" =~ ^[0-9]+$ ]] || die "rollback duration must be an integer number of seconds"
[[ "$ROLLBACK_DURATION_SECONDS" -gt 0 ]] || die "rollback duration must be positive"
if [[ -n "$ENV_FILE" ]]; then
  [[ -f "$ENV_FILE" ]] || die "env file does not exist: $ENV_FILE"
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$RUN_DIR" ]]; then
  RUN_DIR="$ROOT/build/public-edge-incident-rollback/$timestamp"
fi
mkdir -p "$RUN_DIR"

rollback_manifest_sha256="$(file_sha256 "$ROLLBACK_MANIFEST")"
git_sha="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

export QLINK_INCIDENT_ROLLBACK_VERIFIED=true
export QLINK_INCIDENT_ID="$INCIDENT_ID"
export QLINK_ROLLBACK_FROM_RELEASE_ID="$ROLLBACK_FROM_RELEASE_ID"
export QLINK_ROLLBACK_TO_RELEASE_ID="$ROLLBACK_TO_RELEASE_ID"
export QLINK_ROLLBACK_MANIFEST_SHA256="$rollback_manifest_sha256"
export QLINK_ROLLBACK_DURATION_SECONDS="$ROLLBACK_DURATION_SECONDS"
export QLINK_POST_ROLLBACK_PUBLIC_INFRA_READY=true

if [[ -z "$POST_ROLLBACK_LIVE_MANIFEST" ]]; then
  post_run_dir="$RUN_DIR/post-rollback-live-evidence"
  live_args=(scripts/public-edge-live-evidence.sh --run-dir "$post_run_dir")
  if [[ -n "$ENV_FILE" ]]; then
    live_args+=(--env-file "$ENV_FILE")
  fi
  if [[ "$BUILD" -eq 1 ]]; then
    live_args+=(--build)
  else
    live_args+=(--no-build)
  fi
  if [[ -n "$BIN" ]]; then
    live_args+=(--qlink-bin "$BIN")
  fi
  log "running post-rollback public edge live evidence"
  "${live_args[@]}" > "$RUN_DIR/post-rollback-live-evidence.log" 2>&1 \
    || die "post-rollback live evidence failed; see $RUN_DIR/post-rollback-live-evidence.log"
  POST_ROLLBACK_LIVE_MANIFEST="$post_run_dir/manifest.json"
fi

[[ -f "$POST_ROLLBACK_LIVE_MANIFEST" ]] \
  || die "post-rollback live manifest does not exist: $POST_ROLLBACK_LIVE_MANIFEST"

manifest_verification="$RUN_DIR/post-rollback-live-manifest-verification.json"
log "verifying post-rollback public edge live manifest"
ruby scripts/verify-public-edge-live-manifest.rb \
  --expected-sha "$git_sha" \
  --report "$manifest_verification" \
  "$POST_ROLLBACK_LIVE_MANIFEST" > "$RUN_DIR/post-rollback-live-manifest-verification.stdout.json" \
  || die "post-rollback live manifest verification failed; see $manifest_verification"

post_rollback_manifest_sha256="$(file_sha256 "$POST_ROLLBACK_LIVE_MANIFEST")"
evidence="$RUN_DIR/incident-rollback.json"
exports_file="$RUN_DIR/incident-rollback.env"

export QLINK_ROLLBACK_EVIDENCE_GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export QLINK_ROLLBACK_EVIDENCE_GIT_SHA="$git_sha"
export QLINK_ROLLBACK_EVIDENCE_PATH="$evidence"
export QLINK_ROLLBACK_MANIFEST_PATH="$ROLLBACK_MANIFEST"
export QLINK_POST_ROLLBACK_LIVE_MANIFEST_PATH="$POST_ROLLBACK_LIVE_MANIFEST"
export QLINK_POST_ROLLBACK_LIVE_MANIFEST_SHA="$post_rollback_manifest_sha256"
export QLINK_ROLLBACK_MANIFEST_VERIFICATION_PATH="$manifest_verification"
ruby -rjson -e '
  out = ARGV.fetch(0)
  evidence = {
    "evidence_kind" => "quantumLinkPublicEdgeIncidentRollback",
    "generated_at" => ENV.fetch("QLINK_ROLLBACK_EVIDENCE_GENERATED_AT"),
    "git_sha" => ENV.fetch("QLINK_ROLLBACK_EVIDENCE_GIT_SHA"),
    "incident_rollback_verified" => true,
    "incident_id" => ENV.fetch("QLINK_INCIDENT_ID"),
    "rollback_from_release_id" => ENV.fetch("QLINK_ROLLBACK_FROM_RELEASE_ID"),
    "rollback_to_release_id" => ENV.fetch("QLINK_ROLLBACK_TO_RELEASE_ID"),
    "rollback_manifest_path" => ENV.fetch("QLINK_ROLLBACK_MANIFEST_PATH"),
    "rollback_manifest_sha256" => ENV.fetch("QLINK_ROLLBACK_MANIFEST_SHA256"),
    "rollback_duration_seconds" => Integer(ENV.fetch("QLINK_ROLLBACK_DURATION_SECONDS")),
    "post_rollback_public_infra_ready" => true,
    "post_rollback_live_manifest" => ENV.fetch("QLINK_POST_ROLLBACK_LIVE_MANIFEST_PATH"),
    "post_rollback_live_manifest_sha256" => ENV.fetch("QLINK_POST_ROLLBACK_LIVE_MANIFEST_SHA"),
    "post_rollback_live_manifest_verification" => ENV.fetch("QLINK_ROLLBACK_MANIFEST_VERIFICATION_PATH")
  }
  File.write(out, "#{JSON.pretty_generate(evidence)}\n")
' "$evidence"

cat > "$exports_file" <<EOF
QLINK_INCIDENT_ROLLBACK_VERIFIED=true
QLINK_INCIDENT_ID=$INCIDENT_ID
QLINK_ROLLBACK_FROM_RELEASE_ID=$ROLLBACK_FROM_RELEASE_ID
QLINK_ROLLBACK_TO_RELEASE_ID=$ROLLBACK_TO_RELEASE_ID
QLINK_ROLLBACK_MANIFEST_SHA256=$rollback_manifest_sha256
QLINK_ROLLBACK_DURATION_SECONDS=$ROLLBACK_DURATION_SECONDS
QLINK_POST_ROLLBACK_PUBLIC_INFRA_READY=true
EOF
chmod 0600 "$exports_file"

log "PASS incident rollback drill"
echo "evidence=$evidence"
echo "exports=$exports_file"
echo "post_rollback_live_manifest=$POST_ROLLBACK_LIVE_MANIFEST"
