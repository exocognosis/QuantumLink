#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STEAMOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

OUTPUT_DIR="${QLINK_STEAMOS_RC_OUTPUT_DIR:-$REPO_ROOT/dist/steamos-rc}"
EVIDENCE_ROOT="${QLINK_STEAMOS_PRODUCTION_EVIDENCE_ROOT:-}"
EVIDENCE_MANIFEST="${QLINK_STEAMOS_PRODUCTION_EVIDENCE_MANIFEST:-}"
REQUIRE_NON_HARDWARE_READY="${QLINK_STEAMOS_REQUIRE_NON_HARDWARE_READY:-1}"
VERSION="${QLINK_STEAMOS_VERSION:-}"

usage() {
    cat >&2 <<'EOF'
usage: steamos-rc-dry-run.sh [--evidence-root DIR | --evidence-manifest FILE] [--output-dir DIR]

Runs a production-signing SteamOS RC package dry run and verifies the signed
artifact plus non-hardware production evidence. The dry run intentionally still
reports full productionReady=false until Deck validation evidence exists.

Required environment for signed verification:
  QLINK_STEAMOS_RELEASE_PUBLIC_KEY=/path/to/ed25519-public-key.pem
  and either QLINK_STEAMOS_RELEASE_PRIVATE_KEY or QLINK_STEAMOS_SIGNATURE_FILE

Optional:
  QLINK_STEAMOS_VERSION
  QLINK_STEAMOS_BIN_DIR
  QLINK_STEAMOS_SKIP_BUILD=1
  QLINK_STEAMOS_REQUIRE_NON_HARDWARE_READY=0
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --evidence-root)
            EVIDENCE_ROOT="${2:-}"
            EVIDENCE_MANIFEST=""
            shift 2
            ;;
        --evidence-manifest)
            EVIDENCE_MANIFEST="${2:-}"
            EVIDENCE_ROOT=""
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

if [ -z "$EVIDENCE_MANIFEST" ] && [ -z "$EVIDENCE_ROOT" ]; then
    echo "provide --evidence-root or --evidence-manifest" >&2
    usage
    exit 2
fi
if [ -z "${QLINK_STEAMOS_RELEASE_PRIVATE_KEY:-}" ] && [ -z "${QLINK_STEAMOS_SIGNATURE_FILE:-}" ]; then
    echo "production RC dry run requires QLINK_STEAMOS_RELEASE_PRIVATE_KEY or QLINK_STEAMOS_SIGNATURE_FILE" >&2
    exit 2
fi
if [ -z "${QLINK_STEAMOS_RELEASE_PUBLIC_KEY:-}" ]; then
    echo "production RC dry run requires QLINK_STEAMOS_RELEASE_PUBLIC_KEY for signed verification" >&2
    exit 2
fi

install -d -m 0755 "$OUTPUT_DIR"
if [ -z "$EVIDENCE_MANIFEST" ]; then
    EVIDENCE_MANIFEST="$OUTPUT_DIR/production-evidence-manifest.json"
    bash "$SCRIPT_DIR/collect-production-evidence.sh" \
        --evidence-root "$EVIDENCE_ROOT" \
        --output "$EVIDENCE_MANIFEST" > "$OUTPUT_DIR/production-evidence-report.json"
fi

if [ ! -f "$EVIDENCE_MANIFEST" ]; then
    echo "production evidence manifest not found: $EVIDENCE_MANIFEST" >&2
    exit 1
fi

PACKAGE_OUTPUT="$OUTPUT_DIR/package"
rm -rf "$PACKAGE_OUTPUT"

QLINK_STEAMOS_OUTPUT_DIR="$PACKAGE_OUTPUT" \
QLINK_STEAMOS_SIGNING_MODE=production \
QLINK_STEAMOS_PRODUCTION_EVIDENCE_MANIFEST="$EVIDENCE_MANIFEST" \
QLINK_STEAMOS_VERSION="$VERSION" \
QLINK_STEAMOS_REQUIRE_PRODUCTION_READY=0 \
    bash "$SCRIPT_DIR/package-steamos.sh"

ARCHIVE="$(find "$PACKAGE_OUTPUT" -maxdepth 1 -name 'quantumlink-steamos-*.tar.zst' | sort | head -n 1)"
if [ -z "$ARCHIVE" ]; then
    echo "SteamOS RC archive was not produced" >&2
    exit 1
fi

REPORT="${ARCHIVE%.tar.zst}/verify-report.json"
QLINK_STEAMOS_RELEASE_PUBLIC_KEY="${QLINK_STEAMOS_RELEASE_PUBLIC_KEY}" \
QLINK_STEAMOS_REQUIRE_PRODUCTION_READY=0 \
VERIFY_REPORT="$REPORT" \
    bash "$SCRIPT_DIR/verify-steamos-release.sh" "$ARCHIVE" > "$OUTPUT_DIR/verify-release-output.json"

if [ "$REQUIRE_NON_HARDWARE_READY" = "1" ]; then
    python3 - "$REPORT" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    report = json.load(handle)

required_true = [
    "valid",
    "signatureValidated",
    "productionEvidenceValidated",
    "nonHardwareProductionEvidenceValidated",
    "nonHardwareProductionReady",
]
for key in required_true:
    if report.get(key) is not True:
        raise SystemExit(f"SteamOS RC dry run did not satisfy {key}=true")
if report.get("productionReady") is not False:
    raise SystemExit("SteamOS RC dry run must not assert productionReady without Deck evidence")
PY
fi

cat <<EOF
SteamOS RC dry run complete:
  archive: $ARCHIVE
  report:  $REPORT
  evidence: $EVIDENCE_MANIFEST
EOF
