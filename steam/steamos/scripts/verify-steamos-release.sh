#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCHIVE="${1:-}"
VERIFY_REPORT="${VERIFY_REPORT:-}"
REQUIRE_PRODUCTION_READY="${QLINK_STEAMOS_REQUIRE_PRODUCTION_READY:-0}"
PUBLIC_KEY_FILE="${QLINK_STEAMOS_RELEASE_PUBLIC_KEY:-}"
PRODUCTION_EVIDENCE_MANIFEST="${QLINK_STEAMOS_PRODUCTION_EVIDENCE_MANIFEST:-${QLINK_STEAMOS_PRODUCTION_EVIDENCE:-}}"

failures=""
warnings=""
not_production_ready=0
SIGNATURE_MODE=""
SIGNATURE_ALGORITHM=""
SIGNATURE_ARTIFACT=""
SIGNATURE_COVERS_ARCHIVE="false"
SIGNATURE_VALIDATED=0
NON_HARDWARE_PRODUCTION_READY=0
PRODUCTION_EVIDENCE_VALIDATED=0
PRODUCTION_EVIDENCE_REQUIRED=0
PRODUCTION_EVIDENCE_MANIFEST_SHA256=""
MANIFEST_SHA256=""
CHECKSUM_ENTRIES=""
MANIFEST_ARTIFACTS=""

add_failure() {
    failures="${failures}$1
"
}

add_warning() {
    warnings="${warnings}$1
"
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        add_failure "missing required command: $1"
        return 1
    fi
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

line_has_name() {
    local haystack="$1"
    local needle="$2"
    while IFS= read -r line; do
        [ "$line" = "$needle" ] && return 0
    done <<EOF
$haystack
EOF
    return 1
}

json_report() {
    REPORT_PATH="$1" \
    FAILURES="$failures" \
    WARNINGS="$warnings" \
    NOT_PRODUCTION_READY="$not_production_ready" \
    REQUIRE_PRODUCTION_READY="$REQUIRE_PRODUCTION_READY" \
    SIGNATURE_MODE="$SIGNATURE_MODE" \
    SIGNATURE_ALGORITHM="$SIGNATURE_ALGORITHM" \
    SIGNATURE_ARTIFACT="$SIGNATURE_ARTIFACT" \
    SIGNATURE_VALIDATED="$SIGNATURE_VALIDATED" \
    NON_HARDWARE_PRODUCTION_READY="$NON_HARDWARE_PRODUCTION_READY" \
    PRODUCTION_EVIDENCE_MANIFEST="$PRODUCTION_EVIDENCE_MANIFEST" \
    PRODUCTION_EVIDENCE_VALIDATED="$PRODUCTION_EVIDENCE_VALIDATED" \
    PRODUCTION_EVIDENCE_REQUIRED="$PRODUCTION_EVIDENCE_REQUIRED" \
    PRODUCTION_EVIDENCE_MANIFEST_SHA256="$PRODUCTION_EVIDENCE_MANIFEST_SHA256" \
    MANIFEST_SHA256="$MANIFEST_SHA256" \
    ARCHIVE="$ARCHIVE" \
    python3 - <<'PY'
import json
import os

def lines(value):
    return [line for line in value.splitlines() if line]

failures = lines(os.environ["FAILURES"])
warnings = lines(os.environ["WARNINGS"])
not_ready = os.environ["NOT_PRODUCTION_READY"] == "1"
non_hardware_ready = os.environ["NON_HARDWARE_PRODUCTION_READY"] == "1"
report = {
    "archive": os.environ["ARCHIVE"],
    "valid": not failures,
    "productionReady": False,
    "notProductionReady": True,
    "nonHardwareProductionReady": not failures and non_hardware_ready,
    "requireProductionReady": os.environ["REQUIRE_PRODUCTION_READY"] == "1",
    "signatureMode": os.environ["SIGNATURE_MODE"],
    "signatureAlgorithm": os.environ["SIGNATURE_ALGORITHM"],
    "signatureArtifact": os.environ["SIGNATURE_ARTIFACT"],
    "signatureValidated": os.environ["SIGNATURE_VALIDATED"] == "1",
    "productionEvidenceManifest": os.environ["PRODUCTION_EVIDENCE_MANIFEST"],
    "productionEvidenceManifestSha256": os.environ["PRODUCTION_EVIDENCE_MANIFEST_SHA256"],
    "productionEvidenceValidated": os.environ["PRODUCTION_EVIDENCE_VALIDATED"] == "1",
    "nonHardwareProductionEvidenceManifest": os.environ["PRODUCTION_EVIDENCE_MANIFEST"],
    "nonHardwareProductionEvidenceManifestSha256": os.environ["PRODUCTION_EVIDENCE_MANIFEST_SHA256"],
    "nonHardwareProductionEvidenceRequired": os.environ["PRODUCTION_EVIDENCE_REQUIRED"] == "1",
    "nonHardwareProductionEvidenceValidated": os.environ["PRODUCTION_EVIDENCE_VALIDATED"] == "1",
    "manifestSha256": os.environ["MANIFEST_SHA256"],
    "failures": failures,
    "warnings": warnings,
}
with open(os.environ["REPORT_PATH"], "w", encoding="utf-8") as handle:
    json.dump(report, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
print(json.dumps(report, separators=(",", ":"), sort_keys=True))
PY
}

if [ -z "$ARCHIVE" ]; then
    echo "usage: $0 dist/steamos/quantumlink-steamos-<version>.tar.zst" >&2
    exit 2
fi

ARCHIVE="$(cd "$(dirname "$ARCHIVE")" && pwd -P)/$(basename "$ARCHIVE")"
ARCHIVE_BASENAME="$(basename "$ARCHIVE")"
PACKAGE_NAME="${ARCHIVE_BASENAME%.tar.zst}"
SIDECAR_DIR="$(dirname "$ARCHIVE")/$PACKAGE_NAME"
PACKAGED_PRODUCTION_EVIDENCE_MANIFEST="$SIDECAR_DIR/production-evidence-manifest.json"
if [ -z "$VERIFY_REPORT" ]; then
    VERIFY_REPORT="$SIDECAR_DIR/verify-report.json"
fi
if [ -f "$PACKAGED_PRODUCTION_EVIDENCE_MANIFEST" ]; then
    PRODUCTION_EVIDENCE_MANIFEST="$PACKAGED_PRODUCTION_EVIDENCE_MANIFEST"
fi
if [ "$REQUIRE_PRODUCTION_READY" = "1" ]; then
    PRODUCTION_EVIDENCE_REQUIRED=1
fi

need_cmd tar || true
need_cmd zstd || true
need_cmd python3 || true
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    add_failure "missing required command: sha256sum or shasum"
fi

if [ ! -f "$ARCHIVE" ]; then
    add_failure "missing archive: $ARCHIVE"
fi
if [ ! -d "$SIDECAR_DIR" ]; then
    add_failure "missing sidecar directory: $SIDECAR_DIR"
fi

if [ -n "$failures" ]; then
    install -d -m 0755 "$(dirname "$VERIFY_REPORT")"
    json_report "$VERIFY_REPORT"
    exit 1
fi

TMP_ROOT="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

if ! zstd -dc "$ARCHIVE" | tar -xf - -C "$TMP_ROOT"; then
    add_failure "archive extraction failed"
fi

PAYLOAD_ROOT="$TMP_ROOT/$PACKAGE_NAME"
if [ ! -d "$PAYLOAD_ROOT" ]; then
    add_failure "archive does not contain expected root directory: $PACKAGE_NAME"
fi

required_files="
bin/qlinkd
bin/qlinkctl
bin/qlink-desktop
scripts/install-steamos.sh
packaging/desktop/quantumlink-steamos.desktop
packaging/desktop/quantumlink-steamos-game-mode.desktop
packaging/desktop/icons/quantumlink-steamos.png
packaging/libexec/quantumlink-service-control
packaging/polkit/49-quantumlink-service-control.rules
packaging/systemd/qlinkd.service
packaging/systemd/qlinkd.service.d/planning-only.conf.sample
config/config.example.json
config/steam-bypass.toml
config/games/factorio.toml
config/games/minecraft.toml
config/games/steam-remote-play.toml
docs/deck-validation.md
"

if [ -d "$PAYLOAD_ROOT" ]; then
    for rel in $required_files; do
        if [ ! -f "$PAYLOAD_ROOT/$rel" ]; then
            add_failure "missing package file: $rel"
        fi
    done
    for rel in bin/qlinkd bin/qlinkctl bin/qlink-desktop scripts/install-steamos.sh \
        packaging/libexec/quantumlink-service-control; do
        if [ ! -x "$PAYLOAD_ROOT/$rel" ]; then
            add_failure "package file is not executable: $rel"
        fi
    done
    if [ -f "$PAYLOAD_ROOT/scripts/install-steamos.sh" ]; then
        if ! bash -n "$PAYLOAD_ROOT/scripts/install-steamos.sh"; then
            add_failure "install script failed shell syntax check"
        fi
    fi
fi

SUMS="$SIDECAR_DIR/SHA256SUMS.txt"
MANIFEST="$SIDECAR_DIR/release-manifest.json"
SBOM="$SIDECAR_DIR/SBOM.spdx.json"
if [ ! -f "$SUMS" ]; then
    add_failure "missing SHA256SUMS.txt"
fi
if [ ! -f "$MANIFEST" ]; then
    add_failure "missing release-manifest.json"
else
    MANIFEST_SHA256="$(sha256_file "$MANIFEST")"
fi
if [ ! -f "$SBOM" ]; then
    add_failure "missing SBOM.spdx.json"
fi

if [ -f "$SUMS" ]; then
    while read -r expected name; do
        [ -n "$expected" ] || continue
        CHECKSUM_ENTRIES="${CHECKSUM_ENTRIES}${name}
"
        artifact="$SIDECAR_DIR/$name"
        if [ "$name" = "$ARCHIVE_BASENAME" ]; then
            artifact="$ARCHIVE"
        fi
        if [ ! -f "$artifact" ]; then
            add_failure "checksum artifact missing: $name"
            continue
        fi
        actual="$(sha256_file "$artifact")"
        if [ "$actual" != "$expected" ]; then
            add_failure "checksum mismatch for $name"
        fi
    done < "$SUMS"
fi

if [ -f "$MANIFEST" ]; then
    set +e
    MANIFEST="$MANIFEST" ARCHIVE="$ARCHIVE" SIDECAR_DIR="$SIDECAR_DIR" python3 - <<'PY' > "$TMP_ROOT/manifest-check.out"
import hashlib
import json
import os
import sys

manifest_path = os.environ["MANIFEST"]
archive_path = os.environ["ARCHIVE"]
sidecar_dir = os.environ["SIDECAR_DIR"]
with open(manifest_path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)

errors = []
for key, expected in [("product", "QuantumLink SteamOS"), ("platform", "steamos")]:
    if manifest.get(key) != expected:
        errors.append(f"manifest {key} must be {expected}")
if not manifest.get("version"):
    errors.append("manifest version is missing")

def digest(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()

for artifact in manifest.get("artifacts", []):
    name = artifact.get("name")
    if name:
        print("MANIFEST_ARTIFACT=" + str(name))
    path = archive_path if name == os.path.basename(archive_path) else os.path.join(sidecar_dir, name or "")
    if not name or not os.path.isfile(path):
        errors.append(f"manifest artifact missing: {name}")
        continue
    if artifact.get("sha256") != digest(path):
        errors.append(f"manifest artifact hash mismatch: {name}")
    if artifact.get("sizeBytes") != os.path.getsize(path):
        errors.append(f"manifest artifact size mismatch: {name}")

signature = manifest.get("signature", {})
print("SIGNATURE_MODE=" + str(signature.get("mode", "")))
print("SIGNATURE_ALGORITHM=" + str(signature.get("algorithm", "")))
print("SIGNATURE_ARTIFACT=" + str(signature.get("artifact", "")))
print("SIGNATURE_COVERS_ARCHIVE=" + ("true" if os.path.basename(archive_path) in signature.get("covers", []) else "false"))
print("SIGNATURE_PRODUCTION_MODE=" + ("true" if signature.get("productionMode") is True or signature.get("mode") == "production" else "false"))
for error in errors:
    print("ERROR=" + error)
if errors:
    sys.exit(1)
PY
    manifest_status=$?
    set -e
    while IFS= read -r line; do
        case "$line" in
            ERROR=*) add_failure "${line#ERROR=}" ;;
            MANIFEST_ARTIFACT=*) MANIFEST_ARTIFACTS="${MANIFEST_ARTIFACTS}${line#MANIFEST_ARTIFACT=}
" ;;
            SIGNATURE_MODE=*) SIGNATURE_MODE="${line#SIGNATURE_MODE=}" ;;
            SIGNATURE_ALGORITHM=*) SIGNATURE_ALGORITHM="${line#SIGNATURE_ALGORITHM=}" ;;
            SIGNATURE_ARTIFACT=*) SIGNATURE_ARTIFACT="${line#SIGNATURE_ARTIFACT=}" ;;
            SIGNATURE_COVERS_ARCHIVE=*) SIGNATURE_COVERS_ARCHIVE="${line#SIGNATURE_COVERS_ARCHIVE=}" ;;
            SIGNATURE_PRODUCTION_MODE=*) SIGNATURE_PRODUCTION_MODE="${line#SIGNATURE_PRODUCTION_MODE=}" ;;
        esac
    done < "$TMP_ROOT/manifest-check.out"
    if [ "$manifest_status" -ne 0 ]; then
        add_failure "release manifest validation failed"
    fi
fi

SIGNATURE_PRODUCTION_MODE="${SIGNATURE_PRODUCTION_MODE:-false}"

if [ -z "$SIGNATURE_ARTIFACT" ]; then
    add_failure "signature artifact is missing from release manifest"
fi
EXPECTED_SIGNATURE_ARTIFACT=""
case "$SIGNATURE_MODE" in
    dev-classical) EXPECTED_SIGNATURE_ARTIFACT="$ARCHIVE_BASENAME.dev.sig" ;;
    production) EXPECTED_SIGNATURE_ARTIFACT="$ARCHIVE_BASENAME.sig" ;;
    "") ;;
    *) add_failure "unsupported signature mode: $SIGNATURE_MODE" ;;
esac
if [ -n "$SIGNATURE_ARTIFACT" ] && [ -n "$EXPECTED_SIGNATURE_ARTIFACT" ] && [ "$SIGNATURE_ARTIFACT" != "$EXPECTED_SIGNATURE_ARTIFACT" ]; then
    add_failure "signature artifact must be $EXPECTED_SIGNATURE_ARTIFACT for $SIGNATURE_MODE mode"
fi
if [ -z "$SIGNATURE_MODE" ]; then
    add_failure "signature mode is missing from release manifest"
fi
if [ -z "$SIGNATURE_ALGORITHM" ]; then
    add_failure "signature algorithm is missing from release manifest"
fi
if [ "$SIGNATURE_COVERS_ARCHIVE" != "true" ]; then
    add_failure "signature coverage must include archive: $ARCHIVE_BASENAME"
fi

required_checksum_entries="$ARCHIVE_BASENAME
SBOM.spdx.json
release-manifest.json"
if [ -n "$SIGNATURE_ARTIFACT" ]; then
    required_checksum_entries="${required_checksum_entries}
$SIGNATURE_ARTIFACT"
fi
if [ -f "$PACKAGED_PRODUCTION_EVIDENCE_MANIFEST" ] || [ "$SIGNATURE_MODE" = "production" ] || [ "$REQUIRE_PRODUCTION_READY" = "1" ]; then
    required_checksum_entries="${required_checksum_entries}
production-evidence-manifest.json"
fi
while IFS= read -r required_name; do
    [ -n "$required_name" ] || continue
    if ! line_has_name "$CHECKSUM_ENTRIES" "$required_name"; then
        add_failure "missing checksum entry: $required_name"
    fi
done <<EOF
$required_checksum_entries
EOF

required_manifest_artifacts="$ARCHIVE_BASENAME
SBOM.spdx.json"
if [ -n "$SIGNATURE_ARTIFACT" ]; then
    required_manifest_artifacts="${required_manifest_artifacts}
$SIGNATURE_ARTIFACT"
fi
if [ -f "$PACKAGED_PRODUCTION_EVIDENCE_MANIFEST" ] || [ "$SIGNATURE_MODE" = "production" ] || [ "$REQUIRE_PRODUCTION_READY" = "1" ]; then
    required_manifest_artifacts="${required_manifest_artifacts}
production-evidence-manifest.json"
fi
while IFS= read -r required_name; do
    [ -n "$required_name" ] || continue
    if ! line_has_name "$MANIFEST_ARTIFACTS" "$required_name"; then
        add_failure "manifest missing required artifact: $required_name"
    fi
done <<EOF
$required_manifest_artifacts
EOF

if [ "$SIGNATURE_MODE" != "production" ] || [ "$SIGNATURE_PRODUCTION_MODE" != "true" ]; then
    not_production_ready=1
    add_warning "release signature is not production-ready"
else
    signature_path="$SIDECAR_DIR/$SIGNATURE_ARTIFACT"
    if [ ! -f "$signature_path" ]; then
        add_failure "production signature artifact is missing"
    elif [ "$SIGNATURE_ALGORITHM" != "openssl-ed25519-raw" ]; then
        add_failure "unsupported production signature algorithm: $SIGNATURE_ALGORITHM"
    elif ! command -v openssl >/dev/null 2>&1; then
        add_failure "missing required command: openssl"
    elif [ -z "$PUBLIC_KEY_FILE" ] || [ ! -f "$PUBLIC_KEY_FILE" ]; then
        not_production_ready=1
        add_warning "production signature cannot be validated without QLINK_STEAMOS_RELEASE_PUBLIC_KEY"
    elif ! openssl pkeyutl -verify -rawin -pubin -inkey "$PUBLIC_KEY_FILE" -in "$ARCHIVE" -sigfile "$signature_path" >/dev/null 2>&1; then
        add_failure "production signature validation failed"
    else
        SIGNATURE_VALIDATED=1
    fi
fi

if [ "$SIGNATURE_MODE" = "production" ] || [ "$REQUIRE_PRODUCTION_READY" = "1" ]; then
    PRODUCTION_EVIDENCE_REQUIRED=1
fi

if [ -n "$PRODUCTION_EVIDENCE_MANIFEST" ]; then
    if [ "$PRODUCTION_EVIDENCE_REQUIRED" = "1" ] && [ "$PRODUCTION_EVIDENCE_MANIFEST" != "$PACKAGED_PRODUCTION_EVIDENCE_MANIFEST" ]; then
        add_failure "production evidence manifest must be packaged as production-evidence-manifest.json"
    fi
    evidence_input="$PRODUCTION_EVIDENCE_MANIFEST"
    evidence_report="$TMP_ROOT/production-evidence-report.json"
    evidence_errors="$TMP_ROOT/production-evidence.err"
    if [ ! -f "$evidence_input" ]; then
        add_failure "production evidence manifest is missing: $evidence_input"
    else
        PRODUCTION_EVIDENCE_MANIFEST="$(cd "$(dirname "$evidence_input")" && pwd -P)/$(basename "$evidence_input")"
        PRODUCTION_EVIDENCE_MANIFEST_SHA256="$(sha256_file "$PRODUCTION_EVIDENCE_MANIFEST")"
        archived_evidence_root="$PAYLOAD_ROOT/release-evidence"
        archived_evidence_manifest="$archived_evidence_root/production-evidence-manifest.json"
        if [ ! -f "$archived_evidence_manifest" ]; then
            add_failure "signed archive is missing embedded production evidence manifest"
        elif ! cmp -s "$PRODUCTION_EVIDENCE_MANIFEST" "$archived_evidence_manifest"; then
            add_failure "packaged production evidence manifest does not match signed archive"
        elif ! PRODUCTION_EVIDENCE_MANIFEST="$PRODUCTION_EVIDENCE_MANIFEST" \
            ARCHIVED_EVIDENCE_ROOT="$archived_evidence_root" \
            python3 - <<'PY'
import json
import os
from pathlib import Path

manifest_path = Path(os.environ["PRODUCTION_EVIDENCE_MANIFEST"]).resolve()
external_root = manifest_path.parent
archived_root = Path(os.environ["ARCHIVED_EVIDENCE_ROOT"]).resolve()
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
if manifest.get("schemaVersion") != 2:
    raise SystemExit("signed archive evidence must use schemaVersion 2")
references = []
dytallix = manifest.get("dytallix", {})
for entry in (dytallix.get("finality"), dytallix.get("ttlRefresh")):
    if isinstance(entry, dict):
        references.append(entry.get("evidence"))
verifier_signature = dytallix.get("finality", {}).get("verifierSignature", {})
if isinstance(verifier_signature, dict):
    references.extend([
        verifier_signature.get("publicKey"),
        verifier_signature.get("signature"),
    ])
for field in ("lifecycleMatrix", "negativePolicyMatrix"):
    for entry in dytallix.get(field, []):
        if isinstance(entry, dict):
            references.append(entry.get("evidence"))
for entry in manifest.get("rendezvousRelay", {}).get("controls", []):
    if isinstance(entry, dict):
        references.append(entry.get("evidence"))
for reference in references:
    if not isinstance(reference, str) or not reference:
        raise SystemExit("production evidence contains an empty sidecar reference")
    relative = Path(reference)
    external = (external_root / relative).resolve()
    archived = (archived_root / relative).resolve()
    external.relative_to(external_root)
    archived.relative_to(archived_root)
    if not external.is_file() or not archived.is_file():
        raise SystemExit(f"signed archive is missing production evidence sidecar: {reference}")
    if external.read_bytes() != archived.read_bytes():
        raise SystemExit(f"production evidence sidecar does not match signed archive: {reference}")
PY
        then
            add_failure "production evidence sidecars are not bound to the signed archive"
        fi
    fi
    if [ -f "$PRODUCTION_EVIDENCE_MANIFEST" ] && bash "$SCRIPT_DIR/verify-production-evidence.sh" "$PRODUCTION_EVIDENCE_MANIFEST" > "$evidence_report" 2> "$evidence_errors"; then
        evidence_ready="$(python3 - "$evidence_report" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    report = json.load(handle)
print("true" if report.get("productionEvidenceReady") is True else "false")
PY
)"
        if [ "$evidence_ready" = "true" ]; then
            PRODUCTION_EVIDENCE_VALIDATED=1
        else
            not_production_ready=1
            while IFS= read -r evidence_blocker; do
                [ -n "$evidence_blocker" ] && add_warning "production evidence: $evidence_blocker"
            done <<EOF
$(python3 - "$evidence_report" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    report = json.load(handle)
for blocker in report.get("blockers", []):
    print(blocker)
PY
)
EOF
        fi
    elif [ -f "$PRODUCTION_EVIDENCE_MANIFEST" ]; then
        add_failure "production evidence validation failed"
        if [ -s "$evidence_report" ]; then
            while IFS= read -r evidence_failure; do
                [ -n "$evidence_failure" ] && add_failure "production evidence: $evidence_failure"
            done <<EOF
$(python3 - "$evidence_report" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    report = json.load(handle)
for failure in report.get("failures", []):
    print(failure)
PY
)
EOF
        elif [ -s "$evidence_errors" ]; then
            while IFS= read -r evidence_failure; do
                [ -n "$evidence_failure" ] && add_failure "production evidence: $evidence_failure"
            done < "$evidence_errors"
        fi
    fi
elif [ "$PRODUCTION_EVIDENCE_REQUIRED" = "1" ]; then
    not_production_ready=1
    add_warning "production evidence manifest not provided"
fi

if [ -z "$failures" ] && [ "$SIGNATURE_VALIDATED" = "1" ] && [ "$PRODUCTION_EVIDENCE_VALIDATED" = "1" ]; then
    NON_HARDWARE_PRODUCTION_READY=1
    not_production_ready=1
    add_warning "physical Steam Deck validation evidence is not verified by this non-hardware release gate"
fi

if [ -d "$PAYLOAD_ROOT" ]; then
    secret_names="$(find "$PAYLOAD_ROOT" -name '.env' -o -iname '*private*key*' -o -iname '*wallet*' -o -iname '*entitlement*token*' -o -iname '*production*endpoint*secret*' | sed "s#^$PAYLOAD_ROOT/##" || true)"
    if [ -n "$secret_names" ]; then
        while IFS= read -r secret_name; do
            [ -n "$secret_name" ] && add_failure "secret-like path packaged: $secret_name"
        done <<EOF
$secret_names
EOF
    fi
    if grep -R -I -n -E 'BEGIN ((RSA|EC|OPENSSH) )?PRIVATE KEY|ENTITLEMENT_TOKEN|WALLET_SEED|QLINK_PRODUCTION_ENDPOINT_SECRET|DYTALLIX_WALLET_SECRET' "$PAYLOAD_ROOT" > "$TMP_ROOT/secret-grep.out"; then
        while IFS= read -r line; do
            add_failure "secret-like content packaged: ${line#"$PAYLOAD_ROOT/"}"
        done < "$TMP_ROOT/secret-grep.out"
    fi
fi

install -d -m 0755 "$(dirname "$VERIFY_REPORT")"
json_report "$VERIFY_REPORT"

if [ -n "$failures" ]; then
    exit 1
fi
if [ "$REQUIRE_PRODUCTION_READY" = "1" ] && [ "$not_production_ready" = "1" ]; then
    exit 1
fi
exit 0
