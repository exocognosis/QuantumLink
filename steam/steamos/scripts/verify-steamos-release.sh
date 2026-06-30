#!/usr/bin/env bash
set -euo pipefail

ARCHIVE="${1:-}"
VERIFY_REPORT="${VERIFY_REPORT:-}"
REQUIRE_PRODUCTION_READY="${QLINK_STEAMOS_REQUIRE_PRODUCTION_READY:-0}"
PUBLIC_KEY_FILE="${QLINK_STEAMOS_RELEASE_PUBLIC_KEY:-}"

failures=""
warnings=""
not_production_ready=0

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

json_report() {
    REPORT_PATH="$1" \
    FAILURES="$failures" \
    WARNINGS="$warnings" \
    NOT_PRODUCTION_READY="$not_production_ready" \
    ARCHIVE="$ARCHIVE" \
    python3 - <<'PY'
import json
import os

def lines(value):
    return [line for line in value.splitlines() if line]

failures = lines(os.environ["FAILURES"])
warnings = lines(os.environ["WARNINGS"])
not_ready = os.environ["NOT_PRODUCTION_READY"] == "1"
report = {
    "archive": os.environ["ARCHIVE"],
    "valid": not failures,
    "productionReady": not failures and not not_ready,
    "notProductionReady": bool(failures) or not_ready,
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
if [ -z "$VERIFY_REPORT" ]; then
    VERIFY_REPORT="$SIDECAR_DIR/verify-report.json"
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
scripts/install-steamos.sh
packaging/systemd/qlinkd.service
packaging/systemd/qlinkd.service.d/activate-network.conf.sample
config/config.example.json
config/games/factorio.toml
config/games/minecraft.toml
"

if [ -d "$PAYLOAD_ROOT" ]; then
    for rel in $required_files; do
        if [ ! -f "$PAYLOAD_ROOT/$rel" ]; then
            add_failure "missing package file: $rel"
        fi
    done
    for rel in bin/qlinkd bin/qlinkctl scripts/install-steamos.sh; do
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
fi
if [ ! -f "$SBOM" ]; then
    add_failure "missing SBOM.spdx.json"
fi

if [ -f "$SUMS" ]; then
    while read -r expected name; do
        [ -n "$expected" ] || continue
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
print("SIGNATURE_PRODUCTION_READY=" + ("true" if signature.get("productionReady") is True else "false"))
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
            SIGNATURE_MODE=*) SIGNATURE_MODE="${line#SIGNATURE_MODE=}" ;;
            SIGNATURE_ALGORITHM=*) SIGNATURE_ALGORITHM="${line#SIGNATURE_ALGORITHM=}" ;;
            SIGNATURE_ARTIFACT=*) SIGNATURE_ARTIFACT="${line#SIGNATURE_ARTIFACT=}" ;;
            SIGNATURE_PRODUCTION_READY=*) SIGNATURE_PRODUCTION_READY="${line#SIGNATURE_PRODUCTION_READY=}" ;;
        esac
    done < "$TMP_ROOT/manifest-check.out"
    if [ "$manifest_status" -ne 0 ]; then
        add_failure "release manifest validation failed"
    fi
fi

SIGNATURE_MODE="${SIGNATURE_MODE:-}"
SIGNATURE_ALGORITHM="${SIGNATURE_ALGORITHM:-}"
SIGNATURE_ARTIFACT="${SIGNATURE_ARTIFACT:-}"
SIGNATURE_PRODUCTION_READY="${SIGNATURE_PRODUCTION_READY:-false}"

if [ "$SIGNATURE_MODE" != "production" ] || [ "$SIGNATURE_PRODUCTION_READY" != "true" ]; then
    not_production_ready=1
    add_warning "release signature is not production-ready"
else
    signature_path="$SIDECAR_DIR/$SIGNATURE_ARTIFACT"
    if [ ! -f "$signature_path" ]; then
        add_failure "production signature artifact is missing"
    elif [ "$SIGNATURE_ALGORITHM" != "openssl-ed25519-raw" ]; then
        add_failure "unsupported production signature algorithm: $SIGNATURE_ALGORITHM"
    elif [ -z "$PUBLIC_KEY_FILE" ] || [ ! -f "$PUBLIC_KEY_FILE" ]; then
        not_production_ready=1
        add_warning "production signature cannot be validated without QLINK_STEAMOS_RELEASE_PUBLIC_KEY"
    elif ! openssl pkeyutl -verify -rawin -pubin -inkey "$PUBLIC_KEY_FILE" -in "$ARCHIVE" -sigfile "$signature_path" >/dev/null 2>&1; then
        add_failure "production signature validation failed"
    fi
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
