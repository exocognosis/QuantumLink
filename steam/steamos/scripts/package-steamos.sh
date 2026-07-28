#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STEAMOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

PRODUCT="QuantumLink SteamOS"
PLATFORM="steamos"
VERSION="${QLINK_STEAMOS_VERSION:-}"
OUTPUT_DIR="${QLINK_STEAMOS_OUTPUT_DIR:-$REPO_ROOT/dist/steamos}"
BIN_DIR="${QLINK_STEAMOS_BIN_DIR:-$REPO_ROOT/target/release}"
SKIP_BUILD="${QLINK_STEAMOS_SKIP_BUILD:-0}"
SIGNING_MODE="${QLINK_STEAMOS_SIGNING_MODE:-dev-classical}"
SIGNATURE_FILE="${QLINK_STEAMOS_SIGNATURE_FILE:-}"
PRIVATE_KEY_FILE="${QLINK_STEAMOS_RELEASE_PRIVATE_KEY:-}"
PRODUCTION_EVIDENCE_MANIFEST_SOURCE="${QLINK_STEAMOS_PRODUCTION_EVIDENCE_MANIFEST:-}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

file_size() {
    if stat -f '%z' "$1" >/dev/null 2>&1; then
        stat -f '%z' "$1"
    else
        stat -c '%s' "$1"
    fi
}

package_version() {
    awk -F '"' '/^version = / { print $2; exit }' "$STEAMOS_ROOT/rust/qlinkd/Cargo.toml"
}

install_payload_file() {
    src="$1"
    dst="$2"
    mode="$3"

    install -d -m 0755 "$(dirname "$dst")"
    install -m "$mode" "$src" "$dst"
}

if [ -z "$VERSION" ]; then
    VERSION="$(package_version)"
fi
if [ -z "$VERSION" ]; then
    echo "could not determine SteamOS package version" >&2
    exit 1
fi

case "$SIGNING_MODE" in
    dev-classical|production) ;;
    *)
        echo "QLINK_STEAMOS_SIGNING_MODE must be dev-classical or production" >&2
        exit 1
        ;;
esac

need_cmd tar
need_cmd zstd
need_cmd python3
if [ "$SKIP_BUILD" != "1" ]; then
    need_cmd cargo
fi
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    echo "missing required command: sha256sum or shasum" >&2
    exit 1
fi

PACKAGE_NAME="quantumlink-steamos-$VERSION"
SIDECAR_DIR="$OUTPUT_DIR/$PACKAGE_NAME"
WORK_DIR="$OUTPUT_DIR/.package-work-$PACKAGE_NAME"
PAYLOAD_ROOT="$WORK_DIR/$PACKAGE_NAME"
ARCHIVE="$OUTPUT_DIR/$PACKAGE_NAME.tar.zst"
SBOM="$SIDECAR_DIR/SBOM.spdx.json"
MANIFEST="$SIDECAR_DIR/release-manifest.json"
SUMS="$SIDECAR_DIR/SHA256SUMS.txt"
VERIFY_REPORT="$SIDECAR_DIR/verify-report.json"
PRODUCTION_EVIDENCE_MANIFEST="$SIDECAR_DIR/production-evidence-manifest.json"

if [ "$SKIP_BUILD" != "1" ]; then
    cargo build --release -p qlinkd -p qlinkctl
fi

for bin in qlinkd qlinkctl; do
    if [ ! -x "$BIN_DIR/$bin" ]; then
        echo "missing executable binary: $BIN_DIR/$bin" >&2
        exit 1
    fi
done

rm -rf "$SIDECAR_DIR" "$WORK_DIR" "$ARCHIVE"
install -d -m 0755 "$SIDECAR_DIR" "$PAYLOAD_ROOT"

install_payload_file "$BIN_DIR/qlinkd" "$PAYLOAD_ROOT/bin/qlinkd" 0755
install_payload_file "$BIN_DIR/qlinkctl" "$PAYLOAD_ROOT/bin/qlinkctl" 0755
install_payload_file "$STEAMOS_ROOT/scripts/install-steamos.sh" "$PAYLOAD_ROOT/scripts/install-steamos.sh" 0755
install_payload_file "$STEAMOS_ROOT/packaging/systemd/qlinkd.service" "$PAYLOAD_ROOT/packaging/systemd/qlinkd.service" 0644
install_payload_file "$STEAMOS_ROOT/packaging/systemd/qlinkd.service.d/activate-network.conf.sample" \
    "$PAYLOAD_ROOT/packaging/systemd/qlinkd.service.d/activate-network.conf.sample" 0644

install -d -m 0755 "$PAYLOAD_ROOT/config/games" "$PAYLOAD_ROOT/docs"
install_payload_file "$STEAMOS_ROOT/config/steam-bypass.toml" "$PAYLOAD_ROOT/config/steam-bypass.toml" 0644
for profile in "$STEAMOS_ROOT"/config/games/*.toml; do
    install_payload_file "$profile" "$PAYLOAD_ROOT/config/games/$(basename "$profile")" 0644
done

cat > "$PAYLOAD_ROOT/config/config.example.json" <<'JSON'
{
  "interfaceName": "qlink0",
  "overlayCidr": "100.64.0.0/10",
  "overlayIpv4Address": "100.64.10.2",
  "routeMode": "gameOnly",
  "activePeerId": null,
  "rendezvousServers": [
    "tls://rendezvous.example.quantumlink.invalid:9471"
  ],
  "relayServers": [
    "tls://relay.example.quantumlink.invalid:9472"
  ],
  "rendezvousAuthTokenFile": "/etc/quantumlink/secrets/rendezvous.token",
  "relayAuthTokenFile": "/etc/quantumlink/secrets/relay.token",
  "publicationTtlSeconds": 120,
  "advertiseAddress": null,
  "dytallixIdentity": {
    "endpoint": "https://rpc.example.dytallix.invalid",
    "contractAddress": "quantumlink-node-registry-v2",
    "networkId": "dytallix-mainnet",
    "chainId": "dytallix-1",
    "bindingVersion": "stableIdentityV2",
    "allowedRpcEndpoints": [
      "https://rpc.example.dytallix.invalid"
    ]
  },
  "killSwitch": true,
  "lowLatency": true,
  "voiceChatSafe": true
}
JSON

for doc in README.md docs/deck-validation.md docs/production-evidence.md docs/production-readiness.md docs/rendezvous-relay-production.md docs/release-runbook.md; do
    if [ -f "$STEAMOS_ROOT/$doc" ]; then
        install_payload_file "$STEAMOS_ROOT/$doc" "$PAYLOAD_ROOT/$doc" 0644
    fi
done

if [ -n "$PRODUCTION_EVIDENCE_MANIFEST_SOURCE" ]; then
    if [ ! -f "$PRODUCTION_EVIDENCE_MANIFEST_SOURCE" ]; then
        echo "missing production evidence manifest: $PRODUCTION_EVIDENCE_MANIFEST_SOURCE" >&2
        exit 1
    fi
    EVIDENCE_REPORT="$WORK_DIR/production-evidence-report.json"
    if ! bash "$STEAMOS_ROOT/scripts/verify-production-evidence.sh" \
        "$PRODUCTION_EVIDENCE_MANIFEST_SOURCE" >"$EVIDENCE_REPORT"; then
        echo "production evidence manifest or referenced sidecars are invalid" >&2
        exit 1
    fi
    if [ "$SIGNING_MODE" = "production" ] && ! python3 - "$EVIDENCE_REPORT" <<'PY'
import json
import sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if report.get("productionEvidenceReady") is True else 1)
PY
    then
        echo "production signing requires a ready schema-v2 production evidence bundle" >&2
        exit 1
    fi
    install_payload_file "$PRODUCTION_EVIDENCE_MANIFEST_SOURCE" "$PRODUCTION_EVIDENCE_MANIFEST" 0644
    install_payload_file "$PRODUCTION_EVIDENCE_MANIFEST_SOURCE" \
        "$PAYLOAD_ROOT/release-evidence/production-evidence-manifest.json" 0644
    PRODUCTION_EVIDENCE_SOURCE="$PRODUCTION_EVIDENCE_MANIFEST_SOURCE" \
    PRODUCTION_EVIDENCE_SIDECAR_DESTINATION="$SIDECAR_DIR" \
    PRODUCTION_EVIDENCE_ARCHIVE_DESTINATION="$PAYLOAD_ROOT/release-evidence" \
    python3 - <<'PY'
import json
import os
import shutil
from pathlib import Path

manifest_path = Path(os.environ["PRODUCTION_EVIDENCE_SOURCE"]).resolve()
destinations = [
    Path(os.environ["PRODUCTION_EVIDENCE_SIDECAR_DESTINATION"]).resolve(),
    Path(os.environ["PRODUCTION_EVIDENCE_ARCHIVE_DESTINATION"]).resolve(),
]
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
if manifest.get("schemaVersion") != 2:
    raise SystemExit(0)

references = []
dytallix = manifest.get("dytallix", {})
for entry in [dytallix.get("finality"), dytallix.get("ttlRefresh")]:
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

source_root = manifest_path.parent
for reference in references:
    if not isinstance(reference, str) or not reference:
        raise SystemExit("production evidence contains an empty sidecar reference")
    relative = Path(reference)
    if relative.is_absolute() or ".." in relative.parts:
        raise SystemExit(f"production evidence sidecar path is not contained: {reference}")
    source = (source_root / relative).resolve()
    source.relative_to(source_root)
    for destination in destinations:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o644)
PY
fi

find "$PAYLOAD_ROOT" -exec touch -h -t 197001010000.00 {} +
COPYFILE_DISABLE=1 tar -cf - -C "$WORK_DIR" "$PACKAGE_NAME" | zstd -q -19 -T0 -o "$ARCHIVE"

PAYLOAD_ROOT="$PAYLOAD_ROOT" PACKAGE_NAME="$PACKAGE_NAME" VERSION="$VERSION" python3 - <<'PY' > "$SBOM"
import hashlib
import json
import os

root = os.environ["PAYLOAD_ROOT"]
package_name = os.environ["PACKAGE_NAME"]
version = os.environ["VERSION"]
files = []
for base, _, names in os.walk(root):
    for name in sorted(names):
        path = os.path.join(base, name)
        rel = os.path.relpath(path, root)
        with open(path, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        files.append({
            "SPDXID": "SPDXRef-File-" + rel.replace("/", "-").replace(".", "-"),
            "fileName": rel,
            "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
        })

print(json.dumps({
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": package_name,
    "documentNamespace": f"https://quantumlink.local/spdx/{package_name}",
    "creationInfo": {
        "created": "1970-01-01T00:00:00Z",
        "creators": ["Tool: steam/steamos/scripts/package-steamos.sh"],
    },
    "packages": [{
        "SPDXID": "SPDXRef-Package-QuantumLink-SteamOS",
        "name": "QuantumLink SteamOS",
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": True,
    }],
    "files": files,
}, separators=(",", ":"), sort_keys=True))
PY

SIG_ARTIFACT=""
SIG_ALGORITHM="sha256-dev-attestation"
if [ "$SIGNING_MODE" = "production" ]; then
    SIG_ALGORITHM="openssl-ed25519-raw"
    SIG_ARTIFACT="$PACKAGE_NAME.tar.zst.sig"
    if [ -n "$SIGNATURE_FILE" ]; then
        install_payload_file "$SIGNATURE_FILE" "$SIDECAR_DIR/$SIG_ARTIFACT" 0644
    elif [ -n "$PRIVATE_KEY_FILE" ]; then
        need_cmd openssl
        openssl pkeyutl -sign -rawin -inkey "$PRIVATE_KEY_FILE" -in "$ARCHIVE" -out "$SIDECAR_DIR/$SIG_ARTIFACT"
    else
        echo "production signing requested but no QLINK_STEAMOS_SIGNATURE_FILE or QLINK_STEAMOS_RELEASE_PRIVATE_KEY was provided" >&2
        exit 1
    fi
else
    SIG_ARTIFACT="$PACKAGE_NAME.tar.zst.dev.sig"
    {
        printf 'mode=dev-classical\n'
        printf 'archive=%s\n' "$(basename "$ARCHIVE")"
        printf 'sha256=%s\n' "$(sha256_file "$ARCHIVE")"
    } > "$SIDECAR_DIR/$SIG_ARTIFACT"
fi

ARCHIVE_PATH="$ARCHIVE" \
SBOM_PATH="$SBOM" \
SIG_PATH="$SIDECAR_DIR/$SIG_ARTIFACT" \
PRODUCTION_EVIDENCE_MANIFEST="$PRODUCTION_EVIDENCE_MANIFEST" \
MANIFEST_PATH="$MANIFEST" \
PRODUCT="$PRODUCT" \
VERSION="$VERSION" \
PLATFORM="$PLATFORM" \
SIGNING_MODE="$SIGNING_MODE" \
SIG_ARTIFACT="$SIG_ARTIFACT" \
SIG_ALGORITHM="$SIG_ALGORITHM" \
SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
python3 - <<'PY'
import json
import os
import time
from datetime import datetime, timezone
from hashlib import sha256

def digest(path):
    with open(path, "rb") as handle:
        return sha256(handle.read()).hexdigest()

def size(path):
    return os.path.getsize(path)

def artifact(path):
    return {
        "name": os.path.basename(path),
        "sha256": digest(path),
        "sizeBytes": size(path),
    }

created = datetime.fromtimestamp(int(os.environ["SOURCE_DATE_EPOCH"]), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
archive_path = os.environ["ARCHIVE_PATH"]
sbom_path = os.environ["SBOM_PATH"]
sig_path = os.environ["SIG_PATH"]
production_evidence_manifest = os.environ["PRODUCTION_EVIDENCE_MANIFEST"]
manifest = {
    "product": os.environ["PRODUCT"],
    "version": os.environ["VERSION"],
    "platform": os.environ["PLATFORM"],
    "createdAt": created,
    "artifacts": [
        artifact(archive_path),
        artifact(sbom_path),
        artifact(sig_path),
    ],
    "signature": {
        "mode": os.environ["SIGNING_MODE"],
        "algorithm": os.environ["SIG_ALGORITHM"],
        "artifact": os.environ["SIG_ARTIFACT"],
        "productionMode": os.environ["SIGNING_MODE"] == "production",
        "signatureProvided": True,
        "covers": [os.path.basename(archive_path)],
        "validatedBy": "steam/steamos/scripts/verify-steamos-release.sh",
    },
}
if os.path.isfile(production_evidence_manifest):
    manifest["artifacts"].append(artifact(production_evidence_manifest))
with open(os.environ["MANIFEST_PATH"], "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY

: > "$SUMS"
for artifact in "$ARCHIVE" "$SBOM" "$MANIFEST" "$SIDECAR_DIR/$SIG_ARTIFACT"; do
    printf '%s  %s\n' "$(sha256_file "$artifact")" "$(basename "$artifact")" >> "$SUMS"
done
if [ -f "$PRODUCTION_EVIDENCE_MANIFEST" ]; then
    printf '%s  %s\n' "$(sha256_file "$PRODUCTION_EVIDENCE_MANIFEST")" "$(basename "$PRODUCTION_EVIDENCE_MANIFEST")" >> "$SUMS"
fi

VERIFY_REPORT="$VERIFY_REPORT" "$SCRIPT_DIR/verify-steamos-release.sh" "$ARCHIVE"

echo "SteamOS release package written:"
echo "  archive:  $ARCHIVE"
echo "  sidecars: $SIDECAR_DIR"
