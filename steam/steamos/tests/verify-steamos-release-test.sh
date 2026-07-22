#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STEAMOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PACKAGER="$STEAMOS_ROOT/scripts/package-steamos.sh"
VERIFIER="$STEAMOS_ROOT/scripts/verify-steamos-release.sh"
WORKFLOW="$REPO_ROOT/.github/workflows/steamos-release.yml"
TMP_ROOT="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_file() {
    [ -f "$1" ] || fail "expected file: $1"
}

assert_contains() {
    local file="$1"
    local needle="$2"
    grep -Fq "$needle" "$file" || fail "expected $file to contain: $needle"
}

assert_not_contains() {
    local file="$1"
    local needle="$2"
    if grep -Fq "$needle" "$file"; then
        fail "expected $file not to contain: $needle"
    fi
}

assert_json_bool() {
    local file="$1"
    local field="$2"
    local expected="$3"
    python3 - "$file" "$field" "$expected" <<'PY'
import json
import sys

path, dotted, expected = sys.argv[1:]
with open(path, "r", encoding="utf-8") as handle:
    value = json.load(handle)
for part in dotted.split("."):
    value = value[part]
actual = "true" if value is True else "false" if value is False else str(value)
if actual != expected:
    raise SystemExit(f"{dotted}: expected {expected}, got {actual}")
PY
}

assert_json_string() {
    local file="$1"
    local field="$2"
    local expected="$3"
    python3 - "$file" "$field" "$expected" <<'PY'
import json
import sys

path, dotted, expected = sys.argv[1:]
with open(path, "r", encoding="utf-8") as handle:
    value = json.load(handle)
for part in dotted.split("."):
    value = value[part]
if str(value) != expected:
    raise SystemExit(f"{dotted}: expected {expected}, got {value}")
PY
}

write_valid_production_evidence() {
    local path="$1"
    cat > "$path" <<'JSON'
{
  "schemaVersion": 1,
  "evidenceKind": "steamosNonHardwareProductionEvidence",
  "product": "QuantumLink SteamOS",
  "platform": "steamos",
  "releaseScope": "steamos-direct-installer",
  "generatedAt": "2026-07-02T00:00:00Z",
  "status": "pass",
  "host": {
    "hardwareClaimed": false,
    "physicalSteamHardwareRequired": false
  },
  "dytallix": {
    "status": "pass",
    "registryEndpoint": "https://registry.testnet.dytallix.invalid",
    "networkId": "dytallix-testnet",
    "contract": "quantumlink-node-registry",
    "walletAddressesRedacted": true,
    "rawWalletMaterialCommitted": false,
    "caseMatrix": [
      {"case": "active", "trustMode": "publicDytallixRequired", "expectedDecision": "accepted", "observedDecision": "accepted", "evidence": "validation/dytallix/active.json", "redacted": true},
      {"case": "missing", "trustMode": "publicDytallixRequired", "expectedDecision": "rejected", "observedDecision": "rejected", "evidence": "validation/dytallix/missing.json", "redacted": true},
      {"case": "revoked", "trustMode": "publicDytallixRequired", "expectedDecision": "rejected", "observedDecision": "rejected", "evidence": "validation/dytallix/revoked.json", "redacted": true},
      {"case": "suspended", "trustMode": "publicDytallixRequired", "expectedDecision": "rejected", "observedDecision": "rejected", "evidence": "validation/dytallix/suspended.json", "redacted": true},
      {"case": "mismatched", "trustMode": "publicDytallixRequired", "expectedDecision": "rejected", "observedDecision": "rejected", "evidence": "validation/dytallix/mismatched.json", "redacted": true},
      {"case": "stale", "trustMode": "publicDytallixRequired", "expectedDecision": "rejected", "observedDecision": "rejected", "evidence": "validation/dytallix/stale.json", "redacted": true},
      {"case": "unavailable", "trustMode": "publicDytallixRequired", "expectedDecision": "rejected", "observedDecision": "rejected", "evidence": "validation/dytallix/unavailable.json", "redacted": true}
    ]
  },
  "rendezvousRelay": {
    "status": "pass",
    "rendezvousEndpoints": ["https://rv.staging.quantumlink.invalid"],
    "relayEndpoints": ["turns:relay.staging.quantumlink.invalid:5349"],
    "abuseLogsRedacted": true,
    "rawPacketPayloadsCommitted": false,
    "rawGamePayloadsCommitted": false,
    "controls": [
      {"control": "tls", "status": "pass", "evidence": "validation/rendezvous-relay/tls.txt"},
      {"control": "authentication", "status": "pass", "evidence": "validation/rendezvous-relay/auth.txt"},
      {"control": "signed_expiring_records", "status": "pass", "evidence": "validation/rendezvous-relay/records.txt"},
      {"control": "rate_limits", "status": "pass", "evidence": "validation/rendezvous-relay/rate-limits.txt"},
      {"control": "abuse_logs", "status": "pass", "evidence": "validation/rendezvous-relay/abuse-logs.txt"},
      {"control": "revocation_propagation", "status": "pass", "evidence": "validation/rendezvous-relay/revocation.txt"},
      {"control": "relay_denial", "status": "pass", "evidence": "validation/rendezvous-relay/relay-denial.txt"},
      {"control": "retention", "status": "pass", "evidence": "validation/rendezvous-relay/retention.txt"},
      {"control": "key_rotation", "status": "pass", "evidence": "validation/rendezvous-relay/key-rotation.txt"},
      {"control": "endpoint_rotation", "status": "pass", "evidence": "validation/rendezvous-relay/endpoint-rotation.txt"},
      {"control": "incident_shutdown", "status": "pass", "evidence": "validation/rendezvous-relay/incident-shutdown.txt"}
    ]
  }
}
JSON
}

rewrite_production_manifest() {
    local manifest="$1"
    local sig_name="$2"
    local sig_path="$3"
    local evidence_path="${4:-$PACKAGE_ROOT/production-evidence-manifest.json}"
    python3 - "$manifest" "$sig_name" "$sig_path" "$PACKAGE_ARCHIVE" "$PACKAGE_ROOT/SBOM.spdx.json" "$evidence_path" <<'PY'
import hashlib
import json
import os
import sys

manifest_path, sig_name, sig_path, archive_path, sbom_path, evidence_path = sys.argv[1:]

def artifact(path, name=None):
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    return {
        "name": name or os.path.basename(path),
        "sha256": digest,
        "sizeBytes": os.path.getsize(path),
    }

with open(manifest_path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["signature"] = {
    "mode": "production",
    "algorithm": "openssl-ed25519-raw",
    "artifact": sig_name,
    "productionMode": True,
    "signatureProvided": True,
    "covers": [os.path.basename(archive_path)],
    "validatedBy": "steam/steamos/scripts/verify-steamos-release.sh",
}
manifest["artifacts"] = [
    artifact(archive_path),
    artifact(sbom_path),
    artifact(sig_path, sig_name),
]
if os.path.isfile(evidence_path):
    manifest["artifacts"].append(artifact(evidence_path))
with open(manifest_path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY
}

FAKE_BIN="$TMP_ROOT/bin"
mkdir -p "$FAKE_BIN"
for bin in qlinkd qlinkctl; do
    cat > "$FAKE_BIN/$bin" <<'SH'
#!/usr/bin/env bash
echo "fake quantumlink binary"
SH
    chmod 0755 "$FAKE_BIN/$bin"
done

PACKAGE_DIST="$TMP_ROOT/package-dist"
QLINK_STEAMOS_VERSION="9.9.9-release-test" \
QLINK_STEAMOS_OUTPUT_DIR="$PACKAGE_DIST" \
QLINK_STEAMOS_BIN_DIR="$FAKE_BIN" \
QLINK_STEAMOS_SKIP_BUILD=1 \
    bash "$PACKAGER" >"$TMP_ROOT/package.out" 2>"$TMP_ROOT/package.err"

PACKAGE_ROOT="$PACKAGE_DIST/quantumlink-steamos-9.9.9-release-test"
PACKAGE_ARCHIVE="$PACKAGE_DIST/quantumlink-steamos-9.9.9-release-test.tar.zst"
MANIFEST="$PACKAGE_ROOT/release-manifest.json"
VERIFY_REPORT="$PACKAGE_ROOT/verify-report.json"

assert_file "$PACKAGE_ARCHIVE"
assert_file "$MANIFEST"
assert_file "$VERIFY_REPORT"
assert_contains "$MANIFEST" '"mode":"dev-classical"'
assert_not_contains "$MANIFEST" '"productionReady"'
assert_json_bool "$VERIFY_REPORT" "valid" "true"
assert_json_bool "$VERIFY_REPORT" "productionReady" "false"
assert_json_bool "$VERIFY_REPORT" "notProductionReady" "true"
assert_json_bool "$VERIFY_REPORT" "nonHardwareProductionReady" "false"
assert_json_bool "$VERIFY_REPORT" "requireProductionReady" "false"
assert_json_bool "$VERIFY_REPORT" "signatureValidated" "false"
assert_json_bool "$VERIFY_REPORT" "nonHardwareProductionEvidenceValidated" "false"
assert_json_string "$VERIFY_REPORT" "signatureMode" "dev-classical"
assert_contains "$VERIFY_REPORT" '"manifestSha256"'

EVIDENCE_MANIFEST="$TMP_ROOT/production-evidence-manifest.json"
EVIDENCE_PACKAGE_DIST="$TMP_ROOT/evidence-package-dist"
write_valid_production_evidence "$EVIDENCE_MANIFEST"
QLINK_STEAMOS_VERSION="9.9.9-evidence-package-test" \
QLINK_STEAMOS_OUTPUT_DIR="$EVIDENCE_PACKAGE_DIST" \
QLINK_STEAMOS_BIN_DIR="$FAKE_BIN" \
QLINK_STEAMOS_SKIP_BUILD=1 \
QLINK_STEAMOS_PRODUCTION_EVIDENCE_MANIFEST="$EVIDENCE_MANIFEST" \
    bash "$PACKAGER" >"$TMP_ROOT/evidence-package.out" 2>"$TMP_ROOT/evidence-package.err"
EVIDENCE_PACKAGE_ROOT="$EVIDENCE_PACKAGE_DIST/quantumlink-steamos-9.9.9-evidence-package-test"
assert_file "$EVIDENCE_PACKAGE_ROOT/production-evidence-manifest.json"
assert_contains "$EVIDENCE_PACKAGE_ROOT/SHA256SUMS.txt" "production-evidence-manifest.json"
assert_contains "$EVIDENCE_PACKAGE_ROOT/release-manifest.json" "production-evidence-manifest.json"
assert_json_bool "$EVIDENCE_PACKAGE_ROOT/verify-report.json" "nonHardwareProductionEvidenceValidated" "true"
assert_json_bool "$EVIDENCE_PACKAGE_ROOT/verify-report.json" "nonHardwareProductionReady" "false"
assert_json_bool "$EVIDENCE_PACKAGE_ROOT/verify-report.json" "notProductionReady" "true"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

refresh_checksum_entry() {
    local sums="$1"
    local name="$2"
    local path="$3"
    local digest
    digest="$(sha256_file "$path")"
    python3 - "$sums" "$name" "$digest" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
name = sys.argv[2]
digest = sys.argv[3]
lines = path.read_text(encoding="utf-8").splitlines()
updated = False
next_lines = []
for line in lines:
    parts = line.split()
    if len(parts) >= 2 and parts[-1] == name:
        next_lines.append(f"{digest}  {name}")
        updated = True
    else:
        next_lines.append(line)
if not updated:
    next_lines.append(f"{digest}  {name}")
path.write_text("\n".join(next_lines) + "\n", encoding="utf-8")
PY
}

remove_checksum_entry() {
    local sums="$1"
    local name="$2"
    python3 - "$sums" "$name" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
name = sys.argv[2]
lines = [
    line
    for line in path.read_text(encoding="utf-8").splitlines()
    if not (len(line.split()) >= 2 and line.split()[-1] == name)
]
path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
PY
}

if QLINK_STEAMOS_REQUIRE_PRODUCTION_READY=1 \
    VERIFY_REPORT="$TMP_ROOT/require-prod-report.json" \
    bash "$VERIFIER" "$PACKAGE_ARCHIVE" >"$TMP_ROOT/require-prod.out" 2>"$TMP_ROOT/require-prod.err"; then
    fail "expected dev package to fail when production readiness is required"
fi
assert_file "$TMP_ROOT/require-prod-report.json"
assert_json_bool "$TMP_ROOT/require-prod-report.json" "requireProductionReady" "true"
assert_json_bool "$TMP_ROOT/require-prod-report.json" "notProductionReady" "true"

ORIGINAL_SUMS="$TMP_ROOT/SHA256SUMS.original"
cp "$PACKAGE_ROOT/SHA256SUMS.txt" "$ORIGINAL_SUMS"
: > "$PACKAGE_ROOT/SHA256SUMS.txt"
if VERIFY_REPORT="$TMP_ROOT/empty-sums-report.json" \
    bash "$VERIFIER" "$PACKAGE_ARCHIVE" >"$TMP_ROOT/empty-sums.out" 2>"$TMP_ROOT/empty-sums.err"; then
    fail "expected empty SHA256SUMS.txt to fail verification"
fi
assert_contains "$TMP_ROOT/empty-sums-report.json" "missing checksum entry"
cp "$ORIGINAL_SUMS" "$PACKAGE_ROOT/SHA256SUMS.txt"

ORIGINAL_MANIFEST="$TMP_ROOT/release-manifest.original.json"
ORIGINAL_DEV_SIG="$TMP_ROOT/dev-signature.original"
cp "$MANIFEST" "$ORIGINAL_MANIFEST"
cp "$PACKAGE_ROOT/quantumlink-steamos-9.9.9-release-test.tar.zst.dev.sig" "$ORIGINAL_DEV_SIG"
python3 - "$MANIFEST" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["signature"].pop("artifact", None)
manifest["signature"].pop("covers", None)
manifest["artifacts"] = [
    artifact
    for artifact in manifest["artifacts"]
    if not artifact.get("name", "").endswith(".tar.zst.dev.sig")
]
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY
remove_checksum_entry "$PACKAGE_ROOT/SHA256SUMS.txt" "quantumlink-steamos-9.9.9-release-test.tar.zst.dev.sig"
refresh_checksum_entry "$PACKAGE_ROOT/SHA256SUMS.txt" "release-manifest.json" "$MANIFEST"
rm "$PACKAGE_ROOT/quantumlink-steamos-9.9.9-release-test.tar.zst.dev.sig"
if VERIFY_REPORT="$TMP_ROOT/missing-signature-artifact-report.json" \
    bash "$VERIFIER" "$PACKAGE_ARCHIVE" >"$TMP_ROOT/missing-signature-artifact.out" 2>"$TMP_ROOT/missing-signature-artifact.err"; then
    fail "expected package without manifest signature artifact to fail verification"
fi
assert_contains "$TMP_ROOT/missing-signature-artifact-report.json" "signature artifact is missing from release manifest"
cp "$ORIGINAL_MANIFEST" "$MANIFEST"
cp "$ORIGINAL_SUMS" "$PACKAGE_ROOT/SHA256SUMS.txt"
cp "$ORIGINAL_DEV_SIG" "$PACKAGE_ROOT/quantumlink-steamos-9.9.9-release-test.tar.zst.dev.sig"

python3 - "$MANIFEST" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["signature"]["artifact"] = "SBOM.spdx.json"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY
refresh_checksum_entry "$PACKAGE_ROOT/SHA256SUMS.txt" "release-manifest.json" "$MANIFEST"
if VERIFY_REPORT="$TMP_ROOT/signature-alias-report.json" \
    bash "$VERIFIER" "$PACKAGE_ARCHIVE" >"$TMP_ROOT/signature-alias.out" 2>"$TMP_ROOT/signature-alias.err"; then
    fail "expected signature artifact alias to fail verification"
fi
assert_contains "$TMP_ROOT/signature-alias-report.json" "signature artifact must be"
cp "$ORIGINAL_MANIFEST" "$MANIFEST"
cp "$ORIGINAL_SUMS" "$PACKAGE_ROOT/SHA256SUMS.txt"

TAMPERED_MANIFEST="$TMP_ROOT/tampered-manifest.json"
cp "$MANIFEST" "$TAMPERED_MANIFEST"
python3 - "$MANIFEST" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["signature"]["mode"] = "production"
manifest["signature"]["productionMode"] = True
manifest["signature"]["signatureProvided"] = True
manifest["signature"]["algorithm"] = "openssl-ed25519-raw"
manifest["signature"]["artifact"] = "quantumlink-steamos-9.9.9-release-test.tar.zst.sig"
for artifact in manifest["artifacts"]:
    if artifact.get("name", "").endswith(".tar.zst.dev.sig"):
        artifact["name"] = "quantumlink-steamos-9.9.9-release-test.tar.zst.sig"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY
cp "$PACKAGE_ROOT/quantumlink-steamos-9.9.9-release-test.tar.zst.dev.sig" \
    "$PACKAGE_ROOT/quantumlink-steamos-9.9.9-release-test.tar.zst.sig"
MISSING_KEY_EVIDENCE="$TMP_ROOT/missing-key-production-evidence.json"
write_valid_production_evidence "$MISSING_KEY_EVIDENCE"
cp "$MISSING_KEY_EVIDENCE" "$PACKAGE_ROOT/production-evidence-manifest.json"
rewrite_production_manifest "$MANIFEST" \
    "quantumlink-steamos-9.9.9-release-test.tar.zst.sig" \
    "$PACKAGE_ROOT/quantumlink-steamos-9.9.9-release-test.tar.zst.sig" \
    "$PACKAGE_ROOT/production-evidence-manifest.json"
refresh_checksum_entry "$PACKAGE_ROOT/SHA256SUMS.txt" "release-manifest.json" "$MANIFEST"
refresh_checksum_entry "$PACKAGE_ROOT/SHA256SUMS.txt" "quantumlink-steamos-9.9.9-release-test.tar.zst.sig" \
    "$PACKAGE_ROOT/quantumlink-steamos-9.9.9-release-test.tar.zst.sig"
refresh_checksum_entry "$PACKAGE_ROOT/SHA256SUMS.txt" "production-evidence-manifest.json" \
    "$PACKAGE_ROOT/production-evidence-manifest.json"

if QLINK_STEAMOS_REQUIRE_PRODUCTION_READY=1 \
    VERIFY_REPORT="$TMP_ROOT/missing-public-key-report.json" \
    bash "$VERIFIER" "$PACKAGE_ARCHIVE" >"$TMP_ROOT/missing-public-key.out" 2>"$TMP_ROOT/missing-public-key.err"; then
    fail "expected production-mode package to fail without public verification key"
fi
assert_file "$TMP_ROOT/missing-public-key-report.json"
assert_json_bool "$TMP_ROOT/missing-public-key-report.json" "signatureValidated" "false"
assert_json_bool "$TMP_ROOT/missing-public-key-report.json" "nonHardwareProductionEvidenceValidated" "true"
assert_json_bool "$TMP_ROOT/missing-public-key-report.json" "valid" "true"
assert_json_bool "$TMP_ROOT/missing-public-key-report.json" "notProductionReady" "true"
assert_json_string "$TMP_ROOT/missing-public-key-report.json" "signatureMode" "production"

OPENSSL_KEY="$TMP_ROOT/steamos-ed25519-private.pem"
OPENSSL_PUB="$TMP_ROOT/steamos-ed25519-public.pem"
PROD_SIG="$PACKAGE_ROOT/quantumlink-steamos-9.9.9-release-test.tar.zst.sig"
if openssl genpkey -algorithm ED25519 -out "$OPENSSL_KEY" >/dev/null 2>&1; then
    openssl pkey -in "$OPENSSL_KEY" -pubout -out "$OPENSSL_PUB" >/dev/null 2>&1
    openssl pkeyutl -sign -rawin -inkey "$OPENSSL_KEY" -in "$PACKAGE_ARCHIVE" -out "$PROD_SIG"
    rm -f "$PACKAGE_ROOT/production-evidence-manifest.json"
    remove_checksum_entry "$PACKAGE_ROOT/SHA256SUMS.txt" "production-evidence-manifest.json"
    rewrite_production_manifest "$MANIFEST" "$(basename "$PROD_SIG")" "$PROD_SIG"
    refresh_checksum_entry "$PACKAGE_ROOT/SHA256SUMS.txt" "release-manifest.json" "$MANIFEST"
    refresh_checksum_entry "$PACKAGE_ROOT/SHA256SUMS.txt" "$(basename "$PROD_SIG")" "$PROD_SIG"

    if QLINK_STEAMOS_REQUIRE_PRODUCTION_READY=1 \
        QLINK_STEAMOS_RELEASE_PUBLIC_KEY="$OPENSSL_PUB" \
        VERIFY_REPORT="$TMP_ROOT/missing-production-evidence-report.json" \
        bash "$VERIFIER" "$PACKAGE_ARCHIVE" >"$TMP_ROOT/missing-production-evidence.out" 2>"$TMP_ROOT/missing-production-evidence.err"; then
        fail "expected production-ready verification to fail without production evidence"
    fi
    assert_file "$TMP_ROOT/missing-production-evidence-report.json"
    assert_json_bool "$TMP_ROOT/missing-production-evidence-report.json" "signatureValidated" "true"
    assert_json_bool "$TMP_ROOT/missing-production-evidence-report.json" "nonHardwareProductionEvidenceValidated" "false"
    assert_json_bool "$TMP_ROOT/missing-production-evidence-report.json" "notProductionReady" "true"
    assert_contains "$TMP_ROOT/missing-production-evidence-report.json" "production evidence manifest not provided"

    PRODUCTION_EVIDENCE="$TMP_ROOT/production-evidence.json"
    write_valid_production_evidence "$PRODUCTION_EVIDENCE"
    cp "$PRODUCTION_EVIDENCE" "$PACKAGE_ROOT/production-evidence-manifest.json"
    rewrite_production_manifest "$MANIFEST" "$(basename "$PROD_SIG")" "$PROD_SIG" "$PACKAGE_ROOT/production-evidence-manifest.json"
    refresh_checksum_entry "$PACKAGE_ROOT/SHA256SUMS.txt" "release-manifest.json" "$MANIFEST"
    refresh_checksum_entry "$PACKAGE_ROOT/SHA256SUMS.txt" "production-evidence-manifest.json" "$PACKAGE_ROOT/production-evidence-manifest.json"

    QLINK_STEAMOS_RELEASE_PUBLIC_KEY="$OPENSSL_PUB" \
        VERIFY_REPORT="$TMP_ROOT/non-hardware-ready-report.json" \
        bash "$VERIFIER" "$PACKAGE_ARCHIVE" >"$TMP_ROOT/non-hardware-ready.out" 2>"$TMP_ROOT/non-hardware-ready.err"
    assert_file "$TMP_ROOT/non-hardware-ready-report.json"
    assert_json_bool "$TMP_ROOT/non-hardware-ready-report.json" "signatureValidated" "true"
    assert_json_bool "$TMP_ROOT/non-hardware-ready-report.json" "nonHardwareProductionEvidenceValidated" "true"
    assert_json_bool "$TMP_ROOT/non-hardware-ready-report.json" "nonHardwareProductionReady" "true"
    assert_json_bool "$TMP_ROOT/non-hardware-ready-report.json" "productionReady" "false"
    assert_json_bool "$TMP_ROOT/non-hardware-ready-report.json" "notProductionReady" "true"
    assert_contains "$TMP_ROOT/non-hardware-ready-report.json" "production-evidence-manifest.json"
    assert_contains "$TMP_ROOT/non-hardware-ready-report.json" "physical Steam Deck validation evidence is not verified"

    if QLINK_STEAMOS_REQUIRE_PRODUCTION_READY=1 \
        QLINK_STEAMOS_RELEASE_PUBLIC_KEY="$OPENSSL_PUB" \
        VERIFY_REPORT="$TMP_ROOT/full-production-blocked-report.json" \
        bash "$VERIFIER" "$PACKAGE_ARCHIVE" >"$TMP_ROOT/full-production-blocked.out" 2>"$TMP_ROOT/full-production-blocked.err"; then
        fail "expected full production-ready verification to fail without Deck evidence"
    fi
    assert_json_bool "$TMP_ROOT/full-production-blocked-report.json" "nonHardwareProductionReady" "true"
    assert_json_bool "$TMP_ROOT/full-production-blocked-report.json" "productionReady" "false"
else
    echo "verify-steamos-release-test: skipping Ed25519 production signature positive path; local OpenSSL lacks ED25519 genpkey support"
fi
mv "$TAMPERED_MANIFEST" "$MANIFEST"

assert_contains "$WORKFLOW" "steamos-release-verification"
assert_contains "$WORKFLOW" "inputs.signing_mode == 'production'"
assert_contains "$WORKFLOW" "QLINK_STEAMOS_REQUIRE_PRODUCTION_READY"
assert_contains "$WORKFLOW" "QLINK_STEAMOS_PRODUCTION_EVIDENCE_MANIFEST"
assert_contains "$WORKFLOW" "STEAMOS_PRODUCTION_EVIDENCE_MANIFEST_JSON"
assert_contains "$WORKFLOW" "production-evidence-manifest.json"
assert_contains "$WORKFLOW" "verify-production-evidence.sh"

echo "verify-steamos-release-test: ok"
