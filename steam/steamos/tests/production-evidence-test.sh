#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STEAMOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERIFIER="$STEAMOS_ROOT/scripts/verify-production-evidence.sh"
TMP_ROOT="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    local file="$1"
    local needle="$2"
    grep -Fq "$needle" "$file" || fail "expected $file to contain: $needle"
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

write_manifest() {
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

VALID="$TMP_ROOT/production-evidence.json"
write_manifest "$VALID"
bash "$VERIFIER" "$VALID" >"$TMP_ROOT/valid.out" 2>"$TMP_ROOT/valid.err"
assert_json_bool "$TMP_ROOT/valid.out" "valid" "true"
assert_json_bool "$TMP_ROOT/valid.out" "productionEvidenceReady" "true"
assert_json_bool "$TMP_ROOT/valid.out" "dytallixReady" "true"
assert_json_bool "$TMP_ROOT/valid.out" "rendezvousRelayReady" "true"

MISSING_CASE="$TMP_ROOT/missing-case.json"
cp "$VALID" "$MISSING_CASE"
python3 - "$MISSING_CASE" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["dytallix"]["caseMatrix"] = [
    case for case in manifest["dytallix"]["caseMatrix"] if case["case"] != "stale"
]
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY
if bash "$VERIFIER" "$MISSING_CASE" >"$TMP_ROOT/missing-case.out" 2>"$TMP_ROOT/missing-case.err"; then
    fail "expected missing Dytallix stale case to fail"
fi
assert_contains "$TMP_ROOT/missing-case.out" "missing Dytallix case: stale"

SECRET_MARKER="$TMP_ROOT/secret-marker.json"
cp "$VALID" "$SECRET_MARKER"
python3 - "$SECRET_MARKER" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["notes"] = "BEGIN PRIVATE KEY"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY
if bash "$VERIFIER" "$SECRET_MARKER" >"$TMP_ROOT/secret-marker.out" 2>"$TMP_ROOT/secret-marker.err"; then
    fail "expected secret marker to fail"
fi
assert_contains "$TMP_ROOT/secret-marker.out" "forbidden secret marker"

BLOCKED="$TMP_ROOT/blocked.json"
cp "$VALID" "$BLOCKED"
python3 - "$BLOCKED" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["rendezvousRelay"]["controls"][0]["status"] = "blocked"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY
bash "$VERIFIER" "$BLOCKED" >"$TMP_ROOT/blocked.out" 2>"$TMP_ROOT/blocked.err"
assert_json_bool "$TMP_ROOT/blocked.out" "valid" "true"
assert_json_bool "$TMP_ROOT/blocked.out" "productionEvidenceReady" "false"
assert_contains "$TMP_ROOT/blocked.out" "rendezvous/relay control tls status is blocked"

echo "production-evidence-test: ok"
