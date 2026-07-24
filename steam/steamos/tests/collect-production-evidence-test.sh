#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STEAMOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COLLECTOR="$STEAMOS_ROOT/scripts/collect-production-evidence.sh"
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

write_bundle() {
    local root="$1"
    mkdir -p "$root/dytallix" "$root/rendezvous-relay"
    cat > "$root/metadata.json" <<'JSON'
{
  "generatedAt": "2026-07-10T00:00:00Z",
  "status": "pass",
  "dytallix": {
    "status": "pass",
    "registryEndpoint": "https://registry.testnet.dytallix.invalid",
    "networkId": "dytallix-testnet",
    "contract": "quantumlink-node-registry",
    "walletAddressesRedacted": true,
    "rawWalletMaterialCommitted": false,
    "cases": {
      "active": {"observedDecision": "accepted", "evidence": "dytallix/active.json"},
      "missing": {"observedDecision": "rejected", "evidence": "dytallix/missing.json"},
      "revoked": {"observedDecision": "rejected", "evidence": "dytallix/revoked.json"},
      "suspended": {"observedDecision": "rejected", "evidence": "dytallix/suspended.json"},
      "mismatched": {"observedDecision": "rejected", "evidence": "dytallix/mismatched.json"},
      "stale": {"observedDecision": "rejected", "evidence": "dytallix/stale.json"},
      "unavailable": {"observedDecision": "rejected", "evidence": "dytallix/unavailable.json"}
    }
  },
  "rendezvousRelay": {
    "status": "pass",
    "rendezvousEndpoints": ["https://rv.staging.quantumlink.invalid"],
    "relayEndpoints": ["turns:relay.staging.quantumlink.invalid:5349"],
    "abuseLogsRedacted": true,
    "rawPacketPayloadsCommitted": false,
    "rawGamePayloadsCommitted": false,
    "controls": {
      "tls": {"status": "pass", "evidence": "rendezvous-relay/tls.txt"},
      "authentication": {"status": "pass", "evidence": "rendezvous-relay/authentication.txt"},
      "signed_expiring_records": {"status": "pass", "evidence": "rendezvous-relay/signed_expiring_records.txt"},
      "rate_limits": {"status": "pass", "evidence": "rendezvous-relay/rate_limits.txt"},
      "abuse_logs": {"status": "pass", "evidence": "rendezvous-relay/abuse_logs.txt"},
      "revocation_propagation": {"status": "pass", "evidence": "rendezvous-relay/revocation_propagation.txt"},
      "relay_denial": {"status": "pass", "evidence": "rendezvous-relay/relay_denial.txt"},
      "retention": {"status": "pass", "evidence": "rendezvous-relay/retention.txt"},
      "key_rotation": {"status": "pass", "evidence": "rendezvous-relay/key_rotation.txt"},
      "endpoint_rotation": {"status": "pass", "evidence": "rendezvous-relay/endpoint_rotation.txt"},
      "incident_shutdown": {"status": "pass", "evidence": "rendezvous-relay/incident_shutdown.txt"}
    }
  }
}
JSON
    for case_name in active missing revoked suspended mismatched stale unavailable; do
        printf '{"case":"%s","redacted":true,"decisionEvidence":"fixture"}\n' "$case_name" > "$root/dytallix/$case_name.json"
    done
    for control_name in tls authentication signed_expiring_records rate_limits abuse_logs revocation_propagation relay_denial retention key_rotation endpoint_rotation incident_shutdown; do
        printf 'control=%s\nredacted=true\nresult=pass\n' "$control_name" > "$root/rendezvous-relay/$control_name.txt"
    done
}

BUNDLE="$TMP_ROOT/bundle"
write_bundle "$BUNDLE"
MANIFEST="$TMP_ROOT/production-evidence-manifest.json"
bash "$COLLECTOR" --evidence-root "$BUNDLE" --output "$MANIFEST" > "$TMP_ROOT/collector.out" 2>"$TMP_ROOT/collector.err"
assert_json_bool "$TMP_ROOT/collector.out" "productionEvidenceReady" "true"
assert_contains "$MANIFEST" '"sha256"'
bash "$VERIFIER" "$MANIFEST" > "$TMP_ROOT/verifier.out"
assert_json_bool "$TMP_ROOT/verifier.out" "productionEvidenceReady" "true"

MISSING="$TMP_ROOT/missing"
cp -R "$BUNDLE" "$MISSING"
rm "$MISSING/dytallix/stale.json"
if bash "$COLLECTOR" --evidence-root "$MISSING" --output "$TMP_ROOT/missing.json" >"$TMP_ROOT/missing.out" 2>"$TMP_ROOT/missing.err"; then
    fail "expected missing referenced evidence file to fail"
fi
assert_contains "$TMP_ROOT/missing.err" "Dytallix case stale evidence file is missing"

SECRET="$TMP_ROOT/secret"
cp -R "$BUNDLE" "$SECRET"
printf 'BEGIN PRIVATE KEY\n' >> "$SECRET/rendezvous-relay/tls.txt"
if bash "$COLLECTOR" --evidence-root "$SECRET" --output "$TMP_ROOT/secret.json" >"$TMP_ROOT/secret.out" 2>"$TMP_ROOT/secret.err"; then
    fail "expected secret marker in referenced evidence to fail"
fi
assert_contains "$TMP_ROOT/secret.err" "rendezvous/relay control tls evidence contains forbidden"

BLOCKED="$TMP_ROOT/blocked"
cp -R "$BUNDLE" "$BLOCKED"
python3 - "$BLOCKED/metadata.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    metadata = json.load(handle)
metadata["rendezvousRelay"]["controls"]["tls"]["status"] = "blocked"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(metadata, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY
if bash "$COLLECTOR" --evidence-root "$BLOCKED" --output "$TMP_ROOT/blocked.json" >"$TMP_ROOT/blocked.out" 2>"$TMP_ROOT/blocked.err"; then
    fail "expected blocked evidence to fail without --allow-blocked"
fi
assert_contains "$TMP_ROOT/blocked.err" "valid but not ready"
bash "$COLLECTOR" --evidence-root "$BLOCKED" --output "$TMP_ROOT/blocked-allowed.json" --allow-blocked > "$TMP_ROOT/blocked-allowed.out"
assert_json_bool "$TMP_ROOT/blocked-allowed.out" "valid" "true"
assert_json_bool "$TMP_ROOT/blocked-allowed.out" "productionEvidenceReady" "false"

echo "collect-production-evidence-test: ok"
