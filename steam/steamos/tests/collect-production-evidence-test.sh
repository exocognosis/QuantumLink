#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STEAMOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COLLECTOR="$STEAMOS_ROOT/scripts/collect-production-evidence.sh"
VERIFIER="$STEAMOS_ROOT/scripts/verify-production-evidence.sh"
TMP_ROOT="$(mktemp -d)"

cleanup() { rm -rf "$TMP_ROOT"; }
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    grep -Fq "$2" "$1" || fail "expected $1 to contain: $2"
}

assert_json_bool() {
    python3 - "$1" "$2" "$3" <<'PY'
import json
import sys
path, dotted, expected = sys.argv[1:]
value = json.load(open(path, encoding="utf-8"))
for part in dotted.split("."):
    value = value[part]
actual = "true" if value is True else "false" if value is False else str(value)
if actual != expected:
    raise SystemExit(f"{dotted}: expected {expected}, got {actual}")
PY
}

write_bundle() {
    python3 - "$1" <<'PY'
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
lifecycle = {
    "register": ("accepted", 1), "update": ("accepted", 2),
    "suspend": ("accepted", 3), "reactivate": ("accepted", 4),
    "revoke": ("accepted", 5), "post_revocation_reactivation": ("rejected", 5),
}
negative = (
    "legacy_v1_downgrade", "expired_authorization", "device_mismatch",
    "signing_key_mismatch", "wrong_mesh_scope", "ttl_excess",
    "non_monotonic_revision", "missing", "suspended", "revoked",
    "registry_outage",
)
controls = (
    "tls", "authentication", "signed_expiring_records", "rate_limits",
    "abuse_logs", "revocation_propagation", "relay_denial", "retention",
    "key_rotation", "endpoint_rotation", "incident_shutdown",
)

def write(relative, payload):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

network_id = "dytallix-production"
chain_id = "dytallix-1"
contract_address = "dyt1registry"
contract_code_hash = "a" * 64
lifecycle_meta = {}
finalized_transactions = []
for index, (name, (outcome, revision)) in enumerate(lifecycle.items(), start=1):
    relative = f"dytallix/lifecycle/{name}.json"
    height = 900 + index
    readback_status = {
        "register": "active", "update": "active", "suspend": "suspended",
        "reactivate": "active", "revoke": "revoked",
        "post_revocation_reactivation": "revoked",
    }[name]
    readback_digest = hashlib.sha256(f"{name}-readback".encode()).hexdigest()
    write(relative, {
        "evidenceKind": "dytallixLifecycleObservation",
        "case": name, "observedOutcome": outcome, "transactionId": f"tx-{index}",
        "finalizedBlockHeight": height, "stableIdentityRevision": revision,
        "readbackStatus": readback_status, "readbackDigest": readback_digest,
        "networkId": network_id, "chainId": chain_id,
        "contractAddress": contract_address, "contractCodeHash": contract_code_hash,
    })
    finalized_transactions.append({
        "transactionId": f"tx-{index}", "finalizedBlockHeight": height,
        "finalizedBlockHash": f"{index:x}" * 64,
        "case": name, "observedOutcome": outcome,
        "stableIdentityRevision": revision, "readbackStatus": readback_status,
        "readbackDigest": readback_digest,
    })
    lifecycle_meta[name] = {
        "observedOutcome": outcome,
        "transactionId": f"tx-{index}",
        "finalized": True,
        "finalizedBlockHeight": height,
        "stableIdentityRevision": revision,
        "evidence": relative,
    }
negative_meta = {}
for name in negative:
    relative = f"dytallix/negative/{name}.json"
    write(relative, {
        "evidenceKind": "dytallixNegativePolicyObservation",
        "case": name, "observedDecision": "rejected", "policyInputsRedacted": True,
        "networkId": network_id, "chainId": chain_id,
        "contractAddress": contract_address, "contractCodeHash": contract_code_hash,
    })
    negative_meta[name] = {"observedDecision": "rejected", "evidence": relative}
write("dytallix/ttl-refresh.json", {
    "evidenceKind": "dytallixTtlRefreshObservation",
    "observedOutcome": "accepted", "transactionId": "tx-ttl",
    "finalizedBlockHeight": 907, "stableIdentityRevisionBefore": 5,
    "stableIdentityRevisionAfter": 5, "networkId": network_id,
    "chainId": chain_id, "contractAddress": contract_address,
    "contractCodeHash": contract_code_hash, "readbackStatus": "active",
    "readbackDigest": hashlib.sha256(b"ttl-refresh-readback").hexdigest(),
})
finalized_transactions.append({
    "transactionId": "tx-ttl", "finalizedBlockHeight": 907,
    "finalizedBlockHash": "f" * 64, "case": "ttl_refresh",
    "observedOutcome": "accepted", "stableIdentityRevisionBefore": 5,
    "stableIdentityRevisionAfter": 5, "readbackStatus": "active",
    "readbackDigest": hashlib.sha256(b"ttl-refresh-readback").hexdigest(),
})
write("dytallix/finality.json", {
    "evidenceKind": "dytallixIndependentFinalityVerification",
    "independentFromMutationSdk": True, "networkId": network_id,
    "chainId": chain_id, "contractAddress": contract_address,
    "contractCodeHash": contract_code_hash, "finalizedBlockHeight": 1000,
    "finalizedBlockHash": "b" * 64, "finalizedTransactions": finalized_transactions,
})
private_key = root / ".finality-verifier-private.pem"
public_key = root / "dytallix/finality-verifier-public.pem"
signature = root / "dytallix/finality.sig"
subprocess.run(
    ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", private_key],
    check=True,
    capture_output=True,
)
subprocess.run(
    ["openssl", "ec", "-in", private_key, "-pubout", "-out", public_key],
    check=True,
    capture_output=True,
)
subprocess.run(
    ["openssl", "dgst", "-sha256", "-sign", private_key, "-out", signature, root / "dytallix/finality.json"],
    check=True,
    capture_output=True,
)
control_meta = {}
for name in controls:
    relative = f"rendezvous-relay/{name}.json"
    write(relative, {"control": name, "status": "pass"})
    control_meta[name] = {"status": "pass", "evidence": relative}

metadata = {
    "generatedAt": "2026-07-28T00:00:00Z",
    "status": "pass",
    "dytallix": {
        "status": "pass",
        "bindingVersion": "stableIdentityV2",
        "contractSchemaVersion": 2,
        "evidenceClass": "liveChain",
        "registryEndpoint": "https://registry.dytallix.invalid",
        "networkId": network_id,
        "chainId": chain_id,
        "contractAddress": contract_address,
        "contractCodeHash": contract_code_hash,
        "walletAddressesRedacted": True,
        "rawWalletMaterialCommitted": False,
        "finality": {
            "independentlyVerified": True,
            "verificationMethod": "independentFinalizedBlock",
            "finalizedBlockHeight": 1000,
            "finalizedBlockHash": "b" * 64,
            "sdkReceiptOnly": False,
            "evidence": "dytallix/finality.json",
            "verifierSignature": {
                "algorithm": "ecdsa-p256-sha256",
                "publicKey": "dytallix/finality-verifier-public.pem",
                "signature": "dytallix/finality.sig",
            },
        },
        "lifecycle": lifecycle_meta,
        "negativePolicies": negative_meta,
        "ttlRefresh": {
            "observedOutcome": "accepted",
            "transactionId": "tx-ttl",
            "finalized": True,
            "finalizedBlockHeight": 907,
            "stableIdentityRevisionBefore": 5,
            "stableIdentityRevisionAfter": 5,
            "evidence": "dytallix/ttl-refresh.json",
        },
    },
    "rendezvousRelay": {
        "status": "pass",
        "rendezvousEndpoints": ["https://rv.quantumlink.invalid"],
        "relayEndpoints": ["turns:relay.quantumlink.invalid:5349"],
        "abuseLogsRedacted": True,
        "rawPacketPayloadsCommitted": False,
        "rawGamePayloadsCommitted": False,
        "controls": control_meta,
    },
}
(root / "metadata.json").write_text(
    json.dumps(metadata, separators=(",", ":"), sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}

BUNDLE="$TMP_ROOT/bundle"
write_bundle "$BUNDLE"
export QLINK_DYTALLIX_FINALITY_VERIFIER_PUBLIC_KEY="$BUNDLE/dytallix/finality-verifier-public.pem"
OUTPUT_ROOT="$TMP_ROOT/output"
MANIFEST="$OUTPUT_ROOT/production-evidence-manifest.json"
bash "$COLLECTOR" --evidence-root "$BUNDLE" --output "$MANIFEST" >"$TMP_ROOT/collector.out"
assert_json_bool "$TMP_ROOT/collector.out" "productionEvidenceReady" "true"
assert_contains "$MANIFEST" '"schemaVersion":2'
assert_contains "$MANIFEST" '"evidenceClass":"liveChain"'
test -f "$OUTPUT_ROOT/production-evidence/dytallix/finality.json" ||
    fail "collector did not stage finality sidecar beside manifest"
bash "$VERIFIER" "$MANIFEST" >"$TMP_ROOT/verifier.out"
assert_json_bool "$TMP_ROOT/verifier.out" "productionEvidenceReady" "true"

printf 'tampered\n' >>"$OUTPUT_ROOT/production-evidence/dytallix/finality.json"
if bash "$VERIFIER" "$MANIFEST" >"$TMP_ROOT/tampered.out"; then
    fail "expected staged sidecar tampering to fail"
fi
assert_contains "$TMP_ROOT/tampered.out" "sha256 does not match"

MISSING="$TMP_ROOT/missing"
cp -R "$BUNDLE" "$MISSING"
rm "$MISSING/dytallix/negative/registry_outage.json"
if bash "$COLLECTOR" --evidence-root "$MISSING" --output "$TMP_ROOT/missing-output/manifest.json" \
    >"$TMP_ROOT/missing.out" 2>"$TMP_ROOT/missing.err"; then
    fail "expected missing referenced evidence to fail"
fi
assert_contains "$TMP_ROOT/missing.err" "negative policy case registry_outage evidence file is missing"

FIXTURE="$TMP_ROOT/fixture"
cp -R "$BUNDLE" "$FIXTURE"
python3 - "$FIXTURE/metadata.json" <<'PY'
import json
import sys
path = sys.argv[1]
metadata = json.load(open(path, encoding="utf-8"))
metadata["dytallix"]["evidenceClass"] = "fixture"
json.dump(metadata, open(path, "w", encoding="utf-8"), separators=(",", ":"), sort_keys=True)
PY
if bash "$COLLECTOR" --evidence-root "$FIXTURE" --output "$TMP_ROOT/fixture-output/manifest.json" \
    >"$TMP_ROOT/fixture.out" 2>"$TMP_ROOT/fixture.err"; then
    fail "expected fixture evidence collection to fail"
fi
assert_contains "$TMP_ROOT/fixture.err" "evidenceClass must be liveChain"

BLOCKED="$TMP_ROOT/blocked"
cp -R "$BUNDLE" "$BLOCKED"
python3 - "$BLOCKED/metadata.json" <<'PY'
import json
import sys
path = sys.argv[1]
metadata = json.load(open(path, encoding="utf-8"))
metadata["rendezvousRelay"]["controls"]["tls"]["status"] = "blocked"
json.dump(metadata, open(path, "w", encoding="utf-8"), separators=(",", ":"), sort_keys=True)
PY
if bash "$COLLECTOR" --evidence-root "$BLOCKED" --output "$TMP_ROOT/blocked-output/manifest.json" \
    >"$TMP_ROOT/blocked.out" 2>"$TMP_ROOT/blocked.err"; then
    fail "expected blocked evidence to fail without --allow-blocked"
fi
assert_contains "$TMP_ROOT/blocked.err" "valid but not ready"
bash "$COLLECTOR" --evidence-root "$BLOCKED" --output "$TMP_ROOT/blocked-allowed/manifest.json" \
    --allow-blocked >"$TMP_ROOT/blocked-allowed.out"
assert_json_bool "$TMP_ROOT/blocked-allowed.out" "valid" "true"
assert_json_bool "$TMP_ROOT/blocked-allowed.out" "productionEvidenceReady" "false"

echo "collect-production-evidence-test: ok"
