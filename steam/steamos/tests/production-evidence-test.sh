#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STEAMOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
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
with open(path, "r", encoding="utf-8") as handle:
    value = json.load(handle)
for part in dotted.split("."):
    value = value[part]
actual = "true" if value is True else "false" if value is False else str(value)
if actual != expected:
    raise SystemExit(f"{dotted}: expected {expected}, got {actual}")
PY
}

write_v2_manifest() {
    local root="$1"
    mkdir -p "$root/evidence/dytallix/lifecycle" "$root/evidence/dytallix/negative" \
        "$root/evidence/rendezvous"
    python3 - "$root" <<'PY'
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
lifecycle = {
    "register": ("accepted", 1),
    "update": ("accepted", 2),
    "suspend": ("accepted", 3),
    "reactivate": ("accepted", 4),
    "revoke": ("accepted", 5),
    "post_revocation_reactivation": ("rejected", 5),
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

def sidecar(relative, payload):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(payload, sort_keys=True) + "\n").encode()
    path.write_bytes(raw)
    return relative, hashlib.sha256(raw).hexdigest()

network_id = "dytallix-production"
chain_id = "dytallix-1"
contract_address = "dyt1registry"
contract_code_hash = "a" * 64
lifecycle_matrix = []
finalized_transactions = []
for index, (name, (outcome, revision)) in enumerate(lifecycle.items(), start=1):
    height = 900 + index
    readback_status = {
        "register": "active", "update": "active", "suspend": "suspended",
        "reactivate": "active", "revoke": "revoked",
        "post_revocation_reactivation": "revoked",
    }[name]
    readback_digest = hashlib.sha256(f"{name}-readback".encode()).hexdigest()
    path, digest = sidecar(
        f"evidence/dytallix/lifecycle/{name}.json",
        {
            "evidenceKind": "dytallixLifecycleObservation",
            "case": name,
            "observedOutcome": outcome,
            "transactionId": f"tx-{index}",
            "finalizedBlockHeight": height,
            "stableIdentityRevision": revision,
            "readbackStatus": readback_status,
            "readbackDigest": readback_digest,
            "networkId": network_id, "chainId": chain_id,
            "contractAddress": contract_address, "contractCodeHash": contract_code_hash,
        },
    )
    finalized_transactions.append({
        "transactionId": f"tx-{index}",
        "finalizedBlockHeight": height,
        "finalizedBlockHash": f"{index:x}" * 64,
        "case": name, "observedOutcome": outcome,
        "stableIdentityRevision": revision, "readbackStatus": readback_status,
        "readbackDigest": readback_digest,
    })
    lifecycle_matrix.append({
        "case": name,
        "expectedOutcome": outcome,
        "observedOutcome": outcome,
        "transactionId": f"tx-{index}",
        "finalized": True,
        "finalizedBlockHeight": 900 + index,
        "stableIdentityRevision": revision,
        "evidence": path,
        "sha256": digest,
        "redacted": True,
    })
negative_matrix = []
for name in negative:
    path, digest = sidecar(
        f"evidence/dytallix/negative/{name}.json",
        {
            "evidenceKind": "dytallixNegativePolicyObservation",
            "case": name, "observedDecision": "rejected",
            "policyInputsRedacted": True, "networkId": network_id,
            "chainId": chain_id, "contractAddress": contract_address,
            "contractCodeHash": contract_code_hash,
        },
    )
    negative_matrix.append({
        "case": name,
        "expectedDecision": "rejected",
        "observedDecision": "rejected",
        "evidence": path,
        "sha256": digest,
        "redacted": True,
    })
ttl_path, ttl_sha = sidecar(
    "evidence/dytallix/ttl-refresh.json",
    {
        "evidenceKind": "dytallixTtlRefreshObservation",
        "observedOutcome": "accepted", "transactionId": "tx-ttl",
        "finalizedBlockHeight": 907, "stableIdentityRevisionBefore": 5,
        "stableIdentityRevisionAfter": 5, "networkId": network_id,
        "chainId": chain_id, "contractAddress": contract_address,
        "contractCodeHash": contract_code_hash, "readbackStatus": "active",
        "readbackDigest": hashlib.sha256(b"ttl-refresh-readback").hexdigest(),
    },
)
finalized_transactions.append({
    "transactionId": "tx-ttl", "finalizedBlockHeight": 907,
    "finalizedBlockHash": "f" * 64, "case": "ttl_refresh",
    "observedOutcome": "accepted", "stableIdentityRevisionBefore": 5,
    "stableIdentityRevisionAfter": 5, "readbackStatus": "active",
    "readbackDigest": hashlib.sha256(b"ttl-refresh-readback").hexdigest(),
})
finality_path, finality_sha = sidecar(
    "evidence/dytallix/finality.json",
    {
        "evidenceKind": "dytallixIndependentFinalityVerification",
        "independentFromMutationSdk": True,
        "networkId": network_id, "chainId": chain_id,
        "contractAddress": contract_address, "contractCodeHash": contract_code_hash,
        "finalizedBlockHeight": 1000, "finalizedBlockHash": "b" * 64,
        "finalizedTransactions": finalized_transactions,
    },
)
private_key = root / ".finality-verifier-private.pem"
public_key = root / "evidence/dytallix/finality-verifier-public.pem"
signature = root / "evidence/dytallix/finality.sig"
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
    ["openssl", "dgst", "-sha256", "-sign", private_key, "-out", signature, root / finality_path],
    check=True,
    capture_output=True,
)
control_matrix = []
for name in controls:
    path, digest = sidecar(
        f"evidence/rendezvous/{name}.json",
        {"control": name, "result": "pass"},
    )
    control_matrix.append({
        "control": name,
        "status": "pass",
        "evidence": path,
        "sha256": digest,
    })

manifest = {
    "schemaVersion": 2,
    "evidenceKind": "steamosNonHardwareProductionEvidence",
    "product": "QuantumLink SteamOS",
    "platform": "steamos",
    "releaseScope": "steamos-direct-installer",
    "generatedAt": "2026-07-28T00:00:00Z",
    "status": "pass",
    "host": {"hardwareClaimed": False, "physicalSteamHardwareRequired": False},
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
            "evidence": finality_path,
            "sha256": finality_sha,
            "verifierSignature": {
                "algorithm": "ecdsa-p256-sha256",
                "publicKey": "evidence/dytallix/finality-verifier-public.pem",
                "publicKeySha256": hashlib.sha256(public_key.read_bytes()).hexdigest(),
                "signature": "evidence/dytallix/finality.sig",
                "signatureSha256": hashlib.sha256(signature.read_bytes()).hexdigest(),
            },
        },
        "lifecycleMatrix": lifecycle_matrix,
        "negativePolicyMatrix": negative_matrix,
        "ttlRefresh": {
            "observedOutcome": "accepted",
            "transactionId": "tx-ttl",
            "finalized": True,
            "finalizedBlockHeight": 907,
            "stableIdentityRevisionBefore": 5,
            "stableIdentityRevisionAfter": 5,
            "evidence": ttl_path,
            "sha256": ttl_sha,
        },
    },
    "rendezvousRelay": {
        "status": "pass",
        "rendezvousEndpoints": ["https://rv.quantumlink.invalid"],
        "relayEndpoints": ["turns:relay.quantumlink.invalid:5349"],
        "abuseLogsRedacted": True,
        "rawPacketPayloadsCommitted": False,
        "rawGamePayloadsCommitted": False,
        "controls": control_matrix,
    },
}
(root / "production-evidence-manifest.json").write_text(
    json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}

VALID_ROOT="$TMP_ROOT/valid"
write_v2_manifest "$VALID_ROOT"
export QLINK_DYTALLIX_FINALITY_VERIFIER_PUBLIC_KEY="$VALID_ROOT/evidence/dytallix/finality-verifier-public.pem"
VALID="$VALID_ROOT/production-evidence-manifest.json"
bash "$VERIFIER" "$VALID" >"$TMP_ROOT/valid.out"
assert_json_bool "$TMP_ROOT/valid.out" "valid" "true"
assert_json_bool "$TMP_ROOT/valid.out" "productionEvidenceReady" "true"
assert_json_bool "$TMP_ROOT/valid.out" "dytallixReady" "true"
assert_json_bool "$TMP_ROOT/valid.out" "rendezvousRelayReady" "true"

env -u QLINK_DYTALLIX_FINALITY_VERIFIER_PUBLIC_KEY \
    bash "$VERIFIER" "$VALID" >"$TMP_ROOT/no-trusted-key.out"
assert_json_bool "$TMP_ROOT/no-trusted-key.out" "valid" "true"
assert_json_bool "$TMP_ROOT/no-trusted-key.out" "productionEvidenceReady" "false"
assert_contains "$TMP_ROOT/no-trusted-key.out" "trusted Dytallix finality verifier public key is not configured"

openssl ecparam -name prime256v1 -genkey -noout -out "$TMP_ROOT/wrong-private.pem"
openssl ec -in "$TMP_ROOT/wrong-private.pem" -pubout -out "$TMP_ROOT/wrong-public.pem" >/dev/null 2>&1
if QLINK_DYTALLIX_FINALITY_VERIFIER_PUBLIC_KEY="$TMP_ROOT/wrong-public.pem" \
    bash "$VERIFIER" "$VALID" >"$TMP_ROOT/wrong-key.out"; then
    fail "expected an untrusted finality verifier key to fail"
fi
assert_contains "$TMP_ROOT/wrong-key.out" "does not match the trusted key"

for key_kind in p384 rsa; do
    key_root="$TMP_ROOT/$key_kind-key"
    cp -R "$VALID_ROOT" "$key_root"
    if [ "$key_kind" = "p384" ]; then
        openssl ecparam -name secp384r1 -genkey -noout -out "$key_root/private.pem"
        openssl ec -in "$key_root/private.pem" -pubout \
            -out "$key_root/evidence/dytallix/finality-verifier-public.pem" >/dev/null 2>&1
    else
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
            -out "$key_root/private.pem" >/dev/null 2>&1
        openssl pkey -in "$key_root/private.pem" -pubout \
            -out "$key_root/evidence/dytallix/finality-verifier-public.pem" >/dev/null 2>&1
    fi
    openssl dgst -sha256 -sign "$key_root/private.pem" \
        -out "$key_root/evidence/dytallix/finality.sig" \
        "$key_root/evidence/dytallix/finality.json"
    python3 - "$key_root/production-evidence-manifest.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
manifest = json.load(open(path, encoding="utf-8"))
signature = manifest["dytallix"]["finality"]["verifierSignature"]
signature["publicKeySha256"] = hashlib.sha256(
    (path.parent / signature["publicKey"]).read_bytes()
).hexdigest()
signature["signatureSha256"] = hashlib.sha256(
    (path.parent / signature["signature"]).read_bytes()
).hexdigest()
json.dump(manifest, open(path, "w", encoding="utf-8"), separators=(",", ":"), sort_keys=True)
PY
    if QLINK_DYTALLIX_FINALITY_VERIFIER_PUBLIC_KEY="$key_root/evidence/dytallix/finality-verifier-public.pem" \
        bash "$VERIFIER" "$key_root/production-evidence-manifest.json" >"$TMP_ROOT/$key_kind.out"; then
        fail "expected $key_kind finality verifier key to fail"
    fi
    assert_contains "$TMP_ROOT/$key_kind.out" "must be ECDSA P-256"
done

V1="$TMP_ROOT/v1.json"
python3 - "$VALID" "$V1" <<'PY'
import json
import sys
manifest = json.load(open(sys.argv[1], encoding="utf-8"))
manifest["schemaVersion"] = 1
manifest["dytallix"] = {
    "status": "pass",
    "registryEndpoint": "https://registry.dytallix.invalid",
    "networkId": "legacy",
    "contract": "legacy",
    "walletAddressesRedacted": True,
    "rawWalletMaterialCommitted": False,
    "caseMatrix": [
        {
            "case": name,
            "trustMode": "publicDytallixRequired",
            "expectedDecision": decision,
            "observedDecision": decision,
            "evidence": "historical.json",
            "redacted": True,
        }
        for name, decision in {
            "active": "accepted", "missing": "rejected", "revoked": "rejected",
            "suspended": "rejected", "mismatched": "rejected",
            "stale": "rejected", "unavailable": "rejected",
        }.items()
    ],
}
json.dump(manifest, open(sys.argv[2], "w", encoding="utf-8"), separators=(",", ":"), sort_keys=True)
PY
printf '{}\n' >"$TMP_ROOT/historical.json"
bash "$VERIFIER" "$V1" >"$TMP_ROOT/v1.out"
assert_json_bool "$TMP_ROOT/v1.out" "valid" "true"
assert_json_bool "$TMP_ROOT/v1.out" "productionEvidenceReady" "false"
assert_json_bool "$TMP_ROOT/v1.out" "dytallixReady" "false"
assert_contains "$TMP_ROOT/v1.out" "schemaVersion 1 is historical evidence"

TAMPER_ROOT="$TMP_ROOT/tamper"
cp -R "$VALID_ROOT" "$TAMPER_ROOT"
printf 'tampered\n' >>"$TAMPER_ROOT/evidence/dytallix/finality.json"
if bash "$VERIFIER" "$TAMPER_ROOT/production-evidence-manifest.json" >"$TMP_ROOT/tamper.out"; then
    fail "expected a tampered finality sidecar to fail"
fi
assert_contains "$TMP_ROOT/tamper.out" "sha256 does not match"

MISSING_ROOT="$TMP_ROOT/missing"
cp -R "$VALID_ROOT" "$MISSING_ROOT"
rm "$MISSING_ROOT/evidence/dytallix/negative/registry_outage.json"
if bash "$VERIFIER" "$MISSING_ROOT/production-evidence-manifest.json" >"$TMP_ROOT/missing.out"; then
    fail "expected a missing sidecar to fail"
fi
assert_contains "$TMP_ROOT/missing.out" "evidence file is missing"

for mutation in fixture finality ttl negative finality_order claim_mismatch forged_finality; do
    root="$TMP_ROOT/$mutation"
    cp -R "$VALID_ROOT" "$root"
    python3 - "$root/production-evidence-manifest.json" "$mutation" <<'PY'
import hashlib
import json
import sys
path, mutation = sys.argv[1:]
manifest = json.load(open(path, encoding="utf-8"))
if mutation == "fixture":
    manifest["dytallix"]["evidenceClass"] = "fixture"
elif mutation == "finality":
    manifest["dytallix"]["finality"]["independentlyVerified"] = False
elif mutation == "ttl":
    manifest["dytallix"]["ttlRefresh"]["stableIdentityRevisionAfter"] = 6
elif mutation == "negative":
    manifest["dytallix"]["negativePolicyMatrix"] = [
        case for case in manifest["dytallix"]["negativePolicyMatrix"]
        if case["case"] != "expired_authorization"
    ]
elif mutation == "finality_order":
    manifest["dytallix"]["finality"]["finalizedBlockHeight"] = 900
elif mutation == "claim_mismatch":
    entry = manifest["dytallix"]["lifecycleMatrix"][0]
    sidecar = __import__("pathlib").Path(path).parent / entry["evidence"]
    document = json.load(open(sidecar, encoding="utf-8"))
    document["readbackStatus"] = "revoked"
    raw = (json.dumps(document, sort_keys=True) + "\n").encode()
    sidecar.write_bytes(raw)
    entry["sha256"] = hashlib.sha256(raw).hexdigest()
else:
    entry = manifest["dytallix"]["finality"]
    sidecar = __import__("pathlib").Path(path).parent / entry["evidence"]
    document = json.load(open(sidecar, encoding="utf-8"))
    document["finalizedBlockHeight"] = 1001
    raw = (json.dumps(document, sort_keys=True) + "\n").encode()
    sidecar.write_bytes(raw)
    entry["finalizedBlockHeight"] = 1001
    entry["sha256"] = hashlib.sha256(raw).hexdigest()
json.dump(manifest, open(path, "w", encoding="utf-8"), separators=(",", ":"), sort_keys=True)
PY
    if [ "$mutation" = "ttl" ] || [ "$mutation" = "negative" ] ||
        [ "$mutation" = "finality_order" ] || [ "$mutation" = "claim_mismatch" ] ||
        [ "$mutation" = "forged_finality" ]; then
        if bash "$VERIFIER" "$root/production-evidence-manifest.json" >"$TMP_ROOT/$mutation.out"; then
            fail "expected $mutation mutation to fail"
        fi
        if [ "$mutation" = "forged_finality" ]; then
            assert_contains "$TMP_ROOT/$mutation.out" "finality verifier signature is invalid"
        fi
    else
        bash "$VERIFIER" "$root/production-evidence-manifest.json" >"$TMP_ROOT/$mutation.out"
        assert_json_bool "$TMP_ROOT/$mutation.out" "productionEvidenceReady" "false"
        assert_json_bool "$TMP_ROOT/$mutation.out" "dytallixReady" "false"
    fi
done

echo "production-evidence-test: ok"
