#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STEAMOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BRIDGE="$STEAMOS_ROOT/scripts/bridge-public-edge-evidence.py"
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

python3 - "$TMP_ROOT" <<'PY'
import copy
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
git_sha = "a" * 40
generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

base = {
    "generated_at": generated_at,
    "git_sha": git_sha,
    "mode": "public",
    "mesh_id": "public-edge-live-evidence",
    "rendezvous": "tls://rv.quantumlinkvpn.com:9471",
    "relay": "tls://relay.quantumlinkvpn.com:9472",
    "stun": "stun.quantumlinkvpn.com:3478",
    "turn": "turn.quantumlinkvpn.com:3478",
    "control_tls_ca_configured": True,
    "rendezvous_tls_enabled": True,
    "relay_tls_enabled": True,
    "rendezvous_auth_required": True,
    "relay_auth_required": True,
    "rendezvous_auth_verified": True,
    "relay_auth_verified": True,
    "revoked_token_digest_file_configured": True,
    "service_token_revocation_verified": True,
    "rendezvous_revoked_token_rejected": True,
    "relay_revoked_token_rejected": True,
    "rendezvous_replacement_token_accepted": True,
    "relay_replacement_token_accepted": True,
    "rendezvous_revocation_list_sha256": "b" * 64,
    "relay_revocation_list_sha256": "c" * 64,
    "revocation_list_sha256": f'{"b" * 64}:{"c" * 64}',
    "rendezvous_rate_limit_per_window": 120,
    "relay_rate_limit_per_window": 240,
    "admission_rate_limit_window_seconds": 60,
    "rendezvous_metrics_addr": "127.0.0.1:9571",
    "relay_metrics_addr": "127.0.0.1:9572",
    "rendezvous_metrics_scraped": True,
    "relay_metrics_scraped": True,
    "bounds_verified": True,
    "relay_payload_limit_verified": True,
    "relay_saturation_limit_verified": True,
    "max_request_line_bytes": 131072,
    "max_concurrent_connections": 1024,
    "idle_timeout_seconds": 300,
    "relay_max_payload_bytes": 65536,
    "relay_max_peer_id_bytes": 256,
    "relay_max_registered_peers": 2048,
    "relay_max_peer_datagrams_per_window": 120,
    "relay_peer_datagram_window_seconds": 60,
    "rendezvous_auth_failures_total": 1,
    "relay_auth_failures_total": 1,
    "rendezvous_auth_revocations_total": 1,
    "relay_auth_revocations_total": 1,
    "rendezvous_requests_succeeded_total": 3,
    "relay_forwarded_datagrams_total": 3,
    "relay_unknown_destination_drops_total": 0,
    "rendezvous_request_too_large_total": 1,
    "relay_request_too_large_total": 1,
    "relay_payload_too_large_total": 1,
    "relay_peer_rate_limited_total": 1,
    "relay_duplicate_registration_rejections_total": 0,
    "prove_turn_relay": False,
    "remote_peer_id": "qlink_test",
    "advertise_addr": "127.0.0.1:1",
    "turn_permit_peer_ip": "198.51.100.44",
    "direct_probe_timeout_ms": 300,
    "stun_reflexive": "198.51.100.44:55000",
    "turn_relayed": "198.51.100.77:49160",
    "turn_responder_relayed": "",
    "published_candidate_count": 3,
    "published_candidate_types": "Host,ServerReflexive,Relay,QuantumLinkRelay",
    "self_publish_stun_failures": 0,
    "self_publish_turn_failures": 0,
    "selected_path": "relay",
    "frames_sent": 3,
    "total_elapsed_ms": 402,
    "incident_rollback_verified": True,
    "incident_id": "qlink-public-edge-drill",
    "rollback_from_release_id": "public-edge-current",
    "rollback_to_release_id": "public-edge-previous",
    "rollback_manifest_sha256": "d" * 64,
    "rollback_duration_seconds": 42,
    "post_rollback_public_infra_ready": True,
}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")


def lifecycle_proof(valid=True, raw_field=False):
    now_unix = int(datetime.now(timezone.utc).timestamp())
    proof = {
        "schemaVersion": 1,
        "evidenceKind": "quantumLinkSignedRecordLifecycleVerification",
        "status": "pass",
        "generatedAt": generated_at,
        "gitSha": git_sha,
        "rendezvousEndpointSha256": hashlib.sha256(
            base["rendezvous"].encode("utf-8")
        ).hexdigest(),
        "verifier": {
            "kind": "qlink-core-peer-record-verifier",
            "gitSha": git_sha,
            "cryptographicVerificationPerformed": True,
        },
        "publication": {
            "recordSha256": "1" * 64,
            "peerIdSha256": "2" * 64,
            "meshIdSha256": "3" * 64,
            "keyFingerprintSha256": "4" * 64,
            "signatureSha256": "5" * 64,
            "signatureAlgorithm": "ML-DSA-65",
            "signatureValid": valid,
            "peerIdBindingValid": True,
            "meshIdBindingValid": True,
            "sequence": 41,
            "publishedAtUnix": now_unix - 60,
            "expiresAtUnix": now_unix + 240,
            "lookupAtUnix": now_unix - 59,
            "lookupRecordSha256": "1" * 64,
        },
        "expiryProbe": {
            "recordSha256": "6" * 64,
            "peerIdSha256": "2" * 64,
            "meshIdSha256": "3" * 64,
            "keyFingerprintSha256": "4" * 64,
            "signatureSha256": "7" * 64,
            "signatureAlgorithm": "ML-DSA-65",
            "signatureValidBeforeExpiry": True,
            "sequence": 40,
            "expiresAtUnix": now_unix - 180,
            "lookupAtUnix": now_unix - 120,
            "lookupResult": "not_found",
        },
        "refresh": {
            "recordSha256": "8" * 64,
            "peerIdSha256": "2" * 64,
            "meshIdSha256": "3" * 64,
            "keyFingerprintSha256": "4" * 64,
            "signatureSha256": "9" * 64,
            "signatureAlgorithm": "ML-DSA-65",
            "signatureValid": True,
            "peerIdBindingValid": True,
            "meshIdBindingValid": True,
            "sequence": 42,
            "publishedAtUnix": now_unix - 10,
            "expiresAtUnix": now_unix + 540,
            "lookupAtUnix": now_unix - 9,
            "lookupRecordSha256": "8" * 64,
        },
        "redaction": {
            "rawRecordsCommitted": False,
            "privateKeysCommitted": False,
            "iceCredentialsCommitted": False,
            "endpointAddressesCommitted": False,
        },
    }
    if raw_field:
        proof["publication"]["iceCredentials"] = {"username": "raw-user"}
    return proof


def write_run(path, secret=False, escape=False, lifecycle=None):
    app = copy.deepcopy(base)
    turn = copy.deepcopy(base)
    turn.update(
        {
            "prove_turn_relay": True,
            "turn_responder_relayed": "198.51.100.77:49170",
            "published_candidate_types": "Relay",
            "selected_path": "turn-relay",
            "total_elapsed_ms": 57,
        }
    )
    if secret:
        app["notes"] = "BEGIN PRIVATE KEY"
    app_path = path / "app-relay" / "evidence.json"
    turn_path = path / "turn-relay" / "evidence.json"
    write_json(app_path, app)
    write_json(turn_path, turn)
    if escape:
        app_path = root / "outside-evidence.json"
        write_json(app_path, base)
    manifest = {
        "schemaVersion": 1,
        "evidenceKind": "quantumLinkPublicEdgeLiveEvidence",
        "generatedAt": generated_at,
        "gitSha": git_sha,
        "mode": "public",
        "status": "pass",
        "endpoints": {
            "rendezvous": base["rendezvous"],
            "relay": base["relay"],
            "stun": base["stun"],
            "turn": base["turn"],
        },
        "proofs": {
            "appRelay": {"evidence": str(app_path)},
            "turnRelay": {"evidence": str(turn_path)},
        },
    }
    if lifecycle is not None:
        proof_path = path / "signed-records" / "lifecycle.json"
        proof = lifecycle_proof(valid=lifecycle != "invalid", raw_field=lifecycle == "raw")
        if lifecycle == "secret":
            proof["operatorNotes"] = "WALLET_SEED"
        write_json(proof_path, proof)
        source_sha = hashlib.sha256(proof_path.read_bytes()).hexdigest()
        evidence_path = proof_path
        if lifecycle == "symlink":
            evidence_path = path / "signed-records" / "lifecycle-link.json"
            evidence_path.symlink_to(proof_path.name)
        manifest["proofs"]["signedExpiringRecords"] = {
            "evidence": str(evidence_path),
            "sha256": source_sha,
        }
    write_json(path / "manifest.json", manifest)


write_run(root / "public")
write_run(root / "secret", secret=True)
write_run(root / "escape", escape=True)
write_run(root / "signed", lifecycle="valid")
write_run(root / "incomplete-lifecycle", lifecycle="invalid")
write_run(root / "raw-lifecycle", lifecycle="raw")
write_run(root / "secret-lifecycle", lifecycle="secret")
write_run(root / "symlink-lifecycle", lifecycle="symlink")
write_run(root / "tampered-lifecycle", lifecycle="valid")
tampered_path = root / "tampered-lifecycle" / "signed-records" / "lifecycle.json"
tampered = json.loads(tampered_path.read_text(encoding="utf-8"))
tampered["publication"]["lookupAtUnix"] += 1
write_json(tampered_path, tampered)

dytallix_root = root / "dytallix"


def write_dytallix_sidecar(relative, case_name):
    document = {
        "schemaVersion": 2,
        "evidenceClass": "liveChain",
        "bindingVersion": "stableIdentityV2",
        "contractSchemaVersion": 2,
        "case": case_name,
        "redacted": True,
    }
    write_json(dytallix_root / relative, document)
    return {
        "evidence": relative,
        "sha256": hashlib.sha256((dytallix_root / relative).read_bytes()).hexdigest(),
        "redacted": True,
    }


finality = write_dytallix_sidecar("dytallix/finality.json", "finality")
finality.update(
    {
        "independentlyVerified": True,
        "verificationMethod": "independentFinalizedBlock",
        "finalizedBlockHeight": 1100,
        "finalizedBlockHash": "f" * 64,
        "sdkReceiptOnly": False,
    }
)
lifecycle = {}
lifecycle_outcomes = {
    "register": "accepted",
    "update": "accepted",
    "suspend": "accepted",
    "reactivate": "accepted",
    "revoke": "accepted",
    "post_revocation_reactivation": "rejected",
}
for revision, (case_name, outcome) in enumerate(lifecycle_outcomes.items(), start=1):
    entry = write_dytallix_sidecar(f"dytallix/lifecycle/{case_name}.json", case_name)
    entry.update(
        {
            "observedOutcome": outcome,
            "transactionId": f"tx-{case_name}",
            "finalized": True,
            "finalizedBlockHeight": 1042 + revision,
            "stableIdentityRevision": revision,
        }
    )
    lifecycle[case_name] = entry
negative = {}
for case_name in (
    "legacy_v1_downgrade",
    "expired_authorization",
    "device_mismatch",
    "signing_key_mismatch",
    "wrong_mesh_scope",
    "ttl_excess",
    "non_monotonic_revision",
    "missing",
    "suspended",
    "revoked",
    "registry_outage",
):
    entry = write_dytallix_sidecar(f"dytallix/negative/{case_name}.json", case_name)
    entry["observedDecision"] = "rejected"
    negative[case_name] = entry
ttl_refresh = write_dytallix_sidecar("dytallix/ttl-refresh.json", "ttl_refresh")
ttl_refresh.update(
    {
        "observedOutcome": "accepted",
        "transactionId": "tx-ttl-refresh",
        "finalized": True,
        "finalizedBlockHeight": 1050,
        "stableIdentityRevisionBefore": 5,
        "stableIdentityRevisionAfter": 5,
    }
)
pins = {
    "networkId": "dytallix-testnet",
    "chainId": "dytallix-testnet-1",
    "contractAddress": "0x1111111111111111111111111111111111111111",
    "contractCodeHash": "e" * 64,
}


def rewrite_dytallix_entry(relative, entry, document):
    write_json(dytallix_root / relative, document)
    entry["sha256"] = hashlib.sha256((dytallix_root / relative).read_bytes()).hexdigest()


readback_status = {
    "register": "active", "update": "active", "suspend": "suspended",
    "reactivate": "active", "revoke": "revoked",
    "post_revocation_reactivation": "revoked",
}
finalized_transactions = []
for index, (case_name, entry) in enumerate(lifecycle.items(), start=1):
    finalized_transactions.append({
        "transactionId": entry["transactionId"],
        "finalizedBlockHeight": entry["finalizedBlockHeight"],
        "finalizedBlockHash": f"{index:x}" * 64,
        "case": case_name, "observedOutcome": entry["observedOutcome"],
        "stableIdentityRevision": entry["stableIdentityRevision"],
        "readbackStatus": readback_status[case_name],
        "readbackDigest": hashlib.sha256(f"{case_name}-readback".encode()).hexdigest(),
    })
finalized_transactions.append({
    "transactionId": ttl_refresh["transactionId"],
    "finalizedBlockHeight": ttl_refresh["finalizedBlockHeight"],
    "finalizedBlockHash": "f" * 64,
    "case": "ttl_refresh", "observedOutcome": ttl_refresh["observedOutcome"],
    "stableIdentityRevisionBefore": ttl_refresh["stableIdentityRevisionBefore"],
    "stableIdentityRevisionAfter": ttl_refresh["stableIdentityRevisionAfter"],
    "readbackStatus": "active",
    "readbackDigest": hashlib.sha256(b"ttl-refresh-readback").hexdigest(),
})
rewrite_dytallix_entry(
    "dytallix/finality.json",
    finality,
    {
        "evidenceKind": "dytallixIndependentFinalityVerification",
        "independentFromMutationSdk": True,
        **pins,
        "finalizedBlockHeight": finality["finalizedBlockHeight"],
        "finalizedBlockHash": finality["finalizedBlockHash"],
        "finalizedTransactions": finalized_transactions,
    },
)
private_key = dytallix_root / ".finality-verifier-private.pem"
public_key = dytallix_root / "dytallix/finality-verifier-public.pem"
signature = dytallix_root / "dytallix/finality.sig"
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
    [
        "openssl", "dgst", "-sha256", "-sign", private_key, "-out", signature,
        dytallix_root / finality["evidence"],
    ],
    check=True,
    capture_output=True,
)
finality["verifierSignature"] = {
    "algorithm": "ecdsa-p256-sha256",
    "publicKey": "dytallix/finality-verifier-public.pem",
    "publicKeySha256": hashlib.sha256(public_key.read_bytes()).hexdigest(),
    "signature": "dytallix/finality.sig",
    "signatureSha256": hashlib.sha256(signature.read_bytes()).hexdigest(),
}
for case_name, entry in lifecycle.items():
    rewrite_dytallix_entry(
        f"dytallix/lifecycle/{case_name}.json",
        entry,
        {
            "evidenceKind": "dytallixLifecycleObservation",
            "case": case_name, "observedOutcome": entry["observedOutcome"],
            "transactionId": entry["transactionId"],
            "finalizedBlockHeight": entry["finalizedBlockHeight"],
            "stableIdentityRevision": entry["stableIdentityRevision"],
            "readbackStatus": readback_status[case_name],
            "readbackDigest": hashlib.sha256(f"{case_name}-readback".encode()).hexdigest(),
            **pins,
        },
    )
for case_name, entry in negative.items():
    rewrite_dytallix_entry(
        f"dytallix/negative/{case_name}.json",
        entry,
        {
            "evidenceKind": "dytallixNegativePolicyObservation",
            "case": case_name, "observedDecision": entry["observedDecision"],
            "policyInputsRedacted": True, **pins,
        },
    )
rewrite_dytallix_entry(
    "dytallix/ttl-refresh.json",
    ttl_refresh,
    {
        "evidenceKind": "dytallixTtlRefreshObservation",
        "observedOutcome": ttl_refresh["observedOutcome"],
        "transactionId": ttl_refresh["transactionId"],
        "finalizedBlockHeight": ttl_refresh["finalizedBlockHeight"],
        "stableIdentityRevisionBefore": ttl_refresh["stableIdentityRevisionBefore"],
        "stableIdentityRevisionAfter": ttl_refresh["stableIdentityRevisionAfter"],
        "readbackStatus": "active",
        "readbackDigest": hashlib.sha256(b"ttl-refresh-readback").hexdigest(),
        **pins,
    },
)
write_json(
    dytallix_root / "metadata.json",
    {
        "schemaVersion": 2,
        "dytallix": {
            "status": "pass",
            "evidenceClass": "liveChain",
            "bindingVersion": "stableIdentityV2",
            "contractSchemaVersion": 2,
            "registryEndpoint": "https://registry.dytallix.invalid",
            **pins,
            "walletAddressesRedacted": True,
            "rawWalletMaterialCommitted": False,
            "finality": finality,
            "lifecycle": lifecycle,
            "negativePolicies": negative,
            "ttlRefresh": ttl_refresh,
        }
    },
)


def copy_dytallix_bundle(destination, omitted=None):
    for path in dytallix_root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(dytallix_root)
        if omitted is not None and relative.as_posix() == omitted:
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())


downgrade = copy.deepcopy(json.loads((dytallix_root / "metadata.json").read_text()))
copy_dytallix_bundle(root / "dytallix-v1")
downgrade["schemaVersion"] = 1
write_json(root / "dytallix-v1" / "metadata.json", downgrade)

synthetic = copy.deepcopy(json.loads((dytallix_root / "metadata.json").read_text()))
copy_dytallix_bundle(root / "dytallix-synthetic")
synthetic["dytallix"]["evidenceClass"] = "synthetic"
write_json(root / "dytallix-synthetic" / "metadata.json", synthetic)

tampered = copy.deepcopy(json.loads((dytallix_root / "metadata.json").read_text()))
copy_dytallix_bundle(root / "dytallix-tampered")
write_json(root / "dytallix-tampered" / "metadata.json", tampered)
tampered_case = root / "dytallix-tampered" / "dytallix" / "lifecycle" / "register.json"
tampered_document = json.loads(tampered_case.read_text())
tampered_document["tampered"] = True
write_json(tampered_case, tampered_document)

missing = copy.deepcopy(json.loads((dytallix_root / "metadata.json").read_text()))
copy_dytallix_bundle(root / "dytallix-missing", "dytallix/negative/revoked.json")
write_json(root / "dytallix-missing" / "metadata.json", missing)
PY

python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/public/manifest.json" \
    --output-root "$TMP_ROOT/bridged" \
    --allow-blocked > "$TMP_ROOT/bridge.out"

python3 - "$TMP_ROOT/bridge.out" "$TMP_ROOT/bridged/metadata.json" "$TMP_ROOT/bridged/production-evidence.json" <<'PY'
import json
import sys

report_path, metadata_path, manifest_path = sys.argv[1:]
with open(report_path, "r", encoding="utf-8") as handle:
    report = json.load(handle)
assert report["valid"] is True
assert report["productionEvidenceReady"] is False
assert report["dytallixReady"] is False
assert report["rendezvousRelayReady"] is False

with open(metadata_path, "r", encoding="utf-8") as handle:
    metadata = json.load(handle)
assert metadata["rendezvousRelay"]["rendezvousEndpoints"] == ["tls://rv.quantumlinkvpn.com:9471"]
assert metadata["rendezvousRelay"]["relayEndpoints"] == ["tls://relay.quantumlinkvpn.com:9472"]
controls = metadata["rendezvousRelay"]["controls"]
for name in ("tls", "authentication", "rate_limits", "revocation_propagation", "relay_denial"):
    assert controls[name]["status"] == "pass", name
for name in ("signed_expiring_records", "abuse_logs", "retention", "key_rotation", "endpoint_rotation", "incident_shutdown"):
    assert controls[name]["status"] == "blocked", name

with open(manifest_path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)
assert manifest["schemaVersion"] == 2
assert manifest["evidenceKind"] == "steamosNonHardwareProductionEvidence"
assert manifest["dytallix"]["status"] == "blocked"
PY

python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/signed/manifest.json" \
    --output-root "$TMP_ROOT/signed-output" \
    --allow-blocked > "$TMP_ROOT/signed.out"

python3 - "$TMP_ROOT/signed.out" "$TMP_ROOT/signed-output/metadata.json" \
    "$TMP_ROOT/signed-output/rendezvous-relay/signed_expiring_records.json" <<'PY'
import json
import sys

report_path, metadata_path, control_path = sys.argv[1:]
with open(report_path, "r", encoding="utf-8") as handle:
    report = json.load(handle)
assert report["valid"] is True
assert report["productionEvidenceReady"] is False

with open(metadata_path, "r", encoding="utf-8") as handle:
    metadata = json.load(handle)
assert metadata["rendezvousRelay"]["controls"]["signed_expiring_records"]["status"] == "pass"
assert metadata["rendezvousRelay"]["status"] == "blocked"

with open(control_path, "r", encoding="utf-8") as handle:
    control = json.load(handle)
assert control["status"] == "pass"
assert len(control["source"]["signedExpiringRecordsEvidenceSha256"]) == 64
assert control["assertions"]["verifier"]["cryptographicVerificationPerformed"] is True
assert control["assertions"]["refresh"]["sequence"] == 42
assert "iceCredentials" not in control["assertions"]["publication"]
PY

python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/incomplete-lifecycle/manifest.json" \
    --output-root "$TMP_ROOT/incomplete-lifecycle-output" \
    --allow-blocked > "$TMP_ROOT/incomplete-lifecycle.out"

python3 - "$TMP_ROOT/incomplete-lifecycle-output/metadata.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    metadata = json.load(handle)
control = metadata["rendezvousRelay"]["controls"]["signed_expiring_records"]
assert control["status"] == "blocked"
PY

python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/raw-lifecycle/manifest.json" \
    --output-root "$TMP_ROOT/raw-lifecycle-output" \
    --allow-blocked > "$TMP_ROOT/raw-lifecycle.out"

python3 - "$TMP_ROOT/raw-lifecycle-output/metadata.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    metadata = json.load(handle)
assert metadata["rendezvousRelay"]["controls"]["signed_expiring_records"]["status"] == "blocked"
PY

if python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/public/manifest.json" \
    --output-root "$TMP_ROOT/default-blocked" > "$TMP_ROOT/default-blocked.out" 2> "$TMP_ROOT/default-blocked.err"; then
    fail "expected default blocked bridge to fail closed"
fi
assert_contains "$TMP_ROOT/default-blocked.err" "valid but blocked"

export QLINK_DYTALLIX_FINALITY_VERIFIER_PUBLIC_KEY="$TMP_ROOT/dytallix/dytallix/finality-verifier-public.pem"

python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/public/manifest.json" \
    --dytallix-evidence-root "$TMP_ROOT/dytallix" \
    --output-root "$TMP_ROOT/with-dytallix" \
    --allow-blocked > "$TMP_ROOT/with-dytallix.out"

python3 - "$TMP_ROOT/with-dytallix.out" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    report = json.load(handle)
assert report["valid"] is True
assert report["dytallixReady"] is True
assert report["rendezvousRelayReady"] is False
assert report["productionEvidenceReady"] is False
PY

python3 - "$TMP_ROOT/with-dytallix/production-evidence.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    manifest = json.load(handle)
assert manifest["schemaVersion"] == 2
dytallix = manifest["dytallix"]
assert dytallix["evidenceClass"] == "liveChain"
assert dytallix["bindingVersion"] == "stableIdentityV2"
assert dytallix["contractSchemaVersion"] == 2
assert dytallix["chainId"] == "dytallix-testnet-1"
assert dytallix["contractAddress"] == "0x1111111111111111111111111111111111111111"
assert dytallix["contractCodeHash"] == "e" * 64
assert len(dytallix["finality"]["sha256"]) == 64
assert all(len(case["sha256"]) == 64 for case in dytallix["lifecycleMatrix"])
assert all(len(case["sha256"]) == 64 for case in dytallix["negativePolicyMatrix"])
assert len(dytallix["ttlRefresh"]["sha256"]) == 64
PY

if python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/public/manifest.json" \
    --dytallix-evidence-root "$TMP_ROOT/dytallix-v1" \
    --output-root "$TMP_ROOT/dytallix-v1-output" \
    --allow-blocked > "$TMP_ROOT/dytallix-v1.out" 2> "$TMP_ROOT/dytallix-v1.err"; then
    fail "expected schema v1 Dytallix evidence to fail closed"
fi
assert_contains "$TMP_ROOT/dytallix-v1.err" "schemaVersion must be 2"

if python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/public/manifest.json" \
    --dytallix-evidence-root "$TMP_ROOT/dytallix-synthetic" \
    --output-root "$TMP_ROOT/dytallix-synthetic-output" \
    --allow-blocked > "$TMP_ROOT/dytallix-synthetic.out" 2> "$TMP_ROOT/dytallix-synthetic.err"; then
    fail "expected synthetic Dytallix evidence to fail closed"
fi
assert_contains "$TMP_ROOT/dytallix-synthetic.err" "evidenceClass must be liveChain"

if python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/public/manifest.json" \
    --dytallix-evidence-root "$TMP_ROOT/dytallix-missing" \
    --output-root "$TMP_ROOT/dytallix-missing-output" \
    --allow-blocked > "$TMP_ROOT/dytallix-missing.out" 2> "$TMP_ROOT/dytallix-missing.err"; then
    fail "expected missing Dytallix sidecar to fail closed"
fi
assert_contains "$TMP_ROOT/dytallix-missing.err" "must resolve to a regular file"

if python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/public/manifest.json" \
    --dytallix-evidence-root "$TMP_ROOT/dytallix-tampered" \
    --output-root "$TMP_ROOT/dytallix-tampered-output" \
    --allow-blocked > "$TMP_ROOT/dytallix-tampered.out" 2> "$TMP_ROOT/dytallix-tampered.err"; then
    fail "expected tampered Dytallix sidecar to fail closed"
fi
assert_contains "$TMP_ROOT/dytallix-tampered.err" "sha256 does not match"

if python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/secret/manifest.json" \
    --output-root "$TMP_ROOT/secret-output" \
    --allow-blocked > "$TMP_ROOT/secret.out" 2> "$TMP_ROOT/secret.err"; then
    fail "expected secret-bearing public evidence to fail"
fi
assert_contains "$TMP_ROOT/secret.err" "shared public-edge verification failed"

if python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/escape/manifest.json" \
    --output-root "$TMP_ROOT/escape-output" \
    --allow-blocked > "$TMP_ROOT/escape.out" 2> "$TMP_ROOT/escape.err"; then
    fail "expected public evidence path escape to fail"
fi
assert_contains "$TMP_ROOT/escape.err" "inside the public-edge run root"

if python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/secret-lifecycle/manifest.json" \
    --output-root "$TMP_ROOT/secret-lifecycle-output" \
    --allow-blocked > "$TMP_ROOT/secret-lifecycle.out" 2> "$TMP_ROOT/secret-lifecycle.err"; then
    fail "expected secret-bearing signed record proof to fail"
fi
assert_contains "$TMP_ROOT/secret-lifecycle.err" "forbidden secret or raw-artifact marker"

if python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/symlink-lifecycle/manifest.json" \
    --output-root "$TMP_ROOT/symlink-lifecycle-output" \
    --allow-blocked > "$TMP_ROOT/symlink-lifecycle.out" 2> "$TMP_ROOT/symlink-lifecycle.err"; then
    fail "expected symlinked signed record proof to fail"
fi
assert_contains "$TMP_ROOT/symlink-lifecycle.err" "must not be a symbolic link"

if python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/tampered-lifecycle/manifest.json" \
    --output-root "$TMP_ROOT/tampered-lifecycle-output" \
    --allow-blocked > "$TMP_ROOT/tampered-lifecycle.out" 2> "$TMP_ROOT/tampered-lifecycle.err"; then
    fail "expected tampered signed record proof to fail"
fi
assert_contains "$TMP_ROOT/tampered-lifecycle.err" "sha256 does not match"

if grep -R -n -i -E 'PRIVATE KEY|WALLET_SEED|AUTH_TOKEN|TURN_PASSWORD|\.pcap' "$TMP_ROOT/bridged"; then
    fail "bridged bundle contains a forbidden secret or raw-artifact marker"
fi

echo "bridge-public-edge-evidence-test: ok"
