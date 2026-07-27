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
import json
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


def write_run(path, secret=False, escape=False):
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
    write_json(path / "manifest.json", manifest)


write_run(root / "public")
write_run(root / "secret", secret=True)
write_run(root / "escape", escape=True)

dytallix_root = root / "dytallix"
dytallix_cases = {}
expected = {
    "active": "accepted",
    "missing": "rejected",
    "revoked": "rejected",
    "suspended": "rejected",
    "mismatched": "rejected",
    "stale": "rejected",
    "unavailable": "rejected",
}
for case_name, decision in expected.items():
    relative = f"dytallix/{case_name}.json"
    dytallix_cases[case_name] = {
        "observedDecision": decision,
        "evidence": relative,
        "redacted": True,
    }
    write_json(
        dytallix_root / relative,
        {"case": case_name, "observedDecision": decision, "redacted": True},
    )
write_json(
    dytallix_root / "metadata.json",
    {
        "dytallix": {
            "status": "pass",
            "registryEndpoint": "https://registry.dytallix.invalid",
            "networkId": "dytallix-testnet",
            "contract": "quantumlink-node-registry",
            "walletAddressesRedacted": True,
            "rawWalletMaterialCommitted": False,
            "cases": dytallix_cases,
        }
    },
)
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
assert manifest["evidenceKind"] == "steamosNonHardwareProductionEvidence"
assert manifest["dytallix"]["status"] == "blocked"
PY

bash "$VERIFIER" "$TMP_ROOT/bridged/production-evidence.json" > "$TMP_ROOT/verifier.out"

if python3 "$BRIDGE" \
    --public-edge-manifest "$TMP_ROOT/public/manifest.json" \
    --output-root "$TMP_ROOT/default-blocked" > "$TMP_ROOT/default-blocked.out" 2> "$TMP_ROOT/default-blocked.err"; then
    fail "expected default blocked bridge to fail closed"
fi
assert_contains "$TMP_ROOT/default-blocked.err" "valid but blocked"

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

if grep -R -n -i -E 'PRIVATE KEY|WALLET_SEED|AUTH_TOKEN|TURN_PASSWORD|\.pcap' "$TMP_ROOT/bridged"; then
    fail "bridged bundle contains a forbidden secret or raw-artifact marker"
fi

echo "bridge-public-edge-evidence-test: ok"
