#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STEAMOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

EVIDENCE_ROOT="${QLINK_STEAMOS_PRODUCTION_EVIDENCE_ROOT:-}"
OUTPUT_MANIFEST="${QLINK_STEAMOS_OUTPUT_MANIFEST:-}"
ALLOW_BLOCKED="${QLINK_STEAMOS_ALLOW_BLOCKED_EVIDENCE:-0}"

usage() {
    cat >&2 <<'EOF'
usage: collect-production-evidence.sh --evidence-root DIR --output FILE

Builds a redacted SteamOS non-hardware production evidence manifest from an
operator evidence bundle. The bundle must contain metadata.json plus referenced
redacted evidence files. The generated manifest is validated before exit.

Environment aliases:
  QLINK_STEAMOS_PRODUCTION_EVIDENCE_ROOT
  QLINK_STEAMOS_OUTPUT_MANIFEST
  QLINK_STEAMOS_ALLOW_BLOCKED_EVIDENCE=1
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --evidence-root)
            EVIDENCE_ROOT="${2:-}"
            shift 2
            ;;
        --output)
            OUTPUT_MANIFEST="${2:-}"
            shift 2
            ;;
        --allow-blocked)
            ALLOW_BLOCKED=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

if [ -z "$EVIDENCE_ROOT" ] || [ -z "$OUTPUT_MANIFEST" ]; then
    usage
    exit 2
fi

python3 - "$EVIDENCE_ROOT" "$OUTPUT_MANIFEST" <<'PY'
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

evidence_root = Path(sys.argv[1]).resolve()
output_manifest = Path(sys.argv[2])
metadata_path = evidence_root / "metadata.json"
failures: list[str] = []

required_dytallix_cases = {
    "active": "accepted",
    "missing": "rejected",
    "revoked": "rejected",
    "suspended": "rejected",
    "mismatched": "rejected",
    "stale": "rejected",
    "unavailable": "rejected",
}
required_controls = [
    "tls",
    "authentication",
    "signed_expiring_records",
    "rate_limits",
    "abuse_logs",
    "revocation_propagation",
    "relay_denial",
    "retention",
    "key_rotation",
    "endpoint_rotation",
    "incident_shutdown",
]
forbidden = re.compile(
    r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|"
    r"WALLET_SEED|ENTITLEMENT_TOKEN|DYTALLIX_WALLET_SECRET|"
    r"QLINK_PRODUCTION_ENDPOINT_SECRET|STEAMOS_RELEASE_PRIVATE_KEY|"
    r"\.pcapng?\b|support-bundle.*\.(?:tar|tar\.gz|tgz|zst|zip)\b",
    re.IGNORECASE,
)


def fail(message: str) -> None:
    failures.append(message)


def is_nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def secure_url(value: str, allowed: set[str]) -> bool:
    parsed = urlparse(value)
    if parsed.scheme not in allowed:
        return False
    if parsed.scheme == "turns":
        return bool(parsed.netloc or parsed.path)
    return bool(parsed.netloc)


def load_metadata() -> dict:
    if not metadata_path.is_file():
        fail(f"missing metadata file: {metadata_path}")
        return {}
    raw = metadata_path.read_text(encoding="utf-8", errors="ignore")
    if forbidden.search(raw):
        fail("forbidden secret marker found in metadata.json")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        fail(f"metadata.json is invalid JSON: {error}")
        return {}
    if not isinstance(value, dict):
        fail("metadata.json must be a JSON object")
        return {}
    return value


def evidence_digest(rel_path: object, label: str) -> tuple[str, str]:
    if not is_nonempty_string(rel_path):
        fail(f"{label} evidence path is required")
        return "", ""
    rel = Path(str(rel_path))
    if rel.is_absolute() or ".." in rel.parts:
        fail(f"{label} evidence path must be relative and stay inside evidence root")
        return str(rel_path), ""
    path = (evidence_root / rel).resolve()
    try:
        path.relative_to(evidence_root)
    except ValueError:
        fail(f"{label} evidence path escapes evidence root")
        return str(rel_path), ""
    if not path.is_file():
        fail(f"{label} evidence file is missing: {rel}")
        return str(rel_path), ""
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="ignore")
    if forbidden.search(str(rel)) or forbidden.search(text):
        fail(f"{label} evidence contains forbidden secret or raw-artifact marker: {rel}")
    return str(rel).replace(os.sep, "/"), hashlib.sha256(raw).hexdigest()


metadata = load_metadata()
status = metadata.get("status", "pass")
if status not in {"pass", "blocked", "fail"}:
    fail("metadata.status must be pass, blocked, or fail")
    status = "fail"

generated_at = metadata.get("generatedAt")
if not is_nonempty_string(generated_at):
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

dytallix_meta = metadata.get("dytallix")
if not isinstance(dytallix_meta, dict):
    fail("metadata.dytallix section is required")
    dytallix_meta = {}

rendezvous_meta = metadata.get("rendezvousRelay")
if not isinstance(rendezvous_meta, dict):
    fail("metadata.rendezvousRelay section is required")
    rendezvous_meta = {}

dytallix_status = dytallix_meta.get("status", status)
if dytallix_status not in {"pass", "blocked", "fail"}:
    fail("metadata.dytallix.status must be pass, blocked, or fail")
    dytallix_status = "fail"
rendezvous_status = rendezvous_meta.get("status", status)
if rendezvous_status not in {"pass", "blocked", "fail"}:
    fail("metadata.rendezvousRelay.status must be pass, blocked, or fail")
    rendezvous_status = "fail"

registry_endpoint = dytallix_meta.get("registryEndpoint")
if not is_nonempty_string(registry_endpoint) or not secure_url(str(registry_endpoint), {"https"}):
    fail("metadata.dytallix.registryEndpoint must be an https URL")

for field in ("networkId", "contract"):
    if not is_nonempty_string(dytallix_meta.get(field)):
        fail(f"metadata.dytallix.{field} is required")

case_meta = dytallix_meta.get("cases")
if not isinstance(case_meta, dict):
    fail("metadata.dytallix.cases must be an object")
    case_meta = {}

case_matrix = []
for case_name, expected_decision in required_dytallix_cases.items():
    entry = case_meta.get(case_name)
    if not isinstance(entry, dict):
        fail(f"metadata.dytallix.cases.{case_name} is required")
        entry = {}
    evidence_rel, digest = evidence_digest(entry.get("evidence", f"dytallix/{case_name}.json"), f"Dytallix case {case_name}")
    observed = entry.get("observedDecision")
    if not is_nonempty_string(observed):
        fail(f"metadata.dytallix.cases.{case_name}.observedDecision is required")
        observed = "unknown"
    case_matrix.append({
        "case": case_name,
        "trustMode": "publicDytallixRequired",
        "expectedDecision": expected_decision,
        "observedDecision": observed,
        "evidence": evidence_rel,
        "sha256": digest,
        "redacted": entry.get("redacted", True),
    })

rendezvous_endpoints = rendezvous_meta.get("rendezvousEndpoints")
if not isinstance(rendezvous_endpoints, list) or not rendezvous_endpoints:
    fail("metadata.rendezvousRelay.rendezvousEndpoints must be a non-empty array")
    rendezvous_endpoints = []
for endpoint in rendezvous_endpoints:
    if not is_nonempty_string(endpoint) or not secure_url(str(endpoint), {"https"}):
        fail("metadata.rendezvousRelay.rendezvousEndpoints entries must be https URLs")

relay_endpoints = rendezvous_meta.get("relayEndpoints")
if not isinstance(relay_endpoints, list) or not relay_endpoints:
    fail("metadata.rendezvousRelay.relayEndpoints must be a non-empty array")
    relay_endpoints = []
for endpoint in relay_endpoints:
    if not is_nonempty_string(endpoint) or not secure_url(str(endpoint), {"turns", "https"}):
        fail("metadata.rendezvousRelay.relayEndpoints entries must use turns or https")

control_meta = rendezvous_meta.get("controls")
if not isinstance(control_meta, dict):
    fail("metadata.rendezvousRelay.controls must be an object")
    control_meta = {}

controls = []
for control_name in required_controls:
    entry = control_meta.get(control_name)
    if not isinstance(entry, dict):
        fail(f"metadata.rendezvousRelay.controls.{control_name} is required")
        entry = {}
    control_status = entry.get("status", rendezvous_status)
    if control_status not in {"pass", "blocked", "fail"}:
        fail(f"metadata.rendezvousRelay.controls.{control_name}.status must be pass, blocked, or fail")
        control_status = "fail"
    evidence_rel, digest = evidence_digest(
        entry.get("evidence", f"rendezvous-relay/{control_name}.txt"),
        f"rendezvous/relay control {control_name}",
    )
    controls.append({
        "control": control_name,
        "status": control_status,
        "evidence": evidence_rel,
        "sha256": digest,
    })

manifest = {
    "schemaVersion": 1,
    "evidenceKind": "steamosNonHardwareProductionEvidence",
    "product": "QuantumLink SteamOS",
    "platform": "steamos",
    "releaseScope": "steamos-direct-installer",
    "generatedAt": generated_at,
    "status": status,
    "host": {
        "hardwareClaimed": False,
        "physicalSteamHardwareRequired": False,
    },
    "dytallix": {
        "status": dytallix_status,
        "registryEndpoint": registry_endpoint,
        "networkId": dytallix_meta.get("networkId", ""),
        "contract": dytallix_meta.get("contract", ""),
        "walletAddressesRedacted": dytallix_meta.get("walletAddressesRedacted", True),
        "rawWalletMaterialCommitted": dytallix_meta.get("rawWalletMaterialCommitted", False),
        "caseMatrix": case_matrix,
    },
    "rendezvousRelay": {
        "status": rendezvous_status,
        "rendezvousEndpoints": rendezvous_endpoints,
        "relayEndpoints": relay_endpoints,
        "abuseLogsRedacted": rendezvous_meta.get("abuseLogsRedacted", True),
        "rawPacketPayloadsCommitted": rendezvous_meta.get("rawPacketPayloadsCommitted", False),
        "rawGamePayloadsCommitted": rendezvous_meta.get("rawGamePayloadsCommitted", False),
        "controls": controls,
    },
}

output_manifest.parent.mkdir(parents=True, exist_ok=True)
output_manifest.write_text(json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")

if failures:
    for failure in failures:
        print(failure, file=sys.stderr)
    sys.exit(1)
PY

REPORT_PATH="$(mktemp)"
if ! bash "$SCRIPT_DIR/verify-production-evidence.sh" "$OUTPUT_MANIFEST" > "$REPORT_PATH"; then
    cat "$REPORT_PATH" >&2
    rm -f "$REPORT_PATH"
    exit 1
fi

READY="$(python3 - "$REPORT_PATH" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    report = json.load(handle)
print("true" if report.get("productionEvidenceReady") is True else "false")
PY
)"
cat "$REPORT_PATH"
rm -f "$REPORT_PATH"

if [ "$READY" != "true" ] && [ "$ALLOW_BLOCKED" != "1" ]; then
    echo "production evidence manifest is valid but not ready; rerun with --allow-blocked to keep blocked evidence" >&2
    exit 1
fi
