#!/usr/bin/env bash
set -euo pipefail

MANIFEST="${1:-}"

if [ -z "$MANIFEST" ]; then
    echo "usage: $0 steam/steamos/validation/production-evidence.json" >&2
    exit 2
fi

python3 - "$MANIFEST" <<'PY'
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

manifest_path = Path(sys.argv[1])
failures: list[str] = []
warnings: list[str] = []
blockers: list[str] = []


def fail(message: str) -> None:
    failures.append(message)


def block(message: str) -> None:
    blockers.append(message)


def is_nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def is_relative_evidence_path(value: object) -> bool:
    if not is_nonempty_string(value):
        return False
    path = Path(str(value))
    return not path.is_absolute() and ".." not in path.parts


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def endpoint_has_secure_scheme(value: str, allowed: set[str]) -> bool:
    parsed = urlparse(value)
    if parsed.scheme not in allowed:
        return False
    if parsed.scheme == "turns":
        return bool(parsed.netloc or parsed.path)
    return bool(parsed.netloc)


raw_text = ""
manifest: object = {}
if not manifest_path.is_file():
    fail(f"production evidence manifest is missing: {manifest_path}")
else:
    raw_text = manifest_path.read_text(encoding="utf-8", errors="ignore")
    forbidden = re.compile(
        r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|"
        r"WALLET_SEED|ENTITLEMENT_TOKEN|DYTALLIX_WALLET_SECRET|"
        r"QLINK_PRODUCTION_ENDPOINT_SECRET|STEAMOS_RELEASE_PRIVATE_KEY|"
        r"\.pcapng?\b|support-bundle.*\.(?:tar|tar\.gz|tgz|zst|zip)\b",
        re.IGNORECASE,
    )
    if forbidden.search(raw_text):
        fail("forbidden secret marker found in production evidence manifest")
    try:
        manifest = json.loads(raw_text)
    except json.JSONDecodeError as error:
        fail(f"production evidence manifest is invalid JSON: {error}")
        manifest = {}

if not isinstance(manifest, dict):
    fail("production evidence manifest must be a JSON object")
    manifest = {}

if manifest.get("schemaVersion") != 1:
    fail("schemaVersion must be 1")
if manifest.get("evidenceKind") != "steamosNonHardwareProductionEvidence":
    fail("evidenceKind must be steamosNonHardwareProductionEvidence")
if manifest.get("product") != "QuantumLink SteamOS":
    fail("product must be QuantumLink SteamOS")
if manifest.get("platform") != "steamos":
    fail("platform must be steamos")
if manifest.get("releaseScope") != "steamos-direct-installer":
    fail("releaseScope must be steamos-direct-installer")
generated_at = manifest.get("generatedAt")
if not is_nonempty_string(generated_at):
    fail("generatedAt is required")
elif not str(generated_at).endswith("Z"):
    fail("generatedAt must be a UTC RFC3339 timestamp ending in Z")
else:
    try:
        datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
    except ValueError:
        fail("generatedAt must be a valid RFC3339 timestamp")
if manifest.get("status") not in {"pass", "blocked", "fail"}:
    fail("status must be pass, blocked, or fail")
elif manifest.get("status") != "pass":
    block(f"production evidence status is {manifest.get('status')}")

host = manifest.get("host")
if not isinstance(host, dict):
    fail("host section is required")
else:
    if host.get("hardwareClaimed") is not False:
        fail("host.hardwareClaimed must be false for non-hardware production evidence")
    if host.get("physicalSteamHardwareRequired") is not False:
        fail("host.physicalSteamHardwareRequired must be false")

dytallix = manifest.get("dytallix")
dytallix_failures_at_start = len(failures)
dytallix_blockers_at_start = len(blockers)
required_dytallix_cases = {
    "active": "accepted",
    "missing": "rejected",
    "revoked": "rejected",
    "suspended": "rejected",
    "mismatched": "rejected",
    "stale": "rejected",
    "unavailable": "rejected",
}
if not isinstance(dytallix, dict):
    fail("dytallix section is required")
    dytallix = {}
else:
    if dytallix.get("status") != "pass":
        if dytallix.get("status") in {"blocked", "fail"}:
            block(f"dytallix.status is {dytallix.get('status')}")
        else:
            fail("dytallix.status must be pass, blocked, or fail")
    endpoint = dytallix.get("registryEndpoint")
    if not is_nonempty_string(endpoint) or not endpoint_has_secure_scheme(str(endpoint), {"https"}):
        fail("dytallix.registryEndpoint must be an https URL")
    for field in ("networkId", "contract"):
        if not is_nonempty_string(dytallix.get(field)):
            fail(f"dytallix.{field} is required")
    if dytallix.get("walletAddressesRedacted") is not True:
        fail("dytallix.walletAddressesRedacted must be true")
    if dytallix.get("rawWalletMaterialCommitted") is not False:
        fail("dytallix.rawWalletMaterialCommitted must be false")

    case_matrix = dytallix.get("caseMatrix")
    if not isinstance(case_matrix, list):
        fail("dytallix.caseMatrix must be an array")
        case_matrix = []
    cases_by_name = {}
    for entry in case_matrix:
        if not isinstance(entry, dict):
            fail("dytallix.caseMatrix entries must be objects")
            continue
        case_name = entry.get("case")
        if not is_nonempty_string(case_name):
            fail("dytallix.caseMatrix entry is missing case")
            continue
        cases_by_name[str(case_name)] = entry

    for case_name, expected_decision in required_dytallix_cases.items():
        entry = cases_by_name.get(case_name)
        if entry is None:
            fail(f"missing Dytallix case: {case_name}")
            continue
        if entry.get("trustMode") != "publicDytallixRequired":
            fail(f"Dytallix case {case_name} must use publicDytallixRequired trustMode")
        if entry.get("expectedDecision") != expected_decision:
            fail(f"Dytallix case {case_name} expectedDecision must be {expected_decision}")
        if entry.get("observedDecision") != expected_decision:
            block(f"Dytallix case {case_name} observedDecision is {entry.get('observedDecision')}")
        if entry.get("redacted") is not True:
            fail(f"Dytallix case {case_name} must be redacted")
        if not is_relative_evidence_path(entry.get("evidence")):
            fail(f"Dytallix case {case_name} evidence must be a relative path")
        if "sha256" in entry and not is_sha256(entry.get("sha256")):
            fail(f"Dytallix case {case_name} sha256 must be a 64-character lowercase hex digest")

rendezvous = manifest.get("rendezvousRelay")
rendezvous_failures_at_start = len(failures)
rendezvous_blockers_at_start = len(blockers)
required_controls = {
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
}
if not isinstance(rendezvous, dict):
    fail("rendezvousRelay section is required")
    rendezvous = {}
else:
    if rendezvous.get("status") != "pass":
        if rendezvous.get("status") in {"blocked", "fail"}:
            block(f"rendezvousRelay.status is {rendezvous.get('status')}")
        else:
            fail("rendezvousRelay.status must be pass, blocked, or fail")
    rendezvous_endpoints = rendezvous.get("rendezvousEndpoints")
    if not isinstance(rendezvous_endpoints, list) or not rendezvous_endpoints:
        fail("rendezvousRelay.rendezvousEndpoints must be a non-empty array")
        rendezvous_endpoints = []
    for endpoint in rendezvous_endpoints:
        if not is_nonempty_string(endpoint) or not endpoint_has_secure_scheme(str(endpoint), {"https"}):
            fail("rendezvous endpoint must be an https URL")

    relay_endpoints = rendezvous.get("relayEndpoints")
    if not isinstance(relay_endpoints, list) or not relay_endpoints:
        fail("rendezvousRelay.relayEndpoints must be a non-empty array")
        relay_endpoints = []
    for endpoint in relay_endpoints:
        if not is_nonempty_string(endpoint) or not endpoint_has_secure_scheme(str(endpoint), {"turns", "https"}):
            fail("relay endpoint must use turns or https")

    if rendezvous.get("abuseLogsRedacted") is not True:
        fail("rendezvousRelay.abuseLogsRedacted must be true")
    for field in ("rawPacketPayloadsCommitted", "rawGamePayloadsCommitted"):
        if rendezvous.get(field) is not False:
            fail(f"rendezvousRelay.{field} must be false")

    controls = rendezvous.get("controls")
    if not isinstance(controls, list):
        fail("rendezvousRelay.controls must be an array")
        controls = []
    controls_by_name = {}
    for entry in controls:
        if not isinstance(entry, dict):
            fail("rendezvousRelay.controls entries must be objects")
            continue
        control_name = entry.get("control")
        if not is_nonempty_string(control_name):
            fail("rendezvousRelay.controls entry is missing control")
            continue
        controls_by_name[str(control_name)] = entry

    for control_name in sorted(required_controls):
        entry = controls_by_name.get(control_name)
        if entry is None:
            fail(f"missing rendezvous/relay control: {control_name}")
            continue
        if entry.get("status") != "pass":
            if entry.get("status") in {"blocked", "fail"}:
                block(f"rendezvous/relay control {control_name} status is {entry.get('status')}")
            else:
                fail(f"rendezvous/relay control {control_name} status must be pass, blocked, or fail")
        if not is_relative_evidence_path(entry.get("evidence")):
            fail(f"rendezvous/relay control {control_name} evidence must be a relative path")
        if "sha256" in entry and not is_sha256(entry.get("sha256")):
            fail(f"rendezvous/relay control {control_name} sha256 must be a 64-character lowercase hex digest")

dytallix_ready = len(failures) == dytallix_failures_at_start and len(blockers) == dytallix_blockers_at_start
rendezvous_ready = len(failures) == rendezvous_failures_at_start and len(blockers) == rendezvous_blockers_at_start
ready = not failures and not blockers
report = {
    "valid": not failures,
    "productionEvidenceReady": ready,
    "dytallixReady": dytallix_ready,
    "rendezvousRelayReady": rendezvous_ready,
    "manifest": str(manifest_path),
    "blockers": blockers,
    "failures": failures,
    "warnings": warnings,
}
print(json.dumps(report, separators=(",", ":"), sort_keys=True))
raise SystemExit(0 if not failures else 1)
PY
