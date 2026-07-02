#!/usr/bin/env bash
set -euo pipefail

EVIDENCE_DIR="${1:-}"
REQUIRE_HARDWARE="${QLINK_DECK_REQUIRE_HARDWARE:-0}"

if [ -z "$EVIDENCE_DIR" ]; then
    echo "usage: $0 steam/steamos/validation/deck/<timestamp>" >&2
    exit 2
fi

python3 - "$EVIDENCE_DIR" "$REQUIRE_HARDWARE" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

evidence_dir = Path(sys.argv[1])
require_hardware = sys.argv[2] == "1"
report_path = evidence_dir / "validation-report.json"
failures: list[str] = []

def fail(message: str) -> None:
    failures.append(message)

if not evidence_dir.is_dir():
    fail(f"evidence directory is missing: {evidence_dir}")
elif not report_path.is_file():
    fail("validation-report.json is missing")

report = {}
if report_path.is_file():
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"validation-report.json is invalid JSON: {error}")

minimum_required = [
    "status-before.json",
    "status-after.json",
    "doctor.txt",
    "route-leak-check.txt",
    "journal-qlinkd.txt",
    "nftables.txt",
    "ip-route.txt",
    "support-bundle-redaction.txt",
    "validation-report.json",
]
reported_required = report.get("requiredEvidence") or []
if not isinstance(reported_required, list):
    fail("requiredEvidence must be an array when present")
    reported_required = []
required = list(dict.fromkeys(minimum_required + reported_required))
for name in required:
    if not isinstance(name, str) or not name:
        fail("requiredEvidence contains an invalid entry")
        continue
    evidence_name = Path(name)
    if evidence_name.is_absolute() or ".." in evidence_name.parts:
        fail(f"requiredEvidence entry must be relative and stay within evidence directory: {name}")
        continue
    if not (evidence_dir / name).is_file():
        fail(f"required evidence file is missing: {name}")

for field in ("rawPcapCommitted", "rawSupportBundleCommitted", "privateMaterialCommitted"):
    if report.get(field) is not False:
        fail(f"{field} must be false")

host = report.get("host") or {}
if report.get("hardwareClaimed") is True:
    if host.get("isSteamOS") is not True:
        fail("hardwareClaimed requires host.isSteamOS=true")
    if host.get("isSteamDeckHardware") is not True:
        fail("hardwareClaimed requires host.isSteamDeckHardware=true")

if require_hardware:
    if report.get("hardwareClaimed") is not True:
        fail("hardwareClaimed must be true when QLINK_DECK_REQUIRE_HARDWARE=1")
    if host.get("isSteamOS") is not True:
        fail("host.isSteamOS must be true when hardware is required")
    if host.get("isSteamDeckHardware") is not True:
        fail("host.isSteamDeckHardware must be true when hardware is required")

if not isinstance(report.get("mode"), str) or not report["mode"]:
    fail("mode is required")
if report.get("status") not in {"blocked", "fail", "pass"}:
    fail("status must be blocked, fail, or pass")

forbidden = re.compile(
    r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|"
    r"WALLET_SEED|ENTITLEMENT_TOKEN|DYTALLIX_WALLET_SECRET|"
    r"QLINK_PRODUCTION_ENDPOINT_SECRET",
    re.IGNORECASE,
)
for path in evidence_dir.rglob("*"):
    if not path.is_file():
        continue
    lower_name = path.name.lower()
    if lower_name.endswith((".pcap", ".pcapng")):
        fail(f"raw packet capture artifact is not allowed: {path.relative_to(evidence_dir)}")
    if "support-bundle" in lower_name and lower_name.endswith((".tar", ".tar.gz", ".tgz", ".zst", ".zip")):
        fail(f"raw support bundle archive is not allowed: {path.relative_to(evidence_dir)}")
    try:
        data = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as error:
        fail(f"could not read evidence file {path.name}: {error}")
        continue
    if forbidden.search(data):
        fail(f"forbidden raw/secret material marker found in {path.relative_to(evidence_dir)}")

if failures:
    for message in failures:
        print(message, file=sys.stderr)
    raise SystemExit(1)

print(json.dumps({
    "valid": True,
    "evidenceDir": str(evidence_dir),
    "hardwareClaimed": report.get("hardwareClaimed") is True,
    "mode": report.get("mode"),
    "status": report.get("status"),
}, separators=(",", ":"), sort_keys=True))
PY
