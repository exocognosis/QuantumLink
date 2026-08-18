#!/usr/bin/env bash
set -euo pipefail

EVIDENCE_DIR="${1:-}"
REQUIRE_COMPLETE="${QLINK_DECK_RUNTIME_REQUIRE_COMPLETE:-0}"

[ -n "$EVIDENCE_DIR" ] || {
    echo "usage: $0 <deck-runtime-evidence-directory>" >&2
    exit 2
}

python3 - "$EVIDENCE_DIR" "$REQUIRE_COMPLETE" <<'PY'
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
require_complete = sys.argv[2] == "1"
failures = []

def fail(message):
    failures.append(message)

report_path = root / "runtime-report.json"
if not root.is_dir():
    fail(f"evidence directory is missing: {root}")
if not report_path.is_file():
    fail("runtime-report.json is missing")

report = {}
if report_path.is_file():
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"runtime-report.json is invalid JSON: {error}")

if report.get("schemaVersion") != 1:
    fail("schemaVersion must be 1")
if report.get("evidenceKind") != "steamosDeckRuntimeQualification":
    fail("evidenceKind must be steamosDeckRuntimeQualification")
if report.get("hardwareClaimed") is not True:
    fail("hardwareClaimed must be true")
host = report.get("host", {})
if host.get("isSteamOS") is not True:
    fail("host.isSteamOS must be true")
if host.get("isSteamDeckHardware") is not True:
    fail("host.isSteamDeckHardware must be true")

minimum_required = (
    "runtime-report.json", "status-before.json", "status-after.json"
)
reported_required = report.get("requiredEvidence", [])
if not isinstance(reported_required, list):
    fail("requiredEvidence must be an array")
    reported_required = []
for name in dict.fromkeys((*minimum_required, *reported_required)):
    if not isinstance(name, str) or not name:
        fail("requiredEvidence contains an invalid entry")
        continue
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        fail(f"requiredEvidence must stay inside the evidence directory: {name}")
    elif not (root / relative).is_file():
        fail(f"required evidence file is missing: {name}")

privacy = report.get("privacy", {})
for name in (
    "rawPacketCaptureCommitted",
    "rawSupportBundleCommitted",
    "privateMaterialCommitted",
):
    if privacy.get(name) is not False:
        fail(f"privacy.{name} must be false")

fixture_scope = report.get("fixtureScope", {})
if fixture_scope.get("syntheticExecutables") is not True:
    fail("fixtureScope.syntheticExecutables must be true")
if fixture_scope.get("provesRealGameCompatibility") is not False:
    fail("fixture evidence must not claim real game compatibility")
if fixture_scope.get("provesTwoDeckPacketFlow") is not False:
    fail("fixture evidence must not claim two-Deck packet flow")

required_capabilities = (
    "cgroupV2", "nftablesCgroupV2", "tun",
    "systemdUserScopes", "policykit", "logindSession",
)
capabilities = report.get("runtimeCapabilities", {})
for name in required_capabilities:
    if capabilities.get(name, {}).get("state") != "supported":
        fail(f"runtime capability is not supported: {name}")

statuses = {}
for name in ("status-before.json", "status-after.json"):
    path = root / name
    if not path.is_file():
        continue
    try:
        statuses[name] = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"{name} is invalid JSON: {error}")
for name, status_document in statuses.items():
    if status_document.get("runtimeCapabilities") != capabilities:
        fail(f"{name} runtime capabilities do not match runtime-report.json")

required_checks = (
    "runtimeCapabilities", "policyKitServiceControl",
    "nativeScopeClassification", "descendantScopeInheritance",
    "gameCrashCleanup", "concurrentLaunchDenied",
    "launcherInterruptionCleanup", "daemonRestartCleanup",
)
checks = report.get("checks", {})
if require_complete:
    if report.get("mode") != "run" or report.get("status") != "pass":
        fail("complete evidence requires mode=run and status=pass")
    for name in required_checks:
        if checks.get(name) != "passed":
            fail(f"required runtime check did not pass: {name}")
    final_status = statuses.get("status-after.json", {})
    network = final_status.get("network", {})
    data_plane = final_status.get("dataPlane", {})
    game_process = final_status.get("gameProcess", {})
    if network.get("state") != "applied" or network.get("dryRun") is not False:
        fail("complete evidence requires an applied non-dry-run network")
    if network.get("ownershipRecordPresent") is not True:
        fail("complete evidence requires network teardown ownership")
    if data_plane.get("packetIoAvailable") is not True:
        fail("complete evidence requires packet I/O")
    if game_process.get("state") != "armed":
        fail("complete evidence requires armed game classification after cleanup")

forbidden = re.compile(
    "BE" + r"GIN (?:RSA |EC |OPENSSH )?PRIVATE " + "KEY|"
    + "WALLET" + "_SEED|"
    + "ENTITLEMENT" + "_TOKEN|"
    + "DYTALLIX_WALLET" + "_SECRET|"
    + "QLINK_PRODUCTION_ENDPOINT" + "_SECRET",
    re.IGNORECASE,
)
if root.is_dir():
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in {".pcap", ".pcapng"}:
            fail(f"raw packet capture is not allowed: {path.name}")
            continue
        if forbidden.search(path.read_text(encoding="utf-8", errors="ignore")):
            fail(f"forbidden private material marker found in {path.name}")

if failures:
    for message in failures:
        print(message, file=sys.stderr)
    raise SystemExit(1)

print(json.dumps({
    "valid": True,
    "complete": require_complete,
    "hardwareClaimed": True,
    "mode": report.get("mode"),
    "status": report.get("status"),
}, separators=(",", ":"), sort_keys=True))
PY
