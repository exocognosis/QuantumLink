#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
EVIDENCE_DIR="${QLINK_DECK_RUNTIME_EVIDENCE_DIR:-}"
OS_RELEASE_FILE="${QLINK_DECK_OS_RELEASE_FILE:-/etc/os-release}"
PRODUCT_NAME_FILE="${QLINK_DECK_PRODUCT_NAME_FILE:-/sys/devices/virtual/dmi/id/product_name}"
BOARD_NAME_FILE="${QLINK_DECK_BOARD_NAME_FILE:-/sys/devices/virtual/dmi/id/board_name}"
REPORT="${EVIDENCE_DIR}/runtime-report.json"
STATUS_BEFORE="${EVIDENCE_DIR}/status-before.json"
STATUS_AFTER="${EVIDENCE_DIR}/status-after.json"
WORK_DIR=""
ACTIVE_PID=""
REPORT_WRITTEN=0

RUNTIME_CAPABILITIES=blocked
POLICYKIT_SERVICE_CONTROL=blocked
NATIVE_SCOPE=blocked
DESCENDANT_SCOPE=blocked
CRASH_CLEANUP=blocked
CONCURRENT_LAUNCH=blocked
INTERRUPTION_CLEANUP=blocked
DAEMON_RESTART_CLEANUP=blocked

usage() {
    cat >&2 <<'EOF'
usage: deck-runtime-qualification.sh <preflight|run>

Set QLINK_DECK_RUNTIME_EVIDENCE_DIR to an empty evidence directory.
Set QLINK_DECK_CONFIRM_NETWORK_MUTATION=YES for run mode.
Run as the signed-in SteamOS desktop user, not as root.
EOF
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

os_release_value() {
    local key="$1"
    local value=""
    if [ -r "$OS_RELEASE_FILE" ]; then
        value="$(awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$OS_RELEASE_FILE")"
    fi
    value="${value%\"}"
    value="${value#\"}"
    printf '%s' "$value"
}

read_first_line() {
    if [ -r "$1" ]; then
        sed -n '1p' "$1"
    fi
}

is_steamos() {
    case "$(os_release_value ID):$(os_release_value NAME)" in
        *steamos*|*SteamOS*) return 0 ;;
        *) return 1 ;;
    esac
}

is_steam_deck() {
    case "$(read_first_line "$PRODUCT_NAME_FILE") $(read_first_line "$BOARD_NAME_FILE")" in
        *"Steam Deck"*|*Jupiter*|*Galileo*) return 0 ;;
        *) return 1 ;;
    esac
}

capture_safe_status() {
    local output="$1"
    local temporary="${output}.tmp"
    qlinkctl status | python3 -c '
import json, sys
status = json.load(sys.stdin)
safe = {
    "phase": status.get("phase"),
    "network": {
        "state": status.get("network", {}).get("state"),
        "dryRun": status.get("network", {}).get("dryRun"),
        "ownershipRecordPresent": status.get("network", {}).get("ownershipRecordPresent"),
    },
    "dataPlane": {
        "state": status.get("dataPlane", {}).get("state"),
        "packetIoAvailable": status.get("dataPlane", {}).get("packetIoAvailable"),
    },
    "gameProcess": status.get("gameProfile", {}).get("processClassification", {}),
    "runtimeCapabilities": status.get("runtimeCapabilities", {}),
}
json.dump(safe, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
' > "$temporary"
    mv "$temporary" "$output"
}

validate_runtime_capabilities() {
    python3 - "$STATUS_BEFORE" <<'PY'
import json
import sys

status = json.load(open(sys.argv[1], encoding="utf-8"))
capabilities = status.get("runtimeCapabilities", {})
required = (
    "cgroupV2", "nftablesCgroupV2", "tun",
    "systemdUserScopes", "policykit", "logindSession",
)
failures = []
for name in required:
    capability = capabilities.get(name, {})
    if capability.get("state") != "supported":
        failures.append(f"{name}={capability.get('state', 'missing')}")
if failures:
    raise SystemExit("unsupported runtime capabilities: " + ", ".join(failures))
PY
}

classification_is() {
    local expected="$1"
    qlinkctl status | python3 -c '
import json, sys
expected = sys.argv[1]
status = json.load(sys.stdin)
actual = status.get("gameProfile", {}).get("processClassification", {}).get("state")
raise SystemExit(0 if actual == expected else 1)
' "$expected"
}

wait_for_classification() {
    local expected="$1"
    local attempts=100
    while [ "$attempts" -gt 0 ]; do
        if classification_is "$expected"; then
            return 0
        fi
        attempts=$((attempts - 1))
        sleep 0.1
    done
    fail "game process classification did not reach $expected"
}

wait_for_file() {
    local path="$1"
    local attempts=100
    while [ "$attempts" -gt 0 ]; do
        [ -s "$path" ] && return 0
        attempts=$((attempts - 1))
        sleep 0.1
    done
    fail "fixture output was not created: $path"
}

write_report() {
    local status="$1"
    local detail="$2"
    local hardware=false
    local os_id os_name product_name board_name
    if is_steamos && is_steam_deck; then
        hardware=true
    fi
    os_id="$(os_release_value ID)"
    os_name="$(os_release_value NAME)"
    product_name="$(read_first_line "$PRODUCT_NAME_FILE")"
    board_name="$(read_first_line "$BOARD_NAME_FILE")"
    RUNTIME_CAPABILITIES="$RUNTIME_CAPABILITIES" \
    POLICYKIT_SERVICE_CONTROL="$POLICYKIT_SERVICE_CONTROL" \
    NATIVE_SCOPE="$NATIVE_SCOPE" \
    DESCENDANT_SCOPE="$DESCENDANT_SCOPE" \
    CRASH_CLEANUP="$CRASH_CLEANUP" \
    CONCURRENT_LAUNCH="$CONCURRENT_LAUNCH" \
    INTERRUPTION_CLEANUP="$INTERRUPTION_CLEANUP" \
    DAEMON_RESTART_CLEANUP="$DAEMON_RESTART_CLEANUP" \
    python3 - "$REPORT" "$MODE" "$status" "$detail" "$hardware" \
        "$STATUS_BEFORE" "$os_id" "$os_name" "$product_name" "$board_name" <<'PY'
import json
import os
import sys

(
    path, mode, status, detail, hardware, status_path,
    os_id, os_name, product_name, board_name,
) = sys.argv[1:]
capabilities = {}
try:
    capabilities = json.load(open(status_path, encoding="utf-8")).get(
        "runtimeCapabilities", {}
    )
except (OSError, json.JSONDecodeError):
    pass
checks = {
    "runtimeCapabilities": os.environ["RUNTIME_CAPABILITIES"],
    "policyKitServiceControl": os.environ["POLICYKIT_SERVICE_CONTROL"],
    "nativeScopeClassification": os.environ["NATIVE_SCOPE"],
    "descendantScopeInheritance": os.environ["DESCENDANT_SCOPE"],
    "gameCrashCleanup": os.environ["CRASH_CLEANUP"],
    "concurrentLaunchDenied": os.environ["CONCURRENT_LAUNCH"],
    "launcherInterruptionCleanup": os.environ["INTERRUPTION_CLEANUP"],
    "daemonRestartCleanup": os.environ["DAEMON_RESTART_CLEANUP"],
}
report = {
    "schemaVersion": 1,
    "evidenceKind": "steamosDeckRuntimeQualification",
    "mode": mode,
    "status": status,
    "detail": detail,
    "hardwareClaimed": hardware == "true",
    "host": {
        "osId": os_id,
        "osName": os_name,
        "productName": product_name,
        "boardName": board_name,
        "isSteamOS": "steamos" in os_id.lower() or "steamos" in os_name.lower(),
        "isSteamDeckHardware": any(
            marker in f"{product_name} {board_name}"
            for marker in ("Steam Deck", "Jupiter", "Galileo")
        ),
    },
    "runtimeCapabilities": capabilities,
    "checks": checks,
    "fixtureScope": {
        "syntheticExecutables": True,
        "provesKernelAndLifecycleBehaviorOnly": True,
        "provesRealGameCompatibility": False,
        "provesTwoDeckPacketFlow": False,
    },
    "privacy": {
        "rawPacketCaptureCommitted": False,
        "rawSupportBundleCommitted": False,
        "privateMaterialCommitted": False,
    },
    "requiredEvidence": [
        "runtime-report.json", "status-before.json", "status-after.json"
    ],
}
with open(path, "w", encoding="utf-8") as output:
    json.dump(report, output, indent=2, sort_keys=True)
    output.write("\n")
PY
    REPORT_WRITTEN=1
}

finish() {
    local exit_code=$?
    trap - EXIT
    if [ -n "$ACTIVE_PID" ]; then
        kill -TERM "$ACTIVE_PID" >/dev/null 2>&1 || true
        wait "$ACTIVE_PID" >/dev/null 2>&1 || true
    fi
    if [ "$REPORT_WRITTEN" -eq 0 ] && [ -n "$EVIDENCE_DIR" ] && [ -d "$EVIDENCE_DIR" ]; then
        write_report fail "qualification stopped with exit code $exit_code"
    fi
    if [ -n "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
    exit "$exit_code"
}
trap finish EXIT

run_fixture() {
    local mode="$1"
    local sleep_seconds="$2"
    env QLINK_FIXTURE_MODE="$mode" QLINK_FIXTURE_SLEEP="$sleep_seconds" \
        qlinkctl game launch -- "$WORK_DIR/factorio"
}

run_fixture_background() {
    local mode="$1"
    local sleep_seconds="$2"
    env QLINK_FIXTURE_MODE="$mode" QLINK_FIXTURE_SLEEP="$sleep_seconds" \
        qlinkctl game launch -- "$WORK_DIR/factorio" \
        >"$WORK_DIR/$mode.out" 2>"$WORK_DIR/$mode.err" &
    ACTIVE_PID=$!
}

wait_for_fixture() {
    local expected_status="$1"
    local pid="$ACTIVE_PID"
    ACTIVE_PID=""
    if wait "$pid"; then
        actual_status=0
    else
        actual_status=$?
    fi
    [ "$actual_status" -eq "$expected_status" ] || \
        fail "fixture returned $actual_status instead of $expected_status"
}

[ "$MODE" = preflight ] || [ "$MODE" = run ] || { usage; exit 2; }
[ -n "$EVIDENCE_DIR" ] || fail "QLINK_DECK_RUNTIME_EVIDENCE_DIR is required"
[ ! -e "$EVIDENCE_DIR" ] || fail "evidence directory already exists: $EVIDENCE_DIR"
mkdir -p "$(dirname "$EVIDENCE_DIR")"
mkdir -m 0700 "$EVIDENCE_DIR"
require_command qlinkctl
require_command python3
capture_safe_status "$STATUS_BEFORE"
cp "$STATUS_BEFORE" "$STATUS_AFTER"

if ! is_steamos || ! is_steam_deck; then
    write_report fail "SteamOS on Steam Deck hardware is required"
    fail "SteamOS on Steam Deck hardware is required"
fi

validate_runtime_capabilities
RUNTIME_CAPABILITIES=passed

if [ "$MODE" = preflight ]; then
    write_report blocked "runtime capabilities passed; mutation tests were not requested"
    echo "Deck runtime preflight evidence: $EVIDENCE_DIR"
    exit 0
fi

[ "${QLINK_DECK_CONFIRM_NETWORK_MUTATION:-}" = YES ] || \
    fail "set QLINK_DECK_CONFIRM_NETWORK_MUTATION=YES for run mode"
[ "$(id -u)" -ne 0 ] || fail "run mode must use the signed-in desktop user"
require_command systemctl

qlinkctl profile select factorio >/dev/null
qlinkctl service restart >/dev/null
wait_for_classification armed
POLICYKIT_SERVICE_CONTROL=passed

WORK_DIR="$(mktemp -d)"
cat > "$WORK_DIR/game.exe" <<'EOF'
#!/usr/bin/env bash
cat "/proc/$$/cgroup" > "${QLINK_FIXTURE_WORK}/descendant-child-cgroup.txt"
sleep "${QLINK_FIXTURE_SLEEP:-2}"
EOF
cat > "$WORK_DIR/factorio" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mode="${QLINK_FIXTURE_MODE:-native}"
work="${QLINK_FIXTURE_WORK:?}"
cat "/proc/$$/cgroup" > "$work/${mode}-parent-cgroup.txt"
case "$mode" in
    crash) exit 7 ;;
    descendant)
        "$work/game.exe" &
        wait "$!"
        ;;
    *) sleep "${QLINK_FIXTURE_SLEEP:-2}" ;;
esac
EOF
chmod 0755 "$WORK_DIR/factorio" "$WORK_DIR/game.exe"
export QLINK_FIXTURE_WORK="$WORK_DIR"

run_fixture_background native 3
wait_for_classification active
wait_for_file "$WORK_DIR/native-parent-cgroup.txt"
grep -Fq "quantumlink-game-" "$WORK_DIR/native-parent-cgroup.txt"
wait_for_fixture 0
wait_for_classification armed
NATIVE_SCOPE=passed

run_fixture descendant 1
cmp -s "$WORK_DIR/descendant-parent-cgroup.txt" "$WORK_DIR/descendant-child-cgroup.txt"
wait_for_classification armed
DESCENDANT_SCOPE=passed

if run_fixture crash 0; then
    fail "crash fixture returned success"
else
    crash_status=$?
fi
[ "$crash_status" -eq 7 ] || fail "crash fixture returned $crash_status instead of 7"
wait_for_classification armed
CRASH_CLEANUP=passed

run_fixture_background concurrent-primary 4
wait_for_classification active
if run_fixture concurrent-secondary 0; then
    fail "concurrent launch was accepted"
fi
classification_is active || fail "concurrent launch changed the active classification"
wait_for_fixture 0
wait_for_classification armed
CONCURRENT_LAUNCH=passed

run_fixture_background interrupted 60
wait_for_classification active
kill -TERM "$ACTIVE_PID"
wait_for_fixture 143
wait_for_classification armed
INTERRUPTION_CLEANUP=passed

run_fixture_background daemon-restart 4
wait_for_classification active
qlinkctl service restart >/dev/null
wait_for_classification armed
wait_for_fixture 0
DAEMON_RESTART_CLEANUP=passed

capture_safe_status "$STATUS_AFTER"
write_report pass "Deck kernel and game-launch lifecycle qualification passed"
echo "Deck runtime qualification evidence: $EVIDENCE_DIR"
