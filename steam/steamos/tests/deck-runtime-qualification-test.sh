#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/deck-runtime-qualification.sh"
VERIFIER="$SCRIPT_DIR/verify-deck-runtime-evidence.sh"
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
    grep -Fq "$2" "$1" || fail "expected $1 to contain: $2"
}

FAKE_BIN="$TMP_ROOT/bin"
FIXTURES="$TMP_ROOT/fixtures"
mkdir -p "$FAKE_BIN" "$FIXTURES"

cat > "$FAKE_BIN/qlinkctl" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" != status ]; then
    echo "unexpected mutation command: $*" >&2
    exit 2
fi
cat <<'JSON'
{
  "phase": "connected",
  "network": {"state": "applied", "dryRun": false, "ownershipRecordPresent": true},
  "dataPlane": {"state": "ready", "packetIoAvailable": true},
  "gameProfile": {"processClassification": {"state": "armed"}},
  "runtimeCapabilities": {
    "cgroupV2": {"state": "supported", "detail": null},
    "nftablesCgroupV2": {"state": "supported", "detail": null},
    "tun": {"state": "supported", "detail": null},
    "systemdUserScopes": {"state": "supported", "detail": null},
    "policykit": {"state": "supported", "detail": null},
    "logindSession": {"state": "supported", "detail": null}
  }
}
JSON
EOF
chmod 0755 "$FAKE_BIN/qlinkctl"

cat > "$FIXTURES/os-release" <<'EOF'
NAME="SteamOS"
ID=steamos
EOF
echo "Steam Deck" > "$FIXTURES/product_name"
echo "Galileo" > "$FIXTURES/board_name"

PREFLIGHT="$TMP_ROOT/preflight"
PATH="$FAKE_BIN:$PATH" \
QLINK_DECK_RUNTIME_EVIDENCE_DIR="$PREFLIGHT" \
QLINK_DECK_OS_RELEASE_FILE="$FIXTURES/os-release" \
QLINK_DECK_PRODUCT_NAME_FILE="$FIXTURES/product_name" \
QLINK_DECK_BOARD_NAME_FILE="$FIXTURES/board_name" \
bash "$RUNNER" preflight >/dev/null

bash "$VERIFIER" "$PREFLIGHT" >/dev/null
if QLINK_DECK_RUNTIME_REQUIRE_COMPLETE=1 bash "$VERIFIER" "$PREFLIGHT" \
    >"$TMP_ROOT/incomplete.out" 2>&1; then
    fail "preflight evidence passed the complete runtime gate"
fi
assert_contains "$TMP_ROOT/incomplete.out" "complete evidence requires mode=run and status=pass"

NO_CONFIRM="$TMP_ROOT/no-confirm"
if PATH="$FAKE_BIN:$PATH" \
    QLINK_DECK_RUNTIME_EVIDENCE_DIR="$NO_CONFIRM" \
    QLINK_DECK_OS_RELEASE_FILE="$FIXTURES/os-release" \
    QLINK_DECK_PRODUCT_NAME_FILE="$FIXTURES/product_name" \
    QLINK_DECK_BOARD_NAME_FILE="$FIXTURES/board_name" \
    bash "$RUNNER" run >"$TMP_ROOT/no-confirm.out" 2>&1; then
    fail "run mode changed state without explicit confirmation"
fi
assert_contains "$TMP_ROOT/no-confirm.out" \
    "set QLINK_DECK_CONFIRM_NETWORK_MUTATION=YES for run mode"

COMPLETE="$TMP_ROOT/complete"
cp -R "$PREFLIGHT" "$COMPLETE"
python3 - "$COMPLETE/runtime-report.json" <<'PY'
import json
import sys

path = sys.argv[1]
report = json.load(open(path, encoding="utf-8"))
report["mode"] = "run"
report["status"] = "pass"
for name in report["checks"]:
    report["checks"][name] = "passed"
with open(path, "w", encoding="utf-8") as output:
    json.dump(report, output, indent=2, sort_keys=True)
    output.write("\n")
PY
QLINK_DECK_RUNTIME_REQUIRE_COMPLETE=1 bash "$VERIFIER" "$COMPLETE" >/dev/null

UNSUPPORTED="$TMP_ROOT/unsupported"
cp -R "$COMPLETE" "$UNSUPPORTED"
python3 - "$UNSUPPORTED/runtime-report.json" <<'PY'
import json
import sys

path = sys.argv[1]
report = json.load(open(path, encoding="utf-8"))
report["runtimeCapabilities"]["nftablesCgroupV2"] = {
    "state": "unsupported", "detail": "fixture"
}
with open(path, "w", encoding="utf-8") as output:
    json.dump(report, output, indent=2, sort_keys=True)
    output.write("\n")
PY
if bash "$VERIFIER" "$UNSUPPORTED" >"$TMP_ROOT/unsupported.out" 2>&1; then
    fail "unsupported nftables capability passed verification"
fi
assert_contains "$TMP_ROOT/unsupported.out" \
    "runtime capability is not supported: nftablesCgroupV2"

GENERIC="$TMP_ROOT/generic"
echo 'NAME="Arch Linux"' > "$FIXTURES/generic-os-release"
echo 'ID=arch' >> "$FIXTURES/generic-os-release"
echo "Generic PC" > "$FIXTURES/generic-product"
echo "Generic Board" > "$FIXTURES/generic-board"
if PATH="$FAKE_BIN:$PATH" \
    QLINK_DECK_RUNTIME_EVIDENCE_DIR="$GENERIC" \
    QLINK_DECK_OS_RELEASE_FILE="$FIXTURES/generic-os-release" \
    QLINK_DECK_PRODUCT_NAME_FILE="$FIXTURES/generic-product" \
    QLINK_DECK_BOARD_NAME_FILE="$FIXTURES/generic-board" \
    bash "$RUNNER" preflight >"$TMP_ROOT/generic.out" 2>&1; then
    fail "generic host passed Deck runtime preflight"
fi
assert_contains "$TMP_ROOT/generic.out" "SteamOS on Steam Deck hardware is required"
if bash "$VERIFIER" "$GENERIC" >"$TMP_ROOT/generic-verify.out" 2>&1; then
    fail "generic host evidence passed verification"
fi
assert_contains "$TMP_ROOT/generic-verify.out" "hardwareClaimed must be true"

echo "deck-runtime-qualification-test passed"
