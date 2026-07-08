#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STEAMOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VALIDATOR="$STEAMOS_ROOT/tests/deck-validation.sh"
EVIDENCE_VERIFIER="$STEAMOS_ROOT/tests/verify-deck-evidence.sh"
TMP_ROOT="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_json_bool() {
    local file="$1"
    local field="$2"
    local expected="$3"
    python3 - "$file" "$field" "$expected" <<'PY'
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

assert_contains() {
    local file="$1"
    local needle="$2"
    grep -Fq "$needle" "$file" || fail "expected $file to contain: $needle"
}

FAKE_BIN="$TMP_ROOT/bin"
mkdir -p "$FAKE_BIN"

cat > "$FAKE_BIN/qlinkctl" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
    status)
        cat <<'JSON'
{"phase":"idle","activeParty":null,"peers":[],"killSwitch":true}
JSON
        ;;
    doctor)
        echo "qlinkctl doctor fake ok"
        ;;
    *)
        echo "unexpected qlinkctl command: $*" >&2
        exit 2
        ;;
esac
SH
chmod 0755 "$FAKE_BIN/qlinkctl"

cat > "$FAKE_BIN/ip" <<'SH'
#!/usr/bin/env bash
echo "default via 192.0.2.1 dev wlan0"
echo "100.64.0.0/10 dev qlink0"
SH
chmod 0755 "$FAKE_BIN/ip"

cat > "$FAKE_BIN/nft" <<'SH'
#!/usr/bin/env bash
echo "table inet qlink { }"
SH
chmod 0755 "$FAKE_BIN/nft"

cat > "$FAKE_BIN/journalctl" <<'SH'
#!/usr/bin/env bash
echo "qlinkd fake journal"
SH
chmod 0755 "$FAKE_BIN/journalctl"

STEAMOS_FIXTURES="$TMP_ROOT/steamos"
mkdir -p "$STEAMOS_FIXTURES"
cat > "$STEAMOS_FIXTURES/os-release" <<'EOF'
NAME="SteamOS"
ID=steamos
EOF
echo "Steam Deck" > "$STEAMOS_FIXTURES/product_name"
echo "Galileo" > "$STEAMOS_FIXTURES/board_name"

STEAMOS_EVIDENCE="$TMP_ROOT/evidence-steamos"
PATH="$FAKE_BIN:$PATH" \
QLINK_DECK_EVIDENCE_DIR="$STEAMOS_EVIDENCE" \
QLINK_DECK_OS_RELEASE_FILE="$STEAMOS_FIXTURES/os-release" \
QLINK_DECK_PRODUCT_NAME_FILE="$STEAMOS_FIXTURES/product_name" \
QLINK_DECK_BOARD_NAME_FILE="$STEAMOS_FIXTURES/board_name" \
bash "$VALIDATOR" preflight >/dev/null

assert_json_bool "$STEAMOS_EVIDENCE/validation-report.json" "hardwareClaimed" "true"
assert_json_bool "$STEAMOS_EVIDENCE/validation-report.json" "host.isSteamOS" "true"
assert_json_bool "$STEAMOS_EVIDENCE/validation-report.json" "host.isSteamDeckHardware" "true"
assert_contains "$STEAMOS_EVIDENCE/route-leak-check.txt" "Steam account"
assert_contains "$STEAMOS_EVIDENCE/support-bundle-redaction.txt" "Do not commit raw support bundle archives."
QLINK_DECK_REQUIRE_HARDWARE=1 bash "$EVIDENCE_VERIFIER" "$STEAMOS_EVIDENCE" >/dev/null

GENERIC_FIXTURES="$TMP_ROOT/generic"
mkdir -p "$GENERIC_FIXTURES"
cat > "$GENERIC_FIXTURES/os-release" <<'EOF'
NAME="Ubuntu"
ID=ubuntu
EOF
echo "Generic Laptop" > "$GENERIC_FIXTURES/product_name"
echo "Generic Board" > "$GENERIC_FIXTURES/board_name"

GENERIC_EVIDENCE="$TMP_ROOT/evidence-generic"
PATH="$FAKE_BIN:$PATH" \
QLINK_DECK_EVIDENCE_DIR="$GENERIC_EVIDENCE" \
QLINK_DECK_OS_RELEASE_FILE="$GENERIC_FIXTURES/os-release" \
QLINK_DECK_PRODUCT_NAME_FILE="$GENERIC_FIXTURES/product_name" \
QLINK_DECK_BOARD_NAME_FILE="$GENERIC_FIXTURES/board_name" \
bash "$VALIDATOR" preflight >/dev/null

assert_json_bool "$GENERIC_EVIDENCE/validation-report.json" "hardwareClaimed" "false"
assert_json_bool "$GENERIC_EVIDENCE/validation-report.json" "host.isSteamOS" "false"
assert_json_bool "$GENERIC_EVIDENCE/validation-report.json" "host.isSteamDeckHardware" "false"
bash "$EVIDENCE_VERIFIER" "$GENERIC_EVIDENCE" >/dev/null
if QLINK_DECK_REQUIRE_HARDWARE=1 bash "$EVIDENCE_VERIFIER" "$GENERIC_EVIDENCE" >"$TMP_ROOT/generic-require-hardware.out" 2>&1; then
    fail "expected generic evidence to fail when hardware is required"
fi
assert_contains "$TMP_ROOT/generic-require-hardware.out" "hardwareClaimed must be true"

VALVE_FIXTURES="$TMP_ROOT/valve-generic"
mkdir -p "$VALVE_FIXTURES"
cat > "$VALVE_FIXTURES/os-release" <<'EOF'
NAME="SteamOS"
ID=steamos
EOF
echo "Valve Generic Console" > "$VALVE_FIXTURES/product_name"
echo "Valve Generic Board" > "$VALVE_FIXTURES/board_name"

VALVE_EVIDENCE="$TMP_ROOT/evidence-valve-generic"
PATH="$FAKE_BIN:$PATH" \
QLINK_DECK_EVIDENCE_DIR="$VALVE_EVIDENCE" \
QLINK_DECK_OS_RELEASE_FILE="$VALVE_FIXTURES/os-release" \
QLINK_DECK_PRODUCT_NAME_FILE="$VALVE_FIXTURES/product_name" \
QLINK_DECK_BOARD_NAME_FILE="$VALVE_FIXTURES/board_name" \
bash "$VALIDATOR" preflight >/dev/null

assert_json_bool "$VALVE_EVIDENCE/validation-report.json" "hardwareClaimed" "false"
assert_json_bool "$VALVE_EVIDENCE/validation-report.json" "host.isSteamOS" "true"
assert_json_bool "$VALVE_EVIDENCE/validation-report.json" "host.isSteamDeckHardware" "false"

SHORT_EVIDENCE="$TMP_ROOT/evidence-shortened"
mkdir -p "$SHORT_EVIDENCE"
cat > "$SHORT_EVIDENCE/validation-report.json" <<'JSON'
{
  "mode": "preflight",
  "status": "blocked",
  "hardwareClaimed": true,
  "host": {
    "isSteamOS": true,
    "isSteamDeckHardware": true
  },
  "rawPcapCommitted": false,
  "rawSupportBundleCommitted": false,
  "privateMaterialCommitted": false,
  "requiredEvidence": ["validation-report.json"]
}
JSON
if QLINK_DECK_REQUIRE_HARDWARE=1 bash "$EVIDENCE_VERIFIER" "$SHORT_EVIDENCE" >"$TMP_ROOT/shortened-evidence.out" 2>&1; then
    fail "expected shortened requiredEvidence to fail hard-coded evidence checks"
fi
assert_contains "$TMP_ROOT/shortened-evidence.out" "required evidence file is missing: status-before.json"

ABSOLUTE_EVIDENCE="$TMP_ROOT/evidence-absolute-required"
cp -R "$STEAMOS_EVIDENCE" "$ABSOLUTE_EVIDENCE"
python3 - "$ABSOLUTE_EVIDENCE/validation-report.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    report = json.load(handle)
report["requiredEvidence"].append("/etc/hosts")
with open(path, "w", encoding="utf-8") as handle:
    json.dump(report, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY
if bash "$EVIDENCE_VERIFIER" "$ABSOLUTE_EVIDENCE" >"$TMP_ROOT/absolute-required.out" 2>&1; then
    fail "expected absolute requiredEvidence path to fail"
fi
assert_contains "$TMP_ROOT/absolute-required.out" "requiredEvidence entry must be relative"

echo "deck-validation-test passed"
