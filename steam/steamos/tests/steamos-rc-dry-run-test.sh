#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STEAMOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DRY_RUN="$STEAMOS_ROOT/scripts/steamos-rc-dry-run.sh"
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

if bash "$DRY_RUN" --evidence-manifest "$TMP_ROOT/missing.json" --output-dir "$TMP_ROOT/out" >"$TMP_ROOT/no-key.out" 2>"$TMP_ROOT/no-key.err"; then
    fail "expected dry run to require signing material"
fi
assert_contains "$TMP_ROOT/no-key.err" "requires QLINK_STEAMOS_RELEASE_PRIVATE_KEY or QLINK_STEAMOS_SIGNATURE_FILE"

if ! openssl genpkey -algorithm ED25519 -out "$TMP_ROOT/private.pem" >/dev/null 2>&1; then
    echo "steamos-rc-dry-run-test: skipping signed positive path; local OpenSSL lacks ED25519 genpkey support"
    exit 0
fi
openssl pkey -in "$TMP_ROOT/private.pem" -pubout -out "$TMP_ROOT/public.pem" >/dev/null 2>&1

BUNDLE="$TMP_ROOT/bundle"
mkdir -p "$BUNDLE"
python3 - "$BUNDLE" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
(root / "dytallix").mkdir(parents=True, exist_ok=True)
(root / "rendezvous-relay").mkdir(parents=True, exist_ok=True)
metadata = {
    "generatedAt": "2026-07-10T00:00:00Z",
    "status": "pass",
    "dytallix": {
        "status": "pass",
        "registryEndpoint": "https://registry.testnet.dytallix.invalid",
        "networkId": "dytallix-testnet",
        "contract": "quantumlink-node-registry",
        "walletAddressesRedacted": True,
        "rawWalletMaterialCommitted": False,
        "cases": {},
    },
    "rendezvousRelay": {
        "status": "pass",
        "rendezvousEndpoints": ["https://rv.staging.quantumlink.invalid"],
        "relayEndpoints": ["turns:relay.staging.quantumlink.invalid:5349"],
        "abuseLogsRedacted": True,
        "rawPacketPayloadsCommitted": False,
        "rawGamePayloadsCommitted": False,
        "controls": {},
    },
}
expected = {
    "active": "accepted",
    "missing": "rejected",
    "revoked": "rejected",
    "suspended": "rejected",
    "mismatched": "rejected",
    "stale": "rejected",
    "unavailable": "rejected",
}
for case, decision in expected.items():
    evidence = f"dytallix/{case}.json"
    metadata["dytallix"]["cases"][case] = {"observedDecision": decision, "evidence": evidence}
    (root / evidence).write_text(json.dumps({"case": case, "redacted": True}) + "\n", encoding="utf-8")
for control in [
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
]:
    evidence = f"rendezvous-relay/{control}.txt"
    metadata["rendezvousRelay"]["controls"][control] = {"status": "pass", "evidence": evidence}
    (root / evidence).write_text(f"control={control}\nredacted=true\n", encoding="utf-8")
(root / "metadata.json").write_text(json.dumps(metadata, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")
PY

FAKE_BIN="$TMP_ROOT/bin"
mkdir -p "$FAKE_BIN"
for bin in qlinkd qlinkctl; do
    cat > "$FAKE_BIN/$bin" <<'SH'
#!/usr/bin/env bash
echo "fake quantumlink binary"
SH
    chmod 0755 "$FAKE_BIN/$bin"
done

QLINK_STEAMOS_VERSION="9.9.9-rc-dry-run-test" \
QLINK_STEAMOS_BIN_DIR="$FAKE_BIN" \
QLINK_STEAMOS_SKIP_BUILD=1 \
QLINK_STEAMOS_RELEASE_PRIVATE_KEY="$TMP_ROOT/private.pem" \
QLINK_STEAMOS_RELEASE_PUBLIC_KEY="$TMP_ROOT/public.pem" \
    bash "$DRY_RUN" --evidence-root "$BUNDLE" --output-dir "$TMP_ROOT/rc" > "$TMP_ROOT/rc.out" 2>"$TMP_ROOT/rc.err"

REPORT="$TMP_ROOT/rc/package/quantumlink-steamos-9.9.9-rc-dry-run-test/verify-report.json"
assert_json_bool "$REPORT" "valid" "true"
assert_json_bool "$REPORT" "signatureValidated" "true"
assert_json_bool "$REPORT" "nonHardwareProductionEvidenceValidated" "true"
assert_json_bool "$REPORT" "nonHardwareProductionReady" "true"
assert_json_bool "$REPORT" "productionReady" "false"
assert_contains "$TMP_ROOT/rc.out" "SteamOS RC dry run complete"

echo "steamos-rc-dry-run-test: ok"
