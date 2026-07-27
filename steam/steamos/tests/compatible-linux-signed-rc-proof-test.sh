#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIGNED_RC_TEST="$SCRIPT_DIR/steamos-rc-dry-run-test.sh"
TMP_ROOT="$(mktemp -d)"
OUTPUT="$TMP_ROOT/signed-rc-test.out"

cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

if [ "$(uname -s)" != "Linux" ]; then
    echo "compatible-linux-signed-rc-proof-test: skipped on non-Linux host"
    exit 0
fi

if ! bash "$SIGNED_RC_TEST" >"$OUTPUT" 2>&1; then
    cat "$OUTPUT" >&2
    fail "SteamOS signed RC positive path failed"
fi

cat "$OUTPUT"

if grep -Fq "skipping signed positive path" "$OUTPUT"; then
    fail "compatible-Linux CI must support ephemeral Ed25519 key generation"
fi

grep -Fq "steamos-rc-dry-run-test: ok" "$OUTPUT" \
    || fail "SteamOS signed RC positive path did not complete"

echo "compatible-linux-signed-rc-proof-test: ok"
