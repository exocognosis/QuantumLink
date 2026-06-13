#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$ROOT/build/dytallix-identity-e2e"
QLINKCTL="$ROOT/target/debug/qlinkctl"

if [[ -z "${DYTALLIX_ENDPOINT:-}" ]]; then
  echo "error: DYTALLIX_ENDPOINT must be set for networked registry operations" >&2
  exit 2
fi

if [[ -z "${DYTALLIX_REGISTRY_CONTRACT:-}" ]]; then
  echo "error: DYTALLIX_REGISTRY_CONTRACT must be set for networked registry operations" >&2
  exit 2
fi

mkdir -p "$BUILD_DIR"
cd "$ROOT"

echo "Building qlinkctl..."
cargo build -p qlink-core --bin qlinkctl

echo "Building Dytallix registry WASM contract..."
cargo build \
  --manifest-path "$ROOT/dytallix/quantumlink-node-registry/Cargo.toml" \
  --target wasm32-unknown-unknown \
  --release

SEQUENCE="${DYTALLIX_E2E_SEQUENCE:-$(date +%s)}"
KEYFILE="$BUILD_DIR/device-${SEQUENCE}.seed"
REGISTER_OUTPUT="$BUILD_DIR/register.out"
STATUS_OUTPUT="$BUILD_DIR/status.out"
MISSING_STATUS_OUTPUT="$BUILD_DIR/status-missing.out"
DUPLICATE_REGISTER_OUTPUT="$BUILD_DIR/register-duplicate.out"
REVOKE_OUTPUT="$BUILD_DIR/revoke.out"
REVOKED_STATUS_OUTPUT="$BUILD_DIR/status-revoked.out"

registry_write_args=(
  --endpoint "$DYTALLIX_ENDPOINT"
  --contract-address "$DYTALLIX_REGISTRY_CONTRACT"
)

if [[ -n "${DYTALLIX_KEYSTORE_PATH:-}" ]]; then
  registry_write_args+=(--keystore-path "$DYTALLIX_KEYSTORE_PATH")
fi

if [[ -n "${DYTALLIX_WALLET_NAME:-}" ]]; then
  registry_write_args+=(--wallet-name "$DYTALLIX_WALLET_NAME")
fi

registry_lookup_args=(
  --endpoint "$DYTALLIX_ENDPOINT"
  --contract-address "$DYTALLIX_REGISTRY_CONTRACT"
)

echo "Enrolling QuantumLink identity in the Dytallix registry..."
"$QLINKCTL" identity enroll \
  "${registry_write_args[@]}" \
  --keyfile "$KEYFILE" \
  --mesh-id public-mesh \
  --alias dytallix-e2e \
  --address 127.0.0.1 \
  --port 4433 \
  --route 100.127.0.2/32 \
  --ttl-seconds 300 \
  --sequence "$SEQUENCE" \
  2>&1 | tee "$REGISTER_OUTPUT"

PEER_ID="$(awk -F= '/^peer_id=/{ print $2; exit }' "$REGISTER_OUTPUT")"
if [[ -z "$PEER_ID" ]]; then
  echo "error: identity enroll output did not include peer_id=..." >&2
  exit 1
fi

TX_HASH="$(awk -F= '/^tx_hash=/{ print $2; exit }' "$REGISTER_OUTPUT")"
if [[ -z "$TX_HASH" ]]; then
  echo "error: identity enroll output did not include tx_hash=..." >&2
  exit 1
fi

echo "Checking registered QuantumLink identity status..."
"$QLINKCTL" identity status \
  "${registry_lookup_args[@]}" \
  --peer-id "$PEER_ID" \
  2>&1 | tee "$STATUS_OUTPUT"

if ! grep -qx 'found=true' "$STATUS_OUTPUT"; then
  echo "error: identity status did not report found=true for $PEER_ID" >&2
  exit 1
fi

if ! grep -Eq '"status"[[:space:]]*:[[:space:]]*"active"' "$STATUS_OUTPUT"; then
  echo "error: identity status did not report active status for $PEER_ID" >&2
  exit 1
fi

if [[ "${DYTALLIX_E2E_NEGATIVE:-0}" == "1" ]]; then
  ABSENT_PEER_ID="qlink_absent_${SEQUENCE}"

  echo "Checking missing QuantumLink identity status..."
  "$QLINKCTL" identity status \
    "${registry_lookup_args[@]}" \
    --peer-id "$ABSENT_PEER_ID" \
    2>&1 | tee "$MISSING_STATUS_OUTPUT"

  if ! grep -qx 'found=false' "$MISSING_STATUS_OUTPUT"; then
    echo "error: identity status did not report found=false for absent peer $ABSENT_PEER_ID" >&2
    exit 1
  fi

  echo "Checking duplicate QuantumLink identity registration rejection..."
  set +e
  "$QLINKCTL" identity register \
    "${registry_write_args[@]}" \
    --keyfile "$KEYFILE" \
    --mesh-id public-mesh \
    --alias dytallix-e2e \
    --address 127.0.0.1 \
    --port 4433 \
    --route 100.127.0.2/32 \
    --ttl-seconds 300 \
    --sequence "$SEQUENCE" \
    2>&1 | tee "$DUPLICATE_REGISTER_OUTPUT"
  DUPLICATE_STATUS=${PIPESTATUS[0]}
  set -e

  if [[ "$DUPLICATE_STATUS" -eq 0 ]]; then
    echo "error: duplicate identity register unexpectedly succeeded for $PEER_ID" >&2
    exit 1
  fi
  if ! grep -qi 'node already registered' "$DUPLICATE_REGISTER_OUTPUT"; then
    echo "error: duplicate identity register did not report node already registered" >&2
    exit 1
  fi

  echo "Revoking QuantumLink identity in the Dytallix registry..."
  "$QLINKCTL" identity revoke \
    "${registry_write_args[@]}" \
    --peer-id "$PEER_ID" \
    2>&1 | tee "$REVOKE_OUTPUT"

  if ! grep -q '^tx_hash=' "$REVOKE_OUTPUT"; then
    echo "error: identity revoke output did not include tx_hash=..." >&2
    exit 1
  fi

  echo "Checking revoked QuantumLink identity status..."
  "$QLINKCTL" identity status \
    "${registry_lookup_args[@]}" \
    --peer-id "$PEER_ID" \
    2>&1 | tee "$REVOKED_STATUS_OUTPUT"

  if ! grep -qx 'found=true' "$REVOKED_STATUS_OUTPUT"; then
    echo "error: revoked identity status did not report found=true for $PEER_ID" >&2
    exit 1
  fi
  if ! grep -Eq '"status"[[:space:]]*:[[:space:]]*"revoked"' "$REVOKED_STATUS_OUTPUT"; then
    echo "error: revoked identity status did not report revoked status for $PEER_ID" >&2
    exit 1
  fi

  echo "Dytallix identity registry negative e2e verification passed for peer_id=$PEER_ID"
fi

echo "Dytallix identity registry e2e verification passed for peer_id=$PEER_ID"
