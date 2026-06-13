#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENDPOINT="${QL_DYTALLIX_ENDPOINT:-https://dytallix.com}"
WORKDIR="${QL_DYTALLIX_WORKDIR:-$ROOT/build/dytallix-live-validation}"
CLI="${QL_DYTALLIX_CLI:-dytallix}"
INSTALL_CLI="${QL_DYTALLIX_INSTALL_CLI:-0}"
MUTATE="${QL_DYTALLIX_MUTATE:-0}"
TRANSFER="${QL_DYTALLIX_VALIDATE_TRANSFER:-0}"
RECIPIENT_DADDR="${QL_DYTALLIX_RECIPIENT_DADDR:-}"
REGISTRY_CONTRACT="${QL_DYTALLIX_REGISTRY_CONTRACT:-}"
REGISTRY_QUERY_METHOD="${QL_DYTALLIX_REGISTRY_QUERY_METHOD:-}"
REGISTRY_QUERY_ARGS="${QL_DYTALLIX_REGISTRY_QUERY_ARGS:-}"
QUANTUMLINK_PEER_ID="${QL_QUANTUMLINK_PEER_ID:-}"

LOGDIR="$WORKDIR/logs"
SUMMARY="$WORKDIR/summary.json"
QL_CONFIG="$WORKDIR/quantumlink-dytallix-public.json"
ISOLATED_HOME="$WORKDIR/home"

log() {
  printf '[dytallix-live] %s\n' "$*"
}

die() {
  printf '[dytallix-live] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

run_logged() {
  local name="$1"
  shift
  log "running $name"
  (
    export HOME="$ISOLATED_HOME"
    export DYTALLIX_ENDPOINT="$ENDPOINT"
    "$@"
  ) >"$LOGDIR/$name.out" 2>"$LOGDIR/$name.err"
}

run_logged_optional() {
  local name="$1"
  shift
  log "running optional $name"
  if ! (
    export HOME="$ISOLATED_HOME"
    export DYTALLIX_ENDPOINT="$ENDPOINT"
    "$@"
  ) >"$LOGDIR/$name.out" 2>"$LOGDIR/$name.err"; then
    printf 'optional command failed; see %s/%s.out and %s/%s.err\n' "$LOGDIR" "$name" "$LOGDIR" "$name" >"$LOGDIR/$name.status"
    log "optional $name failed; continuing"
  fi
}

curl_json() {
  local name="$1"
  local url="$2"
  log "GET $url"
  curl --fail --silent --show-error "$url" >"$LOGDIR/$name.json"
  python3 -m json.tool "$LOGDIR/$name.json" >/dev/null
}

write_summary() {
  local faucet_cli_status="passed"
  if [[ -f "$LOGDIR/faucet-status.status" ]]; then
    faucet_cli_status="failed_without_wallet"
  fi
  python3 - "$SUMMARY" "$ENDPOINT" "$REGISTRY_CONTRACT" "$MUTATE" "$TRANSFER" "$RECIPIENT_DADDR" "$QUANTUMLINK_PEER_ID" "$faucet_cli_status" <<'PY'
import json
import sys
from datetime import datetime, timezone

summary_path, endpoint, registry_contract, mutate, transfer, recipient, peer_id, faucet_cli_status = sys.argv[1:]
summary = {
    "generatedAt": datetime.now(timezone.utc).isoformat(),
    "endpoint": endpoint,
    "readOnlyChecks": [
        "cli-help",
        "chain-status",
        "public-faucet-status-route",
    ],
    "optionalCliFaucetStatus": faucet_cli_status,
    "mutatingChecksEnabled": mutate == "1",
    "transferCheckEnabled": transfer == "1",
    "recipientDAddrProvided": bool(recipient),
    "registryContractProvided": bool(registry_contract),
    "quantumLinkPeerIDProvided": bool(peer_id),
}
with open(summary_path, "w", encoding="utf-8") as fh:
    json.dump(summary, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

write_quantumlink_config() {
  python3 - "$QL_CONFIG" "$ENDPOINT" "$REGISTRY_CONTRACT" "$QUANTUMLINK_PEER_ID" <<'PY'
import json
import sys

path, endpoint, registry_contract, peer_id = sys.argv[1:]
payload = {
    "meshTrustPolicy": "public_required",
    "discoveryIdentityMode": "verified",
    "dytallixIdentity": {
        "endpoint": endpoint,
        "contractAddress": registry_contract,
        "publishWalletAddress": False,
    },
    "quantumLinkPeerID": peer_id or None,
    "notes": [
        "Use this as a validation artifact, not as a production config file.",
        "Public meshes must reject peers without an active Dytallix registry record.",
        "Private/dev meshes may switch meshTrustPolicy to private_preferred or development_optional.",
    ],
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

main() {
  require_cmd curl
  require_cmd python3
  mkdir -p "$LOGDIR" "$ISOLATED_HOME"
  chmod 700 "$ISOLATED_HOME"

  if [[ "$INSTALL_CLI" == "1" ]]; then
    require_cmd cargo
    log "installing dytallix CLI from DytallixHQ/dytallix-sdk"
    cargo install --git https://github.com/DytallixHQ/dytallix-sdk.git dytallix-cli --bin dytallix
  fi

  command -v "$CLI" >/dev/null 2>&1 || die "dytallix CLI not found. Set QL_DYTALLIX_INSTALL_CLI=1 or QL_DYTALLIX_CLI=/path/to/dytallix"

  run_logged cli-help "$CLI" --help
  run_logged config-network-testnet "$CLI" config network testnet
  run_logged config-set-endpoint "$CLI" config set endpoint "$ENDPOINT"
  run_logged chain-status "$CLI" chain status
  run_logged_optional faucet-status "$CLI" faucet status
  curl_json public-faucet-status "${ENDPOINT%/}/api/faucet/status"

  if [[ "$MUTATE" == "1" ]]; then
    run_logged init "$CLI" init
    run_logged wallet-info "$CLI" wallet info
    run_logged balance "$CLI" balance
  else
    log "skipping mutating wallet/faucet flow; set QL_DYTALLIX_MUTATE=1 to enable"
  fi

  if [[ "$TRANSFER" == "1" ]]; then
    [[ "$MUTATE" == "1" ]] || die "transfer validation requires QL_DYTALLIX_MUTATE=1"
    [[ -n "$RECIPIENT_DADDR" ]] || die "transfer validation requires QL_DYTALLIX_RECIPIENT_DADDR"
    run_logged send-dgt "$CLI" send --token dgt "$RECIPIENT_DADDR" 1
    run_logged recipient-balance "$CLI" balance "$RECIPIENT_DADDR"
  else
    log "skipping transfer validation; set QL_DYTALLIX_VALIDATE_TRANSFER=1 and QL_DYTALLIX_RECIPIENT_DADDR to enable"
  fi

  if [[ -n "$REGISTRY_CONTRACT" ]]; then
    run_logged registry-contract-info "$CLI" contract info "$REGISTRY_CONTRACT"
    if [[ -n "$REGISTRY_QUERY_METHOD" ]]; then
      # shellcheck disable=SC2206
      local query_args=( $REGISTRY_QUERY_ARGS )
      run_logged registry-contract-query "$CLI" contract query "$REGISTRY_CONTRACT" "$REGISTRY_QUERY_METHOD" "${query_args[@]}"
    fi
  else
    log "skipping QuantumLink registry contract checks; set QL_DYTALLIX_REGISTRY_CONTRACT to enable"
  fi

  write_summary
  write_quantumlink_config
  log "wrote $SUMMARY"
  log "wrote $QL_CONFIG"
  log "logs are in $LOGDIR"
}

main "$@"
