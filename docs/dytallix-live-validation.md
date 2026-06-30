# Dytallix Live Validation Runbook

This runbook proves QuantumLink's Dytallix-backed identity path against the
public Dytallix testnet without silently mutating wallets or consuming faucet
quota.

There are two complementary scripts:

- `scripts/dytallix-live-validation.sh` checks the public Dytallix CLI/gateway
  surface and writes a QuantumLink validation config artifact.
- `scripts/dytallix-identity-e2e.sh` is the canonical QuantumLink identity
  enrollment/status path once a funded wallet and registry contract are
  available.

## Scope

The validation pass covers:

- Dytallix CLI availability and public testnet reachability.
- Public faucet policy visibility.
- Isolated wallet bootstrap when explicitly enabled.
- Optional transfer validation to a caller-supplied recipient D-Addr.
- Optional QuantumLink registry contract presence/query checks.
- QuantumLink public/private/dev mesh policy acceptance criteria.
- Diagnostics and support-bundle evidence required before launch.

The default script mode is read-only. Mutating steps require explicit
environment flags.

## Prerequisites

Install Rust and the Dytallix CLI:

```bash
cargo install --git https://github.com/DytallixHQ/dytallix-sdk.git dytallix-cli --bin dytallix
```

Or let the validation script install it:

```bash
QL_DYTALLIX_INSTALL_CLI=1 scripts/dytallix-live-validation.sh
```

The script writes all CLI state under `build/dytallix-live-validation/home` by
setting `HOME` for Dytallix CLI calls. It does not use `~/.dytallix` unless you
override `QL_DYTALLIX_WORKDIR` to point at your real home.

## Read-Only Smoke

```bash
scripts/dytallix-live-validation.sh
```

Expected artifacts:

- `build/dytallix-live-validation/summary.json`
- `build/dytallix-live-validation/quantumlink-dytallix-public.json`
- command logs under `build/dytallix-live-validation/logs/`

The generated QuantumLink validation config includes public-mesh trust pins:

- `networkId`, default `dytallix-testnet`
- `chainId`, default `dytallix-testnet-1`
- `allowedRpcEndpoints`, default `https://dytallix.com`

Override these with `QL_DYTALLIX_NETWORK_ID`, `QL_DYTALLIX_CHAIN_ID`, and
comma-separated `QL_DYTALLIX_ALLOWED_RPC_ENDPOINTS` when validating a different
trusted registry root.

Expected checks:

- `dytallix --help` succeeds.
- `dytallix config network testnet` succeeds in the isolated home.
- `dytallix config set endpoint https://dytallix.com` succeeds.
- `dytallix chain status` succeeds.
- `dytallix faucet status` succeeds.
- `GET https://dytallix.com/api/faucet/status` returns valid JSON.

## Wallet And Faucet Smoke

This creates a test wallet and may consume public faucet quota:

```bash
QL_DYTALLIX_MUTATE=1 scripts/dytallix-live-validation.sh
```

Expected checks:

- `dytallix init` creates the default wallet.
- `dytallix wallet info` prints the active wallet.
- `dytallix balance` shows DGT and DRT balances or a faucet cooldown state that
  matches the public faucet policy.

## Transfer Smoke

Use a separate recipient address. Do not self-send.

```bash
QL_DYTALLIX_MUTATE=1 \
QL_DYTALLIX_VALIDATE_TRANSFER=1 \
QL_DYTALLIX_RECIPIENT_DADDR=dyt1... \
scripts/dytallix-live-validation.sh
```

Expected checks:

- `dytallix send --token dgt <recipient> 1` submits a transaction.
- `dytallix balance <recipient>` succeeds after submission.

## QuantumLink Registry Contract Checks

Public mesh launch validation requires a deployed QuantumLink node-registry
contract address.

```bash
QL_DYTALLIX_REGISTRY_CONTRACT=<contract-address> \
scripts/dytallix-live-validation.sh
```

Current public validation contract:

```bash
QL_DYTALLIX_REGISTRY_CONTRACT=0x60e5c1a57ef0d3ccfe56d8641e50cc35532bb592 \
scripts/dytallix-live-validation.sh
```

Optional query check:

```bash
QL_DYTALLIX_REGISTRY_CONTRACT=<contract-address> \
QL_DYTALLIX_REGISTRY_QUERY_METHOD=<method> \
QL_DYTALLIX_REGISTRY_QUERY_ARGS="<arg1> <arg2>" \
scripts/dytallix-live-validation.sh
```

The script always writes `quantumlink-dytallix-public.json`, which captures the
endpoint, contract address, public-required mesh policy, and optional
QuantumLink peer ID under test.

## QuantumLink Identity Enrollment E2E

After the public Dytallix smoke succeeds, run the existing QuantumLink identity
e2e script with a funded throwaway wallet:

```bash
source config/dytallix.public.env

export DYTALLIX_ENDPOINT=https://dytallix.com
export DYTALLIX_REGISTRY_CONTRACT=0x60e5c1a57ef0d3ccfe56d8641e50cc35532bb592
export DYTALLIX_KEYSTORE_PATH="$PWD/build/dytallix-testnet/keystore.json"
export DYTALLIX_WALLET_NAME=quantumlink-testnet-ci
export DYTALLIX_E2E_SEQUENCE="$(date +%s)"

scripts/dytallix-identity-e2e.sh
```

Expected checks:

- `qlinkctl identity enroll` emits `peer_id=...`.
- Enrollment emits `tx_hash=...`.
- `qlinkctl identity status` returns `found=true`.
- If the status payload includes a lifecycle state, it is `active`.

Use only throwaway testnet wallets in CI. Keep generated keystores under
`build/` or `$RUNNER_TEMP`, and revoke or rotate test records when the test
contract supports cleanup.

## QuantumLink Product Acceptance

Run these checks after the Dytallix smoke passes and a registry contract is
available.

### Public Mesh

Required behavior:

- `meshTrustPolicy` is `public_required`.
- `discoveryIdentityMode` is `verified` or `public_wallet`.
- Runtime `dytallixIdentity` includes pinned `networkId`, `chainId`, and
  `allowedRpcEndpoints`.
- Missing registry record is rejected.
- Revoked registry record is rejected.
- Expired registry record is rejected.
- Registry binding mismatch is rejected.
- Successful registry record produces a verified peer state.

Required evidence:

- Peers view shows verified/rejected trust badges.
- Security view shows public mesh enforcement.
- Diagnostics includes Dytallix verified, pending, unverified, failed, and
  blocked-history counts.
- Support bundle includes `peers` and `blockedPeers` entries for the rejected
  peer.

### Private Mesh

Required behavior:

- `meshTrustPolicy` is `private_preferred`.
- Valid Dytallix records are verified when present.
- Missing registry record does not block private/dev connectivity.
- UI clearly labels accepted-without-registry peers as not publicly verified.

### Development Mesh

Required behavior:

- `meshTrustPolicy` is `development_optional`.
- `discoveryIdentityMode` may be `off`.
- No wallet or registry contract is required.
- Key rotation is allowed unless an active registered peer ID is present.

## Pass Criteria

A launch validation pass requires:

- Read-only Dytallix smoke passes.
- Wallet/faucet smoke passes or records a documented cooldown/rate-limit state.
- Registry contract address is supplied and `contract info` succeeds.
- Public mesh rejects all negative registry states.
- Private/dev meshes remain usable under optional identity policy.
- Diagnostics and support bundles contain enough evidence to explain every
  rejected peer without packet captures.
