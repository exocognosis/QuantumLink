# Dytallix Upstream Sources

QuantumLink Dytallix identity integration was reconciled against the active checkout layout at:

- QuantumLinkOS: `b387f17c736160794a798e5a7d3e43cd4fdbdee4`

Official DytallixHQ sources inspected and pinned:

| Repository | Commit | Used for |
|------------|--------|----------|
| `https://github.com/DytallixHQ/dytallix-sdk` | `657d0db4794904f7c25192c9d0c1039c5b9fe5f0` | `dytallix-core` address/key handling, SDK keystore, client, contract call transaction encoding, signed submission, public endpoint defaults |
| `https://github.com/DytallixHQ/dytallix-contracts` | `b4ef4cb0c1a6315e300a756290465d21ab8ed7f8` | WASM contract crate shape, storage/runtime conventions, test layout |
| `https://github.com/DytallixHQ/dytallix-node` | `b6d3b868a4f6103e6fe8f7237efc482c7e3b30de` | public testnet/runtime endpoint assumptions |
| `https://github.com/DytallixHQ/dytallix-docs` | `f980a6bcdf3c629b99fba64dafbf5f18d67b1498` | wallet, address, and developer-facing terminology checks |
| `https://github.com/DytallixHQ/dytallix-pqc` | `7c7906222106b54bf20f0048b5ed20cb1781c5f9` | inspected only; SDK/core primitives were sufficient for this slice |

The active implementation depends on `dytallix-core` and `dytallix-sdk` directly from the official SDK repository at the pinned commit above.

## Reconciliation Notes

The older local worktree at `.worktrees/dytallix-identity-registry` was inspected for prior QuantumLink-specific registry work, but its old `rust/qlink-core` layout was not copied directly. The active implementation was reconciled into the current `qlink-core/`, `macos/`, `windows/`, and `steam/` layout.

Outbound registry verification checks the signed `PeerRecord`, including `peer_id`, device key hash, latest peer-record hash, status, and expiry. Inbound responder verification runs after the signed `InboundIdentityAssertion` crypto check and before any frame is queued; it checks `peer_id`, device key hash, status, and expiry because the inbound assertion does not carry a full `PeerRecord`.

## Registry Privacy Boundary

The QuantumLink registry stores compact authorization records only:

- `peer_id`
- `owner_daddr`
- `device_public_key_hash`
- `latest_peer_record_hash`
- `status`
- `updated_at`
- optional `expires_at`, reputation/staking fields, and metadata commitment

VPN packet data, routes, DNS data, endpoints, timing, and session keys are not written to chain. Platform adapters may configure, store, display, and forward Dytallix policy, but the registry trust decision is owned by shared Rust code in `qlink-core`.
