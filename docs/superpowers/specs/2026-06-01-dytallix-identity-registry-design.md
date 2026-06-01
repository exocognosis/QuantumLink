# Dytallix Identity Registry Design

## Summary

QuantumLink will anchor public mesh node identity to Dytallix while keeping private and development meshes usable without mandatory chain access. The Dytallix registry becomes a decentralized trust and discovery-adjacent layer: it proves that a persistent wallet owns or authorizes a QuantumLink node identity, exposes optional public operator identity, and gives peers a stable place to verify status, reputation, and future staking eligibility. VPN traffic remains encrypted, off-chain, and peer-to-peer.

The first implementation should enforce Dytallix registration for public meshes, prefer but not require it for private meshes, and keep it optional for development meshes.

## Goals

- Persist node accountability across sessions without rotating away trust.
- Bind an existing QuantumLink PQC device identity to a Dytallix wallet.
- Let public mesh peers reject unregistered, revoked, or mismatched identities before dialing.
- Avoid broadcasting wallet addresses by default when privacy-preserving verification is enough.
- Leave room for later zero-knowledge or commitment-based identity proofs without blocking the MVP.

## Non-Goals

- Put VPN packet metadata, traffic, routes, or session keys on-chain.
- Require Dytallix staking writes before those Dytallix paths are production-ready.
- Replace QuantumLink signed peer records or inbound identity assertions.
- Implement full zero-knowledge proofs in the first pass.

## User Policy

QuantumLink will add an explicit trust policy derived from mesh type:

| Mesh type | Registry behavior | Connection behavior |
| --- | --- | --- |
| Public | Required | Reject peers without an active matching Dytallix registry entry. |
| Private | Preferred | Accept valid QuantumLink peers, but show warnings and diagnostics when registry verification is missing or stale. |
| Development | Optional | Do not require registry verification; support mock/local registry tests. |

The app UX will expose a discovery identity control:

| Mode | Meaning |
| --- | --- |
| Off | Do not use Dytallix identity for discovery. Intended for dev and fully private meshes. |
| Verified | Prove registry status through lookup or proof, but do not publish the wallet address in rendezvous records. This is the default for public meshes. |
| Public Wallet | Publish the Dytallix wallet address in the discovery record for public operator identity, staking visibility, and reputation. |

Public meshes must not allow `Off`. The app should either disable that option for public meshes or require the user to switch the mesh type to private/development before disabling Dytallix identity.

The term "ZK ID mode" should be reserved for the later privacy-preserving proof mode. In the MVP, "Verified" is registry-backed but not zero-knowledge.

## Registry Data Model

The Dytallix contract stores compact identity records keyed by QuantumLink `peer_id`:

```text
peer_id: string
owner_daddr: string
device_public_key_hash: bytes32
latest_peer_record_hash: bytes32
status: active | revoked | suspended
reputation_score: u64
stake_status: optional enum/string
updated_at: u64
expires_at: optional u64
metadata_commitment: optional bytes32
```

The contract does not store raw peer endpoints, hostnames, route lists, packet data, or session material. The `latest_peer_record_hash` lets peers bind a short-lived rendezvous record to the persistent Dytallix registration without copying the whole record on-chain.

## Registration Flow

1. QuantumLink install or enrollment loads or creates a persistent Dytallix wallet.
2. QuantumLink loads or creates the existing ML-DSA device key through `DeviceKeypairStore`.
3. The Rust core derives the existing `peer_id` from the device public key.
4. QuantumLink builds a registration payload containing `peer_id`, `device_public_key_hash`, `latest_peer_record_hash`, selected visibility mode, and timestamps.
5. The device key signs a binding statement so wallet ownership and device ownership are both represented.
6. The Dytallix wallet submits a registry contract call.
7. QuantumLink caches the resulting registry status for diagnostics and offline tolerance.

The wallet private key remains in the Dytallix keystore or a future Keychain-backed wrapper. The QuantumLink device private key remains in the existing macOS Keychain-backed path.

## Discovery And Connection Flow

For every discovered peer:

1. Fetch the signed QuantumLink `PeerRecord` from rendezvous or cache.
2. Verify the peer record signature, expiry, mesh ID, and `peer_id` to public-key binding.
3. Compute `device_public_key_hash` and `record_hash`.
4. Evaluate the mesh trust policy.
5. Query the Dytallix registry or use a fresh cached registry proof.
6. In public meshes, require:
   - registry entry exists
   - status is `active`
   - `peer_id` matches
   - `device_public_key_hash` matches
   - `latest_peer_record_hash` matches or is within the accepted freshness policy
   - optional staking/reputation threshold passes when configured
7. Only after registry policy passes should QuantumLink dial QUIC/PQC transport and complete the existing inbound identity assertion.

Private meshes follow the same verification path when available, but they do not fail closed unless configured to require Dytallix registration.

## Components

### Dytallix Contract

Add a `quantumlink-node-registry` WASM contract in the Dytallix contracts repo or an adjacent contract package. It should support:

- `register_node(record, device_signature)`
- `update_node(record, device_signature)`
- `revoke_node(peer_id)`
- `get_node(peer_id)`
- `events(peer_id)`

Registration and updates must be authorized by the Dytallix wallet transaction signer. Device signatures prove that the wallet controls or authorizes the QuantumLink node key.

### QuantumLink Rust Core

Add a registry abstraction:

```text
trait IdentityRegistry {
    fn lookup(peer_id) -> RegistryRecord
    fn register(local_identity) -> RegistrationReceipt
    fn verify_binding(peer_record, policy) -> RegistryDecision
}
```

Implementations:

- `MockIdentityRegistry` for tests and dev meshes.
- `DytallixIdentityRegistry` using `dytallix-sdk` for contract query/call flows.

The verifier should live near discovery and peer connection code, not inside packet encryption. This keeps identity policy separate from the data plane.

### Swift App And Tunnel Integration

The app owns user-visible enrollment state:

- wallet present or missing
- registry status
- discovery identity mode
- public/private/dev policy
- last registry verification result

The tunnel/runtime receives only the validated policy and registry configuration needed to enforce connection decisions. It should not own wallet secrets.

## Privacy

Default public behavior is "Verified", not "Public Wallet". Public meshes require chain-backed eligibility, but rendezvous records do not need to include `owner_daddr` unless the user opts into public operator identity.

Future ZK-capable behavior can replace direct wallet lookup with a rotating commitment or nullifier:

```text
prove registered-and-active(peer_id, epoch, policy) without revealing owner_daddr
```

The MVP should name this as future work and avoid claiming zero-knowledge privacy before proofs exist.

## Error Handling

Public meshes fail closed for registry errors unless a configured grace period permits a fresh cached proof. Private meshes warn and continue by default. Development meshes continue without registry verification.

Decision states:

- `accepted`
- `accepted_without_registry_private`
- `rejected_missing_registry`
- `rejected_revoked`
- `rejected_suspended`
- `rejected_key_mismatch`
- `rejected_record_hash_mismatch`
- `rejected_stake_or_reputation`
- `registry_unavailable`

Diagnostics must avoid leaking wallet addresses unless Public Wallet mode is enabled or the user explicitly opens detailed diagnostics.

## Testing

Rust tests:

- public policy rejects missing registry entries
- public policy rejects revoked or suspended records
- public policy rejects public key hash mismatch
- public policy rejects peer record hash mismatch
- private policy warns but accepts when the QuantumLink peer record is valid
- dev policy bypasses registry
- mock registry exercises registration, update, revoke, and lookup

Swift tests:

- policy mapping from mesh type and UX mode
- enrollment status rendering
- configuration encoding for tunnel/runtime
- wallet address redaction outside Public Wallet mode

Integration tests:

- local mock registry with signed peer records
- Dytallix SDK-backed client tests behind an opt-in network flag
- contract schema compatibility tests for register/update/revoke/query

## Rollout

1. Add the contract model and mock verifier.
2. Enforce policy in Rust connection decisions with mock registry tests.
3. Add Dytallix SDK-backed client and contract query support.
4. Add registration/update contract calls.
5. Add Swift enrollment and discovery identity UX.
6. Enable public mesh fail-closed behavior.
7. Add optional staking and reputation checks after the Dytallix staking/write paths are stable.
