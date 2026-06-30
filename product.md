# QuantumLink Product Specification

Updated: 2026-06-28

## Executive summary

QuantumLink is a cross-platform, post-quantum mesh VPN product built around a
shared Rust protocol core and native platform silos for macOS, Windows, and the
Steam/SteamOS gamer track. The product is not a conventional hub-and-spoke VPN
and should not be specified as a literal "serverless" network. The correct
product boundary is:

**No mandatory centralized VPN concentrator in the steady-state data plane, with
server-minimized helper services for discovery, NAT traversal, relay fallback,
updates, and future paid access.**

The traffic path is peer-to-peer or relay-assisted, end-to-end encrypted, and
off-chain. Identity and authorization are verified before peers are allowed to
participate in a public mesh. The product promise is therefore:

**Identity on-chain. Traffic off-chain. Access accountless. Transport
server-minimized.**

The refreshed product direction adds a first-class **on-chain identity
verification** feature backed by Dytallix. Public meshes require a live,
matching Dytallix registry entry before dialing or accepting a peer. Private
meshes can warn and continue when registry status is missing. Development
meshes can disable registry enforcement entirely. This gives QuantumLink a
decentralized trust layer without putting packet data, routes, DNS, peer
endpoints, or session keys on-chain.

QuantumLink is source-ready for local protocol, client, packaging, and platform
development. It is not yet a production VPN bundle. Production release still
requires platform signing, Apple Network Extension entitlement approval for
macOS, hardened public rendezvous/relay infrastructure, production peer-session
key installation into packet-frame encryption, release update signing, and
real-hardware validation across supported platforms.

## Product goals

QuantumLink should optimize for five durable product outcomes:

- Secure device-to-device reachability without a mandatory traffic concentrator.
- Strong peer identity that can survive device restarts, network changes, and
  public mesh discovery.
- Post-quantum session establishment and crypto-agile protocol boundaries.
- Privacy-preserving defaults for discovery, diagnostics, relay use, and
  support bundles.
- Native OS integration instead of a lowest-common-denominator VPN wrapper.

The product should be explained as a private connectivity substrate, not as an
anonymous browsing product. QuantumLink is for remote access, small-team mesh
networking, private development infrastructure, secure device fleets, and
game-aware low-latency routing. It should not promise anonymity, region
evasion, traffic laundering, or unrestricted export until those claims have
legal and technical backing.

## Product pillars

### Post-quantum mesh data plane

QuantumLink's shared core owns ML-KEM-768 session establishment, ML-DSA-65
device credentials, SLH-DSA-SHAKE-128S support for the FIPS 205 path,
SHAKE256 transcript binding, SHAKE256 directional derivation, app-layer PQC
frame protection, and monotonic replay protection.

The legacy hybrid X25519/ML-KEM suite identifier is intentionally rejected. The
v1 direction is post-quantum session establishment without a classical
key-exchange fallback. Any future hybrid or standards-track transition must be
explicitly versioned and tested instead of implied by documentation.

### Server-minimized control plane

The control plane is layered:

- Signed, expiring peer records carry peer identity, device public key, routes,
  endpoint candidates, ICE credentials, QUIC certificate material, expiration,
  and sequence number.
- Rendezvous services publish and look up short-lived peer records.
- ICE/STUN helpers support candidate validation and direct path selection.
- Relay services provide fallback when direct paths fail.
- Peer stores cache verified records for graceful degradation when rendezvous
  is unavailable.

The development rendezvous and relay services in this repository are not
hardened public infrastructure by themselves. A production deployment needs
authentication policy, abuse controls, TLS, monitoring, durable revocation,
retention controls, and operational runbooks.

### On-chain identity verification

Dytallix-backed identity is a first-class product feature. It binds a
QuantumLink peer identity to an on-chain registry record so public mesh peers
can reject unregistered, revoked, suspended, or mismatched identities before
transport setup.

The identity layer is discovery-adjacent, not packet-path infrastructure. It
does not route traffic, decrypt traffic, inspect DNS, hold session keys, or
store raw peer endpoints. The default public mode proves eligibility without
publishing the wallet address in rendezvous records.

### Accountless commercial access

QuantumLink should not require a QuantumLink username/password account to unlock
future paid access. The paid-access model should be a signed cryptographic
entitlement bound to an opaque subject, such as a Dytallix wallet hash or
QuantumLink device public key hash.

Billing may issue or verify entitlement proofs, but billing must not enter the
VPN transport path. It must not see peer IDs, routes, DNS queries, packet
metadata, session keys, or mesh traffic. Product language should use
"accountless access" and "billing outside the transport path," not stronger
claims such as anonymous payment unless the implementation actually delivers
that property.

### Native platform silos

All platform clients use the same protocol core:

- macOS uses SwiftUI, Network Extension, Keychain, XcodeGen, MDM payloads, and
  Apple signing/notarization flows.
- Windows uses a privileged Rust service, Wintun, WFP kill switch, DPAPI,
  named-pipe IPC, WinUI 3, and WiX packaging.
- Steam/SteamOS is a gamer-focused product track with game-aware routing,
  Steam-safe bypass policy, streamer/privacy modes, and low-latency goals.

There should be no separate macOS protocol, Windows protocol, or Steam protocol.
Each silo wraps the shared mesh engine with OS-specific UI, privilege, tunnel,
packaging, and release mechanics.

## Target users and use cases

The highest-value users are:

- Technical individuals and small teams connecting laptops, home labs, NAS
  devices, workstations, and private services without operating a gateway VPN.
- Security-conscious SMB and mid-market IT teams that want mesh connectivity,
  device-bound policy, and clear trust diagnostics without deploying a full
  SD-WAN stack.
- Managed enterprise environments that need per-app VPN, SSO, device
  attestation, enrollment policy, and signed release artifacts.
- Gamers and streamers who need Steam-safe, low-latency connectivity for
  trusted peers without routing store, wallet, checkout, or account-security
  traffic through the tunnel.

V1 should focus on remote development access, private service reachability,
point-to-point administration, small-site networking, and team/fleet mesh
connectivity. V1 should not chase full Ethernet bridging, anonymous browsing,
consumer geo-evasion, or full enterprise ZTNA orchestration.

## Current implementation snapshot

This specification reflects the active repository, especially `qlink-core`,
`macos/`, `windows/`, and `steam/`.

Implemented or scaffolded behavior includes:

- ML-KEM-768 three-message session establishment.
- ML-DSA-65 device credentials by default.
- SLH-DSA-SHA2-128S signing and verification for the FIPS 205 suite path.
- SHAKE256 transcript binding and SHAKE256 directional key derivation.
- Signed, expiring peer records.
- App-layer PQC frame protection with replay rejection for direct mesh links.
- Packet core framing and metadata normalization; the packet core is not a
  classical encryption boundary.
- Native UDP carrier session-wire test coverage; default live mesh dialing
  fails closed until rendezvous publication and direct probing are wired to the
  native UDP carrier.
- Optional dev-only QUIC DATAGRAM carrier transport behind `dev-quic-carrier`,
  rendezvous lookup, direct probes, optional ICE, relay fallback, peer-store
  persistence, per-peer state, and network-event reconnect behavior.
- macOS SwiftUI app, `NEPacketTunnelProvider` scaffold, `QuantumLinkKit`,
  Keychain-backed identity paths, MDM payload templates, XcodeGen project, and
  packaging/release scripts.
- Windows service, Wintun/WFP direction, DPAPI secret storage, named-pipe IPC,
  WinUI 3 surface, WiX packaging, and beta runbook.
- Steam/SteamOS product and policy planning surfaces.

Production gaps include:

- Apple-granted Network Extension entitlements and production provisioning.
- Developer ID signing, notarization, stapling, and Gatekeeper validation.
- Wiring live rendezvous publication and direct probing to the native UDP
  carrier.
- Full ICE/STUN/TURN candidate gathering and nomination for direct and relay
  path selection.
- Hardened public rendezvous and relay infrastructure.
- Signed Sparkle/platform update pipeline paired with a post-quantum release
  manifest layer.
- Production Dytallix mainnet or hardened registry trust root for public
  identity enforcement.
- Real-hardware, multi-platform release validation.

## On-chain identity verification

### Feature definition

On-chain identity verification binds a QuantumLink peer record to a Dytallix
registry entry. The registry proves that a Dytallix wallet owns or authorizes a
QuantumLink device identity. QuantumLink peers use that registry state as a
connection policy input before dialing, accepting, or publishing into public
mesh infrastructure.

The feature must preserve this split:

- The Dytallix registry verifies persistent identity, status, and optional
  reputation or staking policy.
- QuantumLink signed peer records verify fresh discovery and transport
  information.
- QuantumLink inbound identity assertions verify that the connected endpoint is
  the peer that was authorized.
- Packet encryption remains local to the QuantumLink transport and never
  depends on the chain for packet handling.

### Identity modes

| Mode | Meaning | Intended use |
|---|---|---|
| `Off` | Do not use Dytallix identity for discovery or peer policy. | Development meshes and fully private meshes. |
| `Verified` | Verify active registry status without publishing the wallet address in rendezvous records. | Default for public meshes. |
| `Public Wallet` | Publish the Dytallix wallet address in the discovery record for operator identity, reputation, or staking visibility. | Public operators who intentionally want visible identity. |

Public meshes must not allow `Off`. The app should disable that option for
public meshes or require the user to switch the mesh type to private or
development before disabling registry verification.

The term "ZK ID" is reserved for a later proof mode. The MVP `Verified` mode is
registry-backed and privacy-preserving by minimization and redaction, but it is
not zero-knowledge unless a real proof system is implemented.

### Mesh trust policy

| Mesh type | Registry behavior | Connection behavior |
|---|---|---|
| Public | Required | Reject peers without an active matching Dytallix registry entry. |
| Private | Preferred | Accept valid QuantumLink peers, but warn when registry verification is missing, stale, or unavailable. |
| Development | Optional | Do not require registry verification; if enabled, use the same real Dytallix path as other mesh types. |

Public policy should fail closed for missing, revoked, suspended, mismatched, or
unavailable registry state unless a narrowly configured cached-proof grace
period is active.

### Registry data model

The Dytallix contract should store compact identity records keyed by
QuantumLink `peer_id`:

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

The contract must not store raw peer endpoints, hostnames, route lists, DNS
activity, packet data, packet timing, relay paths, or session material.
`latest_peer_record_hash` binds a short-lived rendezvous record to persistent
registration without copying the whole peer record on-chain.

### Enrollment flow

1. QuantumLink loads or creates a persistent Dytallix wallet through the real
   Dytallix wallet or SDK path.
2. QuantumLink loads or creates the existing ML-DSA device identity through the
   platform secret store.
3. The Rust core derives the QuantumLink `peer_id` from the device public key.
4. QuantumLink builds a registration payload containing `peer_id`,
   `device_public_key_hash`, `latest_peer_record_hash`, selected identity mode,
   and timestamps.
5. The device key signs a binding statement so device ownership and wallet
   ownership are both represented.
6. The Dytallix wallet submits the registry contract call.
7. QuantumLink caches registry status and proof freshness for diagnostics and
   offline tolerance.

Wallet secrets stay in the Dytallix keystore or a future Keychain-backed wallet
wrapper. QuantumLink device private keys stay in the platform secret store.
The tunnel/runtime receives only validated policy and registry configuration; it
must not own wallet secrets.

### Verification flow

For every discovered peer:

1. Fetch the signed QuantumLink `PeerRecord` from rendezvous or peer-store
   cache.
2. Verify the peer record signature, expiry, mesh ID, sequence number, and
   public-key binding.
3. Compute `device_public_key_hash` and `latest_peer_record_hash`.
4. Evaluate the mesh trust policy.
5. Query the Dytallix registry or use a fresh cached registry proof.
6. For public meshes, require an active record with matching `peer_id`, matching
   device public key hash, matching or policy-fresh peer record hash, and any
   configured reputation/staking threshold.
7. Start the QuantumLink carrier and app-layer PQC session only after registry
   policy passes.
8. Complete the existing inbound identity assertion before accepting traffic.

Rejected peers should produce operator-readable reasons such as
`rejected_missing_registry`, `rejected_revoked`, `rejected_suspended`,
`rejected_key_mismatch`, `rejected_record_hash_mismatch`,
`rejected_stake_or_reputation`, and `registry_unavailable`.

### UX requirements

The app should expose identity state in operational terms:

- Wallet present or missing.
- Registry endpoint and contract.
- Mesh trust policy.
- Identity mode: `Off`, `Verified`, or `Public Wallet`.
- Current registry status.
- Last successful verification time.
- Last rejection reason.
- Whether the wallet address is hidden or intentionally published.

The default public display should show "Verified" without exposing
`owner_daddr`. Raw wallet addresses should appear only in `Public Wallet` mode,
explicit detailed diagnostics, or operator-approved support export.

## Accountless entitlements and access gates

Paid access is future-state architecture and should not be framed as active beta
charging. The correct model is to charge for a cryptographic entitlement, not
for a QuantumLink login.

A signed entitlement should contain only the minimum required fields:

```text
entitlement_id
subject
plan
features
issued_at
expires_at
max_devices
signing_key_id
signature
```

The `subject` should be opaque, such as a hash of a Dytallix wallet or a
QuantumLink device public key. It should not contain email, peer routes, DNS
activity, endpoint candidates, packet metadata, or session keys.

Access gates should be product-layer gates:

- App gate: unlock paid UI and profile creation only when an entitlement is
  active.
- Rendezvous gate: require active entitlement before public paid mesh
  publication.
- Relay gate: require active entitlement before hosted relay allocation or paid
  bandwidth tiers.
- Peer-policy gate: let public/paid meshes require an entitlement-bound subject
  before dialing or accepting peers.

Free/private mode can remain usable for beta, development, and private meshes
without paid entitlement. Paid public infrastructure should fail closed when an
entitlement is missing, expired, or invalid.

## Architecture and runtime surfaces

The runtime architecture is intentionally split:

- `QuantumLinkApp`: platform UI for enrollment, status, controls, diagnostics,
  identity state, profile lifecycle, and future entitlement state.
- `QuantumLinkTunnel`: packet tunnel or platform tunnel runtime that owns the
  OS packet interface and protected route lifecycle.
- `QuantumLinkKit`: shared macOS models, Keychain storage, Rust FFI bridge,
  packet pump, profile management, MDM helpers, and support bundles.
- `quantumlink-service`: Windows privileged tunnel service and platform runtime.
- `qlink-core`: Rust protocol core for crypto orchestration, signed peer
  records, routing, app-layer PQC frame protection, replay protection, native
  UDP carrier work, optional dev QUIC carrier support, rendezvous, relay,
  ICE/STUN helpers, metrics, tracing, and FFI.

Control-plane services help peers find and reach each other. They are not the
steady-state trust center for packet confidentiality. Relay fallback can see
metadata and timing, but it must not learn payload contents or session keys.

## Security requirements

QuantumLink should assume:

- Passive observers on Wi-Fi, LAN, ISP, relay, and organizational networks.
- Active on-path attackers that reorder, replay, drop, or inject traffic.
- Malicious or compromised rendezvous services.
- Malicious or compromised relay services.
- Stolen or malware-compromised endpoints.
- Curious local networks where discovery itself leaks presence.
- Misconfigured public meshes admitting peers that should have been rejected.

Minimum security requirements:

- ML-KEM-768 session establishment with strict suite negotiation.
- ML-DSA-65 device credentials as the practical default.
- SLH-DSA reserved for specialized FIPS 205 or high-assurance paths.
- Signed, expiring peer records with replay and sequence handling.
- Transcript-bound key derivation and anti-downgrade markers.
- Per-direction packet keys and monotonic packet numbers.
- Rekeying by time and byte threshold.
- Public mesh identity verification before dialing.
- Fail-closed route policy for protected prefixes.
- Revocation and quarantine flows for compromised devices.

Device compromise remains catastrophic for that device until revocation takes
effect. The product should make revocation visible, fast, and testable.

## Privacy and data handling

QuantumLink should treat control-plane metadata as sensitive data. The product
must minimize, pseudonymize, redact, and expire data by default.

Privacy defaults:

- Mesh and device labels are pseudonymous by default.
- Discovery records use short TTLs.
- Public peer-record minimization can prefer relay-only publication where
  appropriate.
- mDNS/local discovery is opt-in outside trusted local contexts.
- DNS search domains default to empty.
- Diagnostics redact raw peer IDs, wallet addresses, and network addresses by
  default.
- Raw support-bundle export requires explicit opt-in.
- Telemetry export is disabled unless required by enterprise policy or explicit
  user/admin consent.

The Dytallix identity feature must preserve these privacy rules. On-chain
records are for identity verification, status, and policy. They are not a place
for traffic, endpoint, DNS, route, or packet metadata.

## Platform requirements

### macOS

The macOS client should remain a SwiftUI app plus
`NEPacketTunnelProvider`-based packet tunnel. It should use Keychain-backed
local secrets, MDM payloads for managed deployments, Developer ID signing,
notarization, and Sparkle-style direct updates where appropriate.

The v1 macOS product should not depend on kernel extensions, custom kernel
drivers, or a pf-based core security model. Protected-route fail-closed behavior
belongs in the packet tunnel lifecycle and managed policy where available.

### Windows

The Windows client should use the privileged Rust service, Wintun adapter path,
WFP kill switch, DPAPI secret storage, named-pipe IPC, WinUI 3 dashboard, WiX
MSI packaging, and Windows-specific beta validation gates.

Windows should share the same `qlink-core` protocol and identity semantics as
macOS. Platform differences should be limited to tunnel mechanics, privilege
boundaries, UI, packaging, and OS policy enforcement.

### Steam and SteamOS

The Steam/SteamOS product track should preserve Steam-safe boundaries. Steam
account, store, wallet, checkout, inventory, marketplace, launcher, and embedded
browser traffic should bypass QuantumLink by default.

The gamer edition should focus on trusted-peer game traffic, latency-sensitive
mode, streamer/privacy controls, and clear disclosure about what traffic is and
is not protected.

## Diagnostics and support

Diagnostics should make mesh behavior explainable without leaking sensitive
data. The local UI and support bundle should expose:

- Direct versus relay path.
- Current peer count and selected path kind.
- Candidate pair and relay status in redacted form.
- RTT, loss estimate, bytes in/out, and route state.
- Last rekey time.
- DNS mode and protected route mode.
- Identity mode and registry status.
- Last peer rejection reason.
- Entitlement status when paid gates are enabled.

Support exports should default to redacted identifiers. Raw peer IDs, wallet
addresses, endpoint candidates, routes, DNS data, and packet captures require an
explicit elevated export action.

## Release and production boundaries

Official production binaries are signed release artifacts. Local source builds,
unsigned packages, CI uploads, and generated Xcode projects are development or
validation artifacts only.

The public repository may contain:

- Source code for `qlink-core`, macOS, Windows, and Steam/SteamOS planning.
- Build and validation scripts.
- Public documentation, examples, tests, and CI definitions.
- macOS and Windows packaging source.

The public repository must not contain:

- Production signing keys or certificates.
- App-store or notarization credentials.
- Hosted rendezvous or relay secrets.
- Telemetry infrastructure secrets.
- Support data, customer data, or private release infrastructure.
- Billing processor secrets or entitlement signing private keys.
- Dytallix wallet private keys.

## Performance, failure modes, and open questions

The first performance targets are engineering SLOs, not marketing claims:

| SLO | Target |
|---|---|
| Median direct connect with warm discovery | < 300 ms |
| Median post-event recovery from `PathChanged` to ready | < 1 s |
| Median relay-fallback activation | < 2 s |

These targets are intentionally anchored to warm discovery and reasonable WAN
conditions. Degraded mobile networks, high packet loss, captive portals, and
blocked UDP can exceed them. The repository's loopback and synthetic-WAN
benchmarks should continue to report both product SLO compliance and realistic
degraded-network behavior.

Expected failure modes:

- Symmetric NAT or blocked UDP: direct paths fail and relay fallback activates.
- Bootstrap outage: new internet peers may not be discoverable, but cached peers
  and local discovery can continue where policy allows.
- Relay compromise: payload confidentiality should hold, but metadata exposure
  must be assumed.
- Registry outage: public meshes fail closed unless a configured cached-proof
  grace period applies; private meshes warn and continue by default.
- Entitlement outage: paid public infrastructure should fail closed for paid
  gates while free/private mode remains available where configured.
- Local device compromise: local traffic and credentials are unsafe until the
  device is revoked and quarantined.
- Sleep, wake, roaming, captive portals, and tethering: normal events that must
  trigger path re-probing and route-policy preservation.

Open questions:

- Whether v1 public identity should require only active registry status or also
  minimum staking/reputation policy.
- How quickly to add a future proof-based identity mode that hides wallet
  addresses from the verifier.
- How to pair Sparkle or platform update signing with a post-quantum signed
  release manifest.
- Whether the first production channel should be enterprise-first or public
  direct download plus enterprise packaging.
- How strict the cached-proof grace policy should be for public meshes during
  Dytallix or network outages.
- Which paid entitlement gates should ship first after beta: app unlock,
  rendezvous publication, hosted relay allocation, or public mesh membership.
