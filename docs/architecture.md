# Architecture

QuantumLink is split into three runtime surfaces.

1. `QuantumLinkApp` is the SwiftUI desktop surface. It owns user-visible state, enrollment UX, diagnostics, and profile installation.
2. `QuantumLinkTunnel` is the `NEPacketTunnelProvider` extension. It configures the `utun` interface, applies routes and DNS, and owns packet ingress/egress.
3. `qlink-core` is the Rust protocol core. It owns crypto orchestration, signed peer records, replay protection, route validation, rendezvous, relay development services, the Quinn carrier wrapper, and ICE data-plane scaffolding.

The current source tree is intentionally source-first instead of Xcode-project-first. The unsigned XcodeGen project can be generated locally, but a production Mac release still needs Apple-granted Network Extension entitlement approval, Developer ID signing, and notarization.

## Data Plane

The data plane is an L3 overlay. The packet tunnel provider configures a `utun` interface with protected routes and DNS settings. Packets read from `packetFlow` enter `TunnelPacketPump`, which forwards protected packet frames to a `TunnelTransporting` sink. The Rust packet core normalizes selected IPv4 metadata and emits packet frames only; direct mesh links then protect those frames with the app-layer ML-KEM/SHAKE session frame layer. Raw Quinn loopback modes are disabled in the strict PQC profile because they bypass that app-layer frame session.

## Control Plane

The control plane is server-minimized, not server-free:

- Rendezvous publishes short-lived signed peer records with sequence-rotating pseudonymous aliases.
- Public rendezvous records publish relay candidates only by default so host and server-reflexive addresses are not advertised as location metadata.
- Local mDNS discovery is an opt-in future adapter.
- Private DHT support is intentionally not enabled by default.

## Privacy Defaults

Privacy minimization is built into the default app behavior rather than exposed as a mode. Generated development configurations use overlay addresses in `100.64.0.0/10`, pseudonymous mesh and device labels, tunnel-provided DNS, no DNS search-domain default, and redacted network identifiers in normal app and diagnostic displays. Raw addresses still exist at execution boundaries where the tunnel or a user-entered connection target requires them.

Overlay allocation uses a keyed recursive permutation over the 22-bit host space of `100.64.0.0/10`. The entropy still comes from `SecRandomCopyBytes`; the current macOS implementation uses SHA-256 keyed branch swaps to spread candidates across the pool while preserving deterministic testability and collision probing. That privacy-redaction allocator is outside the packet/session boundary and remains a blocker for a strict zero-classical stack.

## Crypto Boundary

The Rust core exposes versioned internal APIs:

- `PQCHandshake` implements a three-message ML-KEM-768 handshake.
- Suite selection accepts FIPS 203, FIPS 204, and FIPS 205 identifiers and binds the selected suite into the handshake transcript and key derivation.
- `DeviceKeypair` implements ML-DSA-65 and SLH-DSA-SHAKE-128S signing and verification for device credentials.
- `PacketTunnelCore` frames normalized protected-route packets; it does not encrypt them.
- Direct mesh links protect packet frames with app-layer ML-KEM session keys, SHAKE256 masking/authentication, and replay rejection before handing them to Quinn DATAGRAM.
- `PeerRecord` signs route and endpoint advertisements.
- `ReplayWindow` rejects duplicate and stale packet numbers.

Swift should treat the Rust core as the only owner of protocol secrets. Long-term seeds should be stored in the macOS Data Protection keychain through `KeychainSecretStore`. Production packet transport must route packet frames through the mesh PQC frame session and must not hand packet-core frames directly to raw Quinn DATAGRAM sessions.

Known non-compliant full-stack blockers remain outside this app-layer boundary: Quinn/rustls still configures the hybrid `X25519MLKEM768` group, macOS/Windows privacy redaction still uses SHA-256-derived aliases, macOS CMS/profile signing still requests platform SHA-256, and the Quinn/rustls/aws-lc/ring dependency graph still includes classical algorithms.
