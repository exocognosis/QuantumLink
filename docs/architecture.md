# Architecture

QuantumLink is split into three runtime surfaces.

1. `QuantumLinkApp` is the SwiftUI desktop surface. It owns user-visible state, enrollment UX, diagnostics, and profile installation.
2. `QuantumLinkTunnel` is the `NEPacketTunnelProvider` extension. It configures the `utun` interface, applies routes and DNS, and owns packet ingress/egress.
3. `qlink-core` is the Rust protocol core. It owns crypto orchestration, signed peer records, replay protection, route validation, rendezvous, relay development services, and the development QUIC/ICE data-plane scaffolding.

The current source tree is intentionally source-first instead of Xcode-project-first. The unsigned XcodeGen project can be generated locally, but a production Mac release still needs Apple-granted Network Extension entitlement approval, Developer ID signing, and notarization.

## Data Plane

The data plane is an L3 overlay. The packet tunnel provider configures a `utun` interface with protected routes and DNS settings. Packets read from `packetFlow` enter `TunnelPacketPump`, which forwards protected packet frames to a `TunnelTransporting` sink. Before packet-frame encryption, the Rust packet core normalizes selected IPv4 metadata so routine traffic does not carry avoidable local fingerprinting signals. The default local behavior is an explicit development drop sender; `QLINK_TRANSPORT_MODE=dev-quic-loopback` enables a local Rust-backed Quinn QUIC DATAGRAM loopback facade for smoke testing without a Network Extension entitlement.

## Control Plane

The control plane is server-minimized, not server-free:

- Rendezvous publishes short-lived signed peer records with sequence-rotating pseudonymous aliases.
- Public rendezvous records publish relay candidates only by default so host and server-reflexive addresses are not advertised as location metadata.
- Local mDNS discovery is an opt-in future adapter.
- Private DHT support is intentionally not enabled by default.

## Privacy Defaults

Privacy minimization is built into the default app behavior rather than exposed as a mode. Generated development configurations use overlay addresses in `100.64.0.0/10`, pseudonymous mesh and device labels, tunnel-provided DNS, no DNS search-domain default, and redacted network identifiers in normal app and diagnostic displays. Raw addresses still exist at execution boundaries where the tunnel or a user-entered connection target requires them.

Overlay allocation uses a keyed recursive permutation over the 22-bit host space of `100.64.0.0/10`. The entropy still comes from `SecRandomCopyBytes`; the recursive layer partitions the address space and uses SHA-256 keyed branch swaps to spread candidates across the pool while preserving deterministic testability and collision probing. This is a fractal-style allocator structure, not a non-cryptographic chaotic random source.

## Crypto Boundary

The Rust core exposes versioned internal APIs:

- `PQCHandshake` implements a three-message ML-KEM-768 handshake.
- Suite selection accepts FIPS 203, FIPS 204, and FIPS 205 identifiers and binds the selected suite into the handshake transcript and key derivation.
- `DeviceKeypair` implements ML-DSA-65 and SLH-DSA-SHA2-128S signing and verification for device credentials.
- `PacketTunnelCore` encrypts transport frames with suite-bound AEAD keys before handing them to the transport facade.
- `PeerRecord` signs route and endpoint advertisements.
- `ReplayWindow` rejects duplicate and stale packet numbers.

Swift should treat the Rust core as the only owner of protocol secrets. Long-term seeds should be stored in the macOS Data Protection keychain through `KeychainSecretStore`. Production peer sessions still need to install negotiated session keys into the packet core instead of using the current development-core suite-bound frame keys.
