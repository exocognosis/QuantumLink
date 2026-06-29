# QuantumLink Specification

QuantumLink is a macOS-first peer-to-peer mesh VPN scaffold. The implementation target is a server-minimized L3 overlay: peers exchange traffic directly when possible, use rendezvous for discovery, and fall back to relay paths when direct connectivity is unavailable. It does not require a centralized VPN concentrator in the steady-state data plane.

This specification reflects the current repository implementation, especially `qlink-core`.

## Runtime Surfaces

- `QuantumLinkApp`: SwiftUI app for enrollment, mesh status, operator controls, diagnostics, and profile lifecycle.
- `QuantumLinkTunnel`: `NEPacketTunnelProvider` scaffold that configures `utun`, routes, DNS, packet ingress/egress, and kill-switch behavior.
- `QuantumLinkKit`: shared Swift models, configuration, Keychain storage, Rust FFI bridge, packet pump, profile management, MDM helpers, and support bundles.
- `qlink-core`: Rust protocol core for crypto orchestration, signed peer records, routing, packet-frame protection, replay protection, QUIC transport scaffolding, rendezvous, relay, ICE/STUN helpers, metrics, and FFI.

## Cryptographic Model

The current handshake is post-quantum only for session establishment. It does not implement an X25519 or other classical key-exchange fallback.

Supported suite identifiers:

- `QLINK-FIPS203-MLKEM768-SHAKE256-v1`
- `QLINK-FIPS204-MLDSA65-SHAKE256-v1`
- `QLINK-FIPS205-SLHDSA-SHAKE128S-SHAKE256-v1`

Implemented crypto behavior:

- ML-KEM-768 three-message session establishment.
- SHAKE256 transcript binding.
- SHAKE256 directional key derivation with suite binding.
- ML-DSA-65 device credentials by default.
- SLH-DSA-SHAKE-128S signing and verification for the FIPS 205 suite path.
- Signed, expiring peer records containing peer identity, device public key, routes, endpoint candidates, ICE credentials, QUIC certificate material, expiration, and sequence number.
- Suite-validated packet framing in `PacketTunnelCore` plus app-layer PQC frame protection on negotiated session paths.
- Monotonic packet-number replay protection.

The legacy `QLINK-HYBRID-X25519-MLKEM768-HKDFSHA256-v1` suite is intentionally rejected. Production peer sessions still need to install negotiated session keys into packet-frame encryption; current packet-frame keys are development suite-bound keys.

## Data Plane

QuantumLink is an L3 overlay. The packet tunnel provider configures a `utun` interface with protected routes and DNS settings. Protected IPv4 packets pass through `TunnelPacketPump` and `PacketTunnelCore`, where route policy is enforced, selected IPv4 metadata is normalized, and transport frames are encrypted before they are sent to the transport.

Current transport modes:

- `developmentDrop`: default fail-closed sender for local development without a data plane.
- `devQuicLoopback`: Rust-backed local Quinn QUIC DATAGRAM loopback for smoke testing.
- `meshQuic`: Rust mesh transport wrapper for rendezvous lookup, direct probes, optional ICE, relay fallback, peer-store persistence, per-peer state, and network-event reconnect behavior.

## Control Plane

The control plane is server-minimized, not server-free.

- Rendezvous services publish and look up short-lived signed peer records.
- Relay services provide fallback when direct peer paths fail.
- ICE/STUN helpers support connectivity checks and candidate validation.
- Peer stores cache verified records for graceful degradation when rendezvous is unavailable.
- Public peer-record minimization can prefer relay-only publication so host and server-reflexive addresses are not exposed by default.

The included rendezvous and relay services are development tools. They are not hardened public infrastructure without TLS, authentication policy, abuse controls, durable revocation, monitoring, and retention controls.

## macOS and Production Boundaries

QuantumLink is source-ready for local app, protocol, and packaging development. It is not yet a production VPN bundle.

Production release still requires:

- Apple-granted Network Extension entitlements.
- Developer ID signing and notarization.
- Provisioning profiles for the app and tunnel extension.
- MDM pre-approval flows for managed deployments.
- Production peer-session key installation into packet-frame encryption.
- Hardened public rendezvous/relay infrastructure.
- Release update signing and a post-quantum manifest layer.

## Privacy Defaults

- Overlay addresses use `100.64.0.0/10`.
- Mesh and device labels are pseudonymous by default.
- DNS search domains default to empty.
- Normal diagnostics redact raw network identifiers.
- Support bundle raw export requires explicit opt-in.
- mDNS/local discovery is not a silent always-on public-network behavior.
