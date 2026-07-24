# QuantumLink Features

This feature list is synchronized with the current repository implementation. It separates local development features from production-complete VPN behavior.

## Implemented Development Baseline

- SwiftUI macOS app shell with mesh status, onboarding, connection, activity, network, peer, route, security, diagnostics, and configuration views.
- Packet tunnel provider scaffold using `NEPacketTunnelProvider` and `utun`.
- Shared Swift configuration model for routes, DNS, discovery, relay, rendezvous, MTU, crypto policy, and kill-switch policy.
- Fail-closed packet pump behavior when the Rust data plane is unavailable.
- Rust FFI bridge for tunnel packet core, development QUIC loopback, mesh transport, device keypairs, metrics, and tracing.
- Keychain-backed Swift storage helpers for ML-DSA device keypair seeds and peer-store encryption keys.
- MDM payload builders for managed defaults, extension preapproval, strict kill switch, VPN On Demand, and per-app VPN.
- Support bundle export with redaction-first diagnostics.
- Build scripts for Swift tests, Rust tests, Rust XCFramework generation, XcodeGen project generation, unsigned Xcode builds, development artifact packaging, and Developer ID packaging scaffolding.

## Cryptography and Identity

- ML-KEM-768 session establishment without a classical key-exchange fallback.
- FIPS 203, FIPS 204, and FIPS 205 suite identifiers with anti-downgrade suite binding.
- ML-DSA-65 default device credential generation, persistence, signing, and verification.
- SLH-DSA-SHA2-128S signing and verification for the FIPS 205 suite path.
- Peer IDs derived from device public-key material.
- Signed, expiring peer records for rendezvous publication.
- Inbound identity assertions and optional peer ACL evaluation.
- App-layer PQC frame protection using ML-KEM session keys, SHAKE256 masking/authentication, and replay rejection.
- Packet-core route enforcement, packet metadata normalization, peer-session readiness gates, and monotonic packet-number replay window.
- macOS FFI hooks and development-runtime wiring for packet-core peer-session install/clear/readiness plus peer-session and replay-drop metrics.

## Mesh and Transport

- Development rendezvous server and client, with optional bearer-token admission
  and per-client IP rate limiting for public-edge rehearsal.
- Development relay server and client, with optional bearer-token registration,
  per-client IP rate limiting, and registered-source validation for relayed
  datagrams.
- Native UDP carrier is the default mesh data-plane carrier; Quinn/rustls is feature-gated for legacy development.
- Mesh connector state machine for rendezvous lookup, native direct candidate probes, PQC relay fallback, published QuantumLink relay-candidate fallback, last-good path caching, and reconnect handling.
- Optional ICE/STUN helper paths for connectivity checks, plus feature-gated TURN relay-candidate gathering. Published TURN relay candidates are consumed as UDP-relayed carrier targets when live, and the `turn-relay` proof path keeps a resident allocation with CreatePermission plus Send/Data indication handling distinct from the QuantumLink app-relay carrier.
- File-backed peer store with optional ChaCha20-Poly1305 envelope encryption.
- OpenMetrics endpoint support when explicitly configured.

## macOS Operations

- Local development app can run without a signed Network Extension by using simulated mesh state or development loopback transport.
- Unsigned XcodeGen project scaffolding can be generated without Apple credentials.
- The macOS development runtime installs, clears, and rotates packet-core peer-session readiness from the live default-peer mesh session, so protected packet flow fails closed until an authenticated peer session is available.
- macOS connection profiles, managed configuration, and party-mesh invite flows can select a remote QuantumLink peer ID and carry it into the packet-session readiness gate.
- Real packet tunnel execution requires Apple Network Extension entitlements, provisioning, signing, and notarization.
- Enterprise rollout is designed around MDM, per-app VPN payloads, VPN On Demand rules, and extension preapproval.

## Not Production-Complete

- Public rendezvous/relay TLS is implemented behind `public-edge-tls`, but
  durable revocation, abuse monitoring, retention controls, connection quotas,
  and deployed hardening evidence remain open.
- RFC-complete public ICE nomination behavior and TURN relay-candidate data-plane proof against deployed public infrastructure.
- Notarized Developer ID app and tunnel extension bundle.
- Real-hardware validation of signed/provisioned Network Extension builds, including peer-session readiness under live packet flow.
- Managed Device Attestation and SSO integration.
- Full post-quantum update manifest and release-signing layer.
- Anonymity guarantees beyond metadata minimization.
