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
- ChaCha20-Poly1305 packet-frame protection in the Rust packet core.
- Monotonic packet-number replay window.

## Mesh and Transport

- Development rendezvous server and client.
- Development relay server and client.
- Quinn QUIC DATAGRAM loopback smoke path.
- Mesh connector state machine for rendezvous lookup, direct candidate probes, relay fallback, last-good path caching, and reconnect handling.
- Optional ICE/STUN helper paths for connectivity checks.
- File-backed peer store with optional ChaCha20-Poly1305 envelope encryption.
- OpenMetrics endpoint support when explicitly configured.

## macOS Operations

- Local development app can run without a signed Network Extension by using simulated mesh state or development loopback transport.
- Unsigned XcodeGen project scaffolding can be generated without Apple credentials.
- Real packet tunnel execution requires Apple Network Extension entitlements, provisioning, signing, and notarization.
- Enterprise rollout is designed around MDM, per-app VPN payloads, VPN On Demand rules, and extension preapproval.

## Not Production-Complete

- Production peer-session key installation into packet-frame encryption.
- Hardened public rendezvous and relay services.
- Full public ICE/STUN/TURN deployment and nomination behavior.
- Notarized Developer ID app and tunnel extension bundle.
- Managed Device Attestation and SSO integration.
- Full post-quantum update manifest and release-signing layer.
- Anonymity guarantees beyond metadata minimization.
