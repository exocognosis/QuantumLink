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
- SHAKE256-KDF suite identifiers (`QLINK-FIPS203-MLKEM768-SHAKE256-v1`, ML-DSA-65, SLH-DSA-SHAKE128S) with anti-downgrade suite binding; legacy HKDF/X25519 identifiers are explicitly rejected.
- ML-DSA-65 default device credential generation, persistence, signing, and verification.
- SLH-DSA (SHAKE) signing and verification for the FIPS 205 suite path.
- Peer IDs derived from device public-key material.
- Signed, expiring peer records for rendezvous publication.
- Inbound identity assertions and optional peer ACL evaluation.
- **On-chain Dytallix identity:** node-registry contract deployed to the Dytallix testnet; `MeshTrustPolicy` (public-required / private-preferred / development-optional) enforced on both the outbound connector and inbound responder — public meshes fail closed on peers without an active registry record (live-verified against the deployed contract).
- Production peer-session key installation into ChaCha20-Poly1305 packet-frame encryption.
- Monotonic packet-number replay window.

## Mesh and Transport

- Native UDP carrier + PQC session handshake driving the live data plane (the dev-quic loopback is retained behind a feature flag for tests only).
- Rendezvous + relay server/client; QuantumLink native relay plus a standard TURN (RFC 5766/8656) client for relay-candidate gathering from coturn-style infrastructure.
- Mesh connector state machine for rendezvous lookup, direct candidate probes, relay fallback, last-good path caching, and reconnect handling.
- RFC 8445 candidate model — host / server-reflexive (STUN) / relay (native + TURN) with priority-ordered nomination.
- File-backed peer store with optional ChaCha20-Poly1305 envelope encryption.
- OpenMetrics endpoint support when explicitly configured.

## macOS Operations

- Local development app can run without a signed Network Extension by using simulated mesh state or development loopback transport.
- Unsigned XcodeGen project scaffolding can be generated without Apple credentials.
- Real packet tunnel execution requires Apple Network Extension entitlements, provisioning, signing, and notarization.
- Enterprise rollout is designed around MDM, per-app VPN payloads, VPN On Demand rules, and extension preapproval.

## Not Production-Complete

- Hardened public rendezvous and relay services (production abuse controls, TLS, revocation, retention limits).
- Wiring the STUN/TURN candidate gatherers into the mesh's self-candidate publishing (the TURN client + RFC 8445 candidate model exist; the mesh does not gather them by default yet).
- Swift app-UI surfacing of the identity module and a full-Xcode rebuild of the signed `.app` (see `docs/xcode-rebuild-onchain-identity-runbook.md`).
- Notarized Developer ID app and tunnel extension bundle.
- Managed Device Attestation and SSO integration.
- Full post-quantum update manifest and release-signing layer.
- Anonymity guarantees beyond metadata minimization.
