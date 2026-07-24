# QuantumLink Threat Model

## Overview

QuantumLink is a post-quantum, peer-to-peer mesh VPN scaffold built around one shared Rust `qlink-core` protocol core. The repository includes a macOS reference edition with a SwiftUI app and `NEPacketTunnelProvider`, a Windows alpha scaffold with a WinUI dashboard and LocalSystem service, and a Steam planning scaffold. The intended data plane is a server-minimized L3 overlay: peers exchange protected traffic directly when possible, use rendezvous for discovery, and can fall back to relay paths when direct connectivity fails.

This document is repository-scoped. It covers the current implementation baseline, not an audited production VPN release. The current code contains important production boundaries:

- The shared Rust handshake implements ML-KEM-768 session establishment and derives directional session keys.
- Device identity and peer records use ML-DSA-65 by default, with SLH-DSA-SHA2-128S support for the FIPS 205 suite path.
- Signed peer records bind peer IDs, device public keys, endpoint candidates, ICE credentials, QUIC certificate material, routes, expiration, and sequence numbers.
- The packet core encrypts packet frames with ChaCha20-Poly1305 using suite-bound development keys today. Production peer sessions still need to install negotiated session keys into packet-frame encryption before production confidentiality or HNDL resistance should be claimed for carried user traffic.
- The included rendezvous and relay services are development services with bearer-token admission and per-client IP rate limits. They are not hardened public infrastructure without TLS, durable revocation, monitoring, resource quotas, and retention controls.

For quantum-era risks in more detail, see `QUANTUM_THREATS.md`.

### Security Objectives

Confidentiality:

- Keep protected-route packet plaintext, device key seeds, peer-store keys, Dytallix wallet keys, signing identities, and diagnostics private.
- Resist passive capture and Harvest Now, Decrypt Later (HNDL) for the post-quantum session-establishment design.
- Avoid leaking unnecessary LAN, endpoint, peer, mesh, wallet, and route metadata through discovery records, logs, or support bundles.

Integrity:

- Prevent packet injection, frame tampering, route manipulation, peer-record poisoning, registry-binding substitution, and malicious profile/update changes.
- Fail closed for protected traffic when the Rust core or mesh transport is unavailable.

Authentication and authorization:

- Verify peer identities through signed peer records, device-derived peer IDs, per-peer QUIC certificate binding, inbound identity assertions, optional peer ACLs, and optional Dytallix registry binding.
- Prevent unauthorized nodes from joining public meshes when `public_required` trust policy is configured.

Availability:

- Preserve connectivity through direct paths, ICE/STUN checks, relay fallback, last-good path caching, and peer-store fallback when appropriate.
- Bound malformed control messages and avoid letting untrusted peers or services exhaust memory or bypass policy.

### Assets

- User packet plaintext entering and leaving platform tunnel adapters, including macOS `NEPacketTunnelProvider` and the Windows Wintun/WFP service path.
- ML-KEM session keys and any future packet-frame keys derived from those session secrets.
- ML-DSA device keypair seeds stored through `DeviceKeypairStore` and `KeychainSecretStore`.
- Peer-store encryption keys, signed `PeerRecord`s, peer ACLs, route policy, ICE credentials, and QUIC certificate material.
- Dytallix wallet keys, wallet authorization signatures, registry records, node status, and registry endpoint pins.
- MDM payloads, configuration profiles, PKCS#12 signing identities, Developer ID/notarization credentials, Authenticode signing credentials, Sparkle/update signing material, MSI artifacts, and release artifacts.
- Diagnostics, logs, support bundles, performance artifacts, and local development configuration.

## Threat Model, Trust Boundaries, and Assumptions

### Adversary Classes

1. Passive network adversary and HNDL collector

Capabilities:

- Observe local network, ISP, backbone, relay, rendezvous, or public-internet traffic.
- Record QUIC traffic, rendezvous lookups, relay traffic, STUN/ICE probes, endpoint metadata, and timing indefinitely.
- Attempt future decryption using improved classical cryptanalysis or a cryptographically relevant quantum computer.

Security expectation:

- The ML-KEM handshake design is intended to protect session-establishment secrets from passive HNDL collection, assuming ML-KEM and HKDF remain secure and randomness is sound.
- Current packet-frame encryption must not be treated as production HNDL protection until negotiated session keys are wired into `PacketTunnelCore`.
- QUIC/TLS in `quic_transport.rs` is a transport carrier and still uses conventional TLS mechanisms. The post-quantum security boundary should be the signed peer identity and packet-frame/session-key layer, not WebPKI or classical TLS alone.

2. Active man-in-the-middle

Capabilities:

- Intercept, modify, replay, drop, delay, or inject traffic.
- Substitute rendezvous records, endpoint candidates, registry query responses, relay datagrams, STUN/ICE messages, QUIC certificates, or packet frames.
- Attempt downgrade to unsupported suites or unauthenticated transport paths.

Security expectation:

- Suite identifiers are versioned and unsupported or legacy hybrid suite names are rejected in `crypto.rs`.
- `PeerRecord::verify` binds mesh ID, peer ID, device public key, endpoint candidates, routes, expiration, sequence, ICE credentials, and QUIC certificate material under the peer device signature.
- `connect_with_trusted_cert` pins QUIC server trust to the certificate from the signed peer record.
- Inbound identity assertions bind peer ID, mesh ID, timestamp, nonce, and device public key under the connecting peer's device signature.
- These controls must be present on production paths. Bare local handshake simulations and development loopbacks are not sufficient MITM protection by themselves.

3. Quantum adversary

Capabilities:

- Has, or later obtains, a cryptographically relevant quantum computer.
- Attempts to break RSA/ECC, classical TLS key exchange, classical code-signing assumptions, and recorded traffic.

Security expectation:

- The current Rust cryptographic model intentionally avoids a classical key-exchange fallback for the `PQCHandshake`.
- ML-KEM, ML-DSA, SLH-DSA, SHA-256, HKDF-SHA-256, and ChaCha20-Poly1305 are assumed secure at their intended levels.
- Quantum resistance is not universal across all repository surfaces. Apple signing, notarization, CMS-signed `.mobileconfig` payloads, QUIC/TLS internals, GitHub Actions, and third-party dependencies still rely on conventional platform cryptography.

4. Malicious peer

Capabilities:

- Controls a valid peer identity, publishes signed records, connects directly or through relay, sends malformed packets or control messages, advertises routes, and consumes connection resources.
- Attempts route hijacking, traffic analysis, stale-record abuse, replay, endpoint poisoning, ACL probing, or packet/frame injection.

Security expectation:

- Route policy is enforced in both macOS network settings and the Rust packet core.
- Peer IDs are derived from device public keys; signed records and inbound assertions prevent simple impersonation.
- Peer ACLs can deny known peers or require allowlists.
- Public meshes can require Dytallix registry binding before dialing.
- Current repository controls do not yet provide production-grade quotas, abuse scoring, Sybil resistance, or rate limiting for all network services.

5. Sybil and registry adversary

Capabilities:

- Creates many identities, manipulates public discovery, attempts registry endpoint substitution, or supplies stale/revoked/suspended registry records.
- Operates or compromises an RPC endpoint used for registry lookups.

Security expectation:

- Public meshes can require registry records and reject missing, revoked, suspended, expired, or mismatched bindings.
- Registry lookup configuration supports pinned network ID, chain ID, and allowed RPC endpoints.
- Dytallix testnet trust infrastructure is a beta interoperability and wallet/device-binding root. It is not a complete production Sybil-resistance or reputation system.

6. Denial-of-service adversary

Capabilities:

- Floods rendezvous, relay, QUIC, STUN/ICE, FFI, packet-frame, support-bundle, metrics, or CLI inputs.
- Sends oversized JSON, malformed frames, repeated connection attempts, invalid peer records, or expensive signature-verification traffic.

Security expectation:

- Several control paths bound message size or reject malformed input, for example inbound identity assertions are capped at 32 KiB.
- Development rendezvous and relay services can run TLS JSON control protocols with optional bearer-token admission, credential-file token loading, and per-client IP rate limits; keep them source-limited during beta until abuse controls are deployed.
- Production deployments still need connection quotas, abuse monitoring, durable authenticated service access, token revocation, and resource accounting.

7. Key compromise adversary

Capabilities:

- Obtains a device key seed, peer-store encryption key, Dytallix wallet key, PKCS#12 signing identity, build secret, or update-signing secret.
- Uses the key to impersonate a peer, publish records, sign registry updates, sign configuration profiles, or ship malicious updates.

Security expectation:

- Device key seeds and peer-store encryption keys are stored in the macOS Data Protection Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
- Dytallix keystore files are chmodded to `0600` on Unix.
- Registry revocation, key rotation, and support for fresh device identities are part of the intended response model.
- A stolen active signing key remains high impact until revoked and rotated.

8. Traffic correlation and metadata adversary

Capabilities:

- Observes both ends of paths, rendezvous/relay metadata, endpoint candidates, timing, packet sizes, Dytallix wallet linkage, and repeated peer IDs.
- Attempts to link users, devices, meshes, wallets, game parties, or locations.

Security expectation:

- QuantumLink minimizes some metadata by default: pseudonymous mesh/device labels, relay-only publication options, redacted diagnostics, no DNS search-domain default, endpoint redaction, and IPv4 metadata normalization before frame encryption.
- QuantumLink does not currently provide anonymity, multi-hop routing, cover traffic, timing obfuscation, or unlinkability against a global observer.

### Trust Boundaries

Local app and tunnel surfaces:

- On macOS, `QuantumLinkApp` and `QuantumLinkTunnel` are separate runtime surfaces. App messages, provider configuration, MDM payloads, and profile installation cross a trust boundary into the tunnel provider.
- On Windows, the WinUI dashboard talks to a privileged LocalSystem service over named-pipe IPC. The service owns Wintun, WFP kill-switch policy, route/DNS programming, DPAPI-backed secrets, path observation, and packet pumping.
- Platform tunnel components configure protected routes, DNS, packet reads/writes, kill-switch behavior, network lifecycle events, and packet pumping.

Swift and Rust FFI:

- macOS `QuantumLinkKit` passes JSON configuration, packet bytes, transport frames, peer IDs, peer-store keys, and keypair handles across FFI into `qlink-core`.
- Windows links `qlink-core` into the service process and crosses a named-pipe IPC boundary between unprivileged UI and privileged service.
- FFI input validation, memory ownership, pointer lifetimes, error redaction, and crash resistance are security-sensitive.

Device secrets and local storage:

- Keychain-held device seeds and peer-store encryption keys are trusted local secrets.
- Plaintext peer-store mode exists for back compatibility and CLI/dev flows. It is not equivalent to encrypted peer-store mode for metadata confidentiality.
- Dytallix wallet keystore files are outside `TunnelConfiguration`, support bundles, and NetworkExtension provider configuration.

Discovery and control plane:

- Rendezvous, relay, STUN/ICE, mDNS, peer-store cache, and Dytallix registry data are untrusted until verified.
- A rendezvous service is a publication and lookup channel, not a trust anchor.
- A relay can see source/destination metadata and timing and can drop or delay traffic. It should not be able to forge signed peer identity or authenticated packet frames when production keys are installed.

Data plane:

- Packets from `packetFlow` are untrusted packet bytes from the local OS routing boundary.
- Transport frames from peers or relays are attacker-controlled until authenticated, decrypted, route-checked, and associated with a verified peer.

Diagnostics and operations:

- Logs, support bundles, metrics endpoints, perf artifacts, and release packages cross from private runtime state into user-shareable artifacts.
- Default diagnostics must remain redacted. Raw exports require explicit opt-in.

Build, signing, and release:

- XcodeGen project generation, Rust XCFramework generation, Developer ID signing, notarization, configuration-profile signing, and update publication cross from source code into installable artifacts.
- GitHub Actions and maintainer machines are privileged build systems, not untrusted runtime peers.

### Assumptions

QuantumLink assumes:

- macOS, Windows, Network Extension, Wintun/WFP, Keychain, DPAPI, Secure Enclave/platform security where used, and OS random number generation are not fully compromised.
- ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-128S, SHA-256, HKDF-SHA-256, and ChaCha20-Poly1305 remain secure enough for the selected security targets.
- The `ml-kem`, `ml-dsa`, `slh-dsa`, `quinn`, `rustls`, `chacha20poly1305`, Swift Security framework, and Dytallix dependencies behave as documented and receive dependency updates.
- Operators configure protected routes, excluded routes, DNS, peer ACLs, Dytallix trust policy, registry endpoint pins, and platform kill-switch policy correctly for their deployment.
- Reviewers distinguish development services and smoke-test paths from production VPN behavior.

QuantumLink does not assume:

- Local networks, ISPs, rendezvous services, relay services, STUN servers, Dytallix RPC endpoints, or peer-supplied endpoint candidates are honest.
- A relay or rendezvous service preserves availability, privacy, or ordering.
- Public mesh identity alone gives complete Sybil resistance, reputation, or abuse prevention in the current beta state.
- Current code provides anonymity against global traffic correlation.

Out of scope:

- Malware on the endpoint, root/admin compromise, kernel compromise, or physical compromise of an unlocked device.
- Hardware side-channel attacks against cryptographic operations.
- Compromise of maintainer accounts, GitHub infrastructure, Apple notarization infrastructure, or all release-signing keys.
- Public exposure of the development rendezvous or relay binaries as if they were production services.
- Decrypting traffic if the endpoint intentionally exports raw diagnostics or voluntarily shares secrets.

## Attack Surface, Mitigations, and Attacker Stories

### Packet Tunnel and Data Plane

Primary files:

- `macos/Sources/QuantumLinkTunnel/PacketTunnelProvider.swift`
- `macos/Sources/QuantumLinkKit/TunnelPacketPump.swift`
- `macos/Sources/QuantumLinkKit/TunnelTransport.swift`
- `windows/rust/quantumlink-service/src/pump.rs`
- `windows/rust/quantumlink-service/src/win/wintun_adapter.rs`
- `windows/rust/quantumlink-service/src/win/wfp.rs`
- `qlink-core/src/packet_core.rs`
- `qlink-core/src/routing.rs`
- `qlink-core/src/replay.rs`

Attacker-controlled inputs:

- Local packets observed through `packetFlow`.
- Inbound transport frames from direct peers or relays.
- Route, DNS, MTU, crypto policy, relay, and rendezvous configuration.

Mitigations:

- Platform included/excluded routes steer protected prefixes into `utun` on macOS and Wintun on Windows.
- `TunnelPacketPump` drops protected packets fail-closed when the Rust core is unavailable or the transport is not ready.
- `PacketTunnelCore` accepts IPv4 only, enforces protected-route policy, rejects unsupported crypto suites, authenticates packet frames with AEAD, and normalizes DSCP/ECN, TTL, and non-fragment IPv4 IDs before encryption.
- The strict kill switch tears down the tunnel after sustained unhealthy transport.

Reviewer focus:

- Ensure production frame keys come from negotiated session secrets, not public suite-bound development keys.
- Ensure replay protection is applied on every production packet-frame ingress path, not only provided as a standalone primitive.
- Check that malformed frames, oversized packets, and MTU edge cases cannot crash the provider or Rust core.

### Cryptography, Identity, and HNDL

Primary files:

- `qlink-core/src/crypto.rs`
- `qlink-core/src/discovery.rs`
- `qlink-core/src/inbound_identity.rs`
- `qlink-core/src/quic_transport.rs`
- `macos/Sources/QuantumLinkKit/DeviceKeypairStore.swift`
- `macos/Sources/QuantumLinkKit/KeychainSecretStore.swift`
- `windows/rust/quantumlink-service/src/secret_store.rs`
- `windows/rust/quantumlink-service/src/win/dpapi.rs`

Attacker-controlled inputs:

- Handshake messages, peer records, signatures, device public keys, QUIC certificates, inbound assertions, and session/control messages.

Mitigations:

- `PQCHandshake` validates protocol version and suite names and rejects the legacy hybrid suite.
- Session establishment uses ML-KEM-768, SHA-256 transcript hashing, and HKDF-SHA-256 directional key derivation.
- Device credentials use ML-DSA-65 by default, with SLH-DSA-SHA2-128S available for the FIPS 205 suite path.
- Peer IDs are derived from device public-key bytes.
- `PeerRecord::verify` checks mesh ID, expiration, peer ID/public-key binding, and the device signature.
- Inbound identity assertions check peer ID/public-key binding, mesh ID, freshness, far-future timestamps, and signature validity.
- Device key seeds are stored in Keychain as 32-byte ML-DSA seeds.

Reviewer focus:

- Confirm transcript binding covers all fields needed to prevent downgrade and unknown-key-share attacks.
- Confirm production traffic encryption uses the handshake output and rotates/rekeys on an auditable schedule.
- Confirm unauthenticated development entry points cannot be confused with production peer authentication.
- Confirm signature verification uses canonical bytes consistently and cannot be bypassed by JSON field ambiguity or alternate encodings.

### Rendezvous, Relay, ICE, STUN, and Peer Store

Primary files:

- `qlink-core/src/rendezvous.rs`
- `qlink-core/src/relay.rs`
- `qlink-core/src/mesh_connection.rs`
- `qlink-core/src/ice.rs`
- `qlink-core/src/stun.rs`
- `qlink-core/src/peer_store.rs`

Attacker-controlled inputs:

- Rendezvous publish/lookup requests, signed records, relay datagrams, peer IDs, STUN/ICE packets, endpoint candidates, cached peer records, and network lifecycle changes.

Mitigations:

- Rendezvous verifies signed records before storing them and prunes expired records on lookup.
- Candidate endpoints are signed as part of peer records.
- ICE credentials are included in signed peer records and rotated on publication.
- The connector can use paced direct probes, relay fallback, optional ICE checks, peer ACLs, registry checks, peer-store fallback, and network-event cache invalidation.
- Peer-store v2 encrypts cached records with ChaCha20-Poly1305 when a Keychain-provided key is available and writes files with `0600` permissions.

Reviewer focus:

- Treat rendezvous and relay as malicious. Verify they cannot forge identity, route policy, or packet contents.
- Require non-placeholder admission tokens and rate limits before public-edge
  testing, and add TLS plus durable revocation before broad service exposure.
- Confirm stale peer-store fallback cannot revive revoked peers in public-required deployments.
- Ensure relay metadata visibility is documented and acceptable for the deployment.

### Dytallix Registry and Public Mesh Trust

Primary files:

- `qlink-core/src/dytallix_identity.rs`
- `dytallix/quantumlink-node-registry/src/lib.rs`
- `macos/Sources/QuantumLinkKit/DytallixEnrollmentSettings.swift`
- `macos/Sources/QuantumLinkKit/DiscoveryIdentityPresentation.swift`

Attacker-controlled inputs:

- Registry query responses, RPC endpoint responses, node records, status fields, owner addresses, wallet metadata, registry configuration, and public mesh policy.

Mitigations:

- Public-required meshes fail closed when a registry record is missing.
- Registry binding verifies active status, expiration, peer ID, device-public-key hash, latest peer-record hash, PQC binding hash, node-signing hash, and transport-public-key hash.
- Lookup configuration can pin network ID, chain ID, and allowed RPC endpoints.
- Wallet private keys and keystore paths are kept out of tunnel configuration and support bundles.

Reviewer focus:

- Check every public mesh path enforces `PublicRequired` before dialing or accepting traffic.
- Confirm endpoint allowlists and chain/network pins are used in production.
- Treat reputation and stake fields as future or beta trust signals unless the production registry logic proves otherwise.

### macOS Configuration, MDM, Signing, and Updates

Primary files:

- `macos/Sources/QuantumLinkKit/MobileConfigSigner.swift`
- `macos/Sources/QuantumLinkKit/PKCS12IdentityLoader.swift`
- `macos/Sources/QuantumLinkKit/PerAppVPNPayload.swift`
- `macos/Sources/QuantumLinkKit/VPNOnDemandRules.swift`
- `macos/Sources/QuantumLinkKit/ManagedConfiguration.swift`
- `macos/mdm/*.mobileconfig.template`
- `macos/scripts/package-macos.sh`
- `macos/scripts/sparkle-*.sh`
- `windows/installer/QuantumLink.wxs`
- `windows/scripts/build-windows.ps1`

Attacker-controlled inputs:

- Imported PKCS#12 files and passphrases, mobileconfig template parameters, MDM payload content, Windows service/installer configuration, app/update artifacts, release workflow secrets, and operator-supplied configuration.

Mitigations:

- Mobileconfig signing uses CMS signed-data with SHA-256.
- PKCS#12 imports require a passphrase and return a `SecIdentity`.
- The project clearly separates unsigned local scaffolding from Developer ID signing and notarization.

Reviewer focus:

- Signing identity compromise is high impact.
- Ensure generated profiles do not silently widen routes, DNS, per-app VPN scope, or kill-switch behavior.
- Ensure update signing and notarization claims are only made after production release automation is complete.

### Diagnostics, Logs, and Support Bundles

Primary files:

- `macos/Sources/QuantumLinkKit/SupportBundleExporter.swift`
- `macos/Sources/QuantumLinkKit/PrivacyDefaults.swift`
- `macos/Sources/QuantumLinkKit/RustTracingForwarder.swift`
- `windows/rust/quantumlink-proto/src/privacy.rs`
- `qlink-core/src/metrics_endpoint.rs`

Attacker-controlled inputs:

- Error strings, endpoint literals, peer IDs, route names, registry identifiers, logs, metrics labels, and operator-exported raw diagnostics.

Mitigations:

- Default support bundles redact IP addresses, endpoint literals, mesh IDs, device aliases, peer IDs, registry peer IDs, and network identifiers.
- Normal log paths use `PrivacyDefaults.redactForLog`.
- Raw diagnostics are explicit opt-in.

Reviewer focus:

- Any new diagnostics field should default to redacted if it can identify a user, device, route, endpoint, wallet, or peer.
- Avoid surfacing crypto verification failure detail to untrusted peers, especially ACL details.

### Adversary Story Summary

Passive HNDL collector:

- Records traffic today and hopes to decrypt it later.
- Mitigated for the ML-KEM handshake design, but current carried packet traffic remains a production gap until session-derived frame keys are installed.

Active MITM:

- Substitutes rendezvous records, certs, endpoints, or registry data.
- Mitigated by signed peer records, peer ID/public-key binding, cert binding in records, inbound assertions, registry binding, and suite validation when production paths require them.

Malicious peer:

- Sends validly signed but harmful traffic, advertises bad routes, probes ACLs, or floods resources.
- Mitigated by route policy, ACLs, registry policy, message caps, fail-closed packet handling, and service-level admission/rate limits. Residual DoS and abuse risk remains until connection quotas, telemetry, and operator abuse workflows are added.

Malicious rendezvous or relay:

- Drops, delays, replays, or poisons discovery and forwarded data.
- Should not be trusted for identity. Signed records, TTLs, and authenticated frames provide integrity boundaries. Metadata and availability remain exposed.

Sybil attacker:

- Creates many peers or registry entries.
- Public-required registry binding raises the bar, but production Sybil resistance, stake policy, reputation scoring, and abuse controls are not complete.

Key compromise adversary:

- Steals a device seed or signing key.
- Can impersonate the node until revocation/rotation takes effect. Keychain storage, `0600` keystores, registry revocation, and identity rotation reduce but do not eliminate impact.

Traffic correlation adversary:

- Links endpoints and timing across direct or relay paths.
- Metadata minimization helps, but QuantumLink does not currently provide anonymity against global observation.

## Severity Calibration (Critical, High, Medium, Low)

Critical severity examples:

- Remote unauthenticated code execution in the tunnel provider, Rust core, relay/rendezvous parser, FFI boundary, or update/profile handling path.
- Any production path that sends protected-route packet plaintext outside the tunnel or bypasses fail-closed behavior.
- Accepting unauthenticated or forged peer records, registry bindings, inbound identities, or packet frames as trusted production peers.
- Production packet-frame confidentiality based on public/static keys or otherwise not derived from negotiated session secrets.
- Exfiltration or unauthorized use of Developer ID, notarization, update-signing, PKCS#12, Dytallix wallet, ML-DSA device, or peer-store keys.

High severity examples:

- Active MITM that can substitute endpoint candidates, QUIC certificates, registry responses, or routes despite signed-record and registry checks.
- Public-required mesh paths that silently fall back to development-optional trust.
- A malicious peer escaping route policy, injecting packets into another peer's protected routes, or bypassing peer ACLs.
- Support bundle or log behavior that leaks device key material, wallet keys, passphrases, raw private endpoints, or stable identifiers without explicit raw-export opt-in.
- Public exposure of development rendezvous or relay binaries while representing them as production-hardened infrastructure.

Medium severity examples:

- DoS through connection floods, oversized JSON/control messages, expensive signature verification, relay abuse, or unbounded queues.
- Replay within accepted freshness windows or missing replay enforcement on a non-production path.
- Stale peer-store fallback that preserves connectivity but weakens freshness expectations.
- Metadata leakage through endpoint candidates, relay timing, public wallet mode, metrics labels, or raw diagnostics.
- Plaintext peer-store operation in environments where local disk read access is a realistic attacker capability.

Low severity examples:

- Local-only development CLI behavior requiring a trusted operator and no production exposure.
- Cosmetic or status-display issues that do not affect routing, trust decisions, secrets, diagnostics, or update/profile installation.
- Redacted diagnostic inaccuracies that do not leak sensitive data or mislead operators about security posture.

Security reviewers should prioritize handshake authentication, negotiated key installation, signed peer-record verification, inbound assertion enforcement, Dytallix public-required fail-closed behavior, route-policy enforcement, FFI memory safety, key lifecycle, diagnostics redaction, DoS resistance, and release/update signing boundaries.
