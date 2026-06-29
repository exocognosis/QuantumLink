# Quantum-Specific Threats

QuantumLink is designed for an environment where cryptographically relevant quantum computers (CRQCs) may emerge. Traditional VPNs commonly depend on elliptic-curve or finite-field cryptography that is vulnerable to Shor-class attacks. QuantumLink treats quantum-capable adversaries as a first-class threat model.

This document defines the primary quantum-era attack classes and the corresponding defensive posture for this repository.

## Current Implementation Boundary

QuantumLink is a development baseline, not a production VPN release. The quantum-specific design is strongest in the Rust cryptographic model:

- `PQCHandshake` uses ML-KEM-768 session establishment and rejects the legacy `QLINK-HYBRID-X25519-MLKEM768-HKDFSHA256-v1` suite.
- Device credentials use ML-DSA-65 by default, with SLH-DSA-SHA2-128S support for the FIPS 205 suite path.
- Signed peer records bind device public keys, routes, endpoint candidates, ICE credentials, QUIC certificate material, expiration, and sequence numbers.
- Production peer sessions still need to install negotiated ML-KEM session keys into packet-frame encryption. The current packet-frame encryption path uses development suite-bound keys and must not be represented as production HNDL protection for user traffic.
- QUIC/TLS, Apple signing, notarization, CMS profile signing, GitHub Actions, and third-party infrastructure still rely on conventional platform cryptography. These are outside the primary post-quantum trust boundary unless and until PQ-safe replacements are added.

## Q1. Harvest Now, Decrypt Later (HNDL)

Threat:

Adversaries collect encrypted traffic today with the intention of decrypting it once quantum computing capabilities mature. This is dangerous because exploitation can occur retroactively: traffic intercepted years before a CRQC exists may become readable once legacy cryptographic assumptions fail.

Adversary capabilities:

- Long-term traffic collection.
- Global passive surveillance.
- Backbone-level interception.
- Relay or rendezvous metadata collection.
- Large-scale archival storage.

Potential impact:

- Disclosure of user communications.
- Disclosure of VPN session establishment metadata.
- Disclosure of sensitive business, legal, government, research, or personal traffic.
- Correlation of historical peer activity and endpoint behavior.

Defensive posture:

- The session-establishment design uses ML-KEM-768 rather than classical Diffie-Hellman or elliptic-curve key exchange.
- The Rust crypto layer derives directional session keys from ML-KEM shared secret material and transcript hashing.
- Legacy classical fallback for the QuantumLink handshake is rejected.
- The production target is ephemeral session keys, regular rekeying, and no fallback to quantum-vulnerable key exchange for the primary traffic-protection boundary.

Residual risk:

- Low for the ML-KEM session-establishment design, assuming ML-KEM remains secure and randomness is sound.
- Medium for the current repository baseline until negotiated session keys are installed into packet-frame encryption and production rekeying is implemented.
- Medium where traffic confidentiality depends only on conventional QUIC/TLS or platform cryptography.

## Q2. Quantum Key Recovery

Threat:

A future CRQC capable of executing Shor-class attacks can break RSA, finite-field Diffie-Hellman, and elliptic-curve cryptography.

Adversary capabilities:

- Efficient solution of discrete logarithm problems.
- Efficient factorization of large integers.
- Recovery of classical private keys from public keys.
- Retrospective decryption or impersonation against systems that used classical key establishment or signatures.

Potential impact against classical VPN systems:

- Session decryption.
- Identity impersonation.
- Authentication bypass.
- Collapse of trust in long-lived classical certificates and public keys.

Defensive posture:

- QuantumLink's primary handshake avoids RSA and ECC key establishment.
- Device authentication uses ML-DSA-65 by default and can use SLH-DSA-SHA2-128S on the FIPS 205 suite path.
- Peer IDs are derived from post-quantum device public keys.
- Peer records are signed by post-quantum device credentials and bind the QUIC certificate material used by the transport.

Residual risk:

- Dependent on future cryptanalysis of deployed PQC algorithms.
- Classical platform surfaces remain relevant: QUIC/TLS internals, Apple signing/notarization, CMS profile signing, GitHub Actions, dependency distribution, and maintainer account security are not made quantum-safe merely because the QuantumLink peer identity model is PQC-based.

## Q3. Cryptanalytic Breakthroughs Against PQC

Threat:

Future mathematical advances reduce the security margin of currently approved post-quantum algorithms.

This includes:

- Improvements in lattice reduction algorithms.
- New attacks against Module-LWE.
- New attacks against Module-SIS.
- New attacks against hash-based signature parameters.
- Hybrid classical/quantum cryptanalytic techniques.
- Implementation attacks that make nominally secure primitives exploitable in practice.

Adversary capabilities:

- Unknown and expected to increase over the operational lifetime of the network.
- Potentially private for long periods before public disclosure.

Potential impact:

- Reduced confidentiality margin for ML-KEM-derived sessions.
- Forgery or downgrade pressure against ML-DSA/SLH-DSA identity paths.
- Need for emergency deprecation of affected suites or parameter sets.

Defensive posture:

- QuantumLink uses explicit suite identifiers for FIPS 203, FIPS 204, and FIPS 205 paths.
- Unsupported suite identifiers are rejected.
- The codebase already separates key establishment, signature algorithms, peer records, packet framing, and registry binding enough to support future algorithm upgrades without rewriting every product surface.
- Production readiness should include algorithm deprecation policy, key migration procedures, and compatibility windows for multi-generation identity transitions.

Residual risk:

- Medium. This is the largest long-term uncertainty in any PQC system.
- Critical if a deployed primitive is broken before migration and revocation paths are available.

## Q4. Quantum Identity Forgery

Threat:

An attacker obtains the ability to forge signatures generated by a deployed PQC signature scheme or finds an implementation bug that makes forgery practical.

Potential impact:

- Node impersonation.
- Malicious peer-record publication.
- Route manipulation.
- Unauthorized network participation.
- Registry-binding abuse.
- Trust collapse for public meshes using the affected signature scheme.

Defensive posture:

- Device signatures cover peer records, including endpoint candidates, routes, expiration, ICE credentials, sequence numbers, and QUIC certificate material.
- Peer IDs must match the hash of the embedded device public key.
- Inbound identity assertions require a fresh signed assertion for the expected mesh.
- Dytallix registry binding can reject missing, revoked, suspended, expired, or mismatched node records.
- Peer ACLs can provide an additional operator-controlled deny/allow layer.

Required operational posture:

- Emergency algorithm deprecation.
- Identity revocation.
- Device-key rotation.
- Registry record rotation.
- Migration from affected signatures to a replacement suite.
- Clear operator guidance for mixed-suite transition periods.

Residual risk:

- Low to medium while deployed PQC signatures remain secure and revocation works.
- Critical if a signature scheme is broken and old trust anchors remain accepted.

## Q5. Long-Horizon Data Exposure

Threat:

Some information retains value for decades. Even if immediate exploitation is impossible, future decryption may still create significant harm.

Examples:

- Government communications.
- Legal records.
- Intellectual property.
- Research data.
- Personal identity information.
- Medical, financial, or safety-sensitive communications.
- Business strategy, source code, credentials, or incident-response data.

Defensive posture:

- QuantumLink treats confidentiality requirements beyond the Y2Q horizon as requiring PQC protection from the moment of transmission.
- Security decisions should be based on data longevity, not only current attacker capability.
- HNDL risk should be considered even for passive adversaries that cannot decrypt traffic today.

Residual risk:

- Low once production traffic encryption uses negotiated PQ session keys and rekeys appropriately.
- Medium in the current development baseline because production packet-key installation is still incomplete.

## Q6. Quantum Downgrade and Legacy Fallback

Threat:

An active attacker attempts to force a peer into a classical, hybrid, legacy, or unauthenticated mode that weakens quantum resistance.

Adversary capabilities:

- Modifies suite identifiers.
- Replays older records or configs.
- Strips PQC capability indicators.
- Induces fallback to local development modes or conventional transport-only security.

Potential impact:

- Loss of HNDL protection.
- Classical MITM or future key recovery.
- Misleading "connected" state while traffic is protected only by non-PQ mechanisms.

Defensive posture:

- `crypto.rs` validates protocol version and supported suite identifiers.
- The legacy hybrid suite identifier is rejected.
- Peer records and inbound assertions bind the expected mesh and peer identity.
- Reviewers should ensure UI, configuration, and transport fallback behavior cannot silently downgrade production deployments.

Residual risk:

- Low for the core handshake suite validation.
- Medium across the product until all production traffic paths enforce negotiated PQ session keys and reject development-only transports.

## Q7. Quantum-Relevant Supply Chain and Platform Trust

Threat:

QuantumLink may protect peer identity and traffic with PQC while still depending on classical cryptography elsewhere in the supply chain or platform.

Examples:

- Apple Developer ID signing and notarization.
- CMS-signed configuration profiles.
- Sparkle or future update signing.
- GitHub Actions, package registries, and dependency downloads.
- QUIC/TLS internals and certificate formats.
- Maintainer SSH/Git signing keys and release credentials.

Potential impact:

- A future quantum adversary may attack release authenticity, update distribution, or platform trust even if the peer protocol is PQ-safe.
- A compromised update path can defeat endpoint security without breaking ML-KEM or ML-DSA.

Defensive posture:

- Treat the peer protocol and the release/platform supply chain as separate trust boundaries.
- Add post-quantum update manifest signing before claiming a fully quantum-resistant distribution.
- Rotate and inventory signing keys.
- Keep dependency update automation and review active.
- Document which surfaces remain classical.

Residual risk:

- Medium until update, package, and platform trust receive explicit post-quantum protections or compensating controls.

## Quantum Security Assumptions

QuantumLink assumes:

- ML-KEM remains resistant to known classical and quantum attacks at the selected parameter set.
- ML-DSA remains resistant to known classical and quantum attacks at the selected parameter set.
- SLH-DSA remains resistant to known classical and quantum attacks at the selected parameter set.
- SHA-256, HKDF-SHA-256, and ChaCha20-Poly1305 remain suitable for their roles.
- Secure random number generation is available.
- No practical quantum attacks currently exist against deployed parameter sets.
- Operators can rotate keys, revoke identities, and update clients when algorithms or implementations need migration.

QuantumLink does not assume:

- Quantum computers will arrive slowly.
- Adversaries will disclose cryptanalytic breakthroughs.
- Legacy cryptography can be safely retained during migration.
- Conventional platform signing, TLS, package distribution, or maintainer-account security becomes post-quantum merely because the peer protocol uses PQC.
- HNDL risk is only relevant after a CRQC exists.

## Quantum Security Philosophy

QuantumLink is engineered under a simple assumption:

A sufficiently capable quantum adversary should not be able to decrypt historical protected traffic, impersonate legitimate nodes, or compromise mesh trust solely through advances in quantum computing.

The system therefore prioritizes quantum-resistant confidentiality, authentication, downgrade resistance, and cryptographic agility over compatibility with legacy cryptographic infrastructure.

For security review, prioritize:

1. Negotiated session-key installation into packet-frame encryption.
2. Removal or containment of development-only keying and transport paths in production.
3. ML-KEM transcript binding and downgrade resistance.
4. ML-DSA and SLH-DSA signature verification.
5. Peer-record and inbound-identity canonicalization.
6. Key rotation, revocation, and migration procedures.
7. Post-quantum update/signing roadmap.
8. Documentation that clearly distinguishes PQ-protected surfaces from classical platform surfaces.
