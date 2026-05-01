# Security Notes

QuantumLink assumes passive observers, active on-path attackers, malicious rendezvous or relay services, compromised relay metadata visibility, stolen devices, and curious local networks.

Implemented baseline:

- Hybrid session establishment with X25519 + ML-KEM-768.
- Transcript-bound HKDF-SHA-256 key derivation.
- Anti-downgrade suite binding through versioned FIPS 203, FIPS 204, and FIPS 205 suite identifiers.
- ML-DSA-65 and SLH-DSA-SHA2-128S device credential signing and verification.
- Authenticated packet-frame encryption for the Rust packet core using suite-bound AEAD keys.
- Signed, expiring peer records for rendezvous publication.
- Monotonic packet-number replay protection.
- Keychain-backed Swift secret storage helpers.
- Fail-closed tunnel scaffold for protected routes when the data plane is unavailable.
- Privacy-preserving defaults without a user-facing mode: overlay addresses in `100.64.0.0/10` allocated through a cryptographically seeded recursive permutation, pseudonymous mesh/device labels, no DNS search-domain default, redacted app/diagnostic network identifiers, and simulated peers that avoid hostnames or LAN endpoints.
- Packet metadata normalization before frame encryption: DSCP/ECN is cleared, TTL is normalized, non-fragment IPv4 IDs are cleared, and IPv4 header checksums are recomputed.
- Public peer-record minimization: clear aliases are replaced with sequence-rotating pseudonyms and rendezvous publication keeps relay candidates only by default.

Not yet production-complete:

- Production QUIC DATAGRAM peer transport beyond the local development facade.
- Production peer-to-peer packet key installation from negotiated session secrets.
- Full ICE/STUN/TURN candidate gathering and nomination beyond local host/STUN parser scaffolding.
- Notarized Developer ID app and extension bundles.
- Managed Device Attestation and SSO integration.
- Full update signing pipeline with a post-quantum manifest layer.
- Hardened public relay abuse controls.
- Full anonymity guarantees. QuantumLink minimizes app/control-plane metadata by default, but outer transport IPs, relay timing, account context, and endpoint behavior can still identify users unless a future relay/egress architecture is built specifically for that threat model.

The development rendezvous and relay binaries are local protocol tools. Do not expose them on the public internet without adding TLS, authentication policy, rate limits, abuse monitoring, durable revocation, and retention controls.
