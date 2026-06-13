# Security Notes

QuantumLink assumes passive observers, active on-path attackers, malicious rendezvous or relay services, compromised relay metadata visibility, stolen devices, and curious local networks.

Implemented baseline:

- Hybrid session establishment with X25519 + ML-KEM-768.
- Transcript-bound HKDF-SHA-256 key derivation.
- Anti-downgrade suite binding through versioned FIPS 203, FIPS 204, and FIPS 205 suite identifiers.
- ML-DSA-65 and SLH-DSA-SHA2-128S device credential signing and verification.
- Authenticated packet-frame encryption for the Rust packet core using suite-bound AEAD keys.
- Signed, expiring peer records for rendezvous publication.
- Dytallix-backed public mesh identity checks: public meshes require an active
  matching registry record, while private/development meshes can keep registry
  verification optional.
- Public mesh Dytallix registry configuration requires pinned network ID, chain
  ID, and trusted RPC endpoints so an untrusted endpoint cannot silently become
  the root of verification.
- Monotonic packet-number replay protection.
- Keychain-backed Swift secret storage helpers.
- Fail-closed tunnel scaffold for protected routes when the data plane is unavailable.
- Privacy-preserving defaults without a user-facing mode: overlay addresses in `100.64.0.0/10` allocated through a cryptographically seeded recursive permutation, pseudonymous mesh/device labels, no DNS search-domain default, redacted app/diagnostic network identifiers, and simulated peers that avoid hostnames or LAN endpoints.
- Packet metadata normalization before frame encryption: DSCP/ECN is cleared, TTL is normalized, non-fragment IPv4 IDs are cleared, and IPv4 header checksums are recomputed.
- Public peer-record minimization: clear aliases are replaced with sequence-rotating pseudonyms and rendezvous publication keeps relay candidates only by default.

Dytallix wallet and registry boundary:

- QuantumLink stores only non-secret enrollment metadata: endpoint, registry
  contract, wallet name, public wallet address, peer ID, and enrollment status.
- Wallet private keys, passphrases, and keystore paths stay outside
  `TunnelConfiguration`, `UserDefaults`, support bundles, and NetworkExtension
  provider configuration.
- The Wallet/Faucet action opens `https://dytallix.com/build/wallet` for wallet
  creation, unlock, funding checks, and testnet faucet cooldown handling.
- Public Wallet mode is opt-in. Verified mode proves registry membership without
  displaying the wallet address in normal discovery/status surfaces.
- Dytallix testnet verification is beta trust infrastructure. It proves
  interoperability and wallet/device binding, but it is not production-grade
  Sybil resistance or a durable reputation root.
- Default support bundles redact mesh IDs, device aliases, peer IDs, registry
  peer IDs, IP addresses, and endpoint literals. Raw diagnostics require
  explicit operator/user opt-in.

Party Mesh invite boundary:

- Party Mesh join codes contain non-secret routing metadata needed to join a game
  party: mesh ID, host alias, host overlay address, rendezvous endpoints, relay
  endpoints, game port, identity mode, and mesh trust policy.
- Party Mesh join codes do not contain wallet private keys, passphrases, Dytallix
  keystore paths, registry contract secrets, peer-store private keys, or live
  packet/session keys.
- Treat Party Mesh codes as invite material. They are safe from key disclosure,
  but they can reveal a party mesh name, host overlay address, and discovery
  endpoints to anyone who receives the code.

Not yet production-complete:

- Production QUIC DATAGRAM peer transport beyond the local development facade.
- Production peer-to-peer packet key installation from negotiated session secrets.
- Full ICE/STUN/TURN candidate gathering and nomination beyond local host/STUN parser scaffolding.
- Notarized Developer ID app and extension bundles.
- Managed Device Attestation and SSO integration.
- Full update signing pipeline with a post-quantum manifest layer.
- Production Dytallix mainnet or hardened production registry trust root.
- Hardened public relay abuse controls.
- Full anonymity guarantees. QuantumLink minimizes app/control-plane metadata by default, but outer transport IPs, relay timing, account context, and endpoint behavior can still identify users unless a future relay/egress architecture is built specifically for that threat model.

The development rendezvous and relay binaries are local protocol tools. Do not expose them on the public internet without adding TLS, authentication policy, rate limits, abuse monitoring, durable revocation, and retention controls.
