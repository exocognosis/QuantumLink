# Security Notes

QuantumLink assumes passive observers, active on-path attackers, malicious rendezvous or relay services, compromised relay metadata visibility, stolen devices, and curious local networks.

Implemented baseline:

- App-layer ML-KEM-768 session establishment without a classical key-exchange fallback.
- Transcript-bound SHAKE256 key derivation.
- Anti-downgrade suite binding through versioned FIPS 203, FIPS 204, and FIPS 205 suite identifiers.
- ML-DSA-65 and SLH-DSA-SHAKE-128S device credential signing and verification.
- App-layer PQC frame protection for direct mesh links using ML-KEM session keys, SHAKE256 masking/authentication, and replay rejection.
- Packet core framing only; the packet core is not a classical encryption boundary.
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
- Packet metadata normalization before packet-frame emission: DSCP/ECN is cleared, TTL is normalized, non-fragment IPv4 IDs are cleared, and IPv4 header checksums are recomputed.
- Packet-session gating is observable through FFI metrics: peer-session-unavailable drops and replay drops are exposed to macOS, and the packet pump counts missing-session drops as fail-closed.
- Public peer-record minimization: clear aliases are replaced with sequence-rotating pseudonyms and rendezvous publication keeps relay candidates only by default.
- Raw QUIC, raw relay, and legacy mesh loopback smoke paths fail closed unless an end-to-end app-layer PQC session exists.
- Native UDP carrier with fragmented authenticated control-message support; default live mesh direct dialing and inbound response use this non-TLS carrier with the app-layer PQC session wire, and tests prove both sides establish matching ML-KEM/SHAKE keys.
- Relay fallback is end-to-end PQC only: when direct native UDP probes fail, the connector can establish the same signed inbound assertion, ML-KEM session, and protected-frame path through a configured or signed `quantum_link_relay` carrier candidate. Raw unauthenticated relay fallback remains rejected.
- Candidate gathering covers host and STUN server-reflexive candidates in default builds, plus TURN relay candidates when `turn-relay` is explicitly enabled. Gather failures are reported per server without suppressing lower-latency direct candidates. Published TURN relay candidates are consumed as UDP relay-assisted carrier targets when live; the QuantumLink app-relay carrier remains distinct.
- A public-edge deployment runbook and smoke harness cover allowlisted
  rendezvous, STUN, TURN allocation, and end-to-end PQC relay-fallback proof
  while open-internet rendezvous/relay TLS/auth remains unfinished.
- Default `qlink-core` builds keep the legacy Quinn/rustls/rcgen carrier dependencies out of the compiled dependency graph; the dev QUIC carrier remains available only with `--features dev-quic-carrier`.

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

Migration note: peer IDs now derive from SHAKE256 over the device public
key material. Devices enrolled under earlier SHA-256-derived peer IDs
must be re-enrolled, republished to rendezvous, and updated in remote
peer configs, ACLs, and registry records. Treat existing peer-store
caches as cold data during this migration: stale signed records keyed by
old peer IDs should fail verification against the new
`DevicePublicKey::peer_id()` value, and operators should purge or
regenerate `peers.json` after rolling the new build.

Not yet production-complete:

- Open-internet rendezvous/QuantumLink-relay TLS, authentication policy, rate limits, abuse monitoring, revocation, and retention controls beyond the current allowlisted/tunneled public-edge runbook.
- Long-lived TURN allocation lifecycle and RFC-complete ICE nomination against deployed public infrastructure beyond the current deterministic candidate ordering and connectivity-check paths.
- Notarized Developer ID app and extension bundles.
- Managed Device Attestation and SSO integration.
- Full update signing pipeline with a post-quantum manifest layer.
- Production Dytallix mainnet or hardened production registry trust root.
- Hardened public relay abuse controls.
- Removal of non-transport platform classical primitives: macOS/Windows privacy redaction still uses SHA-256-derived aliases; macOS CMS/profile signing still uses platform SHA-256 and interacts with platform AES behavior.
- Removal of every classical primitive from every build/tooling path. Default `qlink-core` builds should exclude the dev Quinn/rustls/aws-lc/ring carrier graph, but optional dev-carrier builds, platform signing/redaction helpers, and lockfile contents remain outside a full zero-classical claim.
- Full anonymity guarantees. QuantumLink minimizes app/control-plane metadata by default, but outer transport IPs, relay timing, account context, and endpoint behavior can still identify users unless a future relay/egress architecture is built specifically for that threat model.

The development rendezvous and relay binaries are local protocol tools. Do not expose them to the open internet without adding TLS, authentication policy, rate limits, abuse monitoring, durable revocation, retention controls, and production Dytallix registry pinning for public meshes. For public validation before those controls land, use the allowlisted/tunneled edge runbook in `public-infra-runbook.md`.

For repository-scoped reviewer guides, see `../THREAT_MODEL.md` and `../QUANTUM_THREATS.md`.
