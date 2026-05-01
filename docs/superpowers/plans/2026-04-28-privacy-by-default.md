# Privacy By Default Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make QuantumLink minimize identity and location metadata by default, without adding a user-facing privacy mode.

**Architecture:** Add small privacy helpers in `QuantumLinkKit`, apply them from the default configuration and UI display paths, normalize packet metadata inside the Rust packet core before encryption, and minimize public peer records at construction time. Keep raw network values only where the tunnel needs them to function.

**Tech Stack:** Swift 6 / SwiftPM / XCTest for app and kit behavior; Rust / Cargo tests for packet core and discovery behavior.

---

## File Structure

- Create `Sources/QuantumLinkKit/PrivacyDefaults.swift`: secure random bytes, overlay address generation, pseudonymous labels, and redaction helpers.
- Modify `Sources/QuantumLinkKit/Models.swift`: make default development configuration use privacy-preserving generated defaults.
- Modify `Sources/QuantumLinkKit/MeshController.swift`: replace simulated local aliases and endpoint displays with pseudonymous relay-shaped data.
- Modify `Sources/QuantumLinkApp/QuantumLinkApp.swift`: display redacted profile and diagnostic network identifiers by default.
- Modify `Sources/QuantumLinkTunnel/PacketTunnelProvider.swift`: redact diagnostic last-error strings before export.
- Modify `rust/qlink-core/src/packet_core.rs`: normalize IPv4 metadata before packet-frame encryption.
- Modify `rust/qlink-core/src/discovery.rs`: rotate aliases from peer key/sequence and publish relay endpoints only by default.
- Add `Tests/QuantumLinkKitTests/PrivacyDefaultsTests.swift`: Swift tests for random overlay and redaction behavior.
- Extend existing Swift and Rust tests to cover changed defaults.

## Tasks

### Task 1: Swift Privacy Defaults

**Files:**
- Create: `Sources/QuantumLinkKit/PrivacyDefaults.swift`
- Test: `Tests/QuantumLinkKitTests/PrivacyDefaultsTests.swift`
- Modify: `Sources/QuantumLinkKit/Models.swift`

- [ ] Write failing XCTest coverage for deterministic overlay allocation inside `100.64.0.0/10`, pseudonymous label shape, and IPv4 redaction.
- [ ] Run: `swift test --filter PrivacyDefaultsTests`; expected failure because `PrivacyDefaults` does not exist.
- [ ] Implement `PrivacyDefaults` with `SecRandomCopyBytes`, deterministic injectable byte generation for tests, `randomOverlayIPv4Address`, `pseudonymousLabel`, and `redactNetworkIdentifiers`.
- [ ] Replace fixed `TunnelConfiguration.defaultDevelopment` identifiers with generated overlay address, pseudonymous mesh ID, pseudonymous device alias, `100.64.0.0/10` protected route, empty DNS search domains, and loopback rendezvous/relay for dev.
- [ ] Run: `swift test --filter PrivacyDefaultsTests`; expected pass.

### Task 2: App And Diagnostics Redaction

**Files:**
- Modify: `Sources/QuantumLinkApp/QuantumLinkApp.swift`
- Modify: `Sources/QuantumLinkTunnel/PacketTunnelProvider.swift`
- Test: `Tests/QuantumLinkKitTests/ConnectionProfileTests.swift`

- [ ] Add failing tests for `ConnectionProfile.redactedDisplayName` and `redactedRouteSummary`.
- [ ] Run: `swift test --filter ConnectionProfileTests`; expected failure because redacted display helpers do not exist.
- [ ] Add profile display helpers that redact source/destination IPs for UI labels while preserving raw values for actual connection attempts.
- [ ] Update profile rows and last-error display to use the redacted helpers.
- [ ] Redact `transport_last_error` in tunnel diagnostic summaries.
- [ ] Run: `swift test --filter ConnectionProfileTests`; expected pass.

### Task 3: Packet Metadata Normalization

**Files:**
- Modify: `rust/qlink-core/src/packet_core.rs`

- [ ] Add failing Rust tests proving outbound IPv4 packets are normalized before encryption/decryption: DSCP/ECN cleared, TTL normalized to 64, non-fragment IPv4 ID cleared, and header checksum recomputed.
- [ ] Run: `cargo test -p qlink-core packet_metadata --manifest-path Cargo.toml`; expected failure because normalization is not implemented.
- [ ] Implement `normalize_ipv4_packet` and call it before `encode_transport_frame`.
- [ ] Update the existing round-trip test to expect normalized bytes rather than exact original bytes.
- [ ] Run: `cargo test -p qlink-core packet_core --manifest-path Cargo.toml`; expected pass.

### Task 4: Discovery Record Minimization

**Files:**
- Modify: `rust/qlink-core/src/discovery.rs`

- [ ] Add failing Rust tests proving `UnsignedPeerRecord::new` ignores cleartext aliases, creates sequence-rotating pseudonymous aliases, and removes host/server-reflexive endpoints from public records.
- [ ] Run: `cargo test -p qlink-core discovery --manifest-path Cargo.toml`; expected failure because current peer records keep aliases and host endpoints.
- [ ] Implement deterministic privacy alias derivation from `peer_id` and `sequence`, and filter public endpoints to relay candidates.
- [ ] Run: `cargo test -p qlink-core discovery --manifest-path Cargo.toml`; expected pass.

### Task 5: Full Verification And Docs

**Files:**
- Modify: `docs/security.md`
- Modify: `docs/architecture.md`

- [ ] Update docs to state privacy minimization is default behavior and not a user mode.
- [ ] Run: `swift test`; expected pass except integration skips that require `QLINK_CORE_DYLIB`.
- [ ] Run: `cargo test -p qlink-core --manifest-path Cargo.toml`; expected pass.
- [ ] Run: `swift build --product QuantumLinkApp`; expected pass.

## Self-Review

- Spec coverage: random overlay IP, packet metadata normalization, discovery minimization, diagnostic/profile redaction, and docs are covered.
- Placeholder scan: no open placeholders are present.
- Type consistency: Swift helpers live in `PrivacyDefaults`; profile display helpers live on `ConnectionProfile`; Rust helpers remain private to packet/discovery modules.
