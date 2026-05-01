# Recursive Overlay Allocator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace flat overlay IP masking with a cryptographically seeded recursive address-space permutation.

**Architecture:** Keep `SecRandomCopyBytes` as the entropy source. Add a `RecursiveOverlayAllocator` to `PrivacyDefaults.swift` that recursively partitions the 22-bit host space of `100.64.0.0/10`, uses SHA-256 keyed branch swaps at each level, and returns collision-checked host offsets. `PrivacyDefaults.randomOverlayIPv4Address` becomes a thin integration layer over the allocator.

**Tech Stack:** Swift 6, SwiftPM, XCTest, CryptoKit SHA-256.

---

### Task 1: Recursive Allocator Tests

**Files:**
- Modify: `Tests/QuantumLinkKitTests/PrivacyDefaultsTests.swift`

- [x] Add tests for deterministic recursive permutation, seed diffusion, output range, reserved address rejection, and `randomOverlayIPv4Address` requesting 16 bytes of seed material.
- [x] Run `swift test --filter PrivacyDefaultsTests`; expected failure because `RecursiveOverlayAllocator` does not exist and the current allocator asks for 4 bytes.

### Task 2: Allocator Implementation

**Files:**
- Modify: `Sources/QuantumLinkKit/PrivacyDefaults.swift`

- [x] Add `RecursiveOverlayAllocator` with `hostBitCount = 22`, keyed recursive branch swaps, SHA-256 branch decisions, and deterministic rank derivation from seed bytes.
- [x] Change `randomOverlayIPv4Address` to request 16 seed bytes, generate recursive candidates, reject network/broadcast/gateway/collision addresses, and fall back to bounded linear probing only after recursive attempts are exhausted.
- [x] Run `swift test --filter PrivacyDefaultsTests`; expected pass.

### Task 3: Verification

**Files:**
- Modify: `docs/security.md`
- Modify: `docs/architecture.md`

- [x] Update docs to describe recursive keyed overlay allocation.
- [x] Run `swift test`; expected pass with the existing integration skips.
- [x] Run `swift build --product QuantumLinkApp`; expected pass.
- [x] Run `./script/build_and_run.sh --verify`; expected pass and freshly relaunched `QuantumLinkApp` process.

## Self-Review

- Spec coverage: keyed recursive allocator, CSPRNG entropy, fractal-style recursive partitioning, collision checks, and docs are covered.
- Placeholder scan: no placeholders remain.
- Type consistency: allocator APIs are named `RecursiveOverlayAllocator`, `hostOffset(forRank:attempt:)`, and `candidateHostOffsets(limit:)`.
