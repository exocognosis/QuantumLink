# Windows Release Candidate Go/No-Go

Date: 2026-07-09
Branch: `codex/windows-production-grade-closeout`
Target: Windows x64, IPv4 overlay, private/public mesh
Decision: **NO-GO**

This is the release decision for the closeout branch. The branch materially
raises the Windows implementation and evidence bar, but it is not a production
candidate while any blocker below remains open.

## Completed Repository Controls

- Production release workflow requires signing, timestamping, install
  validation, SBOM, release manifest/evidence, checksums, and fresh
  release-bound rendezvous/relay proof before artifact publication.
- Privileged service configuration includes explicit pipe security policy,
  IP Helper route ownership, strict WFP fail-closed refusal, and no production
  `netsh` fallback.
- Packet processing emits no protected traffic before authenticated peer
  session readiness and exposes no key or peer material in status.
- Public mesh configuration enforces verified Dytallix identity, registry/RPC
  pinning, zero stale-proof grace, and stable rejection categories.
- Rendezvous/relay evidence is fresh, control-specific, digest-bound to the
  release commit/ref, deployment, and endpoint set, and shipped in the
  checksummed release evidence set.
- Windows validation orchestration emits bounded, redacted component reports
  and fails closed for missing, skipped, malformed, or unreadable evidence.
- Support export uses a closed DTO allowlist, bounded fallback, stable failure
  categories, no raw mode, and no logs, payloads, addresses, routes, DNS, SSIDs,
  packet captures, secrets, wallets, or raw peer identifiers.

## Remaining Implementation Blockers

- Strict WFP still refuses startup because persistent/boot-time filter install,
  upgrade, rollback, and uninstall lifecycle is not implemented and proven.
- The Windows service has no live authenticated transport source that installs
  peer-session keys into the packet pump; fail-closed readiness is implemented,
  but a production two-peer data path is not yet established.
- Production rendezvous/relay services and their control-specific proof files
  are not deployed in this repository. The default production evidence
  manifest is intentionally absent, so production release mode fails.

## Required External Evidence

- Official pinned Wintun archive, signed DLL verification, and license bundle.
- Authenticode signing and timestamping with the approved publisher identity.
- Clean Windows 10 22H2, Windows 11 x64, and physical x64 install/first-run
  reports, including PowerShell runtime validation and WinUI Release build.
- Fail-closed, strict-mode, service-crash, route/DNS, sleep/wake, and network
  switch packet captures with no protected-prefix leakage.
- Two-Windows-host direct mesh, hostile-NAT relay fallback, and macOS-Windows
  interoperability reports using authenticated packet-session material.
- MSI upgrade, repair, rollback, uninstall, and residual cleanup evidence.
- Windows-host support-bundle audit confirming the shipped UI/service exposes
  only the documented default-safe export.

## Promotion Rule

Change this decision to **GO** only when every gate in
`windows/docs/production-release-readiness.md` is `Passed`, every evidence link
resolves to an immutable run or checksummed artifact, the default production
evidence verifier exits zero with exact release binding, and
`windows/version.md` is deliberately promoted from alpha. Local static tests,
contract-only reports, blocked manifests, or fail-closed refusal are not
production proof.
