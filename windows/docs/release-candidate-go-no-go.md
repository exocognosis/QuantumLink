# Windows Release Candidate Go/No-Go

Date: 2026-07-09
Branch: `codex/windows-production-finalization`
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
  session readiness; the `peer-session` install is direction- and
  generation-bound to the live handshake,
  leases, rotates on configured time/byte limits, and exposes no binding or
  key material in status/debug output.
- Strict WFP implements separate persistent/boot-time blocks, transactional
  owned-object reconciliation, Wintun-LUID permits, probing, and elevated
  uninstall cleanup without deleting unrelated provider objects.
- A blocked-by-default production matrix workflow binds measured host evidence
  to the exact signed MSI, release manifest, commit, and ref across eight
  Windows/interop lanes.
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

## Remaining Deployment And Host-Proof Blockers

- Strict WFP and authenticated packet-session lifecycle are implemented and
  locally tested, but have not executed on signed Windows 10/11 and physical
  hosts through real Wintun/BFE state.
- Production rendezvous/relay services and their measured control-specific
  proof files are not deployed. The blocked template cannot satisfy the
  production release verifier.
- The repository currently lacks the required signed artifact inputs and
  labeled self-hosted Windows/interop runners, so the production matrix must
  remain blocked rather than manufacture passing evidence.

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
