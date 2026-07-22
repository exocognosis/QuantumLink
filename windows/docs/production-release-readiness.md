# Windows Production Release Readiness

Date: 2026-07-09
Branch: `codex/windows-production-grade-closeout`
Baseline commit: `f8ec6d5135672415cfb9d514e9456f50c68b3cbd`
Worktree: clean at ledger creation
Target: Windows x64 IPv4-overlay private/public mesh

This ledger is the production gate for the Windows release. The beta
runbook remains the operational checklist, but production status is not
earned until every blocking gate below has passing evidence attached from a
Windows host, GitHub Actions run, or signed release artifact bundle.

## Current Status

Windows is an alpha implementation. It has a shared Rust core, Windows
service scaffold, WinUI shell, WiX installer path, and CI coverage for
build/test/smoke slices, but it is not production-ready until the gates in
this file are closed.

## Gate Ledger

| Gate | Status | Required Evidence | Blocking Condition |
|------|--------|-------------------|--------------------|
| Release trust chain | Blocked | GitHub Actions run, signed MSI, timestamp, checksum, SBOM, `windows-release-manifest.json`, `windows-release-evidence.json` | Any unsigned, untimestamped, unverifiable, missing-manifest, missing-SBOM, or checksum-mismatched artifact |
| Wintun provenance | Blocked | Pinned official Wintun URL/SHA, signed `wintun.dll`, bundled license evidence | Missing official source proof, signature proof, or license file |
| Clean install and first run | Blocked | Windows 10 22H2 VM, Windows 11 x64 VM, and physical x64 validation reports | Install, service start, pipe handshake, adapter creation, route/DNS setup, or first connect fails |
| Privileged service boundary | Blocked | Service security validation report covering LocalSystem service, install paths, ProgramData ACLs, DPAPI, and named-pipe ACL | Any writable privileged binary path, weak ProgramData/secrets ACL, or unrestricted production pipe policy |
| WFP kill switch | Blocked | Fail-closed and strict-mode validation reports plus protected-prefix packet captures | Protected-prefix traffic leaks, strict mode starts without WFP, or service-crash posture is undocumented |
| Route and DNS ownership | Blocked | Route/DNS validation report for overlay address, protected prefixes, DNS, MTU, cleanup, sleep/wake, and network switch | Orphan routes, DNS leakage, failed cleanup, or unrecoverable network churn |
| Packet-session key readiness | Blocked | Unit/integration tests proving packets do not leave before authenticated peer-session material exists | Static development key use, cross-peer decrypt acceptance, or plaintext packet emission |
| Dytallix public identity policy | Blocked | Public mesh rejection reports for missing, revoked, suspended, mismatched, and stake/reputation-failed records | Public mesh can operate with identity enforcement disabled or stale invalid registry state |
| Rendezvous and relay production profile | Blocked | `windows/docs/rendezvous-relay-production.md`, `windows/docs/production-evidence.md`, `windows/validation/rendezvous-relay-production-evidence.json`, and production config validation covering auth, TLS, TTL, retention, revocation, monitoring, and incident rollback | Unauthenticated rendezvous/relay, missing TLS, missing retention/revocation policy, excessive metadata exposure, missing sidecar manifest, or blocked sidecar verifier output |
| Diagnostics and support bundle privacy | Blocked | Redaction test report and elevated raw-export audit evidence | Peer IDs, wallet addresses, endpoints, routes, DNS, SSIDs, external IPs, or packet captures leak in default diagnostics |
| Two-host mesh behavior | Blocked | Two Windows hosts, hostile-NAT relay fallback, and macOS-Windows interop reports | Direct mesh, relay fallback, or interop fails |
| Upgrade, repair, rollback, uninstall | Blocked | MSI repair, upgrade, rollback, uninstall, and cleanup reports | Service, adapter, WFP filters, state, or install directories remain unexpectedly after cleanup |

## Evidence Register

Attach evidence by replacing `Pending` with a repository path, GitHub Actions
run URL, release asset name, or manually archived validation bundle.

| Evidence | Current Link |
|----------|--------------|
| Windows release workflow run | Pending |
| Signed MSI and checksum bundle | Pending |
| SBOM | Pending |
| Windows release manifest | Pending |
| Windows release evidence JSON | Pending |
| Windows 10 22H2 VM validation | Pending |
| Windows 11 x64 VM validation | Pending |
| Physical Windows x64 validation | Pending |
| Security validation report | Pending |
| Automated Windows validation manifest | `windows/build/validation/windows-beta-validation-manifest.json` Pending Windows host run |
| Fail-closed leak capture | Pending |
| Strict-mode leak capture | Pending |
| Service-crash kill-switch capture | Pending |
| Two-Windows-machine mesh report | Pending |
| Hostile-NAT relay report | Pending |
| Rendezvous/relay production evidence manifest | `windows/validation/rendezvous-relay-production-evidence.json` Pending |
| macOS-Windows interop report | Pending |
| Dytallix public mesh rejection report | Pending |
| Diagnostics redaction report | `windows/docs/diagnostics-support-bundle.md`; Rust redaction tests pass, Windows UI/host audit Pending |
| Upgrade/repair/rollback/uninstall report | Pending |

## Task 4 Packet-Session Evidence

Local code evidence now covers the packet-session fail-closed default:

- `TunnelConfiguration::packet_core_config_json()` emits
  `requirePeerSession=true` for public, identity-required, or
  rendezvous-backed Windows mesh packet-core construction. Explicit
  local loopback/development smoke config remains exempt so it can test
  packet encode/decode without claiming production key readiness.
- `PacketTunnelCore` and the Windows pump drop protected packets when an
  authenticated peer-session key is unavailable, increment fail-closed
  counters, and emit no transport frame.
- Windows service status and diagnostics expose only operator-safe
  readiness fields (`peerSessionKeyAvailable=false`,
  `peerSessionKeyState=unavailable`) without peer IDs, key material, or
  transport failure details.
- Windows does not yet expose a real authenticated packet-session
  install source to the service. Local echo/development transport does
  not satisfy the production gate and no static development packet key
  is used.

The packet-session key readiness gate remains **Blocked** until a
Windows-host validation report proves that a live two-peer mesh installs
authenticated peer-session metadata, protected packets flow only after
that state is ready, decrypt failures are counted, and no plaintext is
written to Wintun.

## Rendezvous/Relay Production Evidence

Windows production-release mode now requires a repo-relative sidecar manifest
at `windows/validation/rendezvous-relay-production-evidence.json`. The schema
and operator controls are documented in
`windows/docs/rendezvous-relay-production.md` and
`windows/docs/production-evidence.md`.

Run the verifier before setting `production_release=true`:

```sh
ruby windows/scripts/verify-rendezvous-relay-production-evidence.rb \
  --require-ready \
  --expected-sha "$(git rev-parse HEAD)" \
  --expected-ref refs/tags/v1.0.0 \
  windows/validation/rendezvous-relay-production-evidence.json
```

This gate remains **Blocked** until real production endpoint evidence is
supplied. A missing manifest or a manifest with `status: blocked` reports
blockers rather than schema failures, but production-release mode still fails
until every required control has passing redacted evidence.
Passing evidence must be fresh, control-specific, digest-bound to distinct JSON
proof files, bound to the exact release commit/ref and deployment endpoint set,
and preserved inside the checksummed release artifact set.

## Automated Windows Validation Evidence

`windows/scripts/run-beta-validation.ps1` now runs install validation followed
by required security validation and writes a bounded three-file evidence set
under `windows/build/validation/`. Missing or unreadable named-pipe ACL proof,
skipped network checks, missing reports, malformed reports, and contract-only
output all fail closed. Host and user identifiers are redacted by default.

This is code-complete but remains **Blocked** until the scripts execute on the
required Windows 10, Windows 11, and physical x64 hosts. macOS static contract
tests do not substitute for PowerShell execution or Windows-native evidence.

## Diagnostics Privacy Evidence

`windows/docs/diagnostics-support-bundle.md` defines the IPC/UI support export.
The service constructs it from support-only DTO allowlists, caps it at 64 KiB
and 32 ephemeral peer entries, rejects raw-export requests, never includes
logs or packet captures, and emits a bounded fallback instead of panicking.

Rust privacy, size, fallback, compatibility, and IPC tests pass locally. This
gate remains **Blocked** until the Windows UI build and host audit confirm the
shipped binary produces the same default-safe output and no alternate raw
export surface exists.

## Current Release Decision

The current decision is **No-Go**. See
`windows/docs/release-candidate-go-no-go.md` for the code-complete controls,
remaining implementation blockers, required external evidence, and the exact
promotion rule.

## Release Rule

Do not change `windows/version.md` to a production-candidate status until every
blocking gate above is closed with evidence. Windows production claims are
limited to x64 IPv4-overlay private/public mesh use unless separate ARM64,
IPv6, per-app VPN, enterprise ZTNA, or anonymous browsing gates are added and
passed.
