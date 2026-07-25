# Windows Production Release Readiness

Date: 2026-07-24
Branch: `codex/windows-production-evidence-batch`
Baseline commit: `9df393163e94748978cea222597094ee32cf04d5`
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
| WFP kill switch | Blocked | Signed fail-closed and strict-mode host reports, BFE object inventory, reboot/service-crash proof, and protected-prefix packet captures | Protected-prefix traffic leaks, persistent objects fail to survive/reconcile, cleanup mutates non-product objects, or host evidence is absent |
| Route and DNS ownership | Blocked | Route/DNS validation report for overlay address, protected prefixes, DNS, MTU, cleanup, sleep/wake, and network switch | Orphan routes, DNS leakage, failed cleanup, or unrecoverable network churn |
| Packet-session key readiness | Blocked | Local authenticated two-handle rotation tests plus signed Windows/Wintun two-host evidence | Readiness installs without an authenticated handshake, stale generation clears current state, rotation fails, cross-peer acceptance occurs, or Windows-host evidence is absent |
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
| Production validation matrix contract | `windows/validation/contracts/windows-production-validation-matrix.json` |
| Production validation workflow | `.github/workflows/windows-production-validation.yml` |
| Production validation preflight plan | Pending GitHub Actions run |
| Production prerequisite audit | `windows/scripts/audit-windows-production-prerequisites.rb` Pending ready audit |

## Task 4 Packet-Session Evidence

Local code evidence now covers live authenticated packet-session installation:

- `TunnelConfiguration::packet_core_config_json()` emits
  `requirePeerSession=true` for public, identity-required, or
  rendezvous-backed Windows mesh packet-core construction. Explicit
  local loopback/development smoke config remains exempt so it can test
  packet encode/decode without claiming production key readiness.
- Successful authenticated PQC handshakes publish redacted,
  direction-specific readiness leases bound to the transcript, peer ids,
  role, generation, expiry, and byte limit. Traffic keys remain exclusively
  inside `PqcFrameProtector`.
- The Windows engine installs ready/cleared events into separate inbound and
  outbound packet-core slots. Stale directional clears cannot remove a newer
  generation, and multi-peer packet routing is rejected as ambiguous.
- `CryptoPolicy.rekeyAfterSeconds` and `rekeyAfterBytes` drive session
  rotation. The native UDP listener accepts successive authenticated
  sessions on the stable responder socket.
- `PacketTunnelCore` and the Windows pump drop protected packets when an
  authenticated peer session is unavailable, expired, or over its byte
  budget, increment fail-closed counters, and emit no transport frame.
- Windows service status and diagnostics expose only operator-safe
  readiness fields (`peerSessionKeyAvailable=false`,
  `peerSessionKeyState=unavailable`) without peer IDs, key material, or
  transport failure details.
- A two-handle native UDP test proves bidirectional authenticated payloads and
  fresh generations after forced byte-limit rotation. Local
  echo/development transport remains outside the production gate.

The packet-session key readiness gate remains **Blocked** until a
signed Windows-host validation report proves the same path through Wintun on
two physical/VM hosts, including forced rotation, reconnect, decrypt failure,
service restart, and no plaintext emission.

## Strict WFP Lifecycle Evidence

The repository now implements separate boot-time and persistent strict blocks,
a persistent provider/sublayer linked to `QuantumLinkService`, dynamic permits
bound to a nonzero Wintun LUID, transactional owned-object reconciliation,
read-only probing, explicit elevated cleanup, and major-upgrade preservation.
Service startup reconciles persisted strict routes before reporting Running,
and cleanup refuses incompatible provider/sublayer metadata. Local
lifecycle/ownership tests and installer contracts pass.

The gate remains **Blocked** until signed Windows hosts prove BFE inventory,
boot-to-persistent transition, service-crash survival, stale-LUID
reconciliation, protected-prefix and DNS no-leak captures, upgrade/rollback,
uninstall cleanup, and preservation of unrelated WFP objects.

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

`windows/deployment/rendezvous-relay-production.template.json` is the
blocked-by-default deployment contract. The generator only emits passing
control evidence from explicit measured assertions with source SHA-256
bindings; it cannot convert placeholders or contract-only data into a pass.
`windows/scripts/collect-rendezvous-relay-production-measurements.rb` bridges
the live public-edge smoke manifest into the generator's measurement schema,
but it only auto-seeds the assertions that smoke actually proves. Operator
drill source files are still required for certificate rotation,
signed-record rejection, rate-limit denial, abuse-log redaction, revocation,
retention, key rotation, endpoint rotation, and incident shutdown.

## Production Host Matrix

`.github/workflows/windows-production-validation.yml` preflights the exact
release commit/ref, signed artifact inventory, signing inputs, control-plane
DNS, and live self-hosted runner labels. It schedules only lanes whose
prerequisites exist; otherwise it uploads a bounded blocked plan without
hanging. The contract defines Windows 10 22H2 VM, Windows 11 x64 VM, physical
x64, two-host direct, hostile-NAT relay, strict-WFP leak/crash,
upgrade/rollback/uninstall, and macOS-Windows interop lanes. Passing lane
evidence must be measured by the provisioned host harness and digest-bound to
the signed MSI and release manifest.

`windows/scripts/audit-windows-production-prerequisites.rb` records the live
external gate state for self-hosted validation runners, release/matrix secrets,
Wintun variables, and control-plane DNS. Run it before production validation:

```sh
ruby windows/scripts/audit-windows-production-prerequisites.rb \
  --output windows/build/validation/windows-production-prerequisites-audit.json
```

Use `--require-ready` only when preparing a production publication; missing
runners, secrets, explicit timestamp configuration, Wintun variables, or DNS
records must block instead of being converted into placeholder evidence.
`windows-release.yml` also requires a successful Windows Production Validation
Matrix run id, bound to the exact release commit, before publishing production
artifacts to a GitHub Release.

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
