# QuantumLink Windows Version

Version: 0.2.0-windows-alpha
Status: Alpha implementation; production candidate work is tracked in docs/production-release-readiness.md
Date: 2026-06-15

## Baseline

QuantumLink Windows reuses the Rust `qlink-core` (copied from
QuantumLinkOS) for protocol, PQC crypto, peer records, replay
protection, routing helpers, rendezvous, relay, and QUIC/ICE transport.

Implemented in this revision:

- `../qlink-core` - shared core, Windows-clean, produces
  `qlink_core.dll` / `.lib`.
- `rust/quantumlink-proto` - product models + named-pipe IPC schema
  (ports of `Models.swift`, `TunnelMessages.swift`,
  `PrivacyDefaults.swift`).
- `rust/quantumlink-service` - privileged Windows service: Rust packet
  pump (port of `TunnelPacketPump.swift`), strict-mode watchdog, tunnel
  engine, Wintun adapter, WFP kill switch, netsh route/DNS programming,
  DPAPI secret store, IP Helper network observer, named-pipe server,
  SCM integration, loopback smoke test.
- `ui/QuantumLink.Windows` - WinUI 3 dashboard (C#, MVVM), pipe client,
  minimal P/Invoke.
- `installer/` - WiX v4 MSI (service install, wintun.dll packaging,
  uninstall cleanup).
- `.github/workflows/windows-ci.yml` - Windows Rust build/test/smoke
  and WinUI build.

## Release/deployment status

Windows remains alpha. The deployment path for beta is a WiX MSI built from the
release commit, packaged with an officially sourced signed `wintun.dll`,
Authenticode-signed and timestamped, published with a SHA-256 checksum, and
validated cleanly on Windows 10 22H2, Windows 11 x64, and physical x64 Windows
hardware.

Current CI proves the Rust workspace checks/tests, the service smoke test,
release Rust artifact builds, and the WinUI Release build. CI does not yet
prove Wintun sourcing, MSI build/signing, checksum generation, install/uninstall
behavior, WFP/Wintun networking behavior, leak tests, two-machine mesh, or
macOS interop. Those are manual beta gates tracked in
`docs/beta-runbook-windows.md`. Production readiness is tracked in
`docs/production-release-readiness.md`.

## Target architecture

- UI: C# WinUI 3 desktop app (unprivileged, pipe IPC only).
- Privileged runtime: Rust Windows service (LocalSystem) for tunnel
  lifecycle, adapter control, route/DNS updates, and kill-switch
  enforcement.
- Packet adapter: Wintun (`wintun.dll`).
- Secrets: DPAPI machine-scope blobs in ACL'd ProgramData.
- Packaging: signed MSI; winget/enterprise distribution per
  installer/README.md.

## Open items

See "Known gaps / follow-up" in docs/porting-notes.md, the test matrix in
docs/beta-runbook-windows.md, and the production gate ledger in
docs/production-release-readiness.md.
