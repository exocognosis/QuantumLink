# QuantumLink Windows Version

Version: 0.2.0-windows-alpha
Status: Implemented scaffold — Rust service + proto + WinUI 3 UI + installer/CI
Date: 2026-06-11

## Baseline

QuantumLink Windows reuses the Rust `qlink-core` (copied from
QuantumLinkOS) for protocol, PQC crypto, peer records, replay
protection, routing helpers, rendezvous, relay, and QUIC/ICE transport.

Implemented in this revision:

- `../qlink-core` — shared core, Windows-clean, produces
  `qlink_core.dll` / `.lib`.
- `rust/quantumlink-proto` — product models + named-pipe IPC schema
  (ports of `Models.swift`, `TunnelMessages.swift`,
  `PrivacyDefaults.swift`).
- `rust/quantumlink-service` — privileged Windows service: Rust packet
  pump (port of `TunnelPacketPump.swift`), strict-mode watchdog, tunnel
  engine, Wintun adapter, WFP kill switch, netsh route/DNS programming,
  DPAPI secret store, IP Helper network observer, named-pipe server,
  SCM integration, loopback smoke test.
- `ui/QuantumLink.Windows` — WinUI 3 dashboard (C#, MVVM), pipe client,
  minimal P/Invoke.
- `installer/` — WiX v4 MSI (service install, wintun.dll packaging,
  uninstall cleanup).
- `.github/workflows/windows-ci.yml` — Windows build/test/smoke +
  cross-target check.

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

See "Known gaps / follow-up" in docs/porting-notes.md and the test
matrix in docs/beta-runbook-windows.md.
