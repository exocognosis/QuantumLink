# QuantumLink Windows UI (WinUI 3)

Unprivileged dashboard for the QuantumLink Windows service. Talks only
to the named pipe (`\\.\pipe\QuantumLinkService`); performs **no**
admin network operations itself.

## Surface (parity targets with the macOS dashboard)

- [x] Connect / Disconnect
- [x] Platform readiness badge and Windows alpha summary
- [x] Onboarding checklist for service, tunnel, Wintun/WFP policy, and diagnostics export
- [x] Phase, path type, overlay address, protected routes
- [x] Kill-switch indicator
- [x] Identity and route-policy summaries
- [x] Peer list (id, path, overlay address)
- [x] Grouped diagnostics export and peer-id-redacted JSON display
- [x] Help topics for onboarding, peers, diagnostics, crypto, routing, identity, privacy, and troubleshooting
- [ ] Configuration editor (route mode, DNS mode, rendezvous/relay
      servers) — sends `reloadConfiguration`; form pending
- [ ] Live status pushes (schema supports `id: 0` notifications; UI
      currently polls every 2 s)

## Build

```powershell
dotnet build -c Release -p:Platform=x64
```

Requires the Windows App SDK runtime (bundled when published
self-contained; see installer docs).

## Native interop

`Services/QlinkCoreNative.cs` binds only `qlink_core_version` /
`qlink_core_default_suite` from `qlink_core.dll` for the About surface.
All tunnel/mesh/keypair FFI stays inside the privileged service by
design — keep it that way.
