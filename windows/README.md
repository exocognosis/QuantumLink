# QuantumLink for Windows

Windows-native port of QuantumLink: a post-quantum encrypted mesh VPN.
The product core (`qlink-core`, Rust) is shared verbatim with the macOS
app; everything Apple-specific (SwiftUI, NetworkExtension, Keychain,
Sparkle) is replaced with Windows-native equivalents.

## Architecture

```
WinUI 3 app (unprivileged)            ui/QuantumLink.Windows
  |
  | named pipe \\.\pipe\QuantumLinkService  (newline-delimited JSON,
  |                                          schema: rust/quantumlink-proto)
  v
QuantumLink Windows Service (LocalSystem)   rust/quantumlink-service
  |  - packet pump (port of TunnelPacketPump.swift)
  |  - WFP kill switch (replaces NE route ownership)
  |  - DPAPI secret store (replaces Keychain)
  |  - route/DNS programming (replaces NEIPv4Settings)
  |  - IP Helper network observer (replaces NWPathMonitor)
  v
Wintun adapter (Layer 3 TUN, wintun.dll)
  |
  v
qlink-core (Rust, linked natively — no FFI inside the service)
  |  PQC crypto (ML-KEM-768/ML-DSA-65), packet core, replay protection,
  |  QUIC transport, relay, rendezvous, STUN/ICE, peer store
  v
QuantumLink mesh peers
```

## Repository layout

| Path | Contents |
|------|----------|
| `../qlink-core` | Shared protocol core (shared with macOS; produces qlink_core.dll / .lib / qlink_core.dll.lib) |
| `rust/quantumlink-proto` | Product models + IPC schema (port of `Models.swift`/`TunnelMessages.swift`) |
| `rust/quantumlink-service` | Privileged Windows service (Wintun, WFP, DPAPI, named pipe) |
| `ui/QuantumLink.Windows` | WinUI 3 dashboard (C#, unprivileged, pipe client) |
| `installer/` | WiX v4 MSI + packaging docs |
| `docs/` | Architecture, porting notes, beta runbook |
| `.github/workflows/` | Windows CI (build/test/smoke + cross-check from Linux) |

## Build

Rust (any host — Windows-only code is `cfg`-gated):

```sh
cargo test --workspace          # cross-platform engine/pump/IPC tests
cargo run -p quantumlink-service -- smoke   # data-plane fail-closed smoke
```

On Windows additionally:

```powershell
cargo build --release -p quantumlink-service -p qlink-core
dotnet build ui\QuantumLink.Windows -c Release
```

Full packaging: see [installer/README.md](installer/README.md).

## Development on Windows without the installer

```powershell
# elevated terminal (Wintun + WFP + routes need admin)
cargo run -p quantumlink-service -- run      # console mode, Ctrl+C to stop
# then launch the UI, or poke the pipe by hand
```

Service management once installed:

```powershell
quantumlink-service install | uninstall | start | stop
```

## Security model

- The UI is unprivileged and can only talk to the named pipe; the
  service performs all admin-level network changes.
- Kill switch: protected prefixes are blocked at the WFP layer except
  through the Wintun adapter; the packet pump independently fails
  closed; `strict` mode also refuses startup without the kill switch
  and tears the tunnel down after a sustained transport outage
  (watchdog, 30 s).
- Secrets (device-keypair seed, peer-store key) are DPAPI-wrapped
  machine-scope blobs under an ACL'd ProgramData directory.
- Diagnostics redact `qlink_*` peer identifiers (same rules as macOS
  `PrivacyDefaults`).

See [docs/porting-notes.md](docs/porting-notes.md) for the complete
macOS→Windows mapping and current gaps.
