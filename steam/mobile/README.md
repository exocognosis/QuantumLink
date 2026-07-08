# QuantumLink Steam Mobile Runtime

QuantumLink Steam Mobile is the companion-focused mobile edition inside the
Steam silo. It is a **planning-stage scaffold created for future development**:
a native mobile companion app (iOS/Android) that pairs with the desktop and
SteamOS Steam runtimes to show status, view redacted diagnostics, sync
gamer-profile preferences, and issue account-safe remote-control commands.

Status: Planning scaffold. There is no shippable mobile client yet. The silo
currently ships one compiling model crate plus product docs.

- Product direction: [`docs/planning.md`](docs/planning.md)
- Companion architecture: [`docs/architecture.md`](docs/architecture.md)
- Phased development gates: [`docs/roadmap.md`](docs/roadmap.md)
- Version marker: [`version.md`](version.md)

The mobile silo shares Steam-safe policy, privacy redaction, diagnostics
concepts, and game-profile metadata with the rest of the Steam silo. It reuses
the shared `qlink-core` protocol only where mobile FFI packaging and app-store
policy permit; it does not reimplement the protocol.

## Scope Boundaries

Mobile platforms do not expose the desktop model, so this silo deliberately does
**not** contain:

- Windows Filtering Platform integration or Wintun adapter lifecycle.
- A privileged Windows service or Linux daemon.
- PID-based routing, anti-cheat process detection, or fullscreen game detection.
- Direct Steam launcher/storefront traffic control.

Mobile game tunneling is an opt-in future track gated separately on platform VPN
APIs and app-store VPN policy review. The default companion surface is status,
diagnostics, profile sync, and remote control only.

## Steam Compliance Position

QuantumLink Steam Mobile must not disguise Steam account residence, route Steam
commerce traffic for regional pricing, emulate Steam protocols, or interfere
with Steam Guard, checkout, marketplace, wallet, inventory, or account-security
flows. Steam account, store, wallet, checkout, inventory, marketplace, launcher,
and embedded browser traffic bypass any QuantumLink tunnel by default.

## Components

- `rust/qlink-mobile-proto`: planning-stage companion protocol models (pairing,
  scopes, remote-control commands, redacted status, profile sync) shared between
  the mobile app and the desktop/SteamOS runtimes.
- `docs`: product direction, companion architecture, and roadmap.

Native mobile app shells are not built yet and will be added as
`steam/mobile/ios` and `steam/mobile/android` when the roadmap reaches that gate.

## Development Checks

```sh
cargo check -p qlink-mobile-proto
cargo test -p qlink-mobile-proto
```
