# QuantumLink — Steam silo

The **Steam gamer edition**: a Steam-safe, low-latency edition of
QuantumLink for game traffic, plus a mobile companion. Status: planning
scaffold — no implementation code yet.

This silo is distinct from [`../windows`](../windows) even though both
target Windows, because the Steam edition layers a **Steam-compliance
and game-routing policy** on top of the tunnel that the general Windows
client deliberately does not have.

## What it reuses

- [`qlink-core`](../qlink-core) — the one shared Rust protocol/crypto
  core (same crate the macOS and Windows silos build against).
- The **Windows silo's** privileged-service architecture as a
  reference: Wintun adapter, WFP, DPAPI secrets, named-pipe IPC. The
  Steam desktop edition is expected to build on that service rather than
  re-implement it, adding Steam-safe routing as a policy layer.

## What it adds (not in the general Windows client)

- **Steam compliance policy** — Steam account/store/wallet/launcher and
  embedded-browser traffic bypass the tunnel by default; no account-
  residence disguise, no protocol emulation, no process injection. See
  [version.md](version.md) for the full position.
- **Game-aware routing** — PID/app-based per-game routing, SDR (Steam
  Datagram Relay) awareness with bypass/observe defaults, game-server
  ping matching, adaptive bypass when the tunnel worsens latency.
- **Streamer/privacy and DDoS-shielding** modes via mesh nodes.

## Editions

| Edition | Doc | Notes |
|---------|-----|-------|
| Desktop (Windows) | [version.md](version.md) | WinUI 3 + Windows service + Wintun + Steam-safe routing |
| Mobile companion | [docs/version-mobile.md](docs/version-mobile.md) | Pairing/monitoring of the desktop tunnel; not a desktop-class tunnel |

## Planned layout (when implementation starts)

```
steam/
├── desktop/        # WinUI 3 gamer UI + Steam-routing policy crate
│   └── rust/quantumlink-steam-policy   # PID/SDR/account-bypass rules
├── mobile/         # companion app (iOS/Android shells)
└── docs/
```

The Steam-routing policy will live in its own Rust crate added to the
root Cargo workspace, depending on `qlink-core` like the other silos.

## Status / next steps

See [version.md](version.md) "Core Features" and "New Windows/Steam
Work". First implementation step is a `quantumlink-steam-policy` crate
encoding the Steam-safe bypass rules and SDR detection, validated
against the same loopback smoke harness the Windows service uses.
