# QuantumLink Steam Silo

The Steam silo is the gamer-focused QuantumLink edition. It layers Steam-safe routing, game profiles, low-latency host selection, streamer privacy, and party-oriented diagnostics on top of the shared `qlink-core` protocol foundation.

Steam-specific work belongs here. The shared handshake, packet framing, peer records, rendezvous, relay, and transport primitives remain in `qlink-core`.

## Runtimes

| Runtime | Path | Status | Notes |
| --- | --- | --- | --- |
| SteamOS/Linux | `steam/steamos` | Daemon scaffold | `qlinkd`, `qlinkctl`, Linux route/nftables planning, systemd packaging, game profiles. |
| Steam desktop | `steam/desktop` | Planned | Steam-safe desktop policy and game-aware routing on the desktop tunnel runtime. |
| Mobile companion | `steam/mobile` | Planned | Pairing, status, diagnostics, and remote control concepts for party sessions. |

## Current SteamOS Work

The active Steam implementation work is the SteamOS/Linux runtime:

```sh
cargo build --release -p qlinkd -p qlinkctl
sudo ./steam/steamos/scripts/install-steamos.sh
```

See `steam/steamos/README.md` for installation details and `steam/steamos/docs/architecture.md` for the daemon architecture.
