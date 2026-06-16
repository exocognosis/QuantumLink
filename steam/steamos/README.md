# QuantumLink SteamOS Runtime

QuantumLink on SteamOS is a Linux daemon deployment inside the Steam silo. The runtime shape is `qlinkd` under systemd, with `qlinkctl` as the local control and diagnostics surface.

## Components

- `steam/steamos/rust/qlinkd`: SteamOS/Linux daemon scaffold for config loading, local status, mesh state, profile lifecycle, and future TUN ownership.
- `steam/steamos/rust/qlinkctl`: local CLI for daemon status and SteamOS operator commands.
- `steam/steamos/rust/qlink-linux`: Linux TUN, route, and nftables planning helpers.
- `steam/steamos/rust/qlink-proto`: daemon config, status, invite, and local-control models.
- `steam/steamos/rust/qlink-game`: game profile parsing and host-selection policy.
- `steam/steamos/packaging/systemd`: systemd unit files.
- `steam/steamos/scripts`: SteamOS install helpers.
- `steam/steamos/config/games`: built-in game profile examples.

`qlink-core` remains the shared protocol core and is not copied into this silo.

## Quick Start

Build the Linux binaries from the repository root:

```sh
cargo build --release -p qlinkd -p qlinkctl
```

Install from the repository build output:

```sh
sudo ./steam/steamos/scripts/install-steamos.sh
```

Or install from a staged prefix containing `bin/qlinkd` and `bin/qlinkctl`:

```sh
sudo PREFIX=/opt/quantumlink ./steam/steamos/scripts/install-steamos.sh
```

The installer copies binaries to `/usr/local/bin` by default, creates `/etc/quantumlink` and `/var/lib/quantumlink`, installs `steam/steamos/packaging/systemd/qlinkd.service`, reloads systemd, and prints the next commands.

Typical next steps:

```sh
sudoedit /etc/quantumlink/config.json
sudo systemctl enable --now qlinkd
sudo qlinkctl status
```

SteamOS may remount the root filesystem read-only after system updates. Re-run the installer after an OS image refresh if `/usr/local/bin/qlinkd`, `/usr/local/bin/qlinkctl`, or the systemd unit disappears.

## Runtime Model

- Linux creates a dedicated TUN interface, currently documented as `qlink0`.
- Protected game/party routes use the overlay range `100.64.0.0/10`.
- `qlinkd` owns route setup, nftables fail-closed policy, peer state, and profile application.
- Rendezvous services publish and look up short-lived signed peer records.
- Peers attempt direct QUIC paths first, with optional ICE/STUN helpers as the traversal layer matures.
- Relay services are fallback paths for hostile NAT or intentionally hidden paths.
- Game profiles keep the default route off the VPN by default and protect only selected party/title traffic.

## Development Checks

```sh
cargo check -p qlinkd -p qlinkctl -p qlink-linux -p qlink-proto -p qlink-game
cargo test -p qlink-game
bash -n steam/steamos/scripts/install-steamos.sh
```

## Production Boundaries

The SteamOS runtime is a scaffold. Production readiness still requires complete TUN read/write integration in `qlinkd`, robust nftables apply/rollback behavior, non-root local control, hardened rendezvous/relay operations, signed release artifacts, update-channel design, and game compatibility validation for Steam launch options, LAN-discovery-heavy titles, voice chat, and anti-cheat behavior.
