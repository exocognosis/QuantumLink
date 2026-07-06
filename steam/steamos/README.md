# QuantumLink SteamOS Runtime

QuantumLink on SteamOS is a Linux daemon deployment inside the Steam silo. The runtime shape is `qlinkd` under systemd, with `qlinkctl` as the local control and diagnostics surface.

Status: Pre-production daemon scaffold. Production readiness is tracked in
`steam/steamos/docs/production-readiness.md`. SteamOS remains pre-production
until live transport, signed release, Steam-safe routing, and Deck validation
gates pass.

2026-06-30 closeout status: local Rust, shell, installer, and dev-package
verification gates pass, but production publication is a No-Go until production
signing, active rendezvous/relay evidence, public Dytallix registry evidence,
and real Steam Deck validation are linked from the readiness ledger.

## Components

- `steam/steamos/rust/qlinkd`: SteamOS/Linux daemon scaffold for config loading, local status, mesh state, profile lifecycle, explicit network activation, and the local TUN packet-pump boundary.
- `steam/steamos/rust/qlinkctl`: local CLI for daemon status and SteamOS operator commands.
- `steam/steamos/rust/qlink-linux`: Linux TUN packet I/O, route, and nftables planning helpers.
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

For package tests or image assembly, stage into a destination root without root privileges:

```sh
PREFIX=/opt/quantumlink DESTDIR=/tmp/qlink-root ./steam/steamos/scripts/install-steamos.sh
```

The installer copies binaries to `/usr/local/bin` by default, creates `/etc/quantumlink` and `/var/lib/quantumlink`, installs `steam/steamos/packaging/systemd/qlinkd.service`, stages an activated-mode sample drop-in, validates the staged files, reloads systemd for live installs, and prints the next commands. Live installs without `DESTDIR` still require root.

The packaged `qlinkd.service` starts the resident daemon in dry-run planning mode. It validates configuration, builds the intended Linux network plan, and exposes that plan through status, but it does not create TUN devices, change routes, or apply nftables rules by default.

When started with the explicit `--activate-network` mode, `qlinkd` applies the owned TUN/route/nftables plan, opens the configured TUN device for raw Layer 3 packet I/O, initializes the shared `qlink-core` packet pump, and reports data-plane health in status. If TUN packet I/O cannot start after network activation, `qlinkd` runs record-backed network cleanup before exiting.

The installed service also runs `qlinkd --deactivate-network` during stop and stop-post cleanup. Those teardown commands are idempotent: dry-run service starts have no ownership record and therefore no teardown work, while successful activated starts write `/var/lib/quantumlink/network-ownership.json` so stop removes only QuantumLink-owned TUN, route, and nftables state.

Typical next steps:

```sh
sudoedit /etc/quantumlink/config.json
sudo systemctl enable --now qlinkd
sudo qlinkctl status
sudo qlinkctl guide
```

`qlinkctl guide` is the first operator-facing guided UX for SteamOS until a
native SteamOS UI exists. It summarizes onboarding, runtime modes, peer and
invite commands, diagnostics, Steam-safe routing, and the remaining production
gates.

`qlinkctl doctor` includes both network ownership and data-plane readiness:

```text
data-plane state: starting
data-plane interface: qlink0
packet I/O: available
transport ready: no
packet counters: observed=0 queued=0 dropped=0 emitted=0 accepted=0 rejected=0 transportErrors=0
```

`data-plane state: starting` with `transport ready: no` is expected until an authenticated peer session is installed on a live peer transport/rendezvous path. It means the local TUN packet I/O runtime initialized, not that protected traffic is already flowing to remote peers.

## Runtime Modes

- `qlinkd` starts the resident daemon in dry-run planning mode and does not mutate networking.
- `qlinkd --check` validates configuration/status only and exits; it is not a network activation path.
- `qlinkd --activate-network` is the explicit operator opt-in for real TUN, route, and nftables application.
- `qlinkd --deactivate-network` removes qlink-owned network state from the persisted ownership record and exits; it is safe when no ownership record exists.
- `qlinkd --check`, `qlinkd --activate-network`, and `qlinkd --deactivate-network` are mutually exclusive runtime modes.

To run the packaged service with real network application, install the packaged sample as a controlled systemd drop-in instead of editing the installed unit directly:

```sh
sudo cp /etc/systemd/system/qlinkd.service.d/activate-network.conf.sample /etc/systemd/system/qlinkd.service.d/10-activate-network.conf
sudo systemctl daemon-reload
sudo systemctl restart qlinkd
```

The sample contains this override for the default install path:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/qlinkd --activate-network
```

Remove the live drop-in to return to dry-run planning mode:

```sh
sudo rm -f /etc/systemd/system/qlinkd.service.d/10-activate-network.conf
sudo systemctl daemon-reload
sudo systemctl restart qlinkd
```

If the installer was run with a custom `BINDIR`, the installed service and sample are both rewritten to that installed `qlinkd` path. The installed `ExecStop` and `ExecStopPost` lines are rewritten to the same `BINDIR`, so activated service stops use the matching `qlinkd --deactivate-network` binary. Default reinstalls do not create or delete the live `10-activate-network.conf` operator drop-in.

After copying files, the installer validates that `qlinkd` and `qlinkctl` are executable, the unit exists and contains the resolved dry-run `ExecStart` plus teardown `ExecStop`, and the activated-mode sample exists with the resolved activated `ExecStart`. Validation failures exit nonzero.

SteamOS may remount the root filesystem read-only after system updates. Re-run the installer after an OS image refresh if `/usr/local/bin/qlinkd`, `/usr/local/bin/qlinkctl`, or the systemd unit disappears.

## Runtime Model

- Linux creates a dedicated TUN interface, currently documented as `qlink0`.
- Protected game/party routes use the overlay range `100.64.0.0/10`.
- `qlinkd` owns route setup, nftables fail-closed policy, peer state, profile application, and the local packet-pump boundary; the packaged service plans network changes until explicitly started with `--activate-network`, then records ownership for `--deactivate-network` cleanup.
- The packet pump uses shared `qlink-core` packet framing and replay protection. Peer-transport selection and full Deck runtime validation remain separate gates.
- Rendezvous services publish and look up short-lived signed peer records.
- Peers attempt direct QUIC paths first, with optional ICE/STUN helpers as the traversal layer matures.
- Relay services are fallback paths for hostile NAT or intentionally hidden paths.
- Game profiles keep the default route off the VPN by default and protect only selected party/title traffic.

## Development Checks

```sh
cargo check -p qlinkd -p qlinkctl -p qlink-linux -p qlink-proto -p qlink-game
cargo test -p qlink-game -p qlink-proto -p qlink-linux -p qlinkd -p qlinkctl
bash steam/steamos/tests/install-steamos-test.sh
bash -n steam/steamos/scripts/install-steamos.sh
```

## Production Boundaries

The SteamOS runtime is still pre-production. The closeout slice adds local TUN packet I/O, packet-pump transport bridging, fail-closed packet-session tests, Steam-safe route/profile policy, nftables rollback tests, non-root local control, invite peer lifecycle, redacted diagnostics, and dev-package verification. Production readiness still requires real two-Deck transport validation, active public Dytallix registry evidence for public mesh mode, hardened rendezvous/relay endpoint evidence, production-signed release artifacts, and game compatibility validation for Steam launch options, LAN-discovery-heavy titles, voice chat, and anti-cheat behavior.

The blocking release ledger lives at
`steam/steamos/docs/production-readiness.md`.
