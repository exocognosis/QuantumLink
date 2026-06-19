# SteamOS Architecture

QuantumLink on SteamOS is a Linux daemon deployment inside the Steam silo. The product shape is `qlinkd` running under systemd, with `qlinkctl` as the local control and diagnostics surface.

## Components

- `qlinkd` lives in `steam/steamos/rust/qlinkd`, loads `/etc/quantumlink/config.json`, keeps state in `/var/lib/quantumlink`, exposes a local control socket at `/run/quantumlink/qlinkd.sock`, manages profiles, and owns the active mesh session. The default resident mode is dry-run planning-only unless the operator starts it with `--activate-network`.
- `qlinkctl` talks to the daemon for status, enrollment, invites, profile selection, diagnostics, and development service checks. The current scaffold uses a root-owned daemon socket, so status checks use `sudo qlinkctl status` until a non-root control model lands.
- `qlink-devctl` remains the shared-core protocol-development smoke CLI for rendezvous, relay, QUIC, and mesh loopback checks.
- `qlink0` is the intended Linux TUN interface for protected overlay packets.
- `nftables` provides fail-closed policy so protected game traffic does not leak outside the TUN path when QuantumLink is down.
- Rendezvous services store short-lived signed peer records so devices can find current endpoints without a central data-plane concentrator.
- Relay services forward traffic only when direct peer paths are unavailable or intentionally hidden.
- Game profiles decide which title, party, route, or LAN-discovery traffic is protected.

## Packet Flow

This is the intended activated packet flow. The packaged systemd service does not enter this network-apply path by default.

1. A game sends traffic matching an active profile or overlay route.
2. Linux policy routing sends protected destinations to `qlink0`.
3. `qlinkd` reads packets from the TUN interface, applies route/profile policy, and frames the packet for the selected peer path.
4. The mesh connector prefers a direct QUIC path discovered through signed rendezvous records.
5. If direct connectivity fails, the connector uses relay fallback when the profile allows it.
6. nftables drops protected destinations that would otherwise leave through the wrong interface.

## Control Flow

1. `qlinkctl` enrolls or imports an invite.
2. `qlinkd` loads device identity, profile settings, rendezvous endpoints, relay endpoints, and peer cache.
3. The daemon publishes a signed peer record with current routes and endpoint candidates.
4. Peers resolve each other through rendezvous, validate signatures and expiration, then attempt direct connectivity.
5. Status reports expose phase, active party, path type, RTT, jitter, loss, NAT type, and relay privacy.

## SteamOS Defaults

- Use split tunneling by default; do not replace the SteamOS default route.
- Protect game/party traffic and `100.64.0.0/10` overlay routes.
- Prefer direct paths for latency.
- Allow relay fallback for difficult NATs.
- Keep voice chat usable unless a profile explicitly restricts it.
- Treat root filesystem updates as potentially removing `/usr/local` binaries or custom units; the installer is safe to re-run.

## Network Lifecycle

The default resident daemon builds and reports a dry-run Linux network plan during startup. It validates the daemon config, renders the intended `ip` and `nftables` operations, and exposes those commands through `qlinkctl status`. It does not apply TUN, route, or nftables changes when launched by the packaged systemd unit or during `--check`.

`qlinkd --check` is validation/status only and exits without mutating networking. `qlinkd --activate-network` is the explicit operator opt-in for real TUN, route, and nftables application. Packaging ships an activated-mode sample drop-in at `qlinkd.service.d/activate-network.conf.sample`; operators enable it by copying it to a live `.conf` drop-in such as `10-activate-network.conf`, then reloading and restarting systemd. The default installer does not create that live activation drop-in and does not delete existing operator drop-ins during reinstall.

`qlinkd --deactivate-network` is a one-shot teardown path that reads `/var/lib/quantumlink/network-ownership.json`, removes only QuantumLink-owned network state, and exits. These runtime modes are mutually exclusive.

`qlink-linux` separates human-readable plan rendering from privileged execution. Dry-run status still renders operator-friendly `ip` and `nftables` strings, while the execution boundary uses typed argv commands, trusted SteamOS tool paths (`/usr/bin/ip`, `/usr/bin/nft`), and injectable command runners. When activation is explicitly requested, `qlinkd` can mark network state as `applied` or `applyFailed` in status. The packaged unit remains `ExecStart=/usr/local/bin/qlinkd`, so SteamOS installs stay dry-run until an operator adds a systemd drop-in that overrides `ExecStart` with `qlinkd --activate-network`.

Successful activated starts persist a small ownership record under the daemon state directory with the interface, route mode, protected CIDR, fwmark, route table, nftables family/table, schema version, and activation timestamp. Deactivation reconstructs the owned Linux runtime plan from that record, tears down nftables before network objects, removes the record only after successful cleanup, and leaves it in place when cleanup fails so the operator can retry. If no record exists, deactivation is a no-op. The packaged systemd unit wires this through `ExecStop=/usr/local/bin/qlinkd --deactivate-network` and `ExecStopPost=/usr/local/bin/qlinkd --deactivate-network`; `ExecStopPost` is an idempotent crash/start-failure cleanup backstop.

The SteamOS installer supports non-root `DESTDIR` staging for package tests and image assembly while live installs still require root. It rewrites the default `/usr/local/bin/qlinkd` paths in both the base unit and activated sample to the selected `BINDIR`, then validates executable binaries, expected unit commands, and the activated sample before completing.

Full-tunnel planning currently renders `0.0.0.0/0` as the protected CIDR so the intended route shape is visible in status output. A future privileged executor must add explicit underlay exemptions for rendezvous, relay, and local control traffic before enabling real full-tunnel application; otherwise fail-closed rules could block the daemon's own control-plane path.

## Boundaries

The SteamOS silo contains the daemon, CLI, Linux network planning helpers, systemd unit, installer assets, and game profile helpers. The shared protocol core remains in `qlink-core`. Production readiness still requires complete TUN packet integration in `qlinkd`, hardened nftables rollback, public rendezvous/relay hardening, signed release packaging, and broader game compatibility testing.
