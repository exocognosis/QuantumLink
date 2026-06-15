# SteamOS Architecture

QuantumLink on SteamOS is a Linux daemon deployment inside the Steam silo. The product shape is `qlinkd` running under systemd, with `qlinkctl` as the local control and diagnostics surface.

## Components

- `qlinkd` lives in `steam/steamos/rust/qlinkd`, loads `/etc/quantumlink/config.json`, keeps state in `/var/lib/quantumlink`, exposes a local control socket at `/run/quantumlink/qlinkd.sock`, manages profiles, and owns the active mesh session.
- `qlinkctl` talks to the daemon for status, enrollment, invites, profile selection, diagnostics, and development service checks. The current scaffold uses a root-owned daemon socket, so status checks use `sudo qlinkctl status` until a non-root control model lands.
- `qlink-devctl` remains the shared-core protocol-development smoke CLI for rendezvous, relay, QUIC, and mesh loopback checks.
- `qlink0` is the intended Linux TUN interface for protected overlay packets.
- `nftables` provides fail-closed policy so protected game traffic does not leak outside the TUN path when QuantumLink is down.
- Rendezvous services store short-lived signed peer records so devices can find current endpoints without a central data-plane concentrator.
- Relay services forward traffic only when direct peer paths are unavailable or intentionally hidden.
- Game profiles decide which title, party, route, or LAN-discovery traffic is protected.

## Packet Flow

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

## Boundaries

The SteamOS silo contains the daemon, CLI, Linux network planning helpers, systemd unit, installer assets, and game profile helpers. The shared protocol core remains in `rust/qlink-core`. Production readiness still requires complete TUN packet integration in `qlinkd`, hardened nftables rollback, public rendezvous/relay hardening, signed release packaging, and broader game compatibility testing.
