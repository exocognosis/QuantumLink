# QuantumLink SteamOS Runtime

QuantumLink on SteamOS is a Linux daemon deployment inside the Steam silo. The runtime shape is `qlinkd` under systemd, with `qlinkctl` as the local control and diagnostics surface.

Status: Pre-production daemon implementation. Production readiness is tracked in
`steam/steamos/docs/production-readiness.md`. SteamOS remains pre-production
until live public-edge/Dytallix proof, production signing, Steam-safe routing,
and Deck validation gates pass.
The SteamOS security test plan lives at
`steam/steamos/docs/security-test-plan.md`.

Local Rust, shell, installer, evidence-bridge, and signed-RC verification gates
pass. Production publication remains a No-Go until production signing, complete
active rendezvous/relay and public Dytallix evidence, and real Steam Deck
validation are linked from the readiness ledger.

The evidence bridge has fixture coverage for an optional signed-record
lifecycle report. It marks `signed_expiring_records` passed only when a
redacted `qlink-core` verifier report proves ML-DSA publication lookup,
post-expiry rejection, and higher-sequence refresh before expiry. No live
public-edge proof is claimed by this repository state.

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
cargo build --release -p qlinkd -p qlinkctl -p qlink-desktop
```

Install from the repository build output:

```sh
sudo ./steam/steamos/scripts/install-steamos.sh
```

Or install from a staged prefix containing `bin/qlinkd`, `bin/qlinkctl`, and
`bin/qlink-desktop`:

```sh
sudo PREFIX=/opt/quantumlink ./steam/steamos/scripts/install-steamos.sh
```

For package tests or image assembly, stage into a destination root without root privileges:

```sh
PREFIX=/opt/quantumlink DESTDIR=/tmp/qlink-root ./steam/steamos/scripts/install-steamos.sh
```

The installer copies the daemon, CLI, and Desktop Mode application to
`/usr/local/bin` by default. It also installs the application-menu launcher,
icon, systemd service, planning-only recovery sample, configuration, and game
profiles. Live installs without `DESTDIR` require root.

The packaged `qlinkd.service` starts the resident daemon with `--activate-network`. It validates configuration and applies the owned Linux TUN, route, and nftables plan. Unsafe configuration stops startup before packet I/O.

When started with the explicit `--activate-network` mode, `qlinkd` applies the owned TUN/route/nftables plan, opens the configured TUN device for raw Layer 3 packet I/O, initializes the shared `qlink-core` packet pump, and reports data-plane health in status. If TUN packet I/O cannot start after network activation, `qlinkd` runs record-backed network cleanup before exiting.

The installed service also runs `qlinkd --deactivate-network` during stop and stop-post cleanup. Those teardown commands are idempotent. Successful activated starts write `/var/lib/quantumlink/network-ownership.json`, so stop removes only QuantumLink-owned TUN, route, and nftables state.

Typical next steps:

```sh
sudoedit /etc/quantumlink/config.json
sudo systemctl enable --now qlinkd
sudo qlinkctl status
sudo qlinkctl guide
sudo qlinkctl onboarding
```

`qlink-desktop` is the SteamOS Desktop Mode control application. It uses
`qlinkctl` for status, peer, service, support-bundle, and Dytallix operations.
The UI process does not read daemon or wallet secrets directly. Service start,
stop, and restart use the fixed `qlinkctl service` command and the SteamOS
PolicyKit authentication prompt.

Game profile selection uses the same control boundary. `qlinkd` validates the
installed profile catalog and owns the selected-profile state under
`/var/lib/quantumlink`. The desktop application and CLI cannot write that state
directly.

In `gameOnly` mode, the selected profile supplies the executable basename and
UDP ports. The base nftables plan contains no unscoped port marks. It drops
unmarked overlay traffic until a validated game launch activates exact cgroup
v2 and UDP port rules. No selected profile or no classified game means all
overlay game traffic is fail-closed.

```sh
qlinkctl profile list
qlinkctl profile status
qlinkctl profile select factorio
qlinkctl profile clear
qlinkctl game launch -- /path/to/factorio
```

For a Steam shortcut, set the launch option to:

```text
/usr/local/bin/qlinkctl game launch -- %command%
```

The launcher uses `systemd-run --user --scope` with
`quantumlink-game.slice`. `qlinkd` verifies the caller's cgroup v2 path,
selected profile, executable basename, and session ID before it adds any game
route mark. It removes the rules by nftables handle after the game exits. It
does not use a shell or inject code into the game.

The installer provides two launchers. `QuantumLink` starts Desktop Mode.
`QuantumLink Game Mode` starts the same application with controller navigation
and a full-screen request. Add the Game Mode launcher to Steam as a non-Steam
game. QuantumLink does not modify Steam shortcut files.

`qlinkctl guide` remains the terminal operator reference for active networking,
`qlink0`, nftables, Steam-safe routing, game profiles, and validation gates.

`qlinkctl onboarding` reads the live daemon status plus the local peer store and
formats a checklist for the current Deck: daemon reachability, dry-run or
activated network readiness, peer invite import, packet I/O, transport
readiness, safe next commands, and the pre-production release boundary.

`qlinkctl doctor` includes both network ownership and data-plane readiness:

```text
data-plane state: starting
data-plane interface: qlink0
packet I/O: available
transport ready: no
packet counters: observed=0 queued=0 dropped=0 emitted=0 accepted=0 rejected=0 transportErrors=0
```

The resident daemon builds a live mesh transport and drives the bidirectional
packet pump. For a configured mesh it selects exactly one current, non-revoked
peer from the trusted invite store, applies an exact inbound ACL, and installs
the shared transport's authenticated directional packet-session leases into the
packet core. Rekey, expiry, disconnect, and clear events are generation-aware.
The daemon drops the complete transport if the selected peer is removed,
revoked, expired, or replaced on disk.

For a configured rendezvous service, `qlinkd` also runs a dedicated signed
peer-record publication worker. It reserves monotonic sequence numbers in
`/var/lib/quantumlink/publication-state.json`, writes the current public record
to an owner-only `publication-record.json` outbox, refreshes at TTL/2, and
retries without blocking packet or control processing. Linux netlink
route/link/address changes trigger an immediate reconnect and republish. The
packet path remains fail-closed before the first successful publication and
after record expiry.

Select the protected packet target explicitly when more than one peer is
eligible:

```sh
sudo qlinkctl peer select <peer-id>
```

Public-edge authentication tokens are loaded only from absolute owner-only
files such as `/etc/quantumlink/secrets/rendezvous.token`; token values do not
belong in `config.json`.

`publicationTtlSeconds` defaults to `120`. `advertiseAddress` can override the
responder bind address when a stable public NAT/proxy endpoint is required.
Wallet seeds and signing credentials never enter `qlinkd`; public Dytallix
enrollment, update, suspension, and revocation remain offline provisioning
actions. Public mode requires `bindingVersion: "stableIdentityV2"`; the daemon
performs lookup-only validation and will not silently downgrade to v1.

Provisioning is daemon-independent, not network-disconnected. It reads the
pinned Dytallix settings from `/etc/quantumlink/config.json`, requires an
explicit owner-only wallet keystore for mutations, and emits JSON receipts:

```sh
sudo qlinkctl dytallix status
sudo qlinkctl dytallix register --keystore /secure/path/wallet.json --wallet main
sudo qlinkctl dytallix update --keystore /secure/path/wallet.json --wallet main
sudo qlinkctl dytallix suspend --keystore /secure/path/wallet.json --peer-id <peer-id>
sudo qlinkctl dytallix reactivate --keystore /secure/path/wallet.json --wallet main
sudo qlinkctl dytallix revoke --keystore /secure/path/wallet.json \
  --peer-id <peer-id> --confirm-peer-id <peer-id>
```

Register, update, and reactivate load the existing device seed from
`/var/lib/quantumlink`; they never generate a replacement identity. Suspend and
revoke can operate by explicit peer ID without device-key access. A successful
receipt proves transaction confirmation and exact registry readback, but does
not claim finalized-chain inclusion; that remains a separate production gate.

Full-tunnel mode requires `underlayExemptions` with canonical IPv4 CIDRs for
rendezvous, relay, registry, and external DNS endpoints that must stay outside
the tunnel. The daemon rejects empty or unsafe exemption sets before it applies
network state.

The gaming network requirements are in
`steam/steamos/docs/gaming-vpn-product-requirements.md`.

## Runtime Modes

- `qlinkd` starts the resident daemon in planning-only mode and does not mutate networking.
- `qlinkd --check` validates configuration/status only and exits; it is not a network activation path.
- `qlinkd --activate-network` applies the real TUN, route, and nftables plan. The packaged service uses this mode.
- `qlinkd --deactivate-network` removes qlink-owned network state from the persisted ownership record and exits; it is safe when no ownership record exists.
- `qlinkd --check`, `qlinkd --activate-network`, and `qlinkd --deactivate-network` are mutually exclusive runtime modes.

To place the packaged service in planning-only recovery mode, install the packaged sample as a controlled systemd drop-in:

```sh
sudo cp /etc/systemd/system/qlinkd.service.d/planning-only.conf.sample /etc/systemd/system/qlinkd.service.d/10-planning-only.conf
sudo systemctl daemon-reload
sudo systemctl restart qlinkd
```

The sample contains this override for the default install path:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/qlinkd
```

Remove the live drop-in to return to active networking:

```sh
sudo rm -f /etc/systemd/system/qlinkd.service.d/10-planning-only.conf
sudo systemctl daemon-reload
sudo systemctl restart qlinkd
```

If the installer was run with a custom `BINDIR`, the installed service and sample are both rewritten to that installed `qlinkd` path. The installed `ExecStop` and `ExecStopPost` lines use the same `BINDIR`. Default reinstalls do not create or delete the live planning-only operator drop-in.

After copying files, the installer validates all three binaries, both desktop
launchers, the icon, the active systemd unit, and the planning-only sample.
Validation failures exit nonzero.

SteamOS may remount the root filesystem read-only after system updates. Re-run
the installer after an OS image refresh if the QuantumLink binaries, launcher,
icon, or systemd unit disappear.

## Runtime Model

- Linux creates a dedicated TUN interface, currently documented as `qlink0`.
- Protected game/party routes use the overlay range `100.64.0.0/10`.
- `qlinkd` owns route setup, nftables fail-closed policy, peer state, profile application, and the local packet-pump boundary. The packaged service activates the network plan and records ownership for `--deactivate-network` cleanup.
- The packet pump uses shared `qlink-core` packet framing and replay protection, and the resident daemon drives it against a live `DaemonMeshTransport` with authenticated directional packet-session leases. Full Deck runtime validation remains a separate gate.
- Rendezvous services publish and look up short-lived signed peer records.
- Peers attempt direct QUIC paths first, with optional ICE/STUN helpers as the traversal layer matures.
- Relay services are fallback paths for hostile NAT or intentionally hidden paths.
- Game profiles keep the default route off the VPN by default. The daemon
  stores an explicit selected profile. `qlinkctl game launch` binds the
  selected executable and UDP ports to a dedicated cgroup v2 scope. Steam Deck
  kernel and route-leak proof remains open.

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
