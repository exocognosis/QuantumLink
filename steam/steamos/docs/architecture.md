# SteamOS Architecture

QuantumLink on SteamOS is a Linux daemon deployment inside the Steam silo. The product shape is `qlinkd` running under systemd, with `qlinkctl` as the local control and diagnostics surface.

## Components

- `qlinkd` lives in `steam/steamos/rust/qlinkd`, loads `/etc/quantumlink/config.json`, keeps state in `/var/lib/quantumlink`, exposes a local control socket at `/run/quantumlink/qlinkd.sock`, manages profiles, and owns the active mesh session. The default resident mode is dry-run planning-only unless the operator starts it with `--activate-network`.
- `qlinkctl` talks to the daemon for status, enrollment, invites, profile selection, diagnostics, and development service checks. The current scaffold uses a root-owned daemon socket, so status checks use `sudo qlinkctl status` until a non-root control model lands. Its operator guide derives the Steam-safe disclosure from the shared `qlink-game` bypass policy so disclosure and enforcement share one source.
- `qlinkd::identity` owns a persistent device identity — an ML-DSA keypair plus a peer-store envelope key stored `0600` under the state directory. It is the SteamOS analogue of the Windows DPAPI secret store and the macOS Keychain, and it supplies the `peer_id` and inbound-assertion signing key the mesh transport requires.
- `qlinkd::mesh_runtime::DaemonMeshTransport` is the live transport the resident pump drives: the shared `qlink-core` `MeshTransportHandle` (QUIC/native-UDP carrier, PQC handshake, rendezvous, relay fallback, peer-store, reconnect) built from the device identity, or a local-echo development transport when no rendezvous server is configured. It mirrors the Windows service's `ActiveTransport` and implements the daemon's existing `MeshFrameTransport` contract.
- `qlinkd::game` makes `qlink-game` a first-class daemon dependency: it loads the Steam-safe bypass policy and per-game routing profiles from the config directory, validates the protected overlay CIDR against the policy, and surfaces the posture in the resident banner.
- `qlink-devctl` remains the shared-core protocol-development smoke CLI for rendezvous, relay, QUIC, and mesh loopback checks.
- `qlink0` is the intended Linux TUN interface for protected overlay packets; activated mode now opens it for raw Layer 3 packet I/O after the owned network plan applies.
- `nftables` provides fail-closed policy so protected game traffic does not leak outside the TUN path when QuantumLink is down.
- Rendezvous services store short-lived signed peer records so devices can find current endpoints without a central data-plane concentrator.
- Relay services forward traffic only when direct peer paths are unavailable or intentionally hidden.
- Game profiles decide which title, party, route, or LAN-discovery traffic is protected.

## Packet Flow

This is the intended activated packet flow. The packaged systemd service does not enter this network-apply path by default.

1. A game sends traffic matching an active profile or overlay route.
2. Linux policy routing sends protected destinations to `qlink0`.
3. `qlinkd` reads packets from the TUN interface, applies `qlink-core` packet policy/framing/replay protection, and prepares transport frames for the selected peer path.
4. The mesh connector prefers a direct QUIC path discovered through signed rendezvous records.
5. If direct connectivity fails, the connector uses relay fallback when the profile allows it.
6. nftables drops protected destinations that would otherwise leave through the wrong interface.

## Control Flow

1. `qlinkctl` enrolls or imports an invite.
2. `qlinkd` loads device identity, profile settings, rendezvous endpoints, relay endpoints, and peer cache.
3. The daemon publishes a signed peer record with current routes and endpoint candidates.
4. Peers resolve each other through rendezvous, validate signatures and expiration, then attempt direct connectivity.
5. Status reports expose phase, active party, path type, RTT, jitter, loss, NAT type, and relay privacy.

## Resident Publication

`qlinkd` owns a dedicated publication worker around the shared
`MeshTransportHandle` publication API. The worker:

- reserves each sequence number to an owner-only state file before attempting
  network I/O, preventing sequence reuse after crashes;
- publishes the responder certificate, candidates, and overlay routes in an
  ML-DSA-signed peer record;
- refreshes at TTL/2 and retains a valid prior record during bounded retries;
- writes the current public record to an owner-only diagnostics/evidence
  outbox; stable v2 enrollment does not require a wallet transaction per TTL
  refresh;
- reacts to Linux netlink route, link, and address changes by reconnecting the
  shared transport and requesting immediate republication; and
- fails the protected packet path before initial publication and after expiry.

The publication worker has its own Tokio runtime and never blocks the packet
pump or local control socket.

## Dytallix Boundary

`qlinkd` receives lookup-only Dytallix configuration and periodically
validates the local device enrollment and separately revalidates required
public-peer trust. Wallet keys remain outside the daemon. Public SteamOS mode
requires the explicit `stableIdentityV2` binding and refuses the legacy v1
default. The v2 contract binds wallet ownership, device identity, node signing
identity, authorization lifetime, optional mesh scope, and maximum signed
peer-record TTL. Ephemeral endpoints, ICE credentials, routes, transport
certificate, sequence, and expiry remain in the ML-DSA-signed peer record.

Enrollment, update, emergency suspension, and terminal revocation are offline
operator actions. Runtime publication does not require wallet access or an
on-chain write for each refresh. Daemon status reports local registry binding
separately from selected remote-peer trust so one cannot be mistaken for proof
of the other.

## Evidence Boundary

The SteamOS evidence bridge consumes redacted reports; it does not consume or
publish raw peer records, private keys, ICE credentials, or endpoint
addresses. A `signed_expiring_records` pass requires a source report from the
repository-owned `qlink-core` verifier that binds the same ML-DSA identity and
source revision across publication, post-expiry lookup, and a
higher-sequence pre-expiry refresh. The bridge validates hashes, decisions,
sequence ordering, and time ordering, then emits only a whitelisted summary
plus the source report digest.

This is an evidence contract, not live endpoint evidence. Fixture coverage
proves the bridge behavior; an off-host public-edge run still has to produce
and link the report before the rendezvous/relay production gate can pass.

## SteamOS Defaults

- Use split tunneling by default; do not replace the SteamOS default route.
- Protect game/party traffic and `100.64.0.0/10` overlay routes.
- Prefer direct paths for latency.
- Allow relay fallback for difficult NATs.
- Keep voice chat usable unless a profile explicitly restricts it.
- Treat root filesystem updates as potentially removing `/usr/local` binaries or custom units; the installer is safe to re-run.

## Network Lifecycle

The packaged resident daemon applies the owned Linux network plan during startup. It validates the daemon config, applies typed `ip` and `nftables` operations, and exposes those commands through `qlinkctl status`. Startup fails before packet I/O when the plan is unsafe. `--check` remains non-mutating.

`qlinkd --check` is validation/status only and exits without mutating networking. `qlinkd --activate-network` starts real TUN, route, nftables, and local packet I/O. The packaged unit uses this mode. Packaging ships `planning-only.conf.sample` as a recovery override. The override starts `qlinkd` without network activation.

`qlinkd --deactivate-network` is a one-shot teardown path that reads `/var/lib/quantumlink/network-ownership.json`, removes only QuantumLink-owned network state, and exits. These runtime modes are mutually exclusive.

`qlink-linux` separates human-readable plan rendering from privileged execution. The execution boundary uses typed argv commands, trusted SteamOS tool paths (`/usr/bin/ip`, `/usr/bin/nft`), and injectable command runners. `qlinkd` reports `applied` or `applyFailed` in status. The packaged unit uses `ExecStart=/usr/local/bin/qlinkd --activate-network`.

Successful activated starts persist a small ownership record under the daemon state directory with the interface, route mode, protected CIDR, fwmark, route table, nftables family/table, schema version, and activation timestamp. Deactivation reconstructs the owned Linux runtime plan from that record, tears down nftables before network objects, removes the record only after successful cleanup, and leaves it in place when cleanup fails so the operator can retry. If no record exists, deactivation is a no-op. The packaged systemd unit wires this through `ExecStop=/usr/local/bin/qlinkd --deactivate-network` and `ExecStopPost=/usr/local/bin/qlinkd --deactivate-network`; `ExecStopPost` is an idempotent crash/start-failure cleanup backstop.

After successful activated network application, the daemon opens the configured
TUN device, initializes a `qlink-core` packet tunnel core, builds the live
`DaemonMeshTransport`, and drives the bidirectional pump alongside the control
socket. The production mesh path carries the exact authenticated outbound lease
and per-frame inbound lease from `MeshTransportHandle` into the packet core.
Ready and clear events preserve peer ID, direction, generation, transcript
binding, expiry, and byte rekey limit.

The trusted invite store remains separate from the shared-core signed peer
record cache. Exactly one current, non-revoked packet target is selected,
automatically only when unambiguous or explicitly through
`qlinkctl peer select`. Its peer ID and mesh ID configure the transport, and an
exact inbound ACL rejects other peers before packet processing. The resident
loop rechecks the selected peer on disk and drops the complete transport after
removal, revocation, expiry, or replacement. Two-Deck live reachability remains
a hardware-validation gate.

If packet I/O startup fails after network activation, the daemon invokes record-backed deactivation before exiting. That keeps an operator from being left with active routes or nftables rules when the TUN reader/writer cannot start.

The SteamOS installer supports non-root `DESTDIR` staging for package tests and image assembly while live installs still require root. It rewrites the default `/usr/local/bin/qlinkd` paths in both the base unit and planning-only sample to the selected `BINDIR`, then validates executable binaries and expected unit commands before completing.

Full-tunnel activation requires explicit canonical IPv4 CIDRs in `underlayExemptions`. nftables returns those destinations before it marks or drops full-tunnel traffic. Empty, duplicate, non-canonical, catch-all, and overlay-overlapping exemptions fail validation. Operators must include the current rendezvous, relay, registry, and external DNS endpoints that must remain on the underlay.

## Desktop Control Boundary

`qlink-desktop` is an unprivileged native Rust application for SteamOS Desktop
Mode and Game Mode. It runs each control request on a background worker and
passes typed argument arrays to `qlinkctl`. It does not open the daemon socket,
peer store, device seed, Dytallix keystore, wallet files, or daemon state files
directly.

The application provides connection, peer, Dytallix identity, runtime metric,
game-profile, and redacted support-bundle controls. The Game Mode launch option
adds controller navigation for pages and profiles. Connect selects one eligible
peer and restarts `qlinkd`. Disconnect stops `qlinkd`, which runs owned network
cleanup.
`qlinkctl service start|stop|restart` invokes `/usr/bin/pkexec` with the fixed
`/usr/bin/systemctl` path and fixed `qlinkd.service` unit. No user value enters
the privileged command vector.

Profile controls use typed local-socket requests. `qlinkd` validates a selected
ID against the installed `qlink-game` catalog. It then writes
`/var/lib/quantumlink/game-profile-selection.json` with owner-only permissions.
Daemon status returns the selected profile and the validated available-profile
catalog. In `gameOnly` mode, daemon startup records the selected profile's UDP
ports but installs no unscoped port marks. It drops unmarked overlay traffic
before the interface leak rule. This state is fail-closed until a game launch
creates a classified process scope.

`qlinkctl game launch -- <command> [args...]` runs the selected profile through
a dedicated user `systemd` scope in `quantumlink-game.slice`. The inner control
request reaches `qlinkd` before the game starts. On Linux, `qlinkd` reads the
caller's PID and UID from `SO_PEERCRED`, reads its cgroup v2 path from `/proc`,
and verifies the exact user slice, QuantumLink slice, scope unit, session ID,
selected profile, and executable basename. It then adds nftables route rules
that require the exact cgroup path and selected UDP source or destination port.
The outer command removes these rules by nftables handle after the scoped game
exits. No shell or game-process injection is used.

An active profile change does not patch live firewall rules. The daemon stores
the desired profile and reports `restartRequired=true`. `qlink-desktop` then
uses the fixed `qlinkctl service restart` command. The systemd stop path removes
the owned table before startup applies the replacement plan. Direct game
launches that do not use `qlinkctl game launch` remain fail-closed.

## Boundaries

The SteamOS silo contains the daemon, CLI, Linux TUN/network helpers, systemd
unit, installer assets, and game profile helpers. The shared protocol core
remains in `qlink-core`. Production readiness still requires Deck-host
two-Deck data-plane validation, complete live rendezvous/relay and Dytallix
evidence, production signing evidence, and broader game compatibility testing.
