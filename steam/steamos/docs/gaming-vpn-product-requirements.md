# SteamOS Gaming VPN Product Requirements

## Scope

These requirements apply to the QuantumLink SteamOS Desktop and Steam Deck
product. They define the first direct-installer release and the later public
mesh release.

The first release protects trusted friend and game traffic. It does not route
Steam account or commerce traffic through QuantumLink.

## Network Requirements

| Priority | Requirement | Product rule | Current state |
|---|---|---|---|
| P0 | Low path delay | Prefer a measured direct path. Use a relay only when the direct path fails or the relay has a better measured score. | Implemented locally. Hardware proof is open. |
| P0 | Per-flow path affinity | Pin each UDP or TCP 5-tuple to one path. Do not split packets from one game flow across direct and relay paths. Switch the flow only after a path failure or a sustained threshold breach. | Policy required. Runtime proof is open. |
| P0 | Path stability | Use hysteresis before path changes. A small score change must not move an active game flow. | Not implemented. |
| P0 | Loss and jitter control | Measure round-trip time, jitter, packet loss, and path changes. Treat loss and jitter as primary path-selection inputs. | Metrics models exist. Live sampling and selection proof are partial. |
| P0 | Datagram MTU safety | Use Datagram Packetization Layer Path MTU Discovery. Avoid IP fragmentation. Re-probe after interface or path changes. | Fixed 1280-byte TUN MTU exists. Dynamic discovery is not implemented. |
| P0 | Steam-safe split tunnel | Bypass Steam account, store, wallet, checkout, inventory, marketplace, launcher, browser, update, and login traffic by default. | Policy and local tests exist. Deck route-leak proof is open. |
| P0 | Selected profile enforcement | In game-only mode, mark only traffic from the selected executable's launch cgroup and selected UDP ports inside the protected overlay. Drop all other overlay traffic. | Launch-bound cgroup v2 and UDP rules are implemented locally. Deck kernel and route-leak proof are open. |
| P0 | Protected-flow fail closure | Drop protected game traffic when its authenticated peer session is unavailable. Do not block bypass traffic. | Implemented locally. Deck proof is open. |
| P0 | Fast recovery | Re-probe and restore the path after suspend, resume, Wi-Fi roaming, dock changes, or NAT rebinding. | Network-change handling exists. Timing proof is open. |
| P0 | Voice safety | Preserve UDP voice flows and avoid head-of-line blocking. Show whether voice traffic is protected or bypassed. | Profile flags exist. Live proof is open. |
| P0 | No process injection | Do not inject code into Steam or game processes. Use Linux routing, TUN, cgroup v2, and nftables controls outside the game process. | Implemented by the `qlinkctl game launch` scope boundary. Deck proof is open. |
| P1 | Relay privacy | Offer a relay path that hides peer IP addresses and rate-limits unauthenticated traffic. | Relay support exists. Public operational proof is open. |
| P1 | LAN discovery | Preserve local discovery for profiles that require it. Do not send discovery broadcasts to unrelated peers. | Profile flags exist. Runtime policy is partial. |
| P1 | Clear path disclosure | Show direct or relay path, protected routes, bypass state, RTT, jitter, loss, and the last path change reason. | Desktop Mode shows current path and metrics. Path-change reason is open. |
| P1 | Controller-first controls | Provide connect, disconnect, peer selection, profile selection, and current path state without a terminal. | Desktop and Game Mode controls, including explicit profile selection, are implemented locally. Steam Deck and Steam Input proof is open. |

"No packet source separation" is treated as **no per-packet path separation**.
QuantumLink must keep one game flow on one path. Process and destination-based
split tunneling remains necessary for Steam-safe routing.

## Dytallix Identity Requirements

SteamOS must use the same Dytallix identity contract and verification semantics
as macOS and Windows.

- `qlink-core` owns the registry model, binding rules, signed peer records,
  policy decisions, and verifier behavior.
- The Steam silo owns device-key storage, wallet command integration, local
  enrollment state, status output, and SteamOS application controls.
- Public meshes require `stableIdentityV2` and fail closed for missing,
  suspended, revoked, expired, mismatched, or unavailable registry state.
- Private friend meshes can use Dytallix verification without making the wallet
  address public.
- Wallet secrets must not enter `qlinkd` or the packet path.
- Production approval requires a deployed-chain lifecycle bundle and an
  independently signed finality report.

## Release Scope

The first production release includes:

- Direct SteamOS installer.
- Private invite-based friend meshes.
- Steam-safe game-only routing.
- Direct path preference and relay fallback.
- Dytallix identity controls for optional private verification.
- CLI diagnostics and Desktop or Game Mode controls.

The first release does not require paid entitlements, Steamworks store
submission, or public-mesh Dytallix enforcement. Public-mesh release remains a
separate production gate.

## Research Basis

- Valve states that relay paths can hide IP addresses and reduce denial-of-service exposure. Valve also states that a relay can increase latency when the relay is not near the game server. QuantumLink must compare direct and relay paths instead of treating relay as always faster. [Steam Datagram Relay](https://partner.steamgames.com/doc/features/multiplayer/steamdatagramrelay)
- Valve exposes ping estimation and direct-versus-relay connectivity in its gaming network APIs. QuantumLink needs the same path visibility for operator decisions. [Steam Networking](https://partner.steamgames.com/doc/features/multiplayer/networking)
- The Internet Engineering Task Force recommends path MTU discovery for datagram transports. It also identifies packet reordering and fragmentation as application risks. [RFC 8899](https://www.rfc-editor.org/rfc/rfc8899.html) and [RFC 8085](https://www.rfc-editor.org/rfc/rfc8085.html)
- The Internet Engineering Task Force identifies per-flow scheduling as the default for traffic that is sensitive to packet reordering. [RFC 8218](https://www.rfc-editor.org/rfc/rfc8218.html)
- Steam Deck VPN projects show demand for Game Mode controls and report Steam login and purchase risks when all Steam traffic uses a VPN. This supports a Steam-safe bypass policy and a controller-accessible status surface. [TunnelDeck](https://github.com/steve228uk/TunnelDeck)

Public user reports are directional evidence. They do not replace QuantumLink
hardware tests or controlled network measurements.
