# QuantumLink Windows Architecture

## Process model

Two processes, one privilege boundary:

1. **QuantumLinkService** (Rust, LocalSystem, auto-start). Owns
   everything that needs elevation or must survive logout: the Wintun
   adapter, route/DNS state, WFP kill-switch filters, DPAPI secrets,
   the mesh transport, and the packet pump.
2. **QuantumLink.Windows.exe** (C#/WinUI 3, runs as the logged-on
   user). Pure presentation; its only capability is the named pipe.

```
UI (asInvoker)
  └── \\.\pipe\QuantumLinkService   newline-delimited JSON
        └── ipc::serve_connection   schema: quantumlink-proto (v1, hello-gated)
              └── TunnelEngine      connect/disconnect/status/diagnostics
                    ├── secret_store (DPAPI)        identity + peer-store key
                    ├── PacketTunnelCore (qlink-core, linked natively)
                    ├── MeshTransportHandle (qlink-core QUIC/relay/rendezvous)
                    ├── TunnelAdapter (Wintun session)
                    ├── win::routes (IP Helper)     IP/routes/DNS
                    ├── win::wfp (KillSwitchGuard)  boot/persistent/dynamic lifecycle
                    └── KillSwitchWatchdog          strict-mode deadline
```

## Data plane

Two service threads per session, mirroring the macOS pump contract:

- **Outbound** (`qlink-pump-out`): Wintun receive → pump
  `handle_packets` → core encode → transport `send_frame`. The pump
  refuses to submit packets to the core while the transport is not
  ready (kill-switch gate) and counts every drop. Public, identity, and
  rendezvous-backed Windows mesh configs set `requirePeerSession=true`.
  Authenticated PQC mesh handshakes publish direction- and
  generation-bound readiness leases; the service installs those leases
  into the packet core before protected packets can leave. Session
  lifetime and byte rotation limits come from `CryptoPolicy`. Traffic
  keys remain owned by `PqcFrameProtector` and are never copied into the
  packet core. Explicit local loopback/development smoke configs do not
  enable this production gate and do not use a static development key.
- **Inbound** (`qlink-pump-in`): transport `try_receive_frame_from_any`
  → pump `accept_transport_frame` (per-peer attribution) → core decode
  → Wintun send. If the authenticated peer session is unavailable or
  frame decode fails, the pump/core count the failure and do not write
  plaintext to Wintun.

Fail-closed layering (identical intent to macOS, different mechanisms):

| Layer | macOS | Windows |
|-------|-------|---------|
| 1. OS steering | NE includedRoutes | route table + WFP block outside tunnel |
| 2. Pump gate | TunnelPacketPump | pump.rs (same logic, same counters) |
| 3. Session-key gate | PacketTunnelCore peer session | identical shared gate; Windows public/mesh configs require it |
| 4. Core policy | packet_core protected_routes | identical (shared crate) |
| 5. Pop-then-send | frames lost, never plaintext | identical |

## Control plane

`hello {schemaVersion}` must open every connection; afterwards
`connect | disconnect | reloadConfiguration | status |
exportDiagnostics | peerState`. One response per request, matching
`id`; `id: 0` is reserved for future unsolicited status pushes.

## State on disk (`%ProgramData%\QuantumLink`)

| Path | Contents | Protection |
|------|----------|-----------|
| `config.json` | TunnelConfiguration (camelCase JSON) | dir ACL |
| `peers.json` | qlink-core FilePeerStore | SHAKE256 v3 envelope (key in DPAPI) |
| `secrets\*.dpapi` | device seed, peer-store key | DPAPI machine scope + entropy + dir ACL |
| `logs\` | service tracing output | dir ACL |

`dytallixIdentity` in `config.json` is service configuration only. The
service stores local secrets with DPAPI/ProgramData, forwards the shared
registry config to `qlink-core`, and surfaces status through the named
pipe. It does not create Windows-specific identity semantics from SIDs,
accounts, hardware IDs, or installer state.

## Lifecycle

- SCM `Stop`/`Shutdown` → engine.disconnect() → routes removed →
  filters dropped (dynamic session) → adapter released.
- `PowerEvent` → `NetworkEvent::PostWake` → transport re-probe.
- IP Helper notifications → `PathChanged`/`ReachabilityChanged` →
  transport re-probe/backoff reset.
- Service crash: dynamic tunnel-interface permits and Wintun handles are
  reclaimed, while strict-mode product-owned persistent blocks remain.
  `failClosed` uses dynamic-session filters. `strict` installs separate
  boot-time and persistent blocks at ALE auth connect v4 and outbound IP
  packet v4, then adds dynamic permits bound to the active Wintun LUID.
  Reconciliation is transactional and only mutates QuantumLink-owned
  provider/sublayer objects. MSI uninstall runs elevated cleanup after
  service stop; major upgrades preserve the blocks for incoming service
  startup reconciliation. Idle service startup reconciles persisted strict
  routes from the validated configuration before reporting Running; changing
  back to `failClosed` removes compatible product-owned persistent state.

Named-pipe access is configured by `windowsSecurity.pipeSddl` in
`config.json`; the default SDDL is
`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`, granting SYSTEM and
Administrators full access and interactive users read/write access.
