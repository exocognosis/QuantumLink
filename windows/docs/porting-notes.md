# macOS → Windows Porting Notes

What was copied, what was ported, what was replaced, and what is still
open. Source references are to the QuantumLinkOS repository.

## Copied verbatim

| Source | Destination | Notes |
|--------|-------------|-------|
| `rust/qlink-core` (entire crate) | `rust/qlink-core` | Already Windows-clean: the only Unix-specific code (`peer_store.rs` file mode 0o600) is `#[cfg(unix)]`-gated; on Windows the peer store relies on the ProgramData ACL + SHAKE256 v3 envelope instead. `cdylib`/`staticlib` crate types already produce `qlink_core.dll`/`.lib`. |
| `config/mesh.example.json` | `config/` | Same configuration semantics. |

## Ported to Rust (shared logic, now testable everywhere)

| Swift source | Rust port | Behavior preserved |
|--------------|-----------|--------------------|
| `Models.swift` | `quantumlink-proto/src/models.rs` | camelCase/rawValue JSON wire-compatible with Swift `Codable`. |
| `TunnelMessages.swift` | `quantumlink-proto/src/ipc.rs` | Commands extended with `hello` handshake + schema version for the pipe transport. |
| `PrivacyDefaults.swift` | `quantumlink-proto/src/privacy.rs` | CGNAT overlay allocation, pseudonymous labels, `qlink_*` redaction. The recursive overlay allocator is simplified to hash-based selection with the same uniformity goal. |
| `TunnelPacketPump.swift` | `quantumlink-service/src/pump.rs` | All four fail-closed defense layers and every counter, including per-peer inbound attribution. This fulfils the "move packet-pump orchestration into Rust" decision; macOS can migrate to it later. |
| `KillSwitchWatchdog.swift` | `quantumlink-service/src/kill_switch.rs` | Strict-mode deadline semantics, fire-once + re-arm, injectable clock. |
| `NetworkPathObserver.swift` | `quantumlink-service/src/netmon.rs` | Same event taxonomy (`PathChanged`/`PreSleep`/`PostWake`/`ReachabilityChanged`) and decision table. |
| `DeviceKeypairStore.swift` / `PeerStoreKey.swift` | `quantumlink-service/src/secret_store.rs` | Same account names, same corrupt-item-regenerate behavior. |
| `PacketTunnelProvider.swift` + `MeshController.swift` orchestration | `quantumlink-service/src/engine.rs` | Connect sequencing, fail-closed vs strict behavior, status snapshot, diagnostics redaction. |
| `TransportSmokeRunner.swift` / `qlinkctl quic-loopback` | `quantumlink-service/src/smoke.rs` | CI-gating loopback data-plane check (`quantumlink-service smoke`). |

## Replaced with Windows-native equivalents

| Apple dependency | Windows replacement | Where |
|------------------|--------------------|-------|
| `NEPacketTunnelProvider` packet flow | Wintun session ring | `win/wintun_adapter.rs` |
| `NEIPv4Settings`/`NEDNSSettings` | IP Helper route/DNS programming; `netsh` is an explicit development fallback | `win/routes.rs` |
| NetworkExtension route ownership (kill switch layer 1) | WFP block+permit filters; `failClosed` is dynamic-session, `strict` uses separate boot-time and persistent blocks plus Wintun-LUID permits | `win/wfp.rs` |
| Keychain | DPAPI machine-scope blobs in ACL'd ProgramData | `win/dpapi.rs` |
| `NWPathMonitor` | `NotifyIpInterfaceChange` + `NotifyNetworkConnectivityHintChange` | `win/netmon.rs` |
| NSWorkspace sleep/wake | `SERVICE_CONTROL_POWEREVENT` | `win/service.rs` |
| App ↔ extension XPC | Named pipe `\\.\pipe\QuantumLinkService` | `win/pipe_server.rs`, `ipc.rs` |
| launchd/system extension | Windows SCM service (LocalSystem, auto-start) | `win/service.rs` |
| SwiftUI app | WinUI 3 + MVVM | `ui/QuantumLink.Windows` |
| `RustCoreBridge.swift` dylib loading | Service links qlink-core natively (no FFI); UI has minimal P/Invoke for version/suite | `Services/QlinkCoreNative.cs` |
| Sparkle/DMG/PKG, notarization | WiX MSI + Authenticode | `installer/` |
| MDM `.mobileconfig` | Managed `config.json` drop into ProgramData (Intune/GPO) | installer docs |

## Not ported (intentionally)

- `MobileConfigSigner/Envelope`, `PerAppVPNPayload`, `VPNOnDemandRules`,
  `CodeRequirementExtractor`, `PKCS12IdentityLoader` — Apple MDM
  machinery with no Windows analog in MVP scope (per-app VPN and
  on-demand rules are post-v1).
- `UpdateController.swift` (Sparkle) — see installer README update
  strategy.
- `RustTracingForwarder.swift` — the service consumes `tracing` events
  natively via `tracing-subscriber`; the FFI tracing bridge remains
  available in qlink-core for the macOS host.

## Known gaps / follow-up (tracked for beta)

Production closeout status for these gaps is tracked in
`production-release-readiness.md`; until the matching production gate has
passing evidence, the gap remains a release blocker.

1. **Strict WFP host proof**: the service implements product-owned
   persistent provider/sublayer state, separate boot-time and persistent
   blocks, dynamic Wintun-LUID permits, transactional reconciliation,
   probing, and elevated uninstall cleanup. Signed Windows-host runs must
   still prove boot, service-crash, stale-LUID, upgrade, rollback,
   uninstall, no-leak, and third-party-object preservation behavior.
2. **Route manager validation**: production default is IP Helper.
   `netsh` remains only as an explicit development fallback with a
   diagnostic, and Windows CI/hardware validation must prove the IP
   Helper path.
3. **Peer management over IPC**: `connect` uses the persisted/default
   configuration; an `addPeer`/`removePeer` command pair exists in the
   engine (`TunnelEngine::add_peer`) but is not yet exposed in the pipe
   schema.
4. **Unsolicited status pushes** (`id: 0`) are specified in the schema
   but the service does not emit them yet; the UI polls at 2 s.
5. **IPv6**: overlay and kill switch are IPv4-only, same as the macOS
   MVP.
6. **Windows ARM64**: deferred; x64 first.
7. **Pipe ACL hardening**: `windowsSecurity.pipeSddl` is parsed and
   non-empty validated from `config.json`; default is
   `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`. Enterprise deployments
   can replace the interactive-user ACE with a group SID.
