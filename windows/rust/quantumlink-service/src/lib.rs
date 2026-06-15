//! QuantumLink Windows tunnel service.
//!
//! Port map from the macOS codebase:
//!
//! | macOS (Swift)                          | Windows (this crate)        |
//! |----------------------------------------|-----------------------------|
//! | `TunnelPacketPump.swift`               | [`pump`]                    |
//! | `KillSwitchWatchdog.swift`             | [`kill_switch`]             |
//! | `KeychainSecretStore.swift`            | [`secret_store`] (DPAPI)    |
//! | `DeviceKeypairStore.swift`/`PeerStoreKey.swift` | [`secret_store::accounts`] |
//! | `NetworkPathObserver.swift`            | [`netmon`]                  |
//! | `PacketTunnelProvider.swift` (NE)      | [`engine`] + [`win`]        |
//! | NetworkExtension route ownership       | [`win::wfp`] + [`win::routes`] |
//! | App<->extension provider messages      | [`ipc`] (named pipe)        |
//!
//! Everything outside [`win`] is platform-neutral and unit-tested on any
//! host; [`win`] is `#[cfg(windows)]` and holds the Wintun adapter, WFP
//! kill switch, route/DNS programming, DPAPI, the named-pipe server, and
//! the Windows service entry points.

pub mod adapter;
pub mod config;
pub mod engine;
pub mod ipc;
pub mod kill_switch;
pub mod netmon;
pub mod pump;
pub mod secret_store;
pub mod smoke;

#[cfg(windows)]
pub mod win;
