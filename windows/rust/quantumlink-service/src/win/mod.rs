//! Windows-only platform layer.
//!
//! Everything in this module replaces an Apple-platform dependency from
//! the macOS app:
//!
//! | Apple dependency                     | Replacement                  |
//! |--------------------------------------|------------------------------|
//! | `NEPacketTunnelProvider` virtual if  | [`wintun_adapter`] (wintun.dll) |
//! | `NEIPv4Settings` routes/DNS          | [`routes`] (netsh + IP Helper) |
//! | NetworkExtension route ownership     | [`wfp`] (Windows Filtering Platform) |
//! | Keychain (`KeychainSecretStore`)     | [`dpapi`]                    |
//! | `NWPathMonitor` / NSWorkspace        | [`netmon`] (IP Helper notifications) |
//! | App<->extension XPC messages         | [`pipe_server`] (named pipe) |
//! | launchd/system extension lifecycle   | [`service`] (Windows SCM)    |

pub mod dpapi;
pub mod netmon;
pub mod pipe_server;
pub mod platform;
pub mod probe;
pub mod routes;
pub mod service;
pub mod wfp;
pub mod wintun_adapter;
