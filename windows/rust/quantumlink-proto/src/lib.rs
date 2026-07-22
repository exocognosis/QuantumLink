//! Shared QuantumLink product models and the UI <-> service IPC schema.
//!
//! This crate is the Rust port of the platform-neutral parts of the macOS
//! `QuantumLinkKit` Swift layer:
//!
//! - `Models.swift`        -> [`models`]
//! - `TunnelMessages.swift`-> [`ipc`]
//! - `PrivacyDefaults.swift` -> [`privacy`]
//!
//! All types serialize as camelCase JSON so configuration files and
//! diagnostics remain wire-compatible with the macOS app's `Codable`
//! encoding. The Windows WinUI client deserializes the same JSON over the
//! named-pipe IPC.

pub mod ipc;
pub mod models;
pub mod privacy;

pub use ipc::*;
pub use models::*;
