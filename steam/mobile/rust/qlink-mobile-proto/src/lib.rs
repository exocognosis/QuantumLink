//! Companion protocol models for the QuantumLink Steam Mobile silo.
//!
//! Planning-stage scaffold. This crate defines the account-safe pairing,
//! remote-control, status, and profile-sync data models that a future mobile
//! companion app and the desktop/SteamOS Steam runtimes would exchange over an
//! authenticated companion channel.
//!
//! It deliberately contains no tunnel, routing, or packet code: mobile
//! platforms do not expose the desktop Wintun/WFP/PID-routing model, and mobile
//! game tunneling is a separate future feasibility gate. Shared protocol,
//! crypto, peer records, and transport remain in `qlink-core`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version for companion messages exchanged with the desktop runtime.
pub const COMPANION_SCHEMA_VERSION: u32 = 1;

/// Mobile platform hosting the companion app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MobilePlatform {
    Ios,
    Android,
}

/// Capability a paired companion may exercise. Scopes are least-privilege by
/// default; remote control is only granted when the user explicitly opts in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CompanionScope {
    /// Read redacted tunnel/mesh status.
    StatusRead,
    /// Read redacted match/session diagnostics.
    Diagnostics,
    /// Push gamer-profile preference changes.
    ProfileSync,
    /// Issue remote-control commands (connect/disconnect/select profile).
    RemoteControl,
}

/// A pairing request sent from the mobile companion to the desktop runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRequest {
    pub device_name: String,
    pub platform: MobilePlatform,
    /// Hash of the companion device public key. Raw keys never travel here.
    pub device_public_key_hash: String,
    pub requested_scopes: Vec<CompanionScope>,
}

/// A granted pairing session returned by the desktop runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingGrant {
    pub session_id: String,
    pub granted_scopes: Vec<CompanionScope>,
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds; must be strictly greater than `issued_at`.
    pub expires_at: u64,
}

impl PairingGrant {
    /// Validate the grant shape: non-empty session id, at least one scope, and
    /// a positive lifetime.
    pub fn validate(&self) -> Result<(), CompanionError> {
        if self.session_id.trim().is_empty() {
            return Err(CompanionError::EmptySessionId);
        }
        if self.granted_scopes.is_empty() {
            return Err(CompanionError::NoScopes);
        }
        if self.expires_at <= self.issued_at {
            return Err(CompanionError::NonPositiveLifetime);
        }
        Ok(())
    }

    /// Whether the grant authorizes the given scope.
    pub fn allows(&self, scope: CompanionScope) -> bool {
        self.granted_scopes.contains(&scope)
    }
}

/// Remote-control commands a companion may issue. Each maps to a required scope
/// via [`CompanionCommand::required_scope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum CompanionCommand {
    ConnectMesh,
    DisconnectMesh,
    SelectProfile { profile_id: String },
    RefreshStatus,
    AcknowledgeAlert { alert_id: String },
}

impl CompanionCommand {
    /// Scope required to execute this command. Reading status only needs
    /// `StatusRead`; everything that mutates tunnel state needs `RemoteControl`.
    pub fn required_scope(&self) -> CompanionScope {
        match self {
            CompanionCommand::RefreshStatus => CompanionScope::StatusRead,
            CompanionCommand::ConnectMesh
            | CompanionCommand::DisconnectMesh
            | CompanionCommand::SelectProfile { .. }
            | CompanionCommand::AcknowledgeAlert { .. } => CompanionScope::RemoteControl,
        }
    }
}

/// Selected transport path kind, surfaced to the companion for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PathKind {
    Direct,
    Relay,
    Offline,
}

/// A redacted health snapshot suitable for display on the mobile companion.
/// Contains no raw peer ids, wallet addresses, or network addresses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelHealthStatus {
    pub connected: bool,
    pub path_kind: PathKind,
    pub peer_count: u32,
    pub rtt_ms: Option<u32>,
    pub loss_pct: Option<f32>,
    /// True when Steam account/commerce traffic is bypassing the tunnel as
    /// required by the Steam-safe policy.
    pub steam_bypass_active: bool,
}

impl TunnelHealthStatus {
    /// A conservative health check for the companion status pill. Steam-safe
    /// bypass must be active for a session to count as healthy.
    pub fn is_healthy(&self) -> bool {
        self.connected && self.steam_bypass_active && !matches!(self.path_kind, PathKind::Offline)
    }
}

/// Gamer-profile preferences synced from the companion to the desktop runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GamerProfilePreferences {
    pub low_latency: bool,
    pub ddos_shielding: bool,
    pub streamer_privacy: bool,
    /// Automatically bypass the tunnel when it worsens latency.
    pub adaptive_bypass: bool,
}

impl Default for GamerProfilePreferences {
    fn default() -> Self {
        Self {
            low_latency: true,
            ddos_shielding: true,
            streamer_privacy: false,
            adaptive_bypass: true,
        }
    }
}

/// Redact a sensitive identifier (peer id, wallet address, IP) for display in
/// the companion diagnostics viewer. Keeps a short, non-reversible prefix hint
/// only. Empty input yields the bare redaction marker.
pub fn redact_identifier(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "[redacted]".to_string();
    }
    let hint: String = trimmed.chars().take(2).collect();
    format!("{hint}\u{2026}[redacted]")
}

/// Errors produced while validating companion protocol messages.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CompanionError {
    #[error("pairing grant session id is empty")]
    EmptySessionId,
    #[error("pairing grant lists no scopes")]
    NoScopes,
    #[error("pairing grant expiry is not after its issue time")]
    NonPositiveLifetime,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_grant() -> PairingGrant {
        PairingGrant {
            session_id: "sess-1".to_string(),
            granted_scopes: vec![CompanionScope::StatusRead],
            issued_at: 1_000,
            expires_at: 2_000,
        }
    }

    #[test]
    fn pairing_grant_validates_lifetime_and_scopes() {
        let grant = sample_grant();
        assert!(grant.validate().is_ok());
        assert!(grant.allows(CompanionScope::StatusRead));
        assert!(!grant.allows(CompanionScope::RemoteControl));
    }

    #[test]
    fn pairing_grant_rejects_bad_shapes() {
        let mut empty_id = sample_grant();
        empty_id.session_id = "  ".to_string();
        assert_eq!(empty_id.validate(), Err(CompanionError::EmptySessionId));

        let mut no_scopes = sample_grant();
        no_scopes.granted_scopes.clear();
        assert_eq!(no_scopes.validate(), Err(CompanionError::NoScopes));

        let mut bad_life = sample_grant();
        bad_life.expires_at = bad_life.issued_at;
        assert_eq!(
            bad_life.validate(),
            Err(CompanionError::NonPositiveLifetime)
        );
    }

    #[test]
    fn commands_map_to_least_privilege_scope() {
        assert_eq!(
            CompanionCommand::RefreshStatus.required_scope(),
            CompanionScope::StatusRead
        );
        assert_eq!(
            CompanionCommand::SelectProfile {
                profile_id: "p1".to_string()
            }
            .required_scope(),
            CompanionScope::RemoteControl
        );
    }

    #[test]
    fn status_health_requires_bypass_and_connection() {
        let mut status = TunnelHealthStatus {
            connected: true,
            path_kind: PathKind::Direct,
            peer_count: 2,
            rtt_ms: Some(24),
            loss_pct: Some(0.1),
            steam_bypass_active: true,
        };
        assert!(status.is_healthy());
        status.steam_bypass_active = false;
        assert!(!status.is_healthy());
    }

    #[test]
    fn redaction_hides_body() {
        assert_eq!(redact_identifier(""), "[redacted]");
        let redacted = redact_identifier("qlink_ab12cd34ef");
        assert!(redacted.contains("[redacted]"));
        assert!(!redacted.contains("ab12cd34ef"));
    }

    #[test]
    fn models_survive_json_roundtrip() {
        let prefs = GamerProfilePreferences::default();
        let json = serde_json::to_string(&prefs).expect("serialize");
        let back: GamerProfilePreferences = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(prefs, back);

        let request = PairingRequest {
            device_name: "Deck Phone".to_string(),
            platform: MobilePlatform::Android,
            device_public_key_hash: "abcdef".to_string(),
            requested_scopes: vec![CompanionScope::StatusRead, CompanionScope::RemoteControl],
        };
        let json = serde_json::to_string(&request).expect("serialize");
        let back: PairingRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(request, back);
    }
}
