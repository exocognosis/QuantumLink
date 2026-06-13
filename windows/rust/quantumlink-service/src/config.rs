//! Service-side configuration persistence.
//!
//! The macOS app persisted `TunnelConfiguration` through the
//! NetworkExtension profile manager; on Windows the service owns a JSON
//! file under `%ProgramData%\QuantumLink\config.json` (directory ACL'd to
//! the service account + Administrators at install time). The UI never
//! writes this file directly — it sends `reloadConfiguration` over the
//! pipe and the service persists.

use quantumlink_proto::models::TunnelConfiguration;
use quantumlink_proto::privacy;
use std::io;
use std::path::{Path, PathBuf};

pub const PROGRAM_DATA_DIR: &str = "QuantumLink";
pub const CONFIG_FILE: &str = "config.json";
pub const PEER_STORE_FILE: &str = "peers.json";
pub const SECRETS_DIR: &str = "secrets";
pub const LOGS_DIR: &str = "logs";

/// Root state directory for the service.
///
/// Windows: `%ProgramData%\QuantumLink` (falls back to
/// `C:\ProgramData\QuantumLink` when the env var is unset, which only
/// happens in stripped service environments). Elsewhere (development
/// hosts, CI): `~/.quantumlink-windows-dev` so the same code paths run
/// without elevation.
pub fn state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join(PROGRAM_DATA_DIR)
    }
    #[cfg(not(windows))]
    {
        let base = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        base.join(".quantumlink-windows-dev")
    }
}

pub fn ensure_state_dirs(root: &Path) -> io::Result<()> {
    std::fs::create_dir_all(root)?;
    std::fs::create_dir_all(root.join(SECRETS_DIR))?;
    std::fs::create_dir_all(root.join(LOGS_DIR))?;
    Ok(())
}

pub fn load_configuration(root: &Path) -> io::Result<Option<TunnelConfiguration>> {
    let path = root.join(CONFIG_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let config = serde_json::from_slice(&bytes).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("config.json is malformed: {error}"),
                )
            })?;
            Ok(Some(config))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Persists atomically (write-temp + rename) so a crash mid-write never
/// leaves a truncated config behind.
pub fn save_configuration(root: &Path, config: &TunnelConfiguration) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(config)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let temp = root.join(format!("{CONFIG_FILE}.tmp"));
    std::fs::write(&temp, bytes)?;
    std::fs::rename(&temp, root.join(CONFIG_FILE))?;
    Ok(())
}

/// Configuration used when nothing has been persisted yet — pseudonymous
/// identifiers, CGNAT overlay, fail-closed kill switch (mirrors
/// `PrivacyDefaults.defaultTunnelConfiguration()`).
pub fn load_or_default(root: &Path) -> TunnelConfiguration {
    match load_configuration(root) {
        Ok(Some(config)) => config,
        Ok(None) => privacy::default_tunnel_configuration(),
        Err(error) => {
            tracing::warn!(%error, "config load failed; using privacy defaults");
            privacy::default_tunnel_configuration()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_round_trips_atomically() {
        let dir = tempfile::tempdir().unwrap();
        ensure_state_dirs(dir.path()).unwrap();
        let config = privacy::default_tunnel_configuration();
        save_configuration(dir.path(), &config).unwrap();
        let loaded = load_configuration(dir.path()).unwrap().unwrap();
        assert_eq!(loaded, config);
        assert!(!dir.path().join(format!("{CONFIG_FILE}.tmp")).exists());
    }

    #[test]
    fn missing_config_yields_privacy_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = load_or_default(dir.path());
        assert_eq!(config.protected_routes, vec![privacy::OVERLAY_CIDR.to_string()]);
        assert!(config.mesh_id.starts_with("mesh-"));
    }
}
