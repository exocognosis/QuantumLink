//! Service-side configuration persistence.
//!
//! The macOS app persisted `TunnelConfiguration` through the
//! NetworkExtension profile manager; on Windows the service owns a JSON
//! file under `%ProgramData%\QuantumLink\config.json` (directory ACL'd to
//! the service account + Administrators at install time). The UI never
//! writes this file directly — it sends `reloadConfiguration` over the
//! pipe and the service persists.

use quantumlink_proto::models::{
    DiscoveryIdentityMode, DnsMode, MeshTrustPolicy, TunnelConfiguration,
};
use quantumlink_proto::privacy;
use std::collections::HashSet;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

pub const PROGRAM_DATA_DIR: &str = "QuantumLink";
pub const CONFIG_FILE: &str = "config.json";
pub const PEER_STORE_FILE: &str = "peers.json";
pub const SECRETS_DIR: &str = "secrets";
pub const LOGS_DIR: &str = "logs";
const MAX_PROTECTED_ROUTES: usize = 256;

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
    validate_configuration(config)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let bytes = serde_json::to_vec_pretty(config)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let temp = root.join(format!("{CONFIG_FILE}.tmp"));
    let final_path = root.join(CONFIG_FILE);

    std::fs::write(&temp, bytes)?;

    #[cfg(windows)]
    {
        // std::fs::rename() does not replace an existing destination on Windows.
        let _ = std::fs::remove_file(&final_path);
    }

    std::fs::rename(&temp, &final_path)?;
    Ok(())
}

pub fn validate_configuration(config: &TunnelConfiguration) -> Result<(), String> {
    if config.protected_routes.is_empty() {
        return Err("at least one protected route is required".into());
    }
    if config.protected_routes.len() > MAX_PROTECTED_ROUTES {
        return Err(format!(
            "protected route count exceeds maximum of {MAX_PROTECTED_ROUTES}"
        ));
    }
    let mut protected_routes = HashSet::with_capacity(config.protected_routes.len());
    for route in &config.protected_routes {
        if !protected_routes.insert(route) {
            return Err(format!("duplicate protected route {route:?}"));
        }
    }
    if config.mtu < 576 {
        return Err("MTU must be at least 576 bytes".into());
    }
    config
        .overlay_ipv4_address
        .parse::<Ipv4Addr>()
        .map_err(|error| format!("overlayIPv4Address is invalid: {error}"))?;
    config
        .tunnel_remote_address
        .parse::<Ipv4Addr>()
        .map_err(|error| format!("tunnelRemoteAddress is invalid: {error}"))?;
    for server in &config.dns_servers {
        server
            .parse::<Ipv4Addr>()
            .map_err(|error| format!("DNS server {server:?} is invalid: {error}"))?;
    }
    if config.dns_mode == DnsMode::TunnelProvided && config.dns_servers.is_empty() {
        return Err("tunnelProvided DNS mode requires at least one DNS server".into());
    }

    let core_config = serde_json::to_vec(&config.packet_core_config_json())
        .map_err(|error| format!("packet core config serialization failed: {error}"))?;
    qlink_core::packet_core::PacketTunnelCore::from_json(&core_config)
        .map_err(|error| error.to_string())?;

    for endpoint in &config.rendezvous_servers {
        validate_socket_endpoint(endpoint, "rendezvous server")?;
    }
    for endpoint in &config.relay_servers {
        validate_socket_endpoint(endpoint, "relay server")?;
    }

    if config.mesh_trust_policy == MeshTrustPolicy::PublicRequired
        && config.discovery_identity_mode == DiscoveryIdentityMode::Off
    {
        return Err("publicRequired dytallix identity must not use mode off".into());
    }
    if config.mesh_trust_policy == MeshTrustPolicy::PublicRequired
        && config.dytallix_identity.is_none()
    {
        return Err("publicRequired dytallix identity requires registry configuration".into());
    }
    Ok(())
}

fn validate_socket_endpoint(endpoint: &str, field: &str) -> Result<(), String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if endpoint.contains("://") || endpoint.chars().any(char::is_whitespace) {
        return Err(format!("{field} must be a host:port endpoint"));
    }
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| format!("{field} must include a port"))?;
    if host.is_empty() {
        return Err(format!("{field} host must not be empty"));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| format!("{field} port must be a valid u16"))?;
    if port == 0 {
        return Err(format!("{field} port must be nonzero"));
    }
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

pub fn load_for_connect(root: &Path) -> io::Result<TunnelConfiguration> {
    match load_configuration(root)? {
        Some(config) => {
            validate_configuration(&config)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            Ok(config)
        }
        None => Ok(privacy::default_tunnel_configuration()),
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
        assert_eq!(
            config.protected_routes,
            vec![privacy::OVERLAY_CIDR.to_string()]
        );
        assert!(config.mesh_id.starts_with("mesh-"));
    }

    #[test]
    fn validation_rejects_empty_protected_routes() {
        let mut config = privacy::default_tunnel_configuration();
        config.protected_routes.clear();
        let error = validate_configuration(&config).unwrap_err();
        assert!(error.contains("protected route"));
    }

    #[test]
    fn validation_rejects_too_many_or_duplicate_protected_routes() {
        let mut config = privacy::default_tunnel_configuration();
        config.protected_routes = vec!["100.64.0.0/10".to_string(); MAX_PROTECTED_ROUTES + 1];
        let error = validate_configuration(&config).unwrap_err();
        assert!(error.contains("protected route count"));

        config.protected_routes = vec!["100.64.0.0/10".to_string(), "100.64.0.0/10".to_string()];
        let error = validate_configuration(&config).unwrap_err();
        assert!(error.contains("duplicate protected route"));
    }

    #[test]
    fn validation_rejects_invalid_tunnel_dns_server() {
        let mut config = privacy::default_tunnel_configuration();
        config.dns_servers = vec!["not-an-ip".to_string()];
        let error = validate_configuration(&config).unwrap_err();
        assert!(error.contains("DNS server"));
    }

    #[test]
    fn validation_rejects_tunnel_dns_mode_without_servers() {
        let mut config = privacy::default_tunnel_configuration();
        config.dns_mode = DnsMode::TunnelProvided;
        config.dns_servers.clear();
        let error = validate_configuration(&config).unwrap_err();
        assert!(error.contains("DNS mode"));
    }

    #[test]
    fn validation_rejects_invalid_protected_route() {
        let mut config = privacy::default_tunnel_configuration();
        config.protected_routes = vec!["100.64.0.0/40".to_string()];
        let error = validate_configuration(&config).unwrap_err();
        assert!(error.contains("prefix") || error.contains("route"));
    }

    #[test]
    fn validation_rejects_invalid_tunnel_remote_address() {
        let mut config = privacy::default_tunnel_configuration();
        config.tunnel_remote_address = "not-an-ip".to_string();
        let error = validate_configuration(&config).unwrap_err();
        assert!(error.contains("tunnelRemoteAddress"));
    }

    #[test]
    fn validation_rejects_invalid_endpoint() {
        let mut config = privacy::default_tunnel_configuration();
        config.rendezvous_servers = vec!["https://127.0.0.1:9471".to_string()];
        let error = validate_configuration(&config).unwrap_err();
        assert!(error.contains("rendezvous server"));
    }

    #[test]
    fn validation_rejects_public_required_identity_mode_off() {
        let mut config = privacy::default_tunnel_configuration();
        config.mesh_trust_policy = MeshTrustPolicy::PublicRequired;
        config.discovery_identity_mode = DiscoveryIdentityMode::Off;
        let error = validate_configuration(&config).unwrap_err();
        assert!(error.contains("publicRequired"));
    }

    #[test]
    fn validation_rejects_public_required_identity_without_registry() {
        let mut config = privacy::default_tunnel_configuration();
        config.mesh_trust_policy = MeshTrustPolicy::PublicRequired;
        config.discovery_identity_mode = DiscoveryIdentityMode::Verified;
        config.dytallix_identity = None;
        let error = validate_configuration(&config).unwrap_err();
        assert!(error.contains("requires registry"));
    }

    #[test]
    fn load_for_connect_rejects_invalid_persisted_config() {
        let dir = tempfile::tempdir().unwrap();
        ensure_state_dirs(dir.path()).unwrap();
        std::fs::write(dir.path().join(CONFIG_FILE), b"{this is not json").unwrap();

        let error = load_for_connect(dir.path()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
