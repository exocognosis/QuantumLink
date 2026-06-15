use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RouteMode {
    GameOnly,
    ProtectedPrefixesOnly,
    FullTunnel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonConfig {
    pub interface_name: String,
    pub overlay_cidr: String,
    pub overlay_ipv4_address: String,
    pub route_mode: RouteMode,
    pub rendezvous_servers: Vec<String>,
    pub relay_servers: Vec<String>,
    pub kill_switch: bool,
    pub low_latency: bool,
    pub voice_chat_safe: bool,
}

impl DaemonConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_interface_name(&self.interface_name)?;
        let overlay = validate_overlay_cidr(&self.overlay_cidr)?;
        let overlay_address = validate_overlay_ipv4_address(&self.overlay_ipv4_address)?;
        validate_overlay_address_membership(
            overlay_address,
            overlay,
            &self.overlay_cidr,
            &self.overlay_ipv4_address,
        )?;
        validate_server_entries("rendezvousServers", &self.rendezvous_servers)?;
        validate_server_entries("relayServers", &self.relay_servers)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigValidationError {
    #[error("invalid interfaceName: must not be empty")]
    EmptyInterfaceName,
    #[error("invalid interfaceName `{name}`: {reason}")]
    InvalidInterfaceName { name: String, reason: &'static str },
    #[error("invalid overlayCidr `{value}`: {reason}")]
    InvalidOverlayCidr { value: String, reason: String },
    #[error("invalid overlayIpv4Address `{value}`: {reason}")]
    InvalidOverlayIpv4Address { value: String, reason: String },
    #[error("invalid {field}[{index}]: must not be empty")]
    EmptyServerEntry { field: &'static str, index: usize },
}

const MAX_LINUX_INTERFACE_NAME_BYTES: usize = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OverlayNetwork {
    address: Ipv4Addr,
    prefix_len: u8,
}

impl OverlayNetwork {
    fn mask(self) -> u32 {
        u32::MAX << (32 - self.prefix_len)
    }

    fn contains(self, address: Ipv4Addr) -> bool {
        let mask = self.mask();
        u32::from(address) & mask == u32::from(self.address)
    }
}

fn validate_interface_name(name: &str) -> Result<(), ConfigValidationError> {
    if name.is_empty() {
        return Err(ConfigValidationError::EmptyInterfaceName);
    }
    if name.len() > MAX_LINUX_INTERFACE_NAME_BYTES {
        return Err(ConfigValidationError::InvalidInterfaceName {
            name: name.to_string(),
            reason: "must be 15 bytes or fewer",
        });
    }
    if name == "." || name == ".." {
        return Err(ConfigValidationError::InvalidInterfaceName {
            name: name.to_string(),
            reason: "must not be '.' or '..'",
        });
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(ConfigValidationError::InvalidInterfaceName {
            name: name.to_string(),
            reason: "must contain only ASCII letters, digits, '.', '_' or '-'",
        });
    }
    Ok(())
}

fn validate_overlay_cidr(value: &str) -> Result<OverlayNetwork, ConfigValidationError> {
    let (address, prefix) =
        value
            .split_once('/')
            .ok_or_else(|| ConfigValidationError::InvalidOverlayCidr {
                value: value.to_string(),
                reason: "must be IPv4 CIDR notation like 100.64.0.0/10".to_string(),
            })?;

    if address.is_empty() || prefix.is_empty() || prefix.contains('/') {
        return Err(ConfigValidationError::InvalidOverlayCidr {
            value: value.to_string(),
            reason: "must be IPv4 CIDR notation like 100.64.0.0/10".to_string(),
        });
    }

    let network_address =
        address
            .parse::<Ipv4Addr>()
            .map_err(|error| ConfigValidationError::InvalidOverlayCidr {
                value: value.to_string(),
                reason: format!("invalid IPv4 network address: {error}"),
            })?;

    let prefix_len =
        prefix
            .parse::<u8>()
            .map_err(|error| ConfigValidationError::InvalidOverlayCidr {
                value: value.to_string(),
                reason: format!("invalid IPv4 prefix length: {error}"),
            })?;
    if !(1..=32).contains(&prefix_len) {
        return Err(ConfigValidationError::InvalidOverlayCidr {
            value: value.to_string(),
            reason: "IPv4 prefix length must be between 1 and 32".to_string(),
        });
    }

    let overlay = OverlayNetwork {
        address: network_address,
        prefix_len,
    };
    let canonical_address = Ipv4Addr::from(u32::from(network_address) & overlay.mask());
    if network_address != canonical_address {
        return Err(ConfigValidationError::InvalidOverlayCidr {
            value: value.to_string(),
            reason: format!("must use canonical network address {canonical_address}/{prefix_len}"),
        });
    }

    Ok(overlay)
}

fn validate_overlay_ipv4_address(value: &str) -> Result<Ipv4Addr, ConfigValidationError> {
    value
        .parse::<Ipv4Addr>()
        .map_err(|error| ConfigValidationError::InvalidOverlayIpv4Address {
            value: value.to_string(),
            reason: format!("invalid IPv4 address: {error}"),
        })
}

fn validate_overlay_address_membership(
    address: Ipv4Addr,
    overlay: OverlayNetwork,
    overlay_cidr: &str,
    overlay_address: &str,
) -> Result<(), ConfigValidationError> {
    if overlay.contains(address) {
        return Ok(());
    }

    Err(ConfigValidationError::InvalidOverlayIpv4Address {
        value: overlay_address.to_string(),
        reason: format!("must be within overlayCidr {overlay_cidr}"),
    })
}

fn validate_server_entries(
    field: &'static str,
    entries: &[String],
) -> Result<(), ConfigValidationError> {
    for (index, entry) in entries.iter().enumerate() {
        if entry.trim().is_empty() {
            return Err(ConfigValidationError::EmptyServerEntry { field, index });
        }
    }
    Ok(())
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            interface_name: "qlink0".to_string(),
            overlay_cidr: "100.64.0.0/10".to_string(),
            overlay_ipv4_address: "100.64.10.2".to_string(),
            route_mode: RouteMode::GameOnly,
            rendezvous_servers: Vec::new(),
            relay_servers: Vec::new(),
            kill_switch: true,
            low_latency: true,
            voice_chat_safe: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConnectionPhase {
    Idle,
    Preparing,
    Connecting,
    Connected,
    Degraded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PathKind {
    Direct,
    Relay,
    Probing,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerStatus {
    pub peer_id: String,
    pub alias: String,
    pub path: PathKind,
    pub median_rtt_ms: Option<u32>,
    pub jitter_ms: Option<u32>,
    pub packet_loss_percent: Option<f32>,
    pub nat_type: Option<String>,
    pub relay_privacy: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonStatus {
    pub phase: ConnectionPhase,
    pub active_party: Option<String>,
    pub peers: Vec<PeerStatus>,
    pub kill_switch: bool,
}

impl DaemonStatus {
    pub fn idle(kill_switch: bool) -> Self {
        Self {
            phase: ConnectionPhase::Idle,
            active_party: None,
            peers: Vec::new(),
            kill_switch,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCode {
    pub mesh_id: String,
    pub party_id: String,
    pub rendezvous: Vec<String>,
    pub relay: Vec<String>,
    pub host_peer_id: String,
    pub expires_at_unix: u64,
}

impl InviteCode {
    pub fn encode(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(self)?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn decode(encoded: &str) -> Result<Self, InviteDecodeError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|error| InviteDecodeError::Base64(error.to_string()))?;
        serde_json::from_slice(&bytes).map_err(InviteDecodeError::Json)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InviteDecodeError {
    #[error("invalid invite encoding: {0}")]
    Base64(String),
    #[error("invalid invite payload: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_steamos_gaming_split_tunnel() {
        let config = DaemonConfig::default();

        assert_eq!(config.interface_name, "qlink0");
        assert_eq!(config.overlay_cidr, "100.64.0.0/10");
        assert_eq!(config.route_mode, RouteMode::GameOnly);
        assert!(config.kill_switch);
        assert!(config.low_latency);
        assert!(config.voice_chat_safe);
    }

    #[test]
    fn default_config_passes_validation() {
        DaemonConfig::default().validate().unwrap();
    }

    #[test]
    fn validation_rejects_empty_interface_name() {
        let mut config = DaemonConfig::default();
        config.interface_name.clear();

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("interfaceName"));
        assert!(error.to_string().contains("empty"));
    }

    #[test]
    fn validation_rejects_invalid_interface_name() {
        let mut config = DaemonConfig::default();
        config.interface_name = "qlink/bad".to_string();

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("interfaceName"));
        assert!(error.to_string().contains("ASCII"));
    }

    #[test]
    fn validation_rejects_invalid_overlay_cidr() {
        let mut config = DaemonConfig::default();
        config.overlay_cidr = "100.64.0.0".to_string();

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("overlayCidr"));
        assert!(error.to_string().contains("CIDR"));
    }

    #[test]
    fn validation_rejects_non_canonical_overlay_cidr() {
        let mut config = DaemonConfig::default();
        config.overlay_cidr = "100.64.10.2/10".to_string();

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("overlayCidr"));
        assert!(error.to_string().contains("network address"));
    }

    #[test]
    fn validation_rejects_zero_length_overlay_prefix() {
        let mut config = DaemonConfig::default();
        config.overlay_cidr = "100.64.0.0/0".to_string();

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("overlayCidr"));
        assert!(error.to_string().contains("between 1 and 32"));
    }

    #[test]
    fn validation_rejects_invalid_overlay_address() {
        let mut config = DaemonConfig::default();
        config.overlay_ipv4_address = "not-an-ip".to_string();

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("overlayIpv4Address"));
        assert!(error.to_string().contains("IPv4"));
    }

    #[test]
    fn validation_rejects_overlay_address_outside_overlay_cidr() {
        let mut config = DaemonConfig::default();
        config.overlay_cidr = "100.64.0.0/10".to_string();
        config.overlay_ipv4_address = "10.0.0.2".to_string();

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("overlayIpv4Address"));
        assert!(error.to_string().contains("overlayCidr"));
    }

    #[test]
    fn validation_rejects_empty_rendezvous_server_entry() {
        let mut config = DaemonConfig::default();
        config.rendezvous_servers = vec!["rv.example:9471".to_string(), " ".to_string()];

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("rendezvousServers[1]"));
        assert!(error.to_string().contains("empty"));
    }

    #[test]
    fn validation_rejects_empty_relay_server_entry() {
        let mut config = DaemonConfig::default();
        config.relay_servers = vec!["relay.example:9472".to_string(), "".to_string()];

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("relayServers[1]"));
        assert!(error.to_string().contains("empty"));
    }

    #[test]
    fn validation_allows_full_tunnel_route_mode_without_extra_flags() {
        let mut config = DaemonConfig::default();
        config.route_mode = RouteMode::FullTunnel;

        config.validate().unwrap();
    }

    #[test]
    fn status_serializes_with_peer_metrics() {
        let status = DaemonStatus {
            phase: ConnectionPhase::Connected,
            active_party: Some("squad-123".to_string()),
            peers: vec![PeerStatus {
                peer_id: "peer-a".to_string(),
                alias: "deck".to_string(),
                path: PathKind::Direct,
                median_rtt_ms: Some(24),
                jitter_ms: Some(3),
                packet_loss_percent: Some(0.5),
                nat_type: Some("port-restricted".to_string()),
                relay_privacy: false,
            }],
            kill_switch: true,
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"activeParty\":\"squad-123\""));
        assert!(json.contains("\"medianRttMs\":24"));
    }

    #[test]
    fn invite_codes_round_trip_without_real_ip_requirement() {
        let invite = InviteCode {
            mesh_id: "mesh-game".to_string(),
            party_id: "party-1".to_string(),
            rendezvous: vec!["rv.example:9471".to_string()],
            relay: vec!["relay.example:9472".to_string()],
            host_peer_id: "peer-host".to_string(),
            expires_at_unix: 1_900_000_000,
        };

        let encoded = invite.encode().unwrap();
        let decoded = InviteCode::decode(&encoded).unwrap();

        assert_eq!(decoded.mesh_id, invite.mesh_id);
        assert_eq!(decoded.relay, invite.relay);
        assert!(!encoded.contains("192.168."));
    }
}
