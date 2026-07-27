use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Read, Write};
use std::net::Ipv4Addr;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const PEER_STORE_FILE: &str = "peers.json";

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
    #[serde(default)]
    pub active_peer_id: Option<String>,
    pub rendezvous_servers: Vec<String>,
    pub relay_servers: Vec<String>,
    #[serde(default)]
    pub rendezvous_auth_token_file: Option<String>,
    #[serde(default)]
    pub relay_auth_token_file: Option<String>,
    #[serde(default)]
    pub dytallix_identity: Option<DytallixIdentityLookupConfig>,
    pub kill_switch: bool,
    pub low_latency: bool,
    pub voice_chat_safe: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DytallixIdentityLookupConfig {
    pub endpoint: String,
    pub contract_address: String,
    pub network_id: String,
    pub chain_id: String,
    #[serde(default)]
    pub allowed_rpc_endpoints: Vec<String>,
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
        validate_optional_nonempty("activePeerId", self.active_peer_id.as_deref())?;
        validate_server_entries("rendezvousServers", &self.rendezvous_servers)?;
        validate_server_entries("relayServers", &self.relay_servers)?;
        validate_optional_nonempty(
            "rendezvousAuthTokenFile",
            self.rendezvous_auth_token_file.as_deref(),
        )?;
        validate_optional_nonempty("relayAuthTokenFile", self.relay_auth_token_file.as_deref())?;
        if let Some(identity) = self.dytallix_identity.as_ref() {
            validate_nonempty("dytallixIdentity.endpoint", &identity.endpoint)?;
            validate_nonempty(
                "dytallixIdentity.contractAddress",
                &identity.contract_address,
            )?;
            validate_nonempty("dytallixIdentity.networkId", &identity.network_id)?;
            validate_nonempty("dytallixIdentity.chainId", &identity.chain_id)?;
            validate_server_entries(
                "dytallixIdentity.allowedRpcEndpoints",
                &identity.allowed_rpc_endpoints,
            )?;
        }
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
    #[error("invalid {field}: must not be empty")]
    EmptyConfigEntry { field: &'static str },
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

fn validate_nonempty(field: &'static str, value: &str) -> Result<(), ConfigValidationError> {
    if value.trim().is_empty() {
        return Err(ConfigValidationError::EmptyConfigEntry { field });
    }
    Ok(())
}

fn validate_optional_nonempty(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ConfigValidationError> {
    if let Some(value) = value {
        validate_nonempty(field, value)?;
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
            active_peer_id: None,
            rendezvous_servers: Vec::new(),
            relay_servers: Vec::new(),
            rendezvous_auth_token_file: None,
            relay_auth_token_file: None,
            dytallix_identity: None,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkPlanState {
    NotStarted,
    Planned,
    ApplyFailed,
    Applied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkStatus {
    pub state: NetworkPlanState,
    pub interface_name: Option<String>,
    pub route_mode: Option<RouteMode>,
    pub protected_cidr: Option<String>,
    pub dry_run: bool,
    #[serde(default)]
    pub ownership_record_present: bool,
    pub commands: Vec<String>,
    pub nftables_rules: Vec<String>,
    pub error: Option<String>,
}

impl NetworkStatus {
    pub fn not_started() -> Self {
        Self {
            state: NetworkPlanState::NotStarted,
            interface_name: None,
            route_mode: None,
            protected_cidr: None,
            dry_run: true,
            ownership_record_present: false,
            commands: Vec::new(),
            nftables_rules: Vec::new(),
            error: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DataPlaneState {
    NotStarted,
    Starting,
    Ready,
    Degraded,
    Failed,
}

impl Default for DataPlaneState {
    fn default() -> Self {
        Self::NotStarted
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketPumpMetrics {
    pub observed_packets: u64,
    pub queued_packets: u64,
    pub dropped_packets: u64,
    pub emitted_packets: u64,
    pub accepted_packets: u64,
    pub rejected_packets: u64,
    pub transport_errors: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataPlaneStatus {
    #[serde(default)]
    pub interface_name: Option<String>,
    #[serde(default)]
    pub state: DataPlaneState,
    #[serde(default)]
    pub packet_io_available: bool,
    #[serde(default)]
    pub transport_ready: bool,
    #[serde(default)]
    pub transport_path: Option<PathKind>,
    #[serde(default)]
    pub peer_session_ready: bool,
    #[serde(default)]
    pub last_transport_error: Option<String>,
    #[serde(default)]
    pub metrics: PacketPumpMetrics,
    #[serde(default)]
    pub error: Option<String>,
}

impl DataPlaneStatus {
    pub fn not_started() -> Self {
        Self {
            interface_name: None,
            state: DataPlaneState::NotStarted,
            packet_io_available: false,
            transport_ready: false,
            transport_path: None,
            peer_session_ready: false,
            last_transport_error: None,
            metrics: PacketPumpMetrics::default(),
            error: None,
        }
    }
}

impl Default for DataPlaneStatus {
    fn default() -> Self {
        Self::not_started()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonStatus {
    pub phase: ConnectionPhase,
    pub active_party: Option<String>,
    pub peers: Vec<PeerStatus>,
    pub kill_switch: bool,
    #[serde(default = "NetworkStatus::not_started")]
    pub network: NetworkStatus,
    #[serde(default = "DataPlaneStatus::not_started")]
    pub data_plane: DataPlaneStatus,
}

impl DaemonStatus {
    pub fn idle(kill_switch: bool) -> Self {
        Self {
            phase: ConnectionPhase::Idle,
            active_party: None,
            peers: Vec::new(),
            kill_switch,
            network: NetworkStatus::not_started(),
            data_plane: DataPlaneStatus::not_started(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MeshTrustMode {
    PrivateFriends,
    PublicDytallixRequired,
    DevelopmentOptional,
}

impl Default for MeshTrustMode {
    fn default() -> Self {
        Self::PrivateFriends
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredPeer {
    pub peer_id: String,
    pub alias: String,
    pub mesh_id: String,
    pub party_id: String,
    pub trust_mode: MeshTrustMode,
    pub trust_source: String,
    pub revoked: bool,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerStore {
    #[serde(default)]
    pub selected_peer_id: Option<String>,
    pub peers: Vec<StoredPeer>,
}

impl PeerStore {
    pub fn upsert(&mut self, peer: StoredPeer) {
        if let Some(existing) = self
            .peers
            .iter_mut()
            .find(|existing| existing.peer_id == peer.peer_id)
        {
            *existing = peer;
        } else {
            self.peers.push(peer);
        }
        self.peers
            .sort_by(|left, right| left.peer_id.cmp(&right.peer_id));
    }

    pub fn remove(&mut self, peer_id: &str) -> bool {
        let original_len = self.peers.len();
        self.peers.retain(|peer| peer.peer_id != peer_id);
        let removed = self.peers.len() != original_len;
        if removed && self.selected_peer_id.as_deref() == Some(peer_id) {
            self.selected_peer_id = None;
        }
        removed
    }

    pub fn revoke(&mut self, peer_id: &str) -> bool {
        if let Some(peer) = self.peers.iter_mut().find(|peer| peer.peer_id == peer_id) {
            peer.revoked = true;
            if self.selected_peer_id.as_deref() == Some(peer_id) {
                self.selected_peer_id = None;
            }
            true
        } else {
            false
        }
    }

    pub fn select(&mut self, peer_id: &str, now_unix: u64) -> bool {
        let eligible = self.peers.iter().any(|peer| {
            peer.peer_id == peer_id && !peer.revoked && peer.expires_at_unix > now_unix
        });
        if eligible {
            self.selected_peer_id = Some(peer_id.to_string());
        }
        eligible
    }

    pub fn dial_candidates(&self, now_unix: u64) -> Vec<StoredPeer> {
        self.peers
            .iter()
            .filter(|peer| !peer.revoked && peer.expires_at_unix > now_unix)
            .cloned()
            .collect()
    }
}

pub fn peer_store_path_from_state_dir(state_dir: impl AsRef<Path>) -> PathBuf {
    state_dir.as_ref().join(PEER_STORE_FILE)
}

pub fn load_peer_store_at(path: impl AsRef<Path>) -> std::io::Result<PeerStore> {
    let path = path.as_ref();
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err(std::io::Error::new(
                    ErrorKind::AlreadyExists,
                    format!("peer store path {} is not a regular file", path.display()),
                ));
            }
            let mut file = open_peer_store_for_read(path)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            serde_json::from_slice(&bytes).map_err(|error| {
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to parse peer store: {error}"),
                )
            })
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(PeerStore::default()),
        Err(error) => Err(error),
    }
}

pub fn store_peer_store_at(
    state_dir: impl AsRef<Path>,
    store: &PeerStore,
) -> std::io::Result<PathBuf> {
    let state_dir = state_dir.as_ref();
    std::fs::create_dir_all(state_dir)?;
    let path = peer_store_path_from_state_dir(state_dir);
    let bytes = serde_json::to_vec_pretty(store).map_err(|error| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("failed to serialize peer store: {error}"),
        )
    })?;
    write_peer_store_atomically(state_dir, &path, &bytes)?;
    Ok(path)
}

fn write_peer_store_atomically(state_dir: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temp_path = peer_store_temp_path(state_dir);
    let write_result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut file = open_peer_store_no_follow(&mut options, &temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(unix)]
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&temp_path, path)
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }

    write_result
}

fn peer_store_temp_path(state_dir: &Path) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    state_dir.join(format!(
        ".{PEER_STORE_FILE}.{}.{}.tmp",
        std::process::id(),
        nonce
    ))
}

fn open_peer_store_for_read(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    open_peer_store_no_follow(&mut options, path)
}

#[cfg(unix)]
fn open_peer_store_no_follow(
    options: &mut std::fs::OpenOptions,
    path: &Path,
) -> std::io::Result<std::fs::File> {
    let before = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Some((metadata.dev(), metadata.ino())),
        Ok(_) => {
            return Err(std::io::Error::new(
                ErrorKind::AlreadyExists,
                format!("peer store path {} is not a regular file", path.display()),
            ))
        }
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };

    let file = options.open(path)?;
    if let Some((expected_dev, expected_ino)) = before {
        let after = file.metadata()?;
        if after.dev() != expected_dev || after.ino() != expected_ino {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                format!("peer store path {} changed during open", path.display()),
            ));
        }
    }

    Ok(file)
}

#[cfg(not(unix))]
fn open_peer_store_no_follow(
    options: &mut std::fs::OpenOptions,
    path: &Path,
) -> std::io::Result<std::fs::File> {
    options.open(path)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCode {
    pub mesh_id: String,
    pub party_id: String,
    pub rendezvous: Vec<String>,
    pub relay: Vec<String>,
    pub host_peer_id: String,
    #[serde(default)]
    pub host_alias: String,
    #[serde(default)]
    pub trust_mode: MeshTrustMode,
    #[serde(default = "default_invite_trust_source")]
    pub trust_source: String,
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

    pub fn stored_peer(&self) -> StoredPeer {
        StoredPeer {
            peer_id: self.host_peer_id.clone(),
            alias: if self.host_alias.trim().is_empty() {
                self.host_peer_id.clone()
            } else {
                self.host_alias.clone()
            },
            mesh_id: self.mesh_id.clone(),
            party_id: self.party_id.clone(),
            trust_mode: self.trust_mode,
            trust_source: self.trust_source.clone(),
            revoked: false,
            expires_at_unix: self.expires_at_unix,
        }
    }
}

fn default_invite_trust_source() -> String {
    "invite".to_string()
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
    fn production_transport_settings_round_trip() {
        let config: DaemonConfig = serde_json::from_value(serde_json::json!({
            "interfaceName": "qlink0",
            "overlayCidr": "100.64.0.0/10",
            "overlayIpv4Address": "100.64.10.2",
            "routeMode": "gameOnly",
            "activePeerId": "peer-a",
            "rendezvousServers": ["tls://rv.example:9471"],
            "relayServers": ["tls://relay.example:9472"],
            "rendezvousAuthTokenFile": "/etc/quantumlink/secrets/rv.token",
            "relayAuthTokenFile": "/etc/quantumlink/secrets/relay.token",
            "dytallixIdentity": {
                "endpoint": "https://registry.example",
                "contractAddress": "quantumlink-node-registry",
                "networkId": "dytallix-mainnet",
                "chainId": "dytallix-1",
                "allowedRpcEndpoints": ["https://rpc.example"]
            },
            "killSwitch": true,
            "lowLatency": true,
            "voiceChatSafe": true
        }))
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.active_peer_id.as_deref(), Some("peer-a"));
        assert_eq!(
            config.dytallix_identity.as_ref().unwrap().network_id,
            "dytallix-mainnet"
        );
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
        let config = DaemonConfig {
            interface_name: "qlink/bad".to_string(),
            ..DaemonConfig::default()
        };

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("interfaceName"));
        assert!(error.to_string().contains("ASCII"));
    }

    #[test]
    fn validation_rejects_invalid_overlay_cidr() {
        let config = DaemonConfig {
            overlay_cidr: "100.64.0.0".to_string(),
            ..DaemonConfig::default()
        };

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("overlayCidr"));
        assert!(error.to_string().contains("CIDR"));
    }

    #[test]
    fn validation_rejects_non_canonical_overlay_cidr() {
        let config = DaemonConfig {
            overlay_cidr: "100.64.10.2/10".to_string(),
            ..DaemonConfig::default()
        };

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("overlayCidr"));
        assert!(error.to_string().contains("network address"));
    }

    #[test]
    fn validation_rejects_zero_length_overlay_prefix() {
        let config = DaemonConfig {
            overlay_cidr: "100.64.0.0/0".to_string(),
            ..DaemonConfig::default()
        };

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("overlayCidr"));
        assert!(error.to_string().contains("between 1 and 32"));
    }

    #[test]
    fn validation_rejects_invalid_overlay_address() {
        let config = DaemonConfig {
            overlay_ipv4_address: "not-an-ip".to_string(),
            ..DaemonConfig::default()
        };

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("overlayIpv4Address"));
        assert!(error.to_string().contains("IPv4"));
    }

    #[test]
    fn validation_rejects_overlay_address_outside_overlay_cidr() {
        let config = DaemonConfig {
            overlay_cidr: "100.64.0.0/10".to_string(),
            overlay_ipv4_address: "10.0.0.2".to_string(),
            ..DaemonConfig::default()
        };

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("overlayIpv4Address"));
        assert!(error.to_string().contains("overlayCidr"));
    }

    #[test]
    fn validation_rejects_empty_rendezvous_server_entry() {
        let config = DaemonConfig {
            rendezvous_servers: vec!["rv.example:9471".to_string(), " ".to_string()],
            ..DaemonConfig::default()
        };

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("rendezvousServers[1]"));
        assert!(error.to_string().contains("empty"));
    }

    #[test]
    fn validation_rejects_empty_relay_server_entry() {
        let config = DaemonConfig {
            relay_servers: vec!["relay.example:9472".to_string(), "".to_string()],
            ..DaemonConfig::default()
        };

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("relayServers[1]"));
        assert!(error.to_string().contains("empty"));
    }

    #[test]
    fn validation_allows_full_tunnel_route_mode_without_extra_flags() {
        let config = DaemonConfig {
            route_mode: RouteMode::FullTunnel,
            ..DaemonConfig::default()
        };

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
            network: NetworkStatus {
                state: NetworkPlanState::Planned,
                interface_name: Some("qlink0".to_string()),
                route_mode: Some(RouteMode::GameOnly),
                protected_cidr: Some("100.64.0.0/10".to_string()),
                dry_run: true,
                ownership_record_present: false,
                commands: vec!["ip tuntap add dev qlink0 mode tun".to_string()],
                nftables_rules: vec!["add table inet qlink".to_string()],
                error: None,
            },
            data_plane: DataPlaneStatus::not_started(),
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"activeParty\":\"squad-123\""));
        assert!(json.contains("\"medianRttMs\":24"));
        assert!(json.contains("\"state\":\"planned\""));
        assert!(json.contains("\"protectedCidr\":\"100.64.0.0/10\""));
        assert!(json.contains("\"dryRun\":true"));
    }

    #[test]
    fn idle_status_starts_with_network_not_started() {
        let status = DaemonStatus::idle(true);

        assert_eq!(status.network.state, NetworkPlanState::NotStarted);
        assert!(status.network.interface_name.is_none());
        assert!(status.network.commands.is_empty());
    }

    #[test]
    fn status_deserializes_legacy_payload_without_network_field() {
        let status: DaemonStatus = serde_json::from_str(
            r#"{
                "phase": "idle",
                "activeParty": null,
                "peers": [],
                "killSwitch": true
            }"#,
        )
        .unwrap();

        assert_eq!(status.phase, ConnectionPhase::Idle);
        assert_eq!(status.network, NetworkStatus::not_started());
    }

    #[test]
    fn idle_status_starts_with_data_plane_not_started() {
        let status = DaemonStatus::idle(true);

        assert_eq!(status.data_plane, DataPlaneStatus::not_started());
        assert_eq!(status.data_plane.state, DataPlaneState::NotStarted);
        assert!(status.data_plane.interface_name.is_none());
        assert!(!status.data_plane.packet_io_available);
        assert!(!status.data_plane.transport_ready);
        assert!(status.data_plane.transport_path.is_none());
        assert!(!status.data_plane.peer_session_ready);
        assert!(status.data_plane.last_transport_error.is_none());
        assert_eq!(status.data_plane.metrics, PacketPumpMetrics::default());
        assert!(status.data_plane.error.is_none());
    }

    #[test]
    fn status_deserializes_legacy_payload_without_data_plane_field() {
        let status: DaemonStatus = serde_json::from_str(
            r#"{
                "phase": "idle",
                "activeParty": null,
                "peers": [],
                "killSwitch": true,
                "network": {
                    "state": "notStarted",
                    "interfaceName": null,
                    "routeMode": null,
                    "protectedCidr": null,
                    "dryRun": true,
                    "ownershipRecordPresent": false,
                    "commands": [],
                    "nftablesRules": [],
                    "error": null
                }
            }"#,
        )
        .unwrap();

        assert_eq!(status.data_plane, DataPlaneStatus::not_started());
    }

    #[test]
    fn status_serializes_data_plane_state_and_packet_pump_metrics() {
        let mut status = DaemonStatus::idle(true);
        status.data_plane = DataPlaneStatus {
            interface_name: Some("qlink0".to_string()),
            state: DataPlaneState::Ready,
            packet_io_available: true,
            transport_ready: true,
            transport_path: Some(PathKind::Direct),
            peer_session_ready: true,
            last_transport_error: None,
            metrics: PacketPumpMetrics {
                observed_packets: 10,
                queued_packets: 9,
                dropped_packets: 1,
                emitted_packets: 8,
                accepted_packets: 7,
                rejected_packets: 2,
                transport_errors: 1,
            },
            error: None,
        };

        let json = serde_json::to_string(&status).unwrap();

        assert!(json.contains(r#""dataPlane":"#));
        assert!(json.contains(r#""interfaceName":"qlink0""#));
        assert!(json.contains(r#""state":"ready""#));
        assert!(json.contains(r#""packetIoAvailable":true"#));
        assert!(json.contains(r#""transportReady":true"#));
        assert!(json.contains(r#""transportPath":"direct""#));
        assert!(json.contains(r#""peerSessionReady":true"#));
        assert!(json.contains(r#""observedPackets":10"#));
        assert!(json.contains(r#""queuedPackets":9"#));
        assert!(json.contains(r#""droppedPackets":1"#));
        assert!(json.contains(r#""emittedPackets":8"#));
        assert!(json.contains(r#""acceptedPackets":7"#));
        assert!(json.contains(r#""rejectedPackets":2"#));
        assert!(json.contains(r#""transportErrors":1"#));
    }

    #[test]
    fn status_serializes_live_transport_readiness() {
        let mut status = DaemonStatus::idle(true);
        status.data_plane = DataPlaneStatus {
            interface_name: Some("qlink0".to_string()),
            state: DataPlaneState::Ready,
            packet_io_available: true,
            transport_ready: true,
            transport_path: Some(PathKind::Direct),
            peer_session_ready: true,
            last_transport_error: None,
            metrics: PacketPumpMetrics::default(),
            error: None,
        };

        let value = serde_json::to_value(&status).unwrap();
        let data_plane = value.get("dataPlane").unwrap();

        assert_eq!(data_plane.get("state").unwrap(), "ready");
        assert_eq!(data_plane.get("packetIoAvailable").unwrap(), true);
        assert_eq!(data_plane.get("transportReady").unwrap(), true);
        assert_eq!(data_plane.get("transportPath").unwrap(), "direct");
        assert_eq!(data_plane.get("peerSessionReady").unwrap(), true);
    }

    #[test]
    fn network_status_serializes_applied_and_apply_failed_states() {
        let mut status = DaemonStatus::idle(true);
        status.network = NetworkStatus {
            state: NetworkPlanState::Applied,
            interface_name: Some("qlink0".to_string()),
            route_mode: Some(RouteMode::GameOnly),
            protected_cidr: Some("100.64.0.0/10".to_string()),
            dry_run: false,
            ownership_record_present: true,
            commands: vec!["ip tuntap add dev qlink0 mode tun".to_string()],
            nftables_rules: vec!["add table inet qlink".to_string()],
            error: None,
        };

        let applied_json = serde_json::to_string(&status).unwrap();
        assert!(applied_json.contains(r#""state":"applied""#));
        assert!(applied_json.contains(r#""dryRun":false"#));
        assert!(applied_json.contains(r#""ownershipRecordPresent":true"#));

        status.network.state = NetworkPlanState::ApplyFailed;
        status.network.error = Some("nftables apply failed".to_string());

        let failed_json = serde_json::to_string(&status).unwrap();
        assert!(failed_json.contains(r#""state":"applyFailed""#));
        assert!(failed_json.contains(r#""error":"nftables apply failed""#));
    }

    #[test]
    fn network_status_deserializes_legacy_payload_without_ownership_field() {
        let status: NetworkStatus = serde_json::from_str(
            r#"{
                "state": "applied",
                "interfaceName": "qlink0",
                "routeMode": "gameOnly",
                "protectedCidr": "100.64.0.0/10",
                "dryRun": false,
                "commands": [],
                "nftablesRules": [],
                "error": null
            }"#,
        )
        .unwrap();

        assert!(!status.ownership_record_present);
    }

    #[test]
    fn invite_codes_round_trip_without_real_ip_requirement() {
        let invite = InviteCode {
            mesh_id: "mesh-game".to_string(),
            party_id: "party-1".to_string(),
            rendezvous: vec!["rv.example:9471".to_string()],
            relay: vec!["relay.example:9472".to_string()],
            host_peer_id: "peer-host".to_string(),
            host_alias: "Host Deck".to_string(),
            trust_mode: MeshTrustMode::PrivateFriends,
            trust_source: "invite".to_string(),
            expires_at_unix: 1_900_000_000,
        };

        let encoded = invite.encode().unwrap();
        let decoded = InviteCode::decode(&encoded).unwrap();

        assert_eq!(decoded.mesh_id, invite.mesh_id);
        assert_eq!(decoded.relay, invite.relay);
        assert!(!encoded.contains("192.168."));
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos()
        ))
    }

    fn stored_peer_fixture() -> StoredPeer {
        StoredPeer {
            peer_id: "peer-host-deck".to_string(),
            alias: "Host Deck".to_string(),
            mesh_id: "mesh-steam-squad".to_string(),
            party_id: "party-nightly".to_string(),
            trust_mode: MeshTrustMode::PrivateFriends,
            trust_source: "invite".to_string(),
            revoked: false,
            expires_at_unix: 4_102_444_800,
        }
    }

    #[test]
    fn peer_store_round_trips_with_private_permissions() {
        let state_dir = unique_temp_dir("qlink-proto-peer-store");
        let mut store = PeerStore::default();
        store.upsert(stored_peer_fixture());

        let path = store_peer_store_at(&state_dir, &store).unwrap();
        let loaded = load_peer_store_at(&path).unwrap();

        assert_eq!(loaded, store);
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[cfg(unix)]
    #[test]
    fn peer_store_rejects_symlink_path() {
        use std::os::unix::fs::symlink;

        let state_dir = unique_temp_dir("qlink-proto-peer-store-symlink");
        std::fs::create_dir_all(&state_dir).unwrap();
        let target = state_dir.join("target.json");
        std::fs::write(&target, r#"{"peers":[]}"#).unwrap();
        let link = peer_store_path_from_state_dir(&state_dir);
        symlink(&target, &link).unwrap();

        let error = load_peer_store_at(&link).unwrap_err();

        assert!(
            error.to_string().contains("not a regular file"),
            "unexpected error: {error}"
        );
        let _ = std::fs::remove_dir_all(state_dir);
    }
}
