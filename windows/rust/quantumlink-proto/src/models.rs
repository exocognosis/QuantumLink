//! Product models — Rust port of `QuantumLinkKit/Models.swift`.
//!
//! Enum raw values and struct field names match the Swift `Codable`
//! encoding (camelCase keys, rawValue strings) so JSON produced by either
//! platform is readable by the other.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum ConnectionPhase {
    #[default]
    Idle,
    Preparing,
    Connecting,
    Connected,
    Degraded,
    Reconnecting,
    Disconnected,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum PathType {
    Direct,
    Relay,
    Probing,
    #[default]
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum RouteMode {
    #[default]
    SplitTunnel,
    ProtectedPrefixesOnly,
    FullTunnel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum DnsMode {
    #[default]
    TunnelProvided,
    System,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiscoveryMode {
    Rendezvous,
    #[serde(rename = "privateDHT")]
    PrivateDht,
    #[serde(rename = "localMDNS")]
    LocalMdns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MeshTrustPolicy {
    PublicRequired,
    PrivatePreferred,
    #[default]
    DevelopmentOptional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryIdentityMode {
    #[default]
    Off,
    Verified,
    PublicWallet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum MeshType {
    Public,
    Private,
    #[default]
    Development,
}

fn default_dytallix_identity_mode() -> DiscoveryIdentityMode {
    DiscoveryIdentityMode::Verified
}

fn default_dytallix_contract() -> String {
    "quantumlink-node-registry".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DytallixIdentityConfiguration {
    #[serde(default = "default_dytallix_identity_mode")]
    pub mode: DiscoveryIdentityMode,
    #[serde(rename = "registryEndpoint", alias = "endpoint")]
    pub registry_endpoint: String,
    #[serde(default = "default_dytallix_contract")]
    pub contract: String,
    #[serde(default)]
    pub cached_proof_grace_seconds: u64,
    #[serde(default)]
    pub contract_address: Option<String>,
    #[serde(default)]
    pub publish_wallet_address: bool,
    #[serde(rename = "networkID", default)]
    pub network_id: Option<String>,
    #[serde(rename = "chainID", default)]
    pub chain_id: Option<String>,
    #[serde(rename = "allowedRPCEndpoints", default)]
    pub allowed_rpc_endpoints: Vec<String>,
    #[serde(default)]
    pub keystore_path: Option<String>,
    #[serde(default)]
    pub wallet_name: Option<String>,
}

impl DytallixIdentityConfiguration {
    pub fn core_contract_identifier(&self) -> String {
        self.contract_address
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(&self.contract)
            .to_string()
    }
}

/// Defines how the tunnel behaves when the data plane cannot protect a
/// packet.
///
/// `FailClosed` (default): traffic for protected prefixes is dropped at
/// the packet pump whenever the transport is not ready. On Windows the
/// WFP kill-switch filters additionally pin protected prefixes to the
/// Wintun adapter so plaintext cannot leak out another interface.
///
/// `Strict`: same as `FailClosed`, plus the service refuses to bring the
/// tunnel up at all if the transport cannot establish during start, and
/// the kill-switch watchdog tears the tunnel down after a sustained
/// unhealthy period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum KillSwitchPolicy {
    #[default]
    FailClosed,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerIdentity {
    #[serde(rename = "peerID")]
    pub peer_id: String,
    pub alias: String,
    pub public_key_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerEndpoint {
    pub candidate_type: String,
    pub address: String,
    pub port: u16,
    pub priority: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerStatus {
    pub identity: PeerIdentity,
    pub path_type: PathType,
    pub endpoints: Vec<PeerEndpoint>,
    pub overlay_address: String,
    #[serde(default)]
    pub rtt_milliseconds: Option<u32>,
    /// Seconds since the Unix epoch; the Swift side encodes `Date`
    /// differently, so this field is canonical for Windows tooling.
    #[serde(default)]
    pub last_rekey_unix: Option<u64>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeshMetrics {
    pub peer_count: u32,
    pub direct_peer_count: u32,
    pub relay_peer_count: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub replay_drops: u64,
    #[serde(default)]
    pub last_path_probe_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DytallixPeerTrustSummary {
    pub required: bool,
    pub policy: MeshTrustPolicy,
    pub identity_mode: DiscoveryIdentityMode,
    pub registry_configured: bool,
    pub verified_peer_count: u32,
    pub unverified_peer_count: u32,
    pub pending_peer_count: u32,
    pub failed_peer_count: u32,
    #[serde(default)]
    pub last_checked_at_unix: Option<u64>,
    #[serde(default)]
    pub last_failure_code: Option<String>,
    #[serde(default)]
    pub last_failure_summary: Option<String>,
    #[serde(default)]
    pub warning: Option<String>,
}

impl Default for DytallixPeerTrustSummary {
    fn default() -> Self {
        Self {
            required: false,
            policy: MeshTrustPolicy::DevelopmentOptional,
            identity_mode: DiscoveryIdentityMode::Off,
            registry_configured: false,
            verified_peer_count: 0,
            unverified_peer_count: 0,
            pending_peer_count: 0,
            failed_peer_count: 0,
            last_checked_at_unix: None,
            last_failure_code: None,
            last_failure_summary: None,
            warning: None,
        }
    }
}

/// Transport-level counters mirrored from the Rust core's
/// `QlinkMeshTransportMetrics` FFI struct.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelTransportMetrics {
    pub state_code: u32,
    pub path_kind_code: u32,
    pub frames_sent: u64,
    pub frames_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub send_failures: u64,
    pub receive_failures: u64,
    pub network_event_count: u64,
    pub reconnect_count: u64,
}

/// Packet-pump counters (port of `PacketPumpCounters` in
/// `TunnelPacketPump.swift`), surfaced over IPC for diagnostics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketPumpMetrics {
    pub packets_observed: u64,
    pub queued_for_transport: u64,
    pub dropped_unprotected: u64,
    pub dropped_fail_closed: u64,
    pub dropped_kill_switch: u64,
    pub failed_submissions: u64,
    pub transport_frames_emitted: u64,
    pub transport_frames_accepted: u64,
    pub failed_inbound_frames: u64,
    pub tunnel_packets_emitted: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelStatus {
    pub phase: ConnectionPhase,
    pub path_type: PathType,
    pub route_mode: RouteMode,
    pub dns_mode: DnsMode,
    #[serde(rename = "overlayIPv4Address")]
    pub overlay_ipv4_address: String,
    pub protected_routes: Vec<String>,
    pub peers: Vec<PeerStatus>,
    pub metrics: MeshMetrics,
    #[serde(default)]
    pub peer_trust: DytallixPeerTrustSummary,
    #[serde(default)]
    pub transport: Option<TunnelTransportMetrics>,
    #[serde(default)]
    pub pump: Option<PacketPumpMetrics>,
    /// Operator-safe packet-session readiness. This reports only the
    /// availability state, never peer IDs, keys, or failure details.
    #[serde(default)]
    pub peer_session_key_available: bool,
    #[serde(default = "default_peer_session_key_state")]
    pub peer_session_key_state: String,
    /// Whether the WFP kill-switch filters are currently installed.
    /// Windows-specific diagnostic; absent on macOS.
    #[serde(default)]
    pub kill_switch_engaged: Option<bool>,
    #[serde(default)]
    pub last_error: Option<String>,
}

impl TunnelStatus {
    pub fn idle() -> Self {
        Self {
            phase: ConnectionPhase::Idle,
            path_type: PathType::Unavailable,
            route_mode: RouteMode::SplitTunnel,
            dns_mode: DnsMode::TunnelProvided,
            overlay_ipv4_address: crate::privacy::TUNNEL_GATEWAY_IPV4.to_string(),
            protected_routes: vec![crate::privacy::OVERLAY_CIDR.to_string()],
            peers: Vec::new(),
            metrics: MeshMetrics::default(),
            peer_trust: DytallixPeerTrustSummary::default(),
            transport: None,
            pump: None,
            peer_session_key_available: false,
            peer_session_key_state: default_peer_session_key_state(),
            kill_switch_engaged: None,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoPolicy {
    pub suite: String,
    pub rekey_after_seconds: f64,
    pub rekey_after_bytes: u64,
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        Self {
            suite: "QLINK-FIPS203-MLKEM768-SHAKE256-v1".to_string(),
            rekey_after_seconds: 3600.0,
            rekey_after_bytes: 1_073_741_824,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelConfiguration {
    #[serde(rename = "meshID")]
    pub mesh_id: String,
    pub device_alias: String,
    #[serde(rename = "overlayIPv4Address")]
    pub overlay_ipv4_address: String,
    pub tunnel_remote_address: String,
    pub protected_routes: Vec<String>,
    #[serde(default)]
    pub excluded_routes: Vec<String>,
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub dns_search_domains: Vec<String>,
    #[serde(default)]
    pub route_mode: RouteMode,
    #[serde(default)]
    pub dns_mode: DnsMode,
    #[serde(default = "default_discovery_modes")]
    pub discovery_modes: Vec<DiscoveryMode>,
    #[serde(default)]
    pub rendezvous_servers: Vec<String>,
    #[serde(default)]
    pub relay_servers: Vec<String>,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    #[serde(default)]
    pub crypto: CryptoPolicy,
    #[serde(default)]
    pub kill_switch: KillSwitchPolicy,
    #[serde(default)]
    pub mesh_type: MeshType,
    #[serde(default)]
    pub mesh_trust_policy: MeshTrustPolicy,
    #[serde(default)]
    pub discovery_identity_mode: DiscoveryIdentityMode,
    #[serde(default)]
    pub dytallix_identity: Option<DytallixIdentityConfiguration>,
}

fn default_discovery_modes() -> Vec<DiscoveryMode> {
    vec![DiscoveryMode::Rendezvous]
}

fn default_mtu() -> u32 {
    1280
}

fn default_peer_session_key_state() -> String {
    "unavailable".to_string()
}

impl TunnelConfiguration {
    pub fn effective_mesh_trust_policy(&self) -> MeshTrustPolicy {
        match self.mesh_type {
            MeshType::Public => MeshTrustPolicy::PublicRequired,
            MeshType::Private => MeshTrustPolicy::PrivatePreferred,
            MeshType::Development => self.mesh_trust_policy,
        }
    }

    /// JSON config consumed by `qlink_tunnel_core_create` (camelCase keys
    /// per `PacketTunnelCoreConfig` in `qlink-core/src/packet_core.rs`).
    pub fn packet_core_config_json(&self) -> serde_json::Value {
        let require_peer_session = self.requires_packet_peer_session();
        serde_json::json!({
            "protectedRoutes": self.protected_routes,
            "excludedRoutes": self.excluded_routes,
            "routeMode": self.route_mode,
            "mtu": self.mtu,
            "crypto": { "suite": self.crypto.suite },
            "requirePeerSession": require_peer_session,
        })
    }

    pub fn requires_packet_peer_session(&self) -> bool {
        !self.rendezvous_servers.is_empty()
            || self.effective_mesh_trust_policy() != MeshTrustPolicy::DevelopmentOptional
            || self.discovery_identity_mode != DiscoveryIdentityMode::Off
            || self.dytallix_identity.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enums_use_swift_raw_values() {
        assert_eq!(
            serde_json::to_string(&RouteMode::SplitTunnel).unwrap(),
            "\"splitTunnel\""
        );
        assert_eq!(
            serde_json::to_string(&KillSwitchPolicy::FailClosed).unwrap(),
            "\"failClosed\""
        );
        assert_eq!(
            serde_json::to_string(&DiscoveryMode::LocalMdns).unwrap(),
            "\"localMDNS\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectionPhase::Reconnecting).unwrap(),
            "\"reconnecting\""
        );
    }

    #[test]
    fn configuration_round_trips_with_defaults() {
        let json = r#"{
            "meshID": "mesh-test",
            "deviceAlias": "device-test",
            "overlayIPv4Address": "100.64.0.2",
            "tunnelRemoteAddress": "100.64.0.1",
            "protectedRoutes": ["100.64.0.0/10"],
            "dnsServers": ["100.64.0.1"]
        }"#;
        let config: TunnelConfiguration = serde_json::from_str(json).unwrap();
        assert_eq!(config.mtu, 1280);
        assert_eq!(config.route_mode, RouteMode::SplitTunnel);
        assert_eq!(config.kill_switch, KillSwitchPolicy::FailClosed);
        assert_eq!(config.mesh_type, MeshType::Development);
        assert_eq!(config.discovery_modes, vec![DiscoveryMode::Rendezvous]);
        assert_eq!(
            config.mesh_trust_policy,
            MeshTrustPolicy::DevelopmentOptional
        );
        assert_eq!(config.discovery_identity_mode, DiscoveryIdentityMode::Off);
        assert!(config.dytallix_identity.is_none());

        let core_config = config.packet_core_config_json();
        assert_eq!(core_config["routeMode"], "splitTunnel");
        assert_eq!(core_config["mtu"], 1280);
    }

    #[test]
    fn packet_core_config_does_not_require_peer_session_for_local_loopback_dev() {
        let config = crate::privacy::default_tunnel_configuration();

        let core_config = config.packet_core_config_json();

        assert_eq!(core_config["requirePeerSession"], false);
    }

    #[test]
    fn packet_core_config_requires_peer_session_for_public_identity_mesh() {
        let mut config = crate::privacy::default_tunnel_configuration();
        config.mesh_trust_policy = MeshTrustPolicy::PublicRequired;
        config.discovery_identity_mode = DiscoveryIdentityMode::Verified;
        config.dytallix_identity = Some(DytallixIdentityConfiguration {
            mode: DiscoveryIdentityMode::Verified,
            registry_endpoint: "https://registry.example".to_string(),
            contract: "quantumlink-node-registry".to_string(),
            cached_proof_grace_seconds: 0,
            contract_address: Some("0xabc1230000000000000000000000000000000000".to_string()),
            publish_wallet_address: false,
            network_id: None,
            chain_id: None,
            allowed_rpc_endpoints: Vec::new(),
            keystore_path: None,
            wallet_name: None,
        });

        let core_config = config.packet_core_config_json();

        assert_eq!(core_config["requirePeerSession"], true);
    }

    #[test]
    fn dytallix_identity_matches_swift_json_keys() {
        let json = r#"{
            "endpoint": "https://registry.example",
            "contractAddress": "0xabc1230000000000000000000000000000000000",
            "publishWalletAddress": true,
            "networkID": "network",
            "chainID": "chain",
            "allowedRPCEndpoints": ["https://rpc.example"]
        }"#;
        let config: DytallixIdentityConfiguration = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.contract_address.as_deref(),
            Some("0xabc1230000000000000000000000000000000000")
        );
        assert_eq!(
            config.core_contract_identifier(),
            "0xabc1230000000000000000000000000000000000".to_string()
        );
        assert!(config.publish_wallet_address);
        assert_eq!(config.network_id.as_deref(), Some("network"));
        assert_eq!(config.chain_id.as_deref(), Some("chain"));
        assert_eq!(config.allowed_rpc_endpoints, vec!["https://rpc.example"]);

        let serialized = serde_json::to_value(config).unwrap();
        assert_eq!(serialized["networkID"], "network");
        assert_eq!(serialized["chainID"], "chain");
        assert_eq!(serialized["allowedRPCEndpoints"][0], "https://rpc.example");
    }

    #[test]
    fn dytallix_identity_accepts_windows_named_registry_contract() {
        let json = r#"{
            "mode": "verified",
            "registryEndpoint": "https://registry.dytallix.example",
            "contract": "quantumlink-node-registry",
            "cachedProofGraceSeconds": 0,
            "networkID": "dytallix-mainnet",
            "chainID": "dytallix-mainnet-1",
            "allowedRPCEndpoints": ["https://registry.dytallix.example"]
        }"#;

        let config: DytallixIdentityConfiguration = serde_json::from_str(json).unwrap();

        assert_eq!(config.mode, DiscoveryIdentityMode::Verified);
        assert_eq!(
            config.registry_endpoint,
            "https://registry.dytallix.example"
        );
        assert_eq!(config.contract, "quantumlink-node-registry");
        assert_eq!(config.cached_proof_grace_seconds, 0);

        let serialized = serde_json::to_value(config).unwrap();
        assert_eq!(
            serialized["registryEndpoint"],
            "https://registry.dytallix.example"
        );
        assert_eq!(serialized["contract"], "quantumlink-node-registry");
        assert_eq!(serialized["cachedProofGraceSeconds"], 0);
    }

    #[test]
    fn tunnel_configuration_carries_mesh_type() {
        let json = r#"{
            "meshID": "mesh-public",
            "meshType": "public",
            "deviceAlias": "device-test",
            "overlayIPv4Address": "100.64.0.2",
            "tunnelRemoteAddress": "100.64.0.1",
            "protectedRoutes": ["100.64.0.0/10"],
            "dnsServers": ["100.64.0.1"]
        }"#;

        let config: TunnelConfiguration = serde_json::from_str(json).unwrap();

        assert_eq!(config.mesh_type, MeshType::Public);
        assert_eq!(serde_json::to_value(config).unwrap()["meshType"], "public");
    }

    #[test]
    fn peer_trust_summary_surfaces_operator_rejection_code() {
        let status = TunnelStatus {
            peer_trust: DytallixPeerTrustSummary {
                failed_peer_count: 1,
                last_failure_code: Some("rejected_record_hash_mismatch".to_string()),
                last_failure_summary: Some(
                    "Peer registry record hash does not match the signed rendezvous record"
                        .to_string(),
                ),
                ..DytallixPeerTrustSummary::default()
            },
            ..TunnelStatus::idle()
        };

        let json = serde_json::to_value(status).unwrap();

        assert_eq!(
            json["peerTrust"]["lastFailureCode"],
            "rejected_record_hash_mismatch"
        );
        assert!(json["peerTrust"]["lastFailureSummary"]
            .as_str()
            .unwrap()
            .contains("registry record hash"));
    }
}
