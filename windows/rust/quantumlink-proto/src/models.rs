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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshTrustPolicy {
    #[serde(
        rename = "publicRequired",
        alias = "PublicRequired",
        alias = "public_required"
    )]
    PublicRequired,
    #[serde(
        rename = "privatePreferred",
        alias = "PrivatePreferred",
        alias = "private_preferred"
    )]
    PrivatePreferred,
    #[serde(
        rename = "developmentOptional",
        alias = "DevelopmentOptional",
        alias = "development_optional"
    )]
    DevelopmentOptional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryIdentityMode {
    #[serde(rename = "off", alias = "Off")]
    Off,
    #[serde(rename = "verified", alias = "Verified")]
    Verified,
    #[serde(
        rename = "publicWallet",
        alias = "PublicWallet",
        alias = "public_wallet"
    )]
    PublicWallet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DytallixRegistryConfiguration {
    pub endpoint: String,
    pub contract_address: String,
    #[serde(default)]
    pub keystore_path: Option<String>,
    #[serde(default)]
    pub wallet_name: Option<String>,
    #[serde(default)]
    pub network_id: Option<String>,
    #[serde(default)]
    pub chain_id: Option<String>,
    #[serde(default)]
    pub allowed_rpc_endpoints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DytallixIdentityConfiguration {
    pub trust_policy: MeshTrustPolicy,
    pub mode: DiscoveryIdentityMode,
    #[serde(default)]
    pub registry: Option<DytallixRegistryConfiguration>,
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
    pub transport: Option<TunnelTransportMetrics>,
    #[serde(default)]
    pub pump: Option<PacketPumpMetrics>,
    /// Whether the WFP kill-switch filters are currently installed.
    /// Windows-specific diagnostic; absent on macOS.
    #[serde(default)]
    pub kill_switch_engaged: Option<bool>,
    #[serde(default)]
    pub dytallix_identity: Option<DytallixIdentityConfiguration>,
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
            transport: None,
            pump: None,
            kill_switch_engaged: None,
            dytallix_identity: None,
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
            suite: "QLINK-FIPS203-MLKEM768-HKDFSHA256-v1".to_string(),
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
    pub dytallix_identity: Option<DytallixIdentityConfiguration>,
}

fn default_discovery_modes() -> Vec<DiscoveryMode> {
    vec![DiscoveryMode::Rendezvous]
}

fn default_mtu() -> u32 {
    1280
}

impl TunnelConfiguration {
    /// JSON config consumed by `qlink_tunnel_core_create` (camelCase keys
    /// per `PacketTunnelCoreConfig` in `qlink-core/src/packet_core.rs`).
    pub fn packet_core_config_json(&self) -> serde_json::Value {
        serde_json::json!({
            "protectedRoutes": self.protected_routes,
            "excludedRoutes": self.excluded_routes,
            "routeMode": self.route_mode,
            "mtu": self.mtu,
            "crypto": { "suite": self.crypto.suite },
        })
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
        assert_eq!(config.discovery_modes, vec![DiscoveryMode::Rendezvous]);

        let core_config = config.packet_core_config_json();
        assert_eq!(core_config["routeMode"], "splitTunnel");
        assert_eq!(core_config["mtu"], 1280);
    }

    #[test]
    fn dytallix_identity_configuration_round_trips() {
        let json = r#"{
            "meshID": "mesh-test",
            "deviceAlias": "device-test",
            "overlayIPv4Address": "100.64.0.2",
            "tunnelRemoteAddress": "100.64.0.1",
            "protectedRoutes": ["100.64.0.0/10"],
            "dnsServers": ["100.64.0.1"],
            "dytallixIdentity": {
                "trustPolicy": "publicRequired",
                "mode": "verified",
                "registry": {
                    "endpoint": "https://dytallix.com",
                    "contractAddress": "0x9a9671441249ee2c364f9b4bc8049e61b082449a"
                }
            }
        }"#;
        let config: TunnelConfiguration = serde_json::from_str(json).unwrap();

        let identity = config.dytallix_identity.unwrap();
        assert_eq!(identity.trust_policy, MeshTrustPolicy::PublicRequired);
        assert_eq!(identity.mode, DiscoveryIdentityMode::Verified);
        assert_eq!(
            identity.registry.unwrap().contract_address,
            "0x9a9671441249ee2c364f9b4bc8049e61b082449a"
        );
    }
}
