pub mod data_plane;
pub mod game;
pub mod identity;
pub mod mesh_runtime;

use data_plane::{packet_core_from_parts, BoxedTunDevice, DataPlaneError, DataPlaneRuntime};
use game::SteamBypassSummary;
use qlink_core::dytallix_identity::{
    evaluate_dytallix_policy_status, DytallixPolicyStatus, MeshTrustPolicy,
};
use qlink_core::packet_core::{FfiRouteMode, PacketTunnelCore};
use qlink_linux::{
    LinuxNetworkPlan, LinuxRuntimePlan, NetworkApplyError, NetworkExecutor, NetworkOperation,
    NetworkPlanError, NftablesExecutor, NftablesOperation, NftablesPlan, TunDeviceConfig,
    TunPacketIo,
};
use qlink_proto::{
    load_peer_store_at, peer_store_path_from_state_dir, store_peer_store_at, ConnectionPhase,
    DaemonConfig, DaemonStatus, DataPlaneState, DataPlaneStatus, InviteCode, MeshTrustMode,
    NetworkPlanState, NetworkStatus, PeerStatus, PeerStore, RouteMode, StoredPeer,
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::io::{BufRead, BufReader};
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use identity::load_or_generate_device_identity;
#[cfg(unix)]
use mesh_runtime::{build_daemon_mesh_transport, DaemonMeshTransport};

#[cfg(unix)]
const MAX_CONTROL_REQUEST_BYTES: usize = 1024;
#[cfg(unix)]
const CONTROL_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(2);
const NETWORK_OWNERSHIP_FILE: &str = "network-ownership.json";
const NETWORK_OWNERSHIP_SCHEMA_VERSION: u8 = 1;
pub const LOCAL_CONTROL_GROUP: &str = "quantumlink";
pub const LOCAL_CONTROL_SOCKET_MODE: u32 = 0o660;
pub const LOCAL_CONTROL_SOCKET_OWNER_UID: u32 = 0;
const QLINK_FWMARK: u32 = 0x514c;
const QLINK_ROUTE_TABLE: u32 = 51820;
const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "qlink";
const FULL_TUNNEL_CIDR: &str = "0.0.0.0/0";
const DATA_PLANE_MTU: usize = 1280;

type EngineDataPlaneRuntime = DataPlaneRuntime<BoxedTunDevice, PacketTunnelCore>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalControlSocketAcl {
    pub path: PathBuf,
    pub owner_uid: u32,
    pub group_name: &'static str,
    pub mode: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlPolicy {
    QuantumlinkGroup,
    ElevatedOnly,
    Unsupported,
}

pub fn local_control_socket_acl() -> LocalControlSocketAcl {
    LocalControlSocketAcl {
        path: DaemonPaths::default().socket,
        owner_uid: LOCAL_CONTROL_SOCKET_OWNER_UID,
        group_name: LOCAL_CONTROL_GROUP,
        mode: LOCAL_CONTROL_SOCKET_MODE,
    }
}

pub fn local_control_command_policy(request: &str) -> ControlPolicy {
    let request = request.trim();
    if request == "status" || request == "doctor" || request == r#"{"type":"status"}"# {
        ControlPolicy::QuantumlinkGroup
    } else if request.contains("activate-network")
        || request.contains("deactivate-network")
        || request.contains("revoke-peer")
        || request.contains("peer-revoke")
    {
        ControlPolicy::ElevatedOnly
    } else {
        ControlPolicy::Unsupported
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonPaths {
    pub config_file: PathBuf,
    pub state_dir: PathBuf,
    pub socket: PathBuf,
}

impl Default for DaemonPaths {
    fn default() -> Self {
        Self {
            config_file: PathBuf::from("/etc/quantumlink/config.json"),
            state_dir: PathBuf::from("/var/lib/quantumlink"),
            socket: PathBuf::from("/run/quantumlink/qlinkd.sock"),
        }
    }
}

impl DaemonPaths {
    /// Directory holding the operator config and the Steam-safe policy files
    /// (`steam-bypass.toml`, `games/*.toml`). Derived from the config file's
    /// parent, falling back to the packaged default location.
    pub fn config_dir(&self) -> PathBuf {
        self.config_file
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/etc/quantumlink"))
    }
}

#[derive(Debug)]
pub enum PeerLifecycleError {
    InviteDecode(qlink_proto::InviteDecodeError),
    ExpiredInvite { expires_at_unix: u64, now_unix: u64 },
    UnknownPeer { peer_id: String },
    Io(std::io::Error),
    DytallixPolicy(qlink_core::QlinkError),
}

impl std::fmt::Display for PeerLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InviteDecode(error) => write!(f, "{error}"),
            Self::ExpiredInvite {
                expires_at_unix,
                now_unix,
            } => write!(
                f,
                "invite expired at {expires_at_unix}; current time is {now_unix}"
            ),
            Self::UnknownPeer { peer_id } => write!(f, "unknown peer {peer_id}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::DytallixPolicy(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for PeerLifecycleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InviteDecode(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::DytallixPolicy(error) => Some(error),
            Self::ExpiredInvite { .. } | Self::UnknownPeer { .. } => None,
        }
    }
}

impl From<qlink_proto::InviteDecodeError> for PeerLifecycleError {
    fn from(error: qlink_proto::InviteDecodeError) -> Self {
        Self::InviteDecode(error)
    }
}

impl From<std::io::Error> for PeerLifecycleError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<qlink_core::QlinkError> for PeerLifecycleError {
    fn from(error: qlink_core::QlinkError) -> Self {
        Self::DytallixPolicy(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDytallixPolicyDecision {
    pub accepted: bool,
    pub warning: Option<String>,
}

pub fn peer_store_path(paths: &DaemonPaths) -> PathBuf {
    peer_store_path_from_state_dir(&paths.state_dir)
}

pub fn load_peer_store(paths: &DaemonPaths) -> Result<PeerStore, PeerLifecycleError> {
    load_peer_store_at(peer_store_path(paths)).map_err(Into::into)
}

pub fn store_peer_store(
    paths: &DaemonPaths,
    store: &PeerStore,
) -> Result<PathBuf, PeerLifecycleError> {
    store_peer_store_at(&paths.state_dir, store).map_err(Into::into)
}

pub fn import_invite(
    paths: &DaemonPaths,
    encoded_invite: &str,
    now_unix: u64,
) -> Result<StoredPeer, PeerLifecycleError> {
    let invite = InviteCode::decode(encoded_invite)?;
    if invite.expires_at_unix <= now_unix {
        return Err(PeerLifecycleError::ExpiredInvite {
            expires_at_unix: invite.expires_at_unix,
            now_unix,
        });
    }

    let peer = invite.stored_peer();
    let mut store = load_peer_store(paths)?;
    store.upsert(peer.clone());
    store_peer_store(paths, &store)?;
    Ok(peer)
}

pub fn dial_candidates(
    paths: &DaemonPaths,
    now_unix: u64,
) -> Result<Vec<StoredPeer>, PeerLifecycleError> {
    Ok(load_peer_store(paths)?.dial_candidates(now_unix))
}

pub fn remove_peer(paths: &DaemonPaths, peer_id: &str) -> Result<(), PeerLifecycleError> {
    let mut store = load_peer_store(paths)?;
    if !store.remove(peer_id) {
        return Err(PeerLifecycleError::UnknownPeer {
            peer_id: peer_id.to_string(),
        });
    }
    store_peer_store(paths, &store)?;
    Ok(())
}

pub fn revoke_peer(paths: &DaemonPaths, peer_id: &str) -> Result<(), PeerLifecycleError> {
    let mut store = load_peer_store(paths)?;
    if !store.revoke(peer_id) {
        return Err(PeerLifecycleError::UnknownPeer {
            peer_id: peer_id.to_string(),
        });
    }
    store_peer_store(paths, &store)?;
    Ok(())
}

pub fn validate_peer_dytallix_policy(
    peer: &StoredPeer,
    status: DytallixPolicyStatus,
) -> Result<PeerDytallixPolicyDecision, PeerLifecycleError> {
    let policy = mesh_trust_policy(peer.trust_mode);
    let decision =
        evaluate_dytallix_policy_status(policy, status, peer_explicitly_requires_dytallix(peer))?;
    Ok(PeerDytallixPolicyDecision {
        accepted: decision.accepted,
        warning: decision.warning,
    })
}

fn mesh_trust_policy(mode: MeshTrustMode) -> MeshTrustPolicy {
    match mode {
        MeshTrustMode::PrivateFriends => MeshTrustPolicy::PrivatePreferred,
        MeshTrustMode::PublicDytallixRequired => MeshTrustPolicy::PublicRequired,
        MeshTrustMode::DevelopmentOptional => MeshTrustPolicy::DevelopmentOptional,
    }
}

fn peer_explicitly_requires_dytallix(peer: &StoredPeer) -> bool {
    peer.trust_mode == MeshTrustMode::PublicDytallixRequired
        || matches!(
            peer.trust_source.as_str(),
            "dytallix-required" | "verified-dytallix" | "public-dytallix"
        )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRuntimePlan {
    pub interface_name: String,
    pub route_mode: RouteMode,
    pub protected_cidr: String,
    pub commands: Vec<String>,
    pub nftables_rules: Vec<String>,
}

impl NetworkRuntimePlan {
    fn from_plan(config: &DaemonConfig, plan: &LinuxRuntimePlan) -> Self {
        Self {
            interface_name: config.interface_name.clone(),
            route_mode: config.route_mode,
            protected_cidr: plan.protected_cidr().to_string(),
            commands: plan.network.commands.clone(),
            nftables_rules: plan.nftables.rules.clone(),
        }
    }

    fn from_config_without_commands(config: &DaemonConfig) -> Self {
        Self {
            interface_name: config.interface_name.clone(),
            route_mode: config.route_mode,
            protected_cidr: protected_cidr_for_record(config).to_string(),
            commands: Vec::new(),
            nftables_rules: Vec::new(),
        }
    }

    fn status(
        &self,
        state: NetworkPlanState,
        dry_run: bool,
        ownership_record_present: bool,
        error: Option<String>,
    ) -> NetworkStatus {
        NetworkStatus {
            state,
            interface_name: Some(self.interface_name.clone()),
            route_mode: Some(self.route_mode),
            protected_cidr: Some(self.protected_cidr.clone()),
            dry_run,
            ownership_record_present,
            commands: self.commands.clone(),
            nftables_rules: self.nftables_rules.clone(),
            error,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkRuntimeState {
    NotStarted,
    Planned(NetworkRuntimePlan),
    Applied(NetworkRuntimePlan),
    ApplyFailed {
        plan: NetworkRuntimePlan,
        error: String,
    },
}

impl NetworkRuntimeState {
    fn planned(config: &DaemonConfig, plan: &LinuxRuntimePlan) -> Self {
        Self::Planned(NetworkRuntimePlan::from_plan(config, plan))
    }

    fn status(&self, ownership_record_present: bool) -> NetworkStatus {
        match self {
            Self::NotStarted => NetworkStatus::not_started(),
            Self::Planned(plan) => plan.status(
                NetworkPlanState::Planned,
                true,
                ownership_record_present,
                None,
            ),
            Self::Applied(plan) => plan.status(
                NetworkPlanState::Applied,
                false,
                ownership_record_present,
                None,
            ),
            Self::ApplyFailed { plan, error } => plan.status(
                NetworkPlanState::ApplyFailed,
                false,
                ownership_record_present,
                Some(error.clone()),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkOwnershipRecord {
    pub schema_version: u8,
    pub interface_name: String,
    pub route_mode: RouteMode,
    pub protected_cidr: String,
    pub fwmark: u32,
    pub route_table: u32,
    pub nft_family: String,
    pub nft_table: String,
    pub activated_at_unix_seconds: u64,
}

impl NetworkOwnershipRecord {
    pub fn from_config(config: &DaemonConfig) -> Self {
        Self {
            schema_version: NETWORK_OWNERSHIP_SCHEMA_VERSION,
            interface_name: config.interface_name.clone(),
            route_mode: config.route_mode,
            protected_cidr: protected_cidr_for_record(config).to_string(),
            fwmark: QLINK_FWMARK,
            route_table: QLINK_ROUTE_TABLE,
            nft_family: NFT_FAMILY.to_string(),
            nft_table: NFT_TABLE.to_string(),
            activated_at_unix_seconds: current_unix_seconds(),
        }
    }

    fn runtime_plan(&self) -> LinuxRuntimePlan {
        LinuxRuntimePlan {
            network: LinuxNetworkPlan::from_operations(vec![
                NetworkOperation::CreateTun {
                    name: self.interface_name.clone(),
                },
                NetworkOperation::AddRule {
                    fwmark: self.fwmark,
                    table: self.route_table,
                },
                NetworkOperation::AddRoute {
                    cidr: self.protected_cidr.clone(),
                    interface: self.interface_name.clone(),
                    table: self.route_table,
                },
            ]),
            nftables: NftablesPlan::from_operations(vec![NftablesOperation::AddTable {
                family: self.nft_family.clone(),
                table: self.nft_table.clone(),
            }]),
            protected_cidr: self.protected_cidr.clone(),
        }
    }
}

fn protected_cidr_for_record(config: &DaemonConfig) -> &str {
    match config.route_mode {
        RouteMode::GameOnly | RouteMode::ProtectedPrefixesOnly => &config.overlay_cidr,
        RouteMode::FullTunnel => FULL_TUNNEL_CIDR,
    }
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[derive(Debug)]
pub enum DaemonInitError {
    NetworkPlan(NetworkPlanError),
}

impl std::fmt::Display for DaemonInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkPlan(error) => write!(f, "failed to plan SteamOS networking: {error}"),
        }
    }
}

impl std::error::Error for DaemonInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NetworkPlan(error) => Some(error),
        }
    }
}

impl From<NetworkPlanError> for DaemonInitError {
    fn from(error: NetworkPlanError) -> Self {
        Self::NetworkPlan(error)
    }
}

#[derive(Debug)]
pub enum DaemonActivationError {
    Network(NetworkApplyError),
    DataPlane(DataPlaneError),
    DataPlaneCleanupFailed {
        data_plane: DataPlaneError,
        cleanup: NetworkApplyError,
    },
}

impl std::fmt::Display for DaemonActivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(error) => write!(f, "{error}"),
            Self::DataPlane(error) => write!(f, "{error}"),
            Self::DataPlaneCleanupFailed {
                data_plane,
                cleanup,
            } => write!(
                f,
                "{data_plane}; network cleanup after data-plane failure failed: {cleanup}"
            ),
        }
    }
}

impl std::error::Error for DaemonActivationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Network(error) => Some(error),
            Self::DataPlane(error) => Some(error),
            Self::DataPlaneCleanupFailed { data_plane, .. } => Some(data_plane),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DaemonRuntimeState {
    pub phase: ConnectionPhase,
    pub active_party: Option<String>,
    pub peers: Vec<PeerStatus>,
    pub kill_switch: bool,
    pub network: NetworkRuntimeState,
    pub data_plane: DataPlaneStatus,
}

impl DaemonRuntimeState {
    pub fn idle(kill_switch: bool) -> Self {
        Self {
            phase: ConnectionPhase::Idle,
            active_party: None,
            peers: Vec::new(),
            kill_switch,
            network: NetworkRuntimeState::NotStarted,
            data_plane: DataPlaneStatus::not_started(),
        }
    }

    pub fn status(&self, ownership_record_present: bool) -> DaemonStatus {
        DaemonStatus {
            phase: self.phase,
            active_party: self.active_party.clone(),
            peers: self.peers.clone(),
            kill_switch: self.kill_switch,
            network: self.network.status(ownership_record_present),
            data_plane: self.data_plane.clone(),
        }
    }
}

#[derive(Debug)]
pub struct DaemonEngine {
    config: DaemonConfig,
    paths: DaemonPaths,
    runtime: DaemonRuntimeState,
    data_plane: Option<EngineDataPlaneRuntime>,
    steam_bypass: SteamBypassSummary,
}

impl DaemonEngine {
    pub fn new(config: DaemonConfig, paths: DaemonPaths) -> Self {
        let runtime = DaemonRuntimeState::idle(config.kill_switch);
        let steam_bypass = SteamBypassSummary::load(&paths.config_dir(), &config);
        Self {
            config,
            paths,
            runtime,
            data_plane: None,
            steam_bypass,
        }
    }

    pub fn try_new(config: DaemonConfig, paths: DaemonPaths) -> Result<Self, DaemonInitError> {
        let plan = LinuxRuntimePlan::from_config(&config)?;
        let runtime = DaemonRuntimeState {
            phase: ConnectionPhase::Idle,
            active_party: None,
            peers: Vec::new(),
            kill_switch: config.kill_switch,
            network: NetworkRuntimeState::planned(&config, &plan),
            data_plane: DataPlaneStatus::not_started(),
        };
        let steam_bypass = SteamBypassSummary::load(&paths.config_dir(), &config);
        Ok(Self {
            config,
            paths,
            runtime,
            data_plane: None,
            steam_bypass,
        })
    }

    pub fn status(&self) -> DaemonStatus {
        let ownership_record_present = load_network_ownership(&self.paths)
            .map(|record| record.is_some())
            .unwrap_or(false);
        let mut status = self.runtime.status(ownership_record_present);
        if let Some(data_plane) = &self.data_plane {
            status.data_plane = data_plane.status();
        }
        status
    }

    pub fn runtime_state(&self) -> &DaemonRuntimeState {
        &self.runtime
    }

    pub fn config(&self) -> &DaemonConfig {
        &self.config
    }

    pub fn paths(&self) -> &DaemonPaths {
        &self.paths
    }

    /// The daemon's Steam-safe bypass posture, loaded from the config
    /// directory. Surfaced in the resident banner and to `qlinkctl doctor`.
    pub fn steam_bypass(&self) -> &SteamBypassSummary {
        &self.steam_bypass
    }

    /// `true` once packet I/O has been started (network activated + TUN open).
    pub fn data_plane_active(&self) -> bool {
        self.data_plane.is_some()
    }

    pub fn mark_preparing(&mut self) {
        self.runtime.phase = ConnectionPhase::Preparing;
    }

    pub fn start_data_plane_with<T>(&mut self, tun: T) -> Result<(), DataPlaneError>
    where
        T: TunPacketIo + Send + 'static,
    {
        let interface_name = tun.config().name.clone();
        if !matches!(self.runtime.network, NetworkRuntimeState::Applied(_)) {
            let error = DataPlaneError::NetworkNotApplied(
                "network must be activated before starting packet I/O".to_string(),
            );
            self.runtime.data_plane = DataPlaneStatus {
                interface_name: Some(interface_name),
                state: DataPlaneState::Failed,
                packet_io_available: false,
                transport_ready: false,
                transport_path: None,
                peer_session_ready: false,
                last_transport_error: Some(error.to_string()),
                metrics: Default::default(),
                error: Some(error.to_string()),
            };
            return Err(error);
        }

        self.runtime.data_plane = DataPlaneStatus {
            interface_name: Some(interface_name.clone()),
            state: DataPlaneState::Starting,
            packet_io_available: false,
            transport_ready: false,
            transport_path: None,
            peer_session_ready: false,
            last_transport_error: None,
            metrics: Default::default(),
            error: None,
        };

        let core = self.packet_core_for_data_plane()?;
        let runtime = DataPlaneRuntime::new(BoxedTunDevice::new(tun), core);
        self.runtime.data_plane = runtime.status();
        self.data_plane = Some(runtime);
        Ok(())
    }

    pub fn activate_network_and_start_data_plane_with<NE, NF, T, F>(
        &mut self,
        network_executor: &mut NE,
        nftables_executor: &mut NF,
        open_tun: F,
    ) -> Result<(), DaemonActivationError>
    where
        NE: NetworkExecutor,
        NF: NftablesExecutor,
        T: TunPacketIo + Send + 'static,
        F: FnOnce(TunDeviceConfig) -> Result<T, DataPlaneError>,
    {
        self.activate_network_with(network_executor, nftables_executor)
            .map_err(DaemonActivationError::Network)?;

        let tun_config = TunDeviceConfig::new(self.config.interface_name.clone(), DATA_PLANE_MTU);
        let tun = open_tun(tun_config).map_err(|error| {
            self.mark_data_plane_start_failed(&error);
            self.cleanup_after_data_plane_start_failure(error, network_executor, nftables_executor)
        })?;

        self.start_data_plane_with(tun).map_err(|error| {
            self.mark_data_plane_start_failed(&error);
            self.cleanup_after_data_plane_start_failure(error, network_executor, nftables_executor)
        })
    }

    pub fn data_plane_runtime_mut(&mut self) -> Option<&mut EngineDataPlaneRuntime> {
        self.data_plane.as_mut()
    }

    fn packet_core_for_data_plane(&self) -> Result<PacketTunnelCore, DataPlaneError> {
        packet_core_from_parts(
            protected_cidr_for_record(&self.config).to_string(),
            route_mode_for_packet_core(self.config.route_mode),
            DATA_PLANE_MTU,
        )
    }

    fn cleanup_after_data_plane_start_failure<NE, NF>(
        &mut self,
        error: DataPlaneError,
        network_executor: &mut NE,
        nftables_executor: &mut NF,
    ) -> DaemonActivationError
    where
        NE: NetworkExecutor,
        NF: NftablesExecutor,
    {
        match deactivate_network_with(&self.paths, network_executor, nftables_executor) {
            Ok(()) => DaemonActivationError::DataPlane(error),
            Err(cleanup) => DaemonActivationError::DataPlaneCleanupFailed {
                data_plane: error,
                cleanup,
            },
        }
    }

    fn mark_data_plane_start_failed(&mut self, error: &DataPlaneError) {
        if let NetworkRuntimeState::Applied(plan) = self.runtime.network.clone() {
            self.runtime.network = NetworkRuntimeState::ApplyFailed {
                plan,
                error: format!("data-plane startup failed: {error}"),
            };
        }
        self.runtime.data_plane = DataPlaneStatus {
            interface_name: Some(self.config.interface_name.clone()),
            state: DataPlaneState::Failed,
            packet_io_available: false,
            transport_ready: false,
            transport_path: None,
            peer_session_ready: false,
            last_transport_error: Some(error.to_string()),
            metrics: Default::default(),
            error: Some(error.to_string()),
        };
    }

    pub fn apply_network_with<NE, NF>(
        &mut self,
        network_executor: &mut NE,
        nftables_executor: &mut NF,
    ) -> Result<(), NetworkApplyError>
    where
        NE: NetworkExecutor,
        NF: NftablesExecutor,
    {
        self.activate_network_with(network_executor, nftables_executor)
    }

    pub fn activate_network_with<NE, NF>(
        &mut self,
        network_executor: &mut NE,
        nftables_executor: &mut NF,
    ) -> Result<(), NetworkApplyError>
    where
        NE: NetworkExecutor,
        NF: NftablesExecutor,
    {
        let plan = match LinuxRuntimePlan::from_config(&self.config) {
            Ok(plan) => plan,
            Err(error) => {
                let error =
                    NetworkApplyError::new(format!("failed to plan SteamOS networking: {error}"));
                self.runtime.network = NetworkRuntimeState::ApplyFailed {
                    plan: NetworkRuntimePlan::from_config_without_commands(&self.config),
                    error: error.message().to_string(),
                };
                return Err(error);
            }
        };
        let runtime_plan = NetworkRuntimePlan::from_plan(&self.config, &plan);

        if let Err(error) = prepare_network_ownership_storage(&self.paths) {
            let error = NetworkApplyError::new(format!(
                "failed to prepare network ownership storage: {error}"
            ));
            self.runtime.network = NetworkRuntimeState::ApplyFailed {
                plan: runtime_plan,
                error: error.message().to_string(),
            };
            return Err(error);
        }

        match plan.apply_with_rollback(network_executor, nftables_executor) {
            Ok(()) => {
                if let Err(error) = store_network_ownership(
                    &self.paths,
                    &NetworkOwnershipRecord::from_config(&self.config),
                ) {
                    let mut message = format!("failed to persist network ownership: {error}");
                    if let Err(rollback_error) =
                        plan.deactivate(network_executor, nftables_executor)
                    {
                        message.push_str(&format!("; rollback failed: {rollback_error}"));
                    }
                    let error = NetworkApplyError::new(message);
                    self.runtime.network = NetworkRuntimeState::ApplyFailed {
                        plan: runtime_plan,
                        error: error.message().to_string(),
                    };
                    return Err(error);
                }
                self.runtime.network = NetworkRuntimeState::Applied(runtime_plan);
                Ok(())
            }
            Err(error) => {
                self.runtime.network = NetworkRuntimeState::ApplyFailed {
                    plan: runtime_plan,
                    error: error.message().to_string(),
                };
                Err(error)
            }
        }
    }
}

fn route_mode_for_packet_core(route_mode: RouteMode) -> FfiRouteMode {
    match route_mode {
        RouteMode::FullTunnel => FfiRouteMode::FullTunnel,
        RouteMode::GameOnly | RouteMode::ProtectedPrefixesOnly => {
            FfiRouteMode::ProtectedPrefixesOnly
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    RunResident { activate_network: bool },
    DeactivateNetwork,
    CheckConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeModeError {
    ConflictingFlags,
}

impl std::fmt::Display for RuntimeModeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConflictingFlags => {
                write!(
                    f,
                    "cannot combine --check, --activate-network, or --deactivate-network"
                )
            }
        }
    }
}

impl std::error::Error for RuntimeModeError {}

impl RuntimeMode {
    pub fn from_args<I, S>(args: I) -> Result<Self, RuntimeModeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut check_config = false;
        let mut activate_network = false;
        let mut deactivate_network = false;

        for arg in args {
            match arg.as_ref() {
                "--check" => check_config = true,
                "--activate-network" => activate_network = true,
                "--deactivate-network" => deactivate_network = true,
                _ => {}
            }
        }

        let selected_modes = [check_config, activate_network, deactivate_network]
            .into_iter()
            .filter(|selected| *selected)
            .count();

        if selected_modes > 1 {
            Err(RuntimeModeError::ConflictingFlags)
        } else if deactivate_network {
            Ok(Self::DeactivateNetwork)
        } else if check_config {
            Ok(Self::CheckConfig)
        } else {
            Ok(Self::RunResident { activate_network })
        }
    }
}

pub fn network_ownership_path(paths: &DaemonPaths) -> PathBuf {
    paths.state_dir.join(NETWORK_OWNERSHIP_FILE)
}

pub fn load_network_ownership(
    paths: &DaemonPaths,
) -> std::io::Result<Option<NetworkOwnershipRecord>> {
    match read_network_ownership_bytes(paths) {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).map(Some).map_err(|error| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!("failed to parse network ownership record: {error}"),
            )
        }),
        Ok(None) => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn store_network_ownership(
    paths: &DaemonPaths,
    record: &NetworkOwnershipRecord,
) -> std::io::Result<()> {
    prepare_network_ownership_storage(paths)?;
    let bytes = serde_json::to_vec_pretty(record).map_err(|error| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("failed to serialize network ownership record: {error}"),
        )
    })?;
    write_network_ownership_atomically(paths, &bytes)
}

fn prepare_network_ownership_storage(paths: &DaemonPaths) -> std::io::Result<()> {
    std::fs::create_dir_all(&paths.state_dir)?;
    let ownership_path = network_ownership_path(paths);
    match std::fs::symlink_metadata(&ownership_path) {
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err(std::io::Error::new(
                    ErrorKind::AlreadyExists,
                    format!(
                        "network ownership path {} is not a regular file",
                        ownership_path.display()
                    ),
                ));
            }
            open_ownership_file_for_update(&ownership_path)?;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let probe_path = paths.state_dir.join(format!(
                ".{NETWORK_OWNERSHIP_FILE}.probe.{}",
                std::process::id()
            ));
            let mut probe = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&probe_path)?;
            probe.write_all(b"ownership preflight")?;
            drop(probe);
            std::fs::remove_file(probe_path)?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn read_network_ownership_bytes(paths: &DaemonPaths) -> std::io::Result<Option<Vec<u8>>> {
    let ownership_path = network_ownership_path(paths);
    match std::fs::symlink_metadata(&ownership_path) {
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err(std::io::Error::new(
                    ErrorKind::AlreadyExists,
                    format!(
                        "network ownership path {} is not a regular file",
                        ownership_path.display()
                    ),
                ));
            }
            let mut file = open_ownership_file_for_read(&ownership_path)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            Ok(Some(bytes))
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn open_ownership_file_for_read(path: &PathBuf) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    open_ownership_file_no_follow(&mut options, path)
}

fn open_ownership_file_for_update(path: &PathBuf) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    open_ownership_file_no_follow(&mut options, path)
}

fn write_network_ownership_atomically(paths: &DaemonPaths, bytes: &[u8]) -> std::io::Result<()> {
    let ownership_path = network_ownership_path(paths);
    let temp_path = network_ownership_temp_path(paths);

    let write_result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = open_ownership_file_no_follow(&mut options, &temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);

        std::fs::rename(&temp_path, &ownership_path)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }

    write_result
}

fn network_ownership_temp_path(paths: &DaemonPaths) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    paths.state_dir.join(format!(
        ".{NETWORK_OWNERSHIP_FILE}.{}.{}.tmp",
        std::process::id(),
        nonce
    ))
}

#[cfg(unix)]
fn open_ownership_file_no_follow(
    options: &mut std::fs::OpenOptions,
    path: &PathBuf,
) -> std::io::Result<std::fs::File> {
    options.custom_flags(libc::O_NOFOLLOW).open(path)
}

#[cfg(not(unix))]
fn open_ownership_file_no_follow(
    options: &mut std::fs::OpenOptions,
    path: &PathBuf,
) -> std::io::Result<std::fs::File> {
    options.open(path)
}

fn remove_network_ownership(paths: &DaemonPaths) -> std::io::Result<()> {
    match std::fs::remove_file(network_ownership_path(paths)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn deactivate_network_with<NE, NF>(
    paths: &DaemonPaths,
    network_executor: &mut NE,
    nftables_executor: &mut NF,
) -> Result<(), NetworkApplyError>
where
    NE: NetworkExecutor,
    NF: NftablesExecutor,
{
    let Some(record) = load_network_ownership(paths).map_err(|error| {
        NetworkApplyError::new(format!("failed to load network ownership: {error}"))
    })?
    else {
        return Ok(());
    };

    if record.schema_version != NETWORK_OWNERSHIP_SCHEMA_VERSION {
        return Err(NetworkApplyError::new(format!(
            "unsupported network ownership schema {}; expected {}",
            record.schema_version, NETWORK_OWNERSHIP_SCHEMA_VERSION
        )));
    }

    record
        .runtime_plan()
        .deactivate(network_executor, nftables_executor)?;
    remove_network_ownership(paths).map_err(|error| {
        NetworkApplyError::new(format!("failed to remove network ownership: {error}"))
    })
}

#[cfg(unix)]
pub fn serve_status_stream(mut stream: UnixStream, engine: &DaemonEngine) -> std::io::Result<()> {
    stream.set_read_timeout(Some(CONTROL_REQUEST_READ_TIMEOUT))?;
    let request = match read_control_request(&stream) {
        Ok(request) => request,
        Err(error) => {
            let message = error.to_string();
            let _ = write_control_error(&mut stream, &message);
            return Err(error);
        }
    };

    if local_control_command_policy(&request) == ControlPolicy::QuantumlinkGroup {
        serde_json::to_writer(&mut stream, &engine.status())?;
        stream.write_all(b"\n")?;
    } else {
        write_control_error(&mut stream, "unsupported request")?;
    }
    Ok(())
}

#[cfg(unix)]
fn read_control_request(stream: &UnixStream) -> std::io::Result<String> {
    let reader = BufReader::new(stream);
    let mut limited_reader = reader.take((MAX_CONTROL_REQUEST_BYTES + 1) as u64);
    let mut request = Vec::new();
    limited_reader.read_until(b'\n', &mut request)?;

    if request.len() > MAX_CONTROL_REQUEST_BYTES {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("request too large; max {MAX_CONTROL_REQUEST_BYTES} bytes"),
        ));
    }

    String::from_utf8(request).map_err(|error| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("control request must be UTF-8: {error}"),
        )
    })
}

#[cfg(unix)]
fn write_control_error(stream: &mut UnixStream, message: &str) -> std::io::Result<()> {
    serde_json::to_writer(
        &mut *stream,
        &serde_json::json!({
            "type": "error",
            "message": message,
        }),
    )?;
    stream.write_all(b"\n")
}

#[cfg(all(unix, test))]
fn serve_status_streams<I>(streams: I, engine: &DaemonEngine) -> std::io::Result<()>
where
    I: IntoIterator<Item = std::io::Result<UnixStream>>,
{
    for stream in streams {
        match stream {
            Ok(stream) => {
                if let Err(error) = serve_status_stream(stream, engine) {
                    eprintln!("qlinkd client error: {error}");
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Idle poll interval for the resident event loop. Bounds control-socket and
/// shutdown-signal latency when neither the TUN nor the transport has work.
#[cfg(unix)]
const RESIDENT_IDLE_POLL: Duration = Duration::from_millis(5);
#[cfg(unix)]
const TRUSTED_PEER_RECHECK_INTERVAL: Duration = Duration::from_secs(1);

#[cfg(unix)]
static RESIDENT_SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn handle_shutdown_signal(_signal: libc::c_int) {
    RESIDENT_SHUTDOWN.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn install_shutdown_signal_handlers() {
    // Async-signal-safe: the handler only flips an atomic. systemd stops the
    // unit with SIGTERM; a foreground operator uses Ctrl-C (SIGINT).
    unsafe {
        libc::signal(libc::SIGTERM, handle_shutdown_signal as usize);
        libc::signal(libc::SIGINT, handle_shutdown_signal as usize);
    }
}

/// Runs the resident daemon: binds the control socket, builds the live mesh
/// transport, and drives the bidirectional packet pump until a shutdown signal
/// (SIGTERM/SIGINT) arrives.
#[cfg(unix)]
pub fn run_resident(engine: DaemonEngine) -> std::io::Result<()> {
    install_shutdown_signal_handlers();
    run_resident_until(engine, &RESIDENT_SHUTDOWN)
}

/// Resident daemon body with an injectable shutdown flag (tests drive it
/// directly). Binds and secures the control socket, then serves the resident
/// loop until `shutdown` is set.
#[cfg(unix)]
pub fn run_resident_until(mut engine: DaemonEngine, shutdown: &AtomicBool) -> std::io::Result<()> {
    let socket = engine.paths().socket.clone();
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if socket.exists() {
        std::fs::remove_file(&socket)?;
    }

    let listener = UnixListener::bind(&socket)?;
    apply_local_control_socket_acl(&socket)?;
    listener.set_nonblocking(true)?;

    eprintln!("qlinkd resident: {}", engine.steam_bypass().banner());
    if let Some(warning) = engine.steam_bypass().alignment_warning.clone() {
        eprintln!("qlinkd steam-safe warning: {warning}");
    }

    let transport = build_resident_transport(&engine);
    if let Some(transport) = &transport {
        eprintln!("qlinkd data-plane transport: {}", transport.describe());
    } else if engine.data_plane_active() {
        eprintln!(
            "qlinkd data plane active but transport unavailable; protected traffic fails closed"
        );
    }

    let result = serve_resident_loop(&mut engine, transport, &listener, shutdown);
    let _ = std::fs::remove_file(&socket);
    result
}

/// The resident event loop: pump the data plane and serve the control socket
/// each tick, sleeping briefly only when a tick did no work. Exits when
/// `shutdown` is set, shutting the transport down on the way out.
#[cfg(unix)]
pub fn serve_resident_loop(
    engine: &mut DaemonEngine,
    mut transport: Option<DaemonMeshTransport>,
    listener: &UnixListener,
    shutdown: &AtomicBool,
) -> std::io::Result<()> {
    let mut buffer = vec![0_u8; DATA_PLANE_MTU];
    let mut result = Ok(());
    let mut next_peer_check = Instant::now() + TRUSTED_PEER_RECHECK_INTERVAL;
    while !shutdown.load(Ordering::SeqCst) {
        if Instant::now() >= next_peer_check {
            let peer_error = transport.as_ref().and_then(|transport| {
                transport
                    .validate_selected_peer(current_unix_seconds())
                    .err()
            });
            if let Some(error) = peer_error {
                eprintln!("qlinkd trusted peer changed; dropping transport: {error}");
                transport.take();
            }
            next_peer_check = Instant::now() + TRUSTED_PEER_RECHECK_INTERVAL;
        }
        match pump_and_serve_once(engine, transport.as_mut(), listener, &mut buffer) {
            Ok(did_work) => {
                if !did_work {
                    std::thread::sleep(RESIDENT_IDLE_POLL);
                }
            }
            Err(error) => {
                result = Err(error);
                break;
            }
        }
    }
    if let Some(transport) = &transport {
        transport.shutdown();
    }
    result
}

/// Builds the live mesh transport for the resident data plane. Returns `None`
/// when the data plane is inactive (dry-run resident) or transport construction
/// fails — in the failure case the pump keeps running and fails closed, exactly
/// as when no peer session is available.
#[cfg(unix)]
fn build_resident_transport(engine: &DaemonEngine) -> Option<DaemonMeshTransport> {
    if !engine.data_plane_active() {
        return None;
    }
    let identity = match load_or_generate_device_identity(&engine.paths().state_dir) {
        Ok(identity) => identity,
        Err(error) => {
            eprintln!("qlinkd device identity unavailable; data plane fails closed: {error}");
            return None;
        }
    };
    match build_daemon_mesh_transport(engine.config(), &identity, &engine.paths().state_dir) {
        Ok(transport) => Some(transport),
        Err(error) => {
            eprintln!("qlinkd mesh transport init failed; data plane fails closed: {error}");
            None
        }
    }
}

/// One resident tick: drive the outbound (TUN → transport) and inbound
/// (transport → TUN) pumps once each, then accept at most one pending control
/// connection. Returns `true` when any work happened, so the caller can avoid
/// sleeping under load. Never blocks: the TUN and control socket are
/// non-blocking and pump errors are logged without tearing down the loop.
#[cfg(unix)]
pub fn pump_and_serve_once(
    engine: &mut DaemonEngine,
    transport: Option<&mut DaemonMeshTransport>,
    listener: &UnixListener,
    buffer: &mut [u8],
) -> std::io::Result<bool> {
    let mut did_work = false;

    if let Some(transport) = transport {
        if let Some(runtime) = engine.data_plane_runtime_mut() {
            match runtime.pump_tun_to_transport_once(&mut *transport, buffer) {
                Ok(result) => {
                    if result.observed_packets > 0 {
                        did_work = true;
                    }
                }
                Err(error) => eprintln!("qlinkd outbound pump error: {error}"),
            }
            match runtime.pump_transport_to_tun_once(&mut *transport) {
                Ok(result) => {
                    if result.accepted_packets > 0 || result.emitted_packets > 0 {
                        did_work = true;
                    }
                }
                Err(error) => eprintln!("qlinkd inbound pump error: {error}"),
            }
        }
    }

    match listener.accept() {
        Ok((stream, _addr)) => {
            stream.set_nonblocking(false)?;
            if let Err(error) = serve_status_stream(stream, engine) {
                eprintln!("qlinkd client error: {error}");
            }
            did_work = true;
        }
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        Err(error) => return Err(error),
    }

    Ok(did_work)
}

#[cfg(unix)]
fn apply_local_control_socket_acl(socket: &PathBuf) -> std::io::Result<()> {
    let group_id = resolve_group_id(LOCAL_CONTROL_GROUP)?;
    let socket_cstr = std::ffi::CString::new(socket.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("socket path contains interior nul: {}", socket.display()),
        )
    })?;

    let chown_result = unsafe {
        libc::chown(
            socket_cstr.as_ptr(),
            LOCAL_CONTROL_SOCKET_OWNER_UID,
            group_id,
        )
    };
    if chown_result != 0 {
        return Err(std::io::Error::last_os_error());
    }

    std::fs::set_permissions(
        socket,
        std::fs::Permissions::from_mode(LOCAL_CONTROL_SOCKET_MODE),
    )
}

#[cfg(unix)]
fn resolve_group_id(name: &str) -> std::io::Result<u32> {
    let name = std::ffi::CString::new(name).map_err(|_| {
        std::io::Error::new(ErrorKind::InvalidInput, "group name contains interior nul")
    })?;
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    if group.is_null() {
        Err(std::io::Error::new(
            ErrorKind::NotFound,
            format!("required system group {LOCAL_CONTROL_GROUP} is missing"),
        ))
    } else {
        Ok(unsafe { (*group).gr_gid })
    }
}

pub fn load_config_or_default(paths: &DaemonPaths) -> std::io::Result<DaemonConfig> {
    match std::fs::read(&paths.config_file) {
        Ok(bytes) => {
            let config = serde_json::from_slice(&bytes).map_err(|error| {
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to parse {}: {error}", paths.config_file.display()),
                )
            })?;
            validate_loaded_config(config, &paths.config_file.display().to_string())
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            validate_loaded_config(DaemonConfig::default(), "default config")
        }
        Err(error) => Err(error),
    }
}

fn validate_loaded_config(config: DaemonConfig, source: &str) -> std::io::Result<DaemonConfig> {
    config.validate().map_err(|error| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("invalid qlinkd config {source}: {error}"),
        )
    })?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlink_linux::{
        LoopbackTunDevice, NetworkApplyError, NetworkExecutor, NetworkOperation, NftablesExecutor,
        NftablesOperation, TunDeviceConfig,
    };

    #[test]
    fn daemon_paths_match_linux_service_layout() {
        let paths = DaemonPaths::default();

        assert_eq!(
            paths.config_file.display().to_string(),
            "/etc/quantumlink/config.json"
        );
        assert_eq!(
            paths.state_dir.display().to_string(),
            "/var/lib/quantumlink"
        );
        assert_eq!(
            paths.socket.display().to_string(),
            "/run/quantumlink/qlinkd.sock"
        );
    }

    #[test]
    fn engine_status_starts_idle_with_kill_switch_enabled() {
        let engine = DaemonEngine::new(DaemonConfig::default(), DaemonPaths::default());
        let status = engine.status();

        assert_eq!(status.phase, ConnectionPhase::Idle);
        assert!(status.kill_switch);
        assert!(status.peers.is_empty());
    }

    #[test]
    fn engine_runtime_state_starts_without_network_side_effects() {
        let engine = DaemonEngine::new(DaemonConfig::default(), DaemonPaths::default());
        let runtime = engine.runtime_state();

        assert_eq!(runtime.phase, ConnectionPhase::Idle);
        assert_eq!(runtime.network, NetworkRuntimeState::NotStarted);
        assert!(runtime.peers.is_empty());
    }

    #[test]
    fn engine_try_new_builds_dry_run_network_plan_from_config() {
        let engine = DaemonEngine::try_new(DaemonConfig::default(), DaemonPaths::default())
            .expect("default config should produce a dry-run network plan");
        let status = engine.status();

        assert_eq!(status.network.state, NetworkPlanState::Planned);
        assert_eq!(status.network.interface_name.as_deref(), Some("qlink0"));
        assert_eq!(
            status.network.protected_cidr.as_deref(),
            Some("100.64.0.0/10")
        );
        assert!(status.network.dry_run);
        assert!(status
            .network
            .commands
            .iter()
            .any(|command| command == "ip addr add 100.64.10.2/32 dev qlink0"));
        assert!(status
            .network
            .nftables_rules
            .iter()
            .any(|rule| rule.contains("ip daddr 100.64.0.0/10")));
    }

    #[derive(Default)]
    struct RecordingNetworkExecutor {
        operations: Vec<NetworkOperation>,
        fail_on_call: Option<usize>,
    }

    impl NetworkExecutor for RecordingNetworkExecutor {
        fn apply(&mut self, operation: &NetworkOperation) -> Result<(), NetworkApplyError> {
            self.operations.push(operation.clone());
            if self.fail_on_call == Some(self.operations.len()) {
                return Err(NetworkApplyError::new("network apply failed"));
            }
            Ok(())
        }

        fn revert(&mut self, operation: &NetworkOperation) -> Result<(), NetworkApplyError> {
            self.operations.push(operation.clone());
            if self.fail_on_call == Some(self.operations.len()) {
                return Err(NetworkApplyError::new("network cleanup failed"));
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingNftablesExecutor {
        operations: Vec<NftablesOperation>,
        fail_on_call: Option<usize>,
    }

    impl NftablesExecutor for RecordingNftablesExecutor {
        fn apply_nftables(
            &mut self,
            operation: &NftablesOperation,
        ) -> Result<(), NetworkApplyError> {
            self.operations.push(operation.clone());
            if self.fail_on_call == Some(self.operations.len()) {
                return Err(NetworkApplyError::new("nftables apply failed"));
            }
            Ok(())
        }

        fn revert_nftables(
            &mut self,
            operation: &NftablesOperation,
        ) -> Result<(), NetworkApplyError> {
            self.operations.push(operation.clone());
            if self.fail_on_call == Some(self.operations.len()) {
                return Err(NetworkApplyError::new("nftables cleanup failed"));
            }
            Ok(())
        }
    }

    struct ReadOnlyStateAfterNftablesApply {
        operations: Vec<NftablesOperation>,
        state_dir: PathBuf,
        expected_apply_calls: usize,
        original_permissions: Option<std::fs::Permissions>,
    }

    impl ReadOnlyStateAfterNftablesApply {
        fn new(state_dir: PathBuf, expected_apply_calls: usize) -> Self {
            Self {
                operations: Vec::new(),
                state_dir,
                expected_apply_calls,
                original_permissions: None,
            }
        }

        fn restore_permissions(&mut self) {
            if let Some(permissions) = self.original_permissions.take() {
                std::fs::set_permissions(&self.state_dir, permissions).unwrap();
            }
        }
    }

    impl Drop for ReadOnlyStateAfterNftablesApply {
        fn drop(&mut self) {
            self.restore_permissions();
        }
    }

    impl NftablesExecutor for ReadOnlyStateAfterNftablesApply {
        fn apply_nftables(
            &mut self,
            operation: &NftablesOperation,
        ) -> Result<(), NetworkApplyError> {
            self.operations.push(operation.clone());
            if self.operations.len() == self.expected_apply_calls {
                let mut permissions = std::fs::metadata(&self.state_dir).unwrap().permissions();
                self.original_permissions = Some(permissions.clone());
                permissions.set_readonly(true);
                std::fs::set_permissions(&self.state_dir, permissions).unwrap();
            }
            Ok(())
        }

        fn revert_nftables(
            &mut self,
            operation: &NftablesOperation,
        ) -> Result<(), NetworkApplyError> {
            self.operations.push(operation.clone());
            Ok(())
        }
    }

    fn test_paths(temp: &tempfile::TempDir) -> DaemonPaths {
        DaemonPaths {
            config_file: temp.path().join("config.json"),
            state_dir: temp.path().join("state"),
            socket: temp.path().join("qlinkd.sock"),
        }
    }

    #[test]
    fn engine_try_new_still_only_plans_network() {
        let network_executor = RecordingNetworkExecutor::default();
        let nftables_executor = RecordingNftablesExecutor::default();

        let engine = DaemonEngine::try_new(DaemonConfig::default(), DaemonPaths::default())
            .expect("default config should produce a dry-run network plan");
        let status = engine.status();

        assert_eq!(status.network.state, NetworkPlanState::Planned);
        assert!(status.network.dry_run);
        assert!(network_executor.operations.is_empty());
        assert!(nftables_executor.operations.is_empty());
        assert!(status.network.error.is_none());
    }

    #[test]
    fn activate_network_with_fake_executors_marks_applied() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), paths)
            .expect("default config should produce a dry-run network plan");
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();

        engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .expect("fake executors should apply");
        let status = engine.status();

        assert_eq!(network_executor.operations.len(), 5);
        assert_eq!(nftables_executor.operations.len(), 5);
        assert_eq!(status.network.state, NetworkPlanState::Applied);
        assert!(!status.network.dry_run);
        assert!(status.network.error.is_none());
        assert!(status
            .network
            .commands
            .iter()
            .any(|command| { command == "ip route add 100.64.0.0/10 dev qlink0 table 51820" }));
    }

    #[test]
    fn data_plane_does_not_start_before_network_activation() {
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), DaemonPaths::default())
            .expect("default config should produce a dry-run network plan");
        let tun = LoopbackTunDevice::new(TunDeviceConfig::new("qlink0", 1280));

        let error = engine.start_data_plane_with(tun).unwrap_err();
        let status = engine.status();

        assert!(error.message().contains("network must be activated"));
        assert_eq!(status.data_plane.state, DataPlaneState::Failed);
        assert_eq!(status.data_plane.interface_name.as_deref(), Some("qlink0"));
        assert!(!status.data_plane.packet_io_available);
        assert!(!status.data_plane.transport_ready);
    }

    #[test]
    fn activated_network_can_start_data_plane_packet_io() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), paths)
            .expect("default config should produce a dry-run network plan");
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();
        engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .expect("fake executors should apply");
        let tun = LoopbackTunDevice::new(TunDeviceConfig::new("qlink0", 1280));

        engine
            .start_data_plane_with(tun)
            .expect("applied network should permit packet I/O start");
        let status = engine.status();

        assert_eq!(status.data_plane.state, DataPlaneState::Starting);
        assert_eq!(status.data_plane.interface_name.as_deref(), Some("qlink0"));
        assert!(status.data_plane.packet_io_available);
        assert!(!status.data_plane.transport_ready);
        assert!(engine.data_plane_runtime_mut().is_some());
    }

    #[test]
    fn activation_helper_cleans_up_network_when_tun_open_fails() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), paths.clone())
            .expect("default config should produce a dry-run network plan");
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();

        let error = engine
            .activate_network_and_start_data_plane_with(
                &mut network_executor,
                &mut nftables_executor,
                |_config| -> Result<LoopbackTunDevice, crate::data_plane::DataPlaneError> {
                    Err(crate::data_plane::DataPlaneError::Tun(
                        "tun open failed".to_string(),
                    ))
                },
            )
            .unwrap_err();
        let status = engine.status();

        assert!(error.to_string().contains("tun open failed"));
        assert!(network_executor.operations.iter().any(|operation| matches!(
            operation,
            NetworkOperation::DeleteTun { name } if name == "qlink0"
        )));
        assert!(nftables_executor
            .operations
            .iter()
            .any(|operation| matches!(
                operation,
                NftablesOperation::DeleteTable { family, table }
                    if family == "inet" && table == "qlink"
            )));
        assert!(load_network_ownership(&paths).unwrap().is_none());
        assert_eq!(status.network.state, NetworkPlanState::ApplyFailed);
        assert_eq!(status.data_plane.state, DataPlaneState::Failed);
        assert!(status
            .network
            .error
            .as_deref()
            .unwrap()
            .contains("data-plane startup failed"));
    }

    #[test]
    fn ownership_path_uses_state_dir() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);

        assert_eq!(
            network_ownership_path(&paths),
            temp.path().join("state").join("network-ownership.json")
        );
    }

    #[test]
    fn activate_network_writes_ownership_record_after_success() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), paths.clone())
            .expect("default config should produce a dry-run network plan");
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();

        engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .expect("fake executors should apply");
        let record = load_network_ownership(&paths)
            .expect("ownership read should succeed")
            .expect("successful activation should persist ownership");
        let status = engine.status();

        assert_eq!(record.schema_version, 1);
        assert_eq!(record.interface_name, "qlink0");
        assert_eq!(record.route_mode, RouteMode::GameOnly);
        assert_eq!(record.protected_cidr, "100.64.0.0/10");
        assert_eq!(record.fwmark, 0x514c);
        assert_eq!(record.route_table, 51820);
        assert_eq!(record.nft_family, "inet");
        assert_eq!(record.nft_table, "qlink");
        assert!(status.network.ownership_record_present);
    }

    #[cfg(unix)]
    #[test]
    fn activation_rolls_back_when_post_apply_ownership_storage_fails() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), paths.clone())
            .expect("default config should produce a dry-run network plan");
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor =
            ReadOnlyStateAfterNftablesApply::new(paths.state_dir.clone(), 5);

        let error = engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .unwrap_err();

        nftables_executor.restore_permissions();
        assert!(error
            .message()
            .contains("failed to persist network ownership"));
        assert!(nftables_executor.operations.len() > 5);
        assert!(nftables_executor
            .operations
            .iter()
            .any(|operation| matches!(
                operation,
                NftablesOperation::DeleteTable { family, table }
                    if family == "inet" && table == "qlink"
            )));
        assert!(network_executor.operations.len() > 5);
        assert!(network_executor.operations.iter().any(|operation| matches!(
            operation,
            NetworkOperation::DeleteTun { name } if name == "qlink0"
        )));
        assert!(load_network_ownership(&paths).unwrap().is_none());
        assert_eq!(engine.status().network.state, NetworkPlanState::ApplyFailed);
    }

    #[test]
    fn failed_activation_does_not_write_ownership_record() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), paths.clone())
            .expect("default config should produce a dry-run network plan");
        let mut network_executor = RecordingNetworkExecutor {
            fail_on_call: Some(1),
            ..RecordingNetworkExecutor::default()
        };
        let mut nftables_executor = RecordingNftablesExecutor::default();

        let _ = engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .unwrap_err();

        assert!(load_network_ownership(&paths).unwrap().is_none());
        assert!(!engine.status().network.ownership_record_present);
    }

    #[test]
    fn full_tunnel_activation_block_does_not_write_ownership_record() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        let config = DaemonConfig {
            route_mode: RouteMode::FullTunnel,
            ..DaemonConfig::default()
        };
        let mut engine = DaemonEngine::new(config, paths.clone());
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();

        let _ = engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .unwrap_err();

        assert!(load_network_ownership(&paths).unwrap().is_none());
        assert!(!engine.status().network.ownership_record_present);
    }

    #[test]
    fn activation_does_not_apply_when_ownership_state_cannot_be_prepared() {
        let temp = tempfile::tempdir().unwrap();
        let paths = DaemonPaths {
            config_file: temp.path().join("config.json"),
            state_dir: temp.path().join("state-file"),
            socket: temp.path().join("qlinkd.sock"),
        };
        std::fs::write(&paths.state_dir, b"not a directory").unwrap();
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), paths)
            .expect("default config should produce a dry-run network plan");
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();

        let error = engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .unwrap_err();

        assert!(error.message().contains("network ownership"));
        assert!(network_executor.operations.is_empty());
        assert!(nftables_executor.operations.is_empty());
        assert_eq!(engine.status().network.state, NetworkPlanState::ApplyFailed);
    }

    #[cfg(unix)]
    #[test]
    fn activation_rejects_symlinked_ownership_path_before_apply() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let target_path = temp.path().join("outside-ownership-target.json");
        std::fs::write(&target_path, b"do not modify").unwrap();
        std::os::unix::fs::symlink(&target_path, network_ownership_path(&paths)).unwrap();
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), paths)
            .expect("default config should produce a dry-run network plan");
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();

        let error = engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .unwrap_err();

        assert!(error.message().contains("network ownership"));
        assert!(network_executor.operations.is_empty());
        assert!(nftables_executor.operations.is_empty());
        assert_eq!(
            std::fs::read(&target_path).unwrap(),
            b"do not modify".to_vec()
        );
    }

    #[test]
    fn activation_does_not_apply_when_ownership_file_path_is_unwritable() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        std::fs::create_dir_all(network_ownership_path(&paths)).unwrap();
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), paths)
            .expect("default config should produce a dry-run network plan");
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();

        let error = engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .unwrap_err();

        assert!(error.message().contains("network ownership"));
        assert!(network_executor.operations.is_empty());
        assert!(nftables_executor.operations.is_empty());
        assert_eq!(engine.status().network.state, NetworkPlanState::ApplyFailed);
    }

    #[test]
    fn activation_does_not_apply_when_existing_ownership_file_is_readonly() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let ownership_path = network_ownership_path(&paths);
        std::fs::write(&ownership_path, b"{}").unwrap();
        let original_permissions = std::fs::metadata(&ownership_path).unwrap().permissions();
        let mut permissions = original_permissions.clone();
        permissions.set_readonly(true);
        std::fs::set_permissions(&ownership_path, permissions).unwrap();

        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), paths)
            .expect("default config should produce a dry-run network plan");
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();

        let error = engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .unwrap_err();

        std::fs::set_permissions(&ownership_path, original_permissions).unwrap();
        assert!(error.message().contains("network ownership"));
        assert!(network_executor.operations.is_empty());
        assert!(nftables_executor.operations.is_empty());
        assert_eq!(engine.status().network.state, NetworkPlanState::ApplyFailed);
    }

    #[test]
    fn deactivate_network_with_no_record_skips_executor_calls() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();

        deactivate_network_with(&paths, &mut network_executor, &mut nftables_executor)
            .expect("missing ownership should be idempotent");

        assert!(network_executor.operations.is_empty());
        assert!(nftables_executor.operations.is_empty());
    }

    #[test]
    fn deactivate_network_uses_record_and_removes_it_on_success() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        store_network_ownership(
            &paths,
            &NetworkOwnershipRecord::from_config(&DaemonConfig {
                interface_name: "qltest0".to_string(),
                overlay_ipv4_address: "100.64.10.9".to_string(),
                ..DaemonConfig::default()
            }),
        )
        .unwrap();
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();

        deactivate_network_with(&paths, &mut network_executor, &mut nftables_executor)
            .expect("cleanup should succeed");

        assert_eq!(nftables_executor.operations.len(), 1);
        assert!(matches!(
            nftables_executor.operations[0],
            NftablesOperation::DeleteTable { ref family, ref table }
                if family == "inet" && table == "qlink"
        ));
        assert_eq!(network_executor.operations.len(), 3);
        assert!(matches!(
            network_executor.operations[0],
            NetworkOperation::RemoveRoute { ref cidr, ref interface, table }
                if cidr == "100.64.0.0/10" && interface == "qltest0" && table == 51820
        ));
        assert!(load_network_ownership(&paths).unwrap().is_none());
    }

    #[test]
    fn deactivate_network_failure_leaves_record_for_retry() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        store_network_ownership(
            &paths,
            &NetworkOwnershipRecord::from_config(&DaemonConfig::default()),
        )
        .unwrap();
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor {
            fail_on_call: Some(1),
            ..RecordingNftablesExecutor::default()
        };

        let error = deactivate_network_with(&paths, &mut network_executor, &mut nftables_executor)
            .unwrap_err();

        assert!(error.message().contains("runtime deactivate failed"));
        assert!(load_network_ownership(&paths).unwrap().is_some());
    }

    #[test]
    fn deactivate_network_rejects_unsupported_ownership_schema_without_executor_calls() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let mut record = NetworkOwnershipRecord::from_config(&DaemonConfig::default());
        record.schema_version = NETWORK_OWNERSHIP_SCHEMA_VERSION + 1;
        std::fs::write(
            network_ownership_path(&paths),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();

        let error = deactivate_network_with(&paths, &mut network_executor, &mut nftables_executor)
            .unwrap_err();

        assert!(error
            .message()
            .contains("unsupported network ownership schema"));
        assert!(network_executor.operations.is_empty());
        assert!(nftables_executor.operations.is_empty());
        assert!(network_ownership_path(&paths).exists());
    }

    #[cfg(unix)]
    #[test]
    fn deactivate_network_rejects_symlinked_ownership_path_without_executor_calls() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let record = NetworkOwnershipRecord::from_config(&DaemonConfig::default());
        let target_path = temp.path().join("outside-ownership-target.json");
        std::fs::write(&target_path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        std::os::unix::fs::symlink(&target_path, network_ownership_path(&paths)).unwrap();
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();

        let error = deactivate_network_with(&paths, &mut network_executor, &mut nftables_executor)
            .unwrap_err();

        assert!(error.message().contains("network ownership"));
        assert!(network_executor.operations.is_empty());
        assert!(nftables_executor.operations.is_empty());
        assert!(network_ownership_path(&paths).exists());
    }

    #[test]
    fn activate_network_rolls_back_network_failure_and_marks_apply_failed() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), paths)
            .expect("default config should produce a dry-run network plan");
        let mut network_executor = RecordingNetworkExecutor {
            fail_on_call: Some(1),
            ..RecordingNetworkExecutor::default()
        };
        let mut nftables_executor = RecordingNftablesExecutor::default();

        let error = engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .unwrap_err();
        let status = engine.status();

        assert!(error
            .message()
            .contains("runtime apply failed: network apply failed"));
        assert_eq!(network_executor.operations.len(), 1);
        assert!(nftables_executor.operations.is_empty());
        assert_eq!(status.network.state, NetworkPlanState::ApplyFailed);
        assert!(!status.network.dry_run);
        assert!(status
            .network
            .error
            .as_deref()
            .expect("activation failure should be recorded")
            .contains("runtime apply failed: network apply failed"));
        assert!(status
            .network
            .commands
            .iter()
            .any(|command| command == "ip tuntap add dev qlink0 mode tun"));
    }

    #[test]
    fn activate_network_rolls_back_completed_network_when_nftables_fails() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_paths(&temp);
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), paths)
            .expect("default config should produce a dry-run network plan");
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor {
            fail_on_call: Some(1),
            ..RecordingNftablesExecutor::default()
        };

        let error = engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .unwrap_err();
        let status = engine.status();

        assert!(error
            .message()
            .contains("runtime apply failed: nftables apply failed"));
        assert_eq!(network_executor.operations.len(), 8);
        assert!(network_executor.operations.iter().any(|operation| matches!(
            operation,
            NetworkOperation::RemoveRule {
                fwmark: 0x514c,
                table: 51820
            }
        )));
        assert!(network_executor.operations.iter().any(|operation| matches!(
            operation,
            NetworkOperation::DeleteTun { name } if name == "qlink0"
        )));
        assert_eq!(nftables_executor.operations.len(), 1);
        assert_eq!(status.network.state, NetworkPlanState::ApplyFailed);
        assert!(!status.network.dry_run);
        assert!(status
            .network
            .error
            .as_deref()
            .expect("activation failure should be recorded")
            .contains("runtime apply failed: nftables apply failed"));
    }

    #[test]
    fn activate_network_blocks_full_tunnel_before_executor_calls() {
        let config = DaemonConfig {
            route_mode: RouteMode::FullTunnel,
            ..DaemonConfig::default()
        };
        let mut engine = DaemonEngine::new(config, DaemonPaths::default());
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();

        let error = engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .unwrap_err();
        let status = engine.status();

        assert!(error
            .message()
            .contains("full tunnel requires explicit underlay exemptions before activation"));
        assert!(network_executor.operations.is_empty());
        assert!(nftables_executor.operations.is_empty());
        assert_eq!(status.network.state, NetworkPlanState::ApplyFailed);
        assert_eq!(status.network.route_mode, Some(RouteMode::FullTunnel));
        assert_eq!(status.network.protected_cidr.as_deref(), Some("0.0.0.0/0"));
        assert!(status.network.commands.is_empty());
        assert!(!status.network.dry_run);
        assert!(status
            .network
            .error
            .as_deref()
            .expect("activation failure should be recorded")
            .contains("full tunnel requires explicit underlay exemptions before activation"));
    }

    #[test]
    fn try_new_full_tunnel_fails_closed_without_underlay_exemptions() {
        let config = DaemonConfig {
            route_mode: RouteMode::FullTunnel,
            ..DaemonConfig::default()
        };

        let error = DaemonEngine::try_new(config, DaemonPaths::default()).unwrap_err();

        assert!(error
            .to_string()
            .contains("full tunnel requires explicit underlay exemptions before activation"));
    }

    #[test]
    fn engine_try_new_rejects_invalid_config_before_runtime_starts() {
        let config = DaemonConfig {
            interface_name: "qlink/bad".to_string(),
            ..DaemonConfig::default()
        };

        let error = DaemonEngine::try_new(config, DaemonPaths::default()).unwrap_err();

        assert!(error.to_string().contains("interfaceName"));
    }

    #[cfg(unix)]
    #[test]
    fn serve_status_stream_rejects_overlong_control_request_without_panicking() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let engine = DaemonEngine::new(DaemonConfig::default(), DaemonPaths::default());
        let (server, mut client) = UnixStream::pair().unwrap();
        let mut request = "x".repeat(4096);
        request.push('\n');
        client.write_all(request.as_bytes()).unwrap();

        let error = serve_status_stream(server, &engine).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(error.to_string().contains("request too large"));
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.contains("request too large"));
    }

    #[cfg(unix)]
    #[test]
    fn serve_status_streams_continues_after_bad_request() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let engine = DaemonEngine::new(DaemonConfig::default(), DaemonPaths::default());
        let (bad_server, mut bad_client) = UnixStream::pair().unwrap();
        let (status_server, mut status_client) = UnixStream::pair().unwrap();
        let mut bad_request = "x".repeat(4096);
        bad_request.push('\n');
        bad_client.write_all(bad_request.as_bytes()).unwrap();
        status_client.write_all(b"status\n").unwrap();

        serve_status_streams(vec![Ok(bad_server), Ok(status_server)], &engine).unwrap();

        let mut bad_response = String::new();
        bad_client.read_to_string(&mut bad_response).unwrap();
        assert!(bad_response.contains("request too large"));

        let mut status_response = String::new();
        status_client.read_to_string(&mut status_response).unwrap();
        assert!(status_response.contains(r#""phase":"idle""#));
    }

    #[test]
    fn default_runtime_mode_is_resident_daemon() {
        assert_eq!(
            RuntimeMode::from_args(std::iter::empty::<&str>()).unwrap(),
            RuntimeMode::RunResident {
                activate_network: false
            }
        );
    }

    #[test]
    fn runtime_mode_parses_explicit_network_activation() {
        assert_eq!(
            RuntimeMode::from_args(["--activate-network"]).unwrap(),
            RuntimeMode::RunResident {
                activate_network: true
            }
        );
    }

    #[test]
    fn runtime_mode_parses_explicit_network_deactivation() {
        assert_eq!(
            RuntimeMode::from_args(["--deactivate-network"]).unwrap(),
            RuntimeMode::DeactivateNetwork
        );
    }

    #[test]
    fn runtime_mode_parses_check_config() {
        assert_eq!(
            RuntimeMode::from_args(["--check"]).unwrap(),
            RuntimeMode::CheckConfig
        );
    }

    #[test]
    fn runtime_mode_rejects_check_with_network_activation() {
        let error = RuntimeMode::from_args(["--check", "--activate-network"]).unwrap_err();

        assert_eq!(error, RuntimeModeError::ConflictingFlags);
        assert!(error.to_string().contains("cannot combine"));
    }

    #[test]
    fn runtime_mode_rejects_deactivate_conflicts() {
        assert_eq!(
            RuntimeMode::from_args(["--check", "--deactivate-network"]).unwrap_err(),
            RuntimeModeError::ConflictingFlags
        );
        assert_eq!(
            RuntimeMode::from_args(["--activate-network", "--deactivate-network"]).unwrap_err(),
            RuntimeModeError::ConflictingFlags
        );
    }

    #[test]
    fn load_config_reads_operator_config_file() {
        let temp = tempfile::tempdir().unwrap();
        let paths = DaemonPaths {
            config_file: temp.path().join("config.json"),
            state_dir: temp.path().join("state"),
            socket: temp.path().join("qlinkd.sock"),
        };
        std::fs::write(
            &paths.config_file,
            r#"{
                "interfaceName": "qltest0",
                "overlayCidr": "100.64.0.0/10",
                "overlayIpv4Address": "100.64.10.9",
                "routeMode": "gameOnly",
                "rendezvousServers": ["127.0.0.1:9471"],
                "relayServers": ["127.0.0.1:9472"],
                "killSwitch": true,
                "lowLatency": false,
                "voiceChatSafe": true
            }"#,
        )
        .unwrap();

        let config = load_config_or_default(&paths).unwrap();

        assert_eq!(config.interface_name, "qltest0");
        assert_eq!(config.overlay_ipv4_address, "100.64.10.9");
        assert!(!config.low_latency);
    }

    #[test]
    fn load_config_defaults_when_config_file_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let paths = DaemonPaths {
            config_file: temp.path().join("missing.json"),
            state_dir: temp.path().join("state"),
            socket: temp.path().join("qlinkd.sock"),
        };

        let config = load_config_or_default(&paths).unwrap();

        assert_eq!(config, DaemonConfig::default());
    }

    #[test]
    fn load_config_rejects_invalid_operator_config_file() {
        let temp = tempfile::tempdir().unwrap();
        let paths = DaemonPaths {
            config_file: temp.path().join("config.json"),
            state_dir: temp.path().join("state"),
            socket: temp.path().join("qlinkd.sock"),
        };
        std::fs::write(
            &paths.config_file,
            r#"{
                "interfaceName": "qlink/bad",
                "overlayCidr": "100.64.0.0/10",
                "overlayIpv4Address": "100.64.10.9",
                "routeMode": "gameOnly",
                "rendezvousServers": [],
                "relayServers": [],
                "killSwitch": true,
                "lowLatency": false,
                "voiceChatSafe": true
            }"#,
        )
        .unwrap();

        let error = load_config_or_default(&paths).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(error.to_string().contains("invalid qlinkd config"));
        assert!(error.to_string().contains("interfaceName"));
    }

    #[cfg(unix)]
    fn activated_engine_with_loopback(paths: DaemonPaths) -> DaemonEngine {
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), paths)
            .expect("default config should produce a network plan");
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();
        engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .expect("fake executors should apply");
        let tun = LoopbackTunDevice::new(TunDeviceConfig::new("qlink0", 1280));
        engine
            .start_data_plane_with(tun)
            .expect("activated network should allow packet I/O");
        engine
    }

    #[cfg(unix)]
    fn protected_ipv4_packet(destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[100, 64, 0, 2]);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    #[cfg(unix)]
    #[test]
    fn pump_and_serve_once_round_trips_protected_packet_through_local_echo() {
        use qlink_linux::TunPacketIo;

        let temp = tempfile::tempdir().unwrap();
        let mut engine = activated_engine_with_loopback(test_paths(&temp));
        let mut transport = DaemonMeshTransport::local_echo();
        let listener = UnixListener::bind(temp.path().join("tick.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut buffer = vec![0_u8; DATA_PLANE_MTU];

        let packet = protected_ipv4_packet([100, 64, 0, 9]);
        engine
            .data_plane_runtime_mut()
            .unwrap()
            .tun_mut()
            .write_packet(&packet)
            .unwrap();

        // Outbound tick: TUN -> pump -> transport. Work happened, and the data
        // plane now reports a ready, peer-session-backed transport.
        let did_work =
            pump_and_serve_once(&mut engine, Some(&mut transport), &listener, &mut buffer).unwrap();
        assert!(did_work);
        let status = engine.status();
        assert_eq!(status.data_plane.state, DataPlaneState::Ready);
        assert!(status.data_plane.transport_ready);
        assert!(status.data_plane.peer_session_ready);
        assert_eq!(
            status.data_plane.transport_path,
            Some(qlink_proto::PathKind::Direct)
        );

        // Inbound tick: transport -> pump -> TUN. The original packet is
        // restored into the loopback device.
        pump_and_serve_once(&mut engine, Some(&mut transport), &listener, &mut buffer).unwrap();
        let len = engine
            .data_plane_runtime_mut()
            .unwrap()
            .tun_mut()
            .read_packet(&mut buffer)
            .unwrap();
        assert_eq!(len, packet.len());
        assert_eq!(&buffer[16..20], &packet[16..20]);
    }

    #[cfg(unix)]
    #[test]
    fn pump_and_serve_once_serves_status_over_control_socket() {
        use std::io::{Read, Write};

        let temp = tempfile::tempdir().unwrap();
        let mut engine = DaemonEngine::new(DaemonConfig::default(), test_paths(&temp));
        let socket_path = temp.path().join("control.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut buffer = vec![0_u8; DATA_PLANE_MTU];

        let mut client = UnixStream::connect(&socket_path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(b"status\n").unwrap();

        // No transport: the tick still accepts and serves the control request.
        let did_work = pump_and_serve_once(&mut engine, None, &listener, &mut buffer).unwrap();
        assert!(did_work);

        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.contains(r#""phase":"idle""#));
    }

    #[cfg(unix)]
    #[test]
    fn pump_and_serve_once_idle_reports_no_work() {
        let temp = tempfile::tempdir().unwrap();
        let mut engine = activated_engine_with_loopback(test_paths(&temp));
        let mut transport = DaemonMeshTransport::local_echo();
        let listener = UnixListener::bind(temp.path().join("idle.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut buffer = vec![0_u8; DATA_PLANE_MTU];

        // Nothing queued on the TUN, no client connected: a tick does no work.
        let did_work =
            pump_and_serve_once(&mut engine, Some(&mut transport), &listener, &mut buffer).unwrap();
        assert!(!did_work);
    }

    #[cfg(unix)]
    #[test]
    fn serve_resident_loop_exits_when_shutdown_is_set() {
        let temp = tempfile::tempdir().unwrap();
        let mut engine = DaemonEngine::new(DaemonConfig::default(), test_paths(&temp));
        let listener = UnixListener::bind(temp.path().join("loop.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let shutdown = AtomicBool::new(true);
        let transport = Some(DaemonMeshTransport::local_echo());

        // Pre-set shutdown: the loop must return promptly and shut the
        // transport down without blocking.
        serve_resident_loop(&mut engine, transport, &listener, &shutdown).unwrap();
    }
}
