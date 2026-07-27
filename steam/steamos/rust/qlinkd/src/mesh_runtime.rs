//! Live mesh transport for the SteamOS daemon.
//!
//! This is the SteamOS counterpart of the Windows service's
//! `engine::ActiveTransport` and the macOS `TunnelTransport` factory: it wraps
//! the shared `qlink_core::mesh_transport::MeshTransportHandle` (QUIC/native-UDP
//! carrier, PQC handshake, rendezvous discovery, relay fallback, peer-store
//! persistence, network-event reconnect) behind the daemon's existing
//! [`MeshFrameTransport`] contract so the packet pump can drive it.
//!
//! Two variants, exactly like Windows:
//!
//! * [`DaemonMeshTransport::Mesh`] — the production transport built from the
//!   operator's rendezvous/relay configuration and the persistent device
//!   identity.
//! * [`DaemonMeshTransport::LocalEcho`] — a development transport used when no
//!   rendezvous server is configured. Frames are queued back for inbound
//!   acceptance, exercising the full encode → decode path (and the fail-closed
//!   peer-session gate) without a network.
//!
//! Authenticated packet-session leases emitted by the shared transport are
//! installed into the SteamOS packet core. Ready, rekey, clear, expiry, and
//! inbound per-frame leases therefore follow the same contract as Windows.

use crate::data_plane::{
    DataPlaneError, InboundTransportFrame, MeshFrameTransport, PeerSessionUpdate,
};
use crate::identity::DeviceIdentity;
use crate::publication::{PublicationController, PublicationSnapshot, PublicationWorkerConfig};
use base64::Engine as _;
use qlink_core::crypto::DeviceKeypair;
use qlink_core::dytallix_identity::{
    DytallixRegistryBindingVersion, DytallixRegistryLookupConfig, MeshTrustPolicy,
};
use qlink_core::mesh_connection::NetworkEvent;
use qlink_core::mesh_transport::{
    MeshTransportConfig, MeshTransportHandle, PacketSessionDirection, PacketSessionEvent,
    PacketSessionLease,
};
use qlink_core::packet_core::{InstalledPeerSession, PeerSessionDirection};
use qlink_core::peer_acl::PeerAcl;
use qlink_proto::{
    load_peer_store_at, peer_store_path_from_state_dir, DaemonConfig, DytallixBindingVersion,
    MeshTrustMode, PathKind, StoredPeer,
};
use std::collections::VecDeque;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Local QUIC bind address. `0.0.0.0:0` lets the OS pick an ephemeral port.
pub const MESH_BIND_ADDR: &str = "0.0.0.0:0";
/// Peer id attributed to the development local-echo loopback session.
pub const LOCAL_ECHO_PEER_ID: &str = "local-echo-peer";
const MESH_PEER_RECORD_STORE_FILE: &str = "mesh-peer-records.json";
const MAX_AUTH_TOKEN_BYTES: u64 = 8 * 1024;

/// `MeshTransportState::Ready` discriminant (mirrors the Windows engine's
/// `state_code() == 1` readiness check).
const MESH_STATE_READY: u32 = 1;
const MESH_PATH_DIRECT: u32 = 1;
const MESH_PATH_RELAY: u32 = 2;

/// The active encrypted transport behind the daemon packet pump.
pub enum DaemonMeshTransport {
    /// Production: shared qlink-core mesh transport.
    Mesh {
        handle: Arc<MeshTransportHandle>,
        selected_peer_id: String,
        trusted_peer_store_path: PathBuf,
        publication: PublicationController,
    },
    /// Development/local-smoke: frames are queued back for inbound acceptance.
    LocalEcho(VecDeque<Vec<u8>>),
}

impl std::fmt::Debug for DaemonMeshTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mesh {
                selected_peer_id, ..
            } => f
                .debug_struct("DaemonMeshTransport::Mesh")
                .field("selected_peer_id", selected_peer_id)
                .finish_non_exhaustive(),
            Self::LocalEcho(queue) => f
                .debug_struct("DaemonMeshTransport::LocalEcho")
                .field("queued_frames", &queue.len())
                .finish(),
        }
    }
}

impl DaemonMeshTransport {
    /// Constructs the development local-echo transport.
    pub fn local_echo() -> Self {
        Self::LocalEcho(VecDeque::new())
    }

    /// `true` when this is the production mesh transport (not local echo).
    pub fn is_mesh(&self) -> bool {
        matches!(self, Self::Mesh { .. })
    }

    /// A one-line, non-sensitive description for logs and the daemon banner.
    pub fn describe(&self) -> String {
        match self {
            Self::Mesh { handle, .. } => format!(
                "mesh(state={}, path={})",
                handle.state_code(),
                handle.path_kind_code()
            ),
            Self::LocalEcho(_) => "local-echo(development)".to_string(),
        }
    }

    /// Releases transport resources. Idempotent; safe to call on shutdown.
    pub fn shutdown(&self) {
        if let Self::Mesh { handle, .. } = self {
            handle.shutdown();
        }
    }

    pub fn publication_snapshot(&self, at_unix: u64) -> Option<PublicationSnapshot> {
        match self {
            Self::Mesh { publication, .. } => Some(publication.snapshot(at_unix)),
            Self::LocalEcho(_) => None,
        }
    }

    fn publication_current(&self) -> bool {
        match self {
            Self::Mesh { publication, .. } => publication.is_current(now_unix()),
            Self::LocalEcho(_) => true,
        }
    }

    pub fn validate_selected_peer(&self, at_unix: u64) -> Result<(), DataPlaneError> {
        let Self::Mesh {
            selected_peer_id,
            trusted_peer_store_path,
            ..
        } = self
        else {
            return Ok(());
        };
        selected_peer_is_authorized(trusted_peer_store_path, selected_peer_id, at_unix)
    }

    pub fn handle_network_change(&self) {
        if let Self::Mesh {
            handle,
            publication,
            ..
        } = self
        {
            handle.handle_network_event(NetworkEvent::PathChanged);
            publication.request_refresh();
        }
    }
}

fn selected_peer_is_authorized(
    trusted_peer_store_path: &Path,
    selected_peer_id: &str,
    at_unix: u64,
) -> Result<(), DataPlaneError> {
    let store = load_peer_store_at(trusted_peer_store_path).map_err(|error| {
        DataPlaneError::Transport(format!(
            "failed to reload trusted peer store {}: {error}",
            trusted_peer_store_path.display()
        ))
    })?;
    let selected_still_current = store
        .dial_candidates(at_unix)
        .iter()
        .any(|peer| peer.peer_id == selected_peer_id)
        && store
            .selected_peer_id
            .as_deref()
            .is_none_or(|selected| selected == selected_peer_id);
    if selected_still_current {
        Ok(())
    } else {
        Err(DataPlaneError::Transport(format!(
            "selected peer {selected_peer_id} was removed, revoked, expired, or replaced"
        )))
    }
}

impl MeshFrameTransport for DaemonMeshTransport {
    fn is_ready(&self) -> bool {
        match self {
            Self::Mesh { handle, .. } => {
                self.publication_current()
                    && handle.state_code() == MESH_STATE_READY
                    && matches!(handle.default_packet_session(), Ok(Some(_)))
            }
            Self::LocalEcho(_) => true,
        }
    }

    fn path_kind(&self) -> PathKind {
        match self {
            Self::Mesh { handle, .. } => path_kind_from_code(handle.path_kind_code()),
            Self::LocalEcho(_) => PathKind::Direct,
        }
    }

    fn peer_session_ready(&self) -> bool {
        match self {
            Self::Mesh { handle, .. } => {
                self.publication_current() && matches!(handle.default_packet_session(), Ok(Some(_)))
            }
            Self::LocalEcho(_) => true,
        }
    }

    fn installed_peer_session(&self) -> Option<InstalledPeerSession> {
        match self {
            Self::Mesh { handle, .. } if self.publication_current() => handle
                .default_packet_session()
                .ok()
                .flatten()
                .map(installed_peer_session),
            Self::Mesh { .. } => None,
            Self::LocalEcho(_) => Some(InstalledPeerSession {
                peer_id: LOCAL_ECHO_PEER_ID.to_string(),
                direction: PeerSessionDirection::Outbound,
                generation: 1,
                transcript_binding: [0; 32],
                expires_at_unix: u64::MAX,
                rekey_after_bytes: 0,
            }),
        }
    }

    fn take_peer_session_updates(&self) -> Vec<PeerSessionUpdate> {
        let Self::Mesh { handle, .. } = self else {
            return Vec::new();
        };
        let mut updates = Vec::new();
        while let Some(event) = handle.try_receive_packet_session_event() {
            updates.push(match event {
                PacketSessionEvent::Ready(session) => {
                    PeerSessionUpdate::Ready(installed_peer_session(session))
                }
                PacketSessionEvent::Cleared {
                    peer_id,
                    direction,
                    generation,
                } => PeerSessionUpdate::Cleared {
                    peer_id,
                    direction: installed_direction(direction),
                    generation,
                },
            });
        }
        updates
    }

    fn send_frame(&mut self, frame: Vec<u8>) -> Result<(), DataPlaneError> {
        if !self.publication_current() {
            return Err(DataPlaneError::Transport(
                "signed local peer record is not current".to_string(),
            ));
        }
        match self {
            Self::Mesh { handle, .. } => handle
                .send_frame(frame)
                .map_err(|error| DataPlaneError::Transport(error.to_string())),
            Self::LocalEcho(queue) => {
                queue.push_back(frame);
                Ok(())
            }
        }
    }

    fn try_receive_frame(&mut self) -> Option<InboundTransportFrame> {
        if !self.publication_current() {
            return None;
        }
        match self {
            Self::Mesh { handle, .. } => {
                handle
                    .try_receive_frame_from_any()
                    .map(|inbound| InboundTransportFrame {
                        frame: inbound.frame,
                        peer_session: installed_peer_session(inbound.packet_session),
                    })
            }
            Self::LocalEcho(queue) => queue.pop_front().map(|frame| InboundTransportFrame {
                frame,
                peer_session: InstalledPeerSession {
                    peer_id: LOCAL_ECHO_PEER_ID.to_string(),
                    direction: PeerSessionDirection::Inbound,
                    generation: 1,
                    transcript_binding: [0; 32],
                    expires_at_unix: u64::MAX,
                    rekey_after_bytes: 0,
                },
            }),
        }
    }

    fn last_transport_error(&self) -> Option<&str> {
        None
    }
}

fn installed_direction(direction: PacketSessionDirection) -> PeerSessionDirection {
    match direction {
        PacketSessionDirection::Outbound => PeerSessionDirection::Outbound,
        PacketSessionDirection::Inbound => PeerSessionDirection::Inbound,
    }
}

fn installed_peer_session(session: PacketSessionLease) -> InstalledPeerSession {
    InstalledPeerSession {
        peer_id: session.peer_id,
        direction: installed_direction(session.direction),
        generation: session.generation,
        transcript_binding: session.transcript_binding,
        expires_at_unix: session.expires_at_unix,
        rekey_after_bytes: session.rekey_after_bytes,
    }
}

fn path_kind_from_code(code: u32) -> PathKind {
    match code {
        MESH_PATH_DIRECT => PathKind::Direct,
        MESH_PATH_RELAY => PathKind::Relay,
        _ => PathKind::Probing,
    }
}

/// Builds the mesh transport configuration from the daemon config + persistent
/// identity. Constructed via JSON so the shared config's serde field defaults
/// (deadlines, probe pacing, backoff) apply, mirroring the Windows engine.
pub fn daemon_mesh_transport_config(
    config: &DaemonConfig,
    identity: &DeviceIdentity,
    state_dir: &Path,
    peer: &StoredPeer,
) -> Result<MeshTransportConfig, DataPlaneError> {
    if peer.trust_mode == MeshTrustMode::DevelopmentOptional {
        return Err(DataPlaneError::Transport(
            "development-optional peers are not accepted by the resident network transport"
                .to_string(),
        ));
    }
    if peer.trust_mode == MeshTrustMode::PublicDytallixRequired
        && config.dytallix_identity.is_none()
    {
        return Err(DataPlaneError::Transport(
            "public Dytallix peer requires pinned dytallixIdentity configuration".to_string(),
        ));
    }
    if peer.trust_mode == MeshTrustMode::PublicDytallixRequired
        && config.dytallix_identity.as_ref().is_some_and(|settings| {
            settings.binding_version != DytallixBindingVersion::StableIdentityV2
        })
    {
        return Err(DataPlaneError::Transport(
            "public Dytallix peer requires bindingVersion=stableIdentityV2; legacy v1 downgrade is refused"
                .to_string(),
        ));
    }
    let peer_store_path = state_dir.join(MESH_PEER_RECORD_STORE_FILE);
    let rendezvous_url = config
        .rendezvous_servers
        .first()
        .cloned()
        .unwrap_or_default();
    let rendezvous_auth_token =
        load_optional_auth_token(config.rendezvous_auth_token_file.as_deref(), "rendezvous")?;
    let relay_auth_token =
        load_optional_auth_token(config.relay_auth_token_file.as_deref(), "relay")?;
    let mesh_trust_policy = mesh_trust_policy(peer.trust_mode);
    let dytallix_identity =
        config
            .dytallix_identity
            .as_ref()
            .map(|settings| DytallixRegistryLookupConfig {
                endpoint: settings.endpoint.clone(),
                contract_address: settings.contract_address.clone(),
                binding_version: match settings.binding_version {
                    DytallixBindingVersion::ExactPeerRecordV1 => {
                        DytallixRegistryBindingVersion::ExactPeerRecordV1
                    }
                    DytallixBindingVersion::StableIdentityV2 => {
                        DytallixRegistryBindingVersion::StableIdentityV2
                    }
                },
                network_id: Some(settings.network_id.clone()),
                chain_id: Some(settings.chain_id.clone()),
                allowed_rpc_endpoints: settings.allowed_rpc_endpoints.clone(),
            });
    let mesh_config_json = serde_json::json!({
        "meshId": peer.mesh_id,
        "localPeerId": identity.peer_id(),
        "remotePeerId": peer.peer_id,
        "rendezvousUrl": rendezvous_url,
        "rendezvousAuthToken": rendezvous_auth_token,
        "relayUrl": config.relay_servers.first(),
        "relayAuthToken": relay_auth_token,
        "bindAddr": MESH_BIND_ADDR,
        "peerStorePath": peer_store_path.to_string_lossy(),
        "peerStoreKeyB64": base64::engine::general_purpose::STANDARD.encode(identity.peer_store_key()),
        "meshTrustPolicy": mesh_trust_policy,
        "dytallixIdentity": dytallix_identity,
        "inboundAcl": PeerAcl::new().with_allow([peer.peer_id.clone()]),
    });
    serde_json::from_value(mesh_config_json)
        .map_err(|error| DataPlaneError::Transport(format!("mesh transport config: {error}")))
}

fn mesh_trust_policy(mode: MeshTrustMode) -> MeshTrustPolicy {
    match mode {
        MeshTrustMode::PrivateFriends => MeshTrustPolicy::PrivatePreferred,
        MeshTrustMode::PublicDytallixRequired => MeshTrustPolicy::PublicRequired,
        MeshTrustMode::DevelopmentOptional => MeshTrustPolicy::DevelopmentOptional,
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn select_packet_peer(
    config: &DaemonConfig,
    state_dir: &Path,
    at_unix: u64,
) -> Result<StoredPeer, DataPlaneError> {
    let store_path = peer_store_path_from_state_dir(state_dir);
    let store = load_peer_store_at(&store_path).map_err(|error| {
        DataPlaneError::Transport(format!(
            "failed to load trusted peer store {}: {error}",
            store_path.display()
        ))
    })?;
    let candidates = store.dial_candidates(at_unix);
    if let Some(active_peer_id) = config
        .active_peer_id
        .as_deref()
        .or(store.selected_peer_id.as_deref())
    {
        return candidates
            .into_iter()
            .find(|peer| peer.peer_id == active_peer_id)
            .ok_or_else(|| {
                DataPlaneError::Transport(format!(
                    "configured active peer {active_peer_id} is missing, expired, or revoked"
                ))
            });
    }
    match candidates.as_slice() {
        [peer] => Ok(peer.clone()),
        [] => Err(DataPlaneError::Transport(
            "no eligible trusted peer is available; import a current invite".to_string(),
        )),
        _ => Err(DataPlaneError::Transport(format!(
            "{} eligible peers are available; set activePeerId explicitly",
            candidates.len()
        ))),
    }
}

fn load_optional_auth_token(
    path: Option<&str>,
    service: &str,
) -> Result<Option<String>, DataPlaneError> {
    path.map(|path| load_auth_token(Path::new(path), service))
        .transpose()
}

fn load_auth_token(path: &Path, service: &str) -> Result<String, DataPlaneError> {
    if !path.is_absolute() {
        return Err(DataPlaneError::Transport(format!(
            "{service} auth token file must use an absolute path"
        )));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        DataPlaneError::Transport(format!(
            "failed to inspect {service} auth token file {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(DataPlaneError::Transport(format!(
            "{service} auth token path {} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_AUTH_TOKEN_BYTES {
        return Err(DataPlaneError::Transport(format!(
            "{service} auth token file exceeds {MAX_AUTH_TOKEN_BYTES} bytes"
        )));
    }
    #[cfg(unix)]
    if metadata.mode() & 0o077 != 0 {
        return Err(DataPlaneError::Transport(format!(
            "{service} auth token file {} must not be group- or world-accessible",
            path.display()
        )));
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|error| {
        DataPlaneError::Transport(format!(
            "failed to open {service} auth token file {}: {error}",
            path.display()
        ))
    })?;
    let mut token = String::new();
    file.take(MAX_AUTH_TOKEN_BYTES + 1)
        .read_to_string(&mut token)
        .map_err(|error| {
            DataPlaneError::Transport(format!(
                "failed to read {service} auth token file {}: {error}",
                path.display()
            ))
        })?;
    let token = token.trim();
    if token.is_empty() {
        return Err(DataPlaneError::Transport(format!(
            "{service} auth token file {} is empty",
            path.display()
        )));
    }
    Ok(token.to_string())
}

/// Builds the live daemon mesh transport. With no rendezvous server configured
/// the daemon uses the local-echo development transport (parity with the
/// Windows engine's no-rendezvous fallback); otherwise it constructs the shared
/// `MeshTransportHandle`, signing inbound identity assertions with the
/// persistent device keypair.
pub fn build_daemon_mesh_transport(
    config: &DaemonConfig,
    identity: &DeviceIdentity,
    state_dir: &Path,
) -> Result<DaemonMeshTransport, DataPlaneError> {
    if config.rendezvous_servers.is_empty() {
        return Ok(DaemonMeshTransport::local_echo());
    }

    let peer = select_packet_peer(config, state_dir, now_unix())?;
    let mesh_config = daemon_mesh_transport_config(config, identity, state_dir, &peer)?;
    let owned_keypair = identity
        .keypair()
        .seed()
        .ok_or_else(|| {
            DataPlaneError::Transport("device keypair has no persistable seed".to_string())
        })
        .and_then(|seed| {
            DeviceKeypair::from_seed(seed)
                .map_err(|error| DataPlaneError::Transport(error.to_string()))
        })?;

    let owned_keypair = Arc::new(owned_keypair);
    let handle = Arc::new(
        MeshTransportHandle::new_with_keypair(mesh_config, Some(owned_keypair.clone()))
            .map_err(|error| DataPlaneError::Transport(error.to_string()))?,
    );
    if let Some(advertise_address) = config.advertise_address.as_deref() {
        let address = advertise_address.parse().map_err(|error| {
            DataPlaneError::Transport(format!(
                "invalid advertiseAddress {advertise_address}: {error}"
            ))
        })?;
        handle.set_advertise_addr(address);
    }
    let publication = PublicationController::start(
        handle.clone(),
        owned_keypair,
        PublicationWorkerConfig {
            rendezvous_url: config.rendezvous_servers[0].clone(),
            rendezvous_auth_token: load_optional_auth_token(
                config.rendezvous_auth_token_file.as_deref(),
                "rendezvous",
            )?,
            ttl_seconds: config.publication_ttl_seconds,
            overlay_routes: vec![config.overlay_cidr.clone()],
            state_dir: state_dir.to_path_buf(),
            selected_peer_id: peer.peer_id.clone(),
            public_dytallix_required: peer.trust_mode == MeshTrustMode::PublicDytallixRequired,
        },
    )
    .map_err(|error| {
        DataPlaneError::Transport(format!("signed publication worker initialization: {error}"))
    })?;
    Ok(DaemonMeshTransport::Mesh {
        handle,
        selected_peer_id: peer.peer_id,
        trusted_peer_store_path: peer_store_path_from_state_dir(state_dir),
        publication,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_plane::{packet_core_from_parts, DataPlaneRuntime};
    use crate::identity::load_or_generate_device_identity;
    use qlink_core::packet_core::{FfiRouteMode, PacketTunnelCore};
    use qlink_linux::{LoopbackTunDevice, TunDeviceConfig, TunPacketIo};
    use qlink_proto::{store_peer_store_at, MeshTrustMode, PeerStore};

    fn identity() -> (tempfile::TempDir, DeviceIdentity) {
        let temp = tempfile::tempdir().unwrap();
        let identity = load_or_generate_device_identity(temp.path()).unwrap();
        (temp, identity)
    }

    fn runtime() -> DataPlaneRuntime<LoopbackTunDevice, PacketTunnelCore> {
        let tun = LoopbackTunDevice::new(TunDeviceConfig::new("qlink0", 1280));
        let core = packet_core_from_parts(
            "100.64.0.0/10".to_string(),
            FfiRouteMode::ProtectedPrefixesOnly,
            1280,
        )
        .unwrap();
        DataPlaneRuntime::new(tun, core)
    }

    fn peer(peer_id: &str, mesh_id: &str) -> StoredPeer {
        StoredPeer {
            peer_id: peer_id.to_string(),
            alias: "trusted deck".to_string(),
            mesh_id: mesh_id.to_string(),
            party_id: "party-a".to_string(),
            trust_mode: MeshTrustMode::PrivateFriends,
            trust_source: "invite".to_string(),
            revoked: false,
            expires_at_unix: u64::MAX,
        }
    }

    fn ipv4_packet(destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[100, 64, 0, 2]);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    #[test]
    fn path_kind_codes_map_to_proto_variants() {
        assert_eq!(path_kind_from_code(1), PathKind::Direct);
        assert_eq!(path_kind_from_code(2), PathKind::Relay);
        assert_eq!(path_kind_from_code(0), PathKind::Probing);
        assert_eq!(path_kind_from_code(99), PathKind::Probing);
    }

    #[test]
    fn packet_session_conversion_preserves_authenticated_lease_fields() {
        let lease = PacketSessionLease {
            peer_id: "peer-a".to_string(),
            direction: PacketSessionDirection::Inbound,
            generation: 7,
            transcript_binding: [9; 32],
            expires_at_unix: 42,
            rekey_after_bytes: 4096,
        };

        let installed = installed_peer_session(lease);

        assert_eq!(installed.peer_id, "peer-a");
        assert_eq!(installed.direction, PeerSessionDirection::Inbound);
        assert_eq!(installed.generation, 7);
        assert_eq!(installed.transcript_binding, [9; 32]);
        assert_eq!(installed.expires_at_unix, 42);
        assert_eq!(installed.rekey_after_bytes, 4096);
    }

    #[test]
    fn no_rendezvous_config_builds_local_echo_transport() {
        let (temp, identity) = identity();
        let config = DaemonConfig::default();

        let transport = build_daemon_mesh_transport(&config, &identity, temp.path()).unwrap();

        assert!(!transport.is_mesh());
        assert!(transport.is_ready());
        assert!(transport.peer_session_ready());
        assert!(transport.installed_peer_session().is_some());
        assert_eq!(transport.path_kind(), PathKind::Direct);
    }

    #[test]
    fn mesh_transport_config_carries_identity_and_endpoints() {
        let (temp, identity) = identity();
        let selected_peer = peer("peer-a", "mesh-a");
        let config = DaemonConfig {
            rendezvous_servers: vec!["127.0.0.1:9471".to_string()],
            relay_servers: vec!["127.0.0.1:9472".to_string()],
            ..DaemonConfig::default()
        };

        let mesh_config =
            daemon_mesh_transport_config(&config, &identity, temp.path(), &selected_peer).unwrap();

        assert_eq!(mesh_config.mesh_id, "mesh-a");
        assert_eq!(mesh_config.local_peer_id, identity.peer_id());
        assert_eq!(mesh_config.remote_peer_id, "peer-a");
        assert_eq!(mesh_config.rendezvous_url, "127.0.0.1:9471");
        assert_eq!(mesh_config.relay_url.as_deref(), Some("127.0.0.1:9472"));
        assert_eq!(
            mesh_config
                .inbound_acl
                .as_ref()
                .unwrap()
                .allow
                .as_ref()
                .unwrap(),
            &["peer-a".to_string()].into_iter().collect()
        );
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(mesh_config.peer_store_key_b64.as_ref().unwrap())
            .unwrap();
        assert_eq!(decoded.len(), 32);
        assert!(mesh_config
            .peer_store_path
            .as_deref()
            .unwrap()
            .ends_with(MESH_PEER_RECORD_STORE_FILE));
    }

    #[test]
    fn public_mesh_refuses_legacy_v1_registry_downgrade() {
        let (temp, identity) = identity();
        let mut selected_peer = peer("peer-a", "mesh-a");
        selected_peer.trust_mode = MeshTrustMode::PublicDytallixRequired;
        let config = DaemonConfig {
            dytallix_identity: Some(qlink_proto::DytallixIdentityLookupConfig {
                endpoint: "https://rpc.example".to_string(),
                contract_address: "quantumlink-node-registry".to_string(),
                network_id: "production".to_string(),
                chain_id: "dytallix-1".to_string(),
                binding_version: DytallixBindingVersion::ExactPeerRecordV1,
                allowed_rpc_endpoints: vec!["https://rpc.example".to_string()],
            }),
            ..DaemonConfig::default()
        };

        let error = daemon_mesh_transport_config(&config, &identity, temp.path(), &selected_peer)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("bindingVersion=stableIdentityV2"));
    }

    #[test]
    fn packet_peer_selection_requires_one_unambiguous_eligible_peer() {
        let temp = tempfile::tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let store = PeerStore {
            selected_peer_id: None,
            peers: vec![peer("peer-a", "mesh-a"), peer("peer-b", "mesh-a")],
        };
        store_peer_store_at(&state_dir, &store).unwrap();

        let ambiguous = select_packet_peer(&DaemonConfig::default(), &state_dir, 1).unwrap_err();
        assert!(ambiguous.to_string().contains("set activePeerId"));

        let config = DaemonConfig {
            active_peer_id: Some("peer-b".to_string()),
            ..DaemonConfig::default()
        };
        let selected = select_packet_peer(&config, &state_dir, 1).unwrap();
        assert_eq!(selected.peer_id, "peer-b");
    }

    #[test]
    fn packet_peer_selection_rejects_revoked_or_expired_active_peer() {
        let temp = tempfile::tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let mut revoked = peer("peer-a", "mesh-a");
        revoked.revoked = true;
        let mut expired = peer("peer-b", "mesh-a");
        expired.expires_at_unix = 10;
        store_peer_store_at(
            &state_dir,
            &PeerStore {
                selected_peer_id: None,
                peers: vec![revoked, expired],
            },
        )
        .unwrap();

        let config = DaemonConfig {
            active_peer_id: Some("peer-a".to_string()),
            ..DaemonConfig::default()
        };
        let error = select_packet_peer(&config, &state_dir, 20).unwrap_err();
        assert!(error.to_string().contains("expired, or revoked"));
    }

    #[test]
    fn selected_peer_revalidation_fails_after_revocation_or_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let store_path = peer_store_path_from_state_dir(&state_dir);
        let mut store = PeerStore {
            selected_peer_id: Some("peer-a".to_string()),
            peers: vec![peer("peer-a", "mesh-a"), peer("peer-b", "mesh-a")],
        };
        store_peer_store_at(&state_dir, &store).unwrap();
        selected_peer_is_authorized(&store_path, "peer-a", 1).unwrap();

        store.revoke("peer-a");
        store.select("peer-b", 1);
        store_peer_store_at(&state_dir, &store).unwrap();
        let error = selected_peer_is_authorized(&store_path, "peer-a", 1).unwrap_err();
        assert!(error.to_string().contains("revoked, expired, or replaced"));
    }

    #[cfg(unix)]
    #[test]
    fn auth_token_loader_requires_owner_only_regular_file() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let token_path = temp.path().join("rendezvous.token");
        std::fs::write(&token_path, "test-token\n").unwrap();
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            load_auth_token(&token_path, "rendezvous").unwrap(),
            "test-token"
        );

        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = load_auth_token(&token_path, "rendezvous").unwrap_err();
        assert!(error.to_string().contains("group- or world-accessible"));
    }

    #[test]
    fn local_echo_round_trips_protected_packet_through_the_data_plane() {
        let mut runtime = runtime();
        let mut transport = DaemonMeshTransport::local_echo();
        let mut buffer = [0_u8; 1280];
        let packet = ipv4_packet([100, 64, 0, 9]);

        // Outbound: tun -> pump -> transport (encrypted frame queued).
        runtime.tun_mut().write_packet(&packet).unwrap();
        let outbound = runtime
            .pump_tun_to_transport_once(&mut transport, &mut buffer)
            .unwrap();
        assert_eq!(outbound.queued_packets, 1);
        assert_eq!(outbound.emitted_packets, 1);
        assert!(runtime.status().transport_ready);
        assert!(runtime.status().peer_session_ready);

        // Inbound: transport -> pump -> tun (packet restored).
        let inbound = runtime.pump_transport_to_tun_once(&mut transport).unwrap();
        assert_eq!(inbound.accepted_packets, 1);
        assert_eq!(inbound.emitted_packets, 1);

        let len = runtime.tun_mut().read_packet(&mut buffer).unwrap();
        assert_eq!(len, packet.len());
        assert_eq!(&buffer[16..20], &packet[16..20]);
    }

    #[test]
    fn local_echo_shutdown_is_a_noop() {
        let transport = DaemonMeshTransport::local_echo();
        transport.shutdown();
        assert!(transport.describe().contains("local-echo"));
    }
}
