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
//! Peer-session-key installation into packet-frame encryption is the shared,
//! cross-platform production gap the product spec calls out ("production
//! peer-session key installation into packet-frame encryption"). Like the
//! Windows engine — whose sink reports `peer_session_key_available = false` for
//! identity/public meshes — the `Mesh` variant reports `peer_session_ready() ==
//! false` and installs no session, so protected packets fail closed until that
//! wiring lands. The `LocalEcho` variant installs a synthetic session so the
//! on-device data path can be demonstrated and tested end to end.

use crate::data_plane::{DataPlaneError, MeshFrameTransport};
use crate::identity::DeviceIdentity;
use base64::Engine as _;
use qlink_core::crypto::DeviceKeypair;
use qlink_core::mesh_transport::{MeshTransportConfig, MeshTransportHandle};
use qlink_core::packet_core::{InstalledPeerSession, PeerSessionDirection};
use qlink_proto::{peer_store_path_from_state_dir, DaemonConfig, PathKind};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;

/// Default mesh identifier for a SteamOS node until per-mesh configuration is
/// exposed. Keeping it stable lets peers on the same gamer mesh discover each
/// other; operators override it by joining a named mesh in a later revision.
pub const DEFAULT_MESH_ID: &str = "steam-default-mesh";
/// Sentinel remote peer id used before any invite is imported. Matches the
/// value the Windows engine and `qlinkctl` use for the primary slot; real
/// peers are added at runtime via [`MeshTransportHandle::add_peer`].
pub const UNCONFIGURED_REMOTE_PEER_ID: &str = "qlink_unconfigured";
/// Local QUIC bind address. `0.0.0.0:0` lets the OS pick an ephemeral port.
pub const MESH_BIND_ADDR: &str = "0.0.0.0:0";
/// Peer id attributed to the development local-echo loopback session.
pub const LOCAL_ECHO_PEER_ID: &str = "local-echo-peer";

/// `MeshTransportState::Ready` discriminant (mirrors the Windows engine's
/// `state_code() == 1` readiness check).
const MESH_STATE_READY: u32 = 1;
const MESH_PATH_DIRECT: u32 = 1;
const MESH_PATH_RELAY: u32 = 2;

/// The active encrypted transport behind the daemon packet pump.
pub enum DaemonMeshTransport {
    /// Production: shared qlink-core mesh transport.
    Mesh(Arc<MeshTransportHandle>),
    /// Development/local-smoke: frames are queued back for inbound acceptance.
    LocalEcho(VecDeque<Vec<u8>>),
}

impl std::fmt::Debug for DaemonMeshTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mesh(_) => f.write_str("DaemonMeshTransport::Mesh"),
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
        matches!(self, Self::Mesh(_))
    }

    /// A one-line, non-sensitive description for logs and the daemon banner.
    pub fn describe(&self) -> String {
        match self {
            Self::Mesh(handle) => format!(
                "mesh(state={}, path={})",
                handle.state_code(),
                handle.path_kind_code()
            ),
            Self::LocalEcho(_) => "local-echo(development)".to_string(),
        }
    }

    /// Releases transport resources. Idempotent; safe to call on shutdown.
    pub fn shutdown(&self) {
        if let Self::Mesh(handle) = self {
            handle.shutdown();
        }
    }
}

impl MeshFrameTransport for DaemonMeshTransport {
    fn is_ready(&self) -> bool {
        match self {
            Self::Mesh(handle) => handle.state_code() == MESH_STATE_READY,
            Self::LocalEcho(_) => true,
        }
    }

    fn path_kind(&self) -> PathKind {
        match self {
            Self::Mesh(handle) => path_kind_from_code(handle.path_kind_code()),
            Self::LocalEcho(_) => PathKind::Direct,
        }
    }

    fn peer_session_ready(&self) -> bool {
        match self {
            // Shared production gap: no peer-session key is installed into the
            // packet core yet, so the production transport fails closed just
            // like the Windows engine. LocalEcho installs a synthetic session.
            Self::Mesh(_) => false,
            Self::LocalEcho(_) => true,
        }
    }

    fn installed_peer_session(&self) -> Option<InstalledPeerSession> {
        match self {
            Self::Mesh(_) => None,
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

    fn send_frame(&mut self, frame: Vec<u8>) -> Result<(), DataPlaneError> {
        match self {
            Self::Mesh(handle) => handle
                .send_frame(frame)
                .map_err(|error| DataPlaneError::Transport(error.to_string())),
            Self::LocalEcho(queue) => {
                queue.push_back(frame);
                Ok(())
            }
        }
    }

    fn try_receive_frame(&mut self) -> Option<Vec<u8>> {
        match self {
            Self::Mesh(handle) => handle
                .try_receive_frame_from_any()
                .map(|inbound| inbound.frame),
            Self::LocalEcho(queue) => queue.pop_front(),
        }
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
) -> Result<MeshTransportConfig, DataPlaneError> {
    let peer_store_path = peer_store_path_from_state_dir(state_dir);
    let rendezvous_url = config
        .rendezvous_servers
        .first()
        .cloned()
        .unwrap_or_default();
    let mesh_config_json = serde_json::json!({
        "meshId": DEFAULT_MESH_ID,
        "localPeerId": identity.peer_id(),
        "remotePeerId": UNCONFIGURED_REMOTE_PEER_ID,
        "rendezvousUrl": rendezvous_url,
        "relayUrl": config.relay_servers.first(),
        "bindAddr": MESH_BIND_ADDR,
        "peerStorePath": peer_store_path.to_string_lossy(),
        "peerStoreKeyB64": base64::engine::general_purpose::STANDARD.encode(identity.peer_store_key()),
    });
    serde_json::from_value(mesh_config_json)
        .map_err(|error| DataPlaneError::Transport(format!("mesh transport config: {error}")))
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

    let mesh_config = daemon_mesh_transport_config(config, identity, state_dir)?;
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

    let handle = MeshTransportHandle::new_with_keypair(mesh_config, Some(Arc::new(owned_keypair)))
        .map_err(|error| DataPlaneError::Transport(error.to_string()))?;
    Ok(DaemonMeshTransport::Mesh(Arc::new(handle)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_plane::{packet_core_from_parts, DataPlaneRuntime};
    use crate::identity::load_or_generate_device_identity;
    use qlink_core::packet_core::{FfiRouteMode, PacketTunnelCore};
    use qlink_linux::{LoopbackTunDevice, TunDeviceConfig, TunPacketIo};

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
        let config = DaemonConfig {
            rendezvous_servers: vec!["127.0.0.1:9471".to_string()],
            relay_servers: vec!["127.0.0.1:9472".to_string()],
            ..DaemonConfig::default()
        };

        let mesh_config = daemon_mesh_transport_config(&config, &identity, temp.path()).unwrap();

        assert_eq!(mesh_config.mesh_id, DEFAULT_MESH_ID);
        assert_eq!(mesh_config.local_peer_id, identity.peer_id());
        assert_eq!(mesh_config.remote_peer_id, UNCONFIGURED_REMOTE_PEER_ID);
        assert_eq!(mesh_config.rendezvous_url, "127.0.0.1:9471");
        assert_eq!(mesh_config.relay_url.as_deref(), Some("127.0.0.1:9472"));
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(mesh_config.peer_store_key_b64.as_ref().unwrap())
            .unwrap();
        assert_eq!(decoded.len(), 32);
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
