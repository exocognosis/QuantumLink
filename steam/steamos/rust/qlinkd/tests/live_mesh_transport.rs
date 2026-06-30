use std::collections::VecDeque;

use qlink_core::packet_core::FfiRouteMode;
use qlink_linux::{DryRunExecutor, LoopbackTunDevice, TunDeviceConfig, TunPacketIo};
use qlink_proto::{DaemonConfig, DataPlaneState, PathKind};
use qlinkd::data_plane::{
    packet_core_from_parts, DataPlaneError, DataPlaneRuntime, MeshFrameTransport,
};
use qlinkd::{DaemonEngine, DaemonPaths};

#[derive(Debug)]
struct FakeMeshTransport {
    ready: bool,
    path: PathKind,
    peer_session_ready: bool,
    frames: VecDeque<Vec<u8>>,
}

impl FakeMeshTransport {
    fn direct_ready() -> Self {
        Self {
            ready: true,
            path: PathKind::Direct,
            peer_session_ready: true,
            frames: VecDeque::new(),
        }
    }

    fn unavailable() -> Self {
        Self {
            ready: false,
            path: PathKind::Unavailable,
            peer_session_ready: false,
            frames: VecDeque::new(),
        }
    }

    fn queued_frames(&self) -> usize {
        self.frames.len()
    }
}

impl MeshFrameTransport for FakeMeshTransport {
    fn is_ready(&self) -> bool {
        self.ready
    }

    fn path_kind(&self) -> PathKind {
        self.path
    }

    fn peer_session_ready(&self) -> bool {
        self.peer_session_ready
    }

    fn send_frame(&mut self, frame: Vec<u8>) -> Result<(), DataPlaneError> {
        if !self.ready {
            return Err(DataPlaneError::Transport(
                "fake mesh transport unavailable".to_string(),
            ));
        }
        self.frames.push_back(frame);
        Ok(())
    }

    fn try_receive_frame(&mut self) -> Option<Vec<u8>> {
        self.frames.pop_front()
    }
}

fn test_paths(temp: &tempfile::TempDir) -> DaemonPaths {
    DaemonPaths {
        config_file: temp.path().join("config.json"),
        state_dir: temp.path().join("state"),
        socket: temp.path().join("qlinkd.sock"),
    }
}

fn activated_engine() -> DaemonEngine {
    let temp = tempfile::tempdir().unwrap();
    let paths = test_paths(&temp);
    let mut engine = DaemonEngine::try_new(DaemonConfig::default(), paths)
        .expect("default config should produce a network plan");
    let mut network_executor = DryRunExecutor::new();
    let mut nftables_executor = DryRunExecutor::new();
    engine
        .activate_network_with(&mut network_executor, &mut nftables_executor)
        .expect("dry-run executors should activate");
    let tun = LoopbackTunDevice::new(TunDeviceConfig::new("qlink0", 1280));
    engine
        .start_data_plane_with(tun)
        .expect("activated network should allow packet I/O");
    engine
}

fn runtime() -> DataPlaneRuntime<LoopbackTunDevice, qlink_core::packet_core::PacketTunnelCore> {
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
fn live_mesh_transport_activated_data_plane_reports_ready_when_mesh_transport_is_ready() {
    let mut engine = activated_engine();
    let packet = ipv4_packet([100, 64, 0, 9]);
    let mut transport = FakeMeshTransport::direct_ready();
    let mut buffer = [0_u8; 1280];

    engine
        .data_plane_runtime_mut()
        .unwrap()
        .tun_mut()
        .write_packet(&packet)
        .unwrap();
    engine
        .data_plane_runtime_mut()
        .unwrap()
        .pump_tun_to_transport_once(&mut transport, &mut buffer)
        .unwrap();
    let status = engine.status();

    assert_eq!(status.data_plane.state, DataPlaneState::Ready);
    assert!(status.data_plane.packet_io_available);
    assert!(status.data_plane.transport_ready);
    assert_eq!(status.data_plane.transport_path, Some(PathKind::Direct));
    assert!(status.data_plane.peer_session_ready);
}

#[test]
fn live_mesh_transport_packet_pump_drops_protected_packets_when_transport_is_not_ready() {
    let mut runtime = runtime();
    let packet = ipv4_packet([100, 64, 0, 9]);
    let mut transport = FakeMeshTransport::unavailable();
    let mut buffer = [0_u8; 1280];

    runtime.tun_mut().write_packet(&packet).unwrap();
    let result = runtime
        .pump_tun_to_transport_once(&mut transport, &mut buffer)
        .unwrap();
    let status = runtime.status();

    assert_eq!(result.dropped_packets, 1);
    assert_eq!(result.emitted_packets, 0);
    assert_eq!(transport.queued_frames(), 0);
    assert!(!status.transport_ready);
    assert_eq!(status.transport_path, Some(PathKind::Unavailable));
    assert!(!status.peer_session_ready);
}

#[test]
fn live_mesh_transport_inbound_transport_frame_emits_tunnel_packet() {
    let mut sender = runtime();
    let mut receiver = runtime();
    let packet = ipv4_packet([100, 64, 0, 9]);
    let mut transport = FakeMeshTransport::direct_ready();
    let mut buffer = [0_u8; 1280];

    sender.tun_mut().write_packet(&packet).unwrap();
    sender
        .pump_tun_to_transport_once(&mut transport, &mut buffer)
        .unwrap();

    let result = receiver.pump_transport_to_tun_once(&mut transport).unwrap();

    assert_eq!(result.accepted_packets, 1);
    assert_eq!(result.emitted_packets, 1);
    let len = receiver.tun_mut().read_packet(&mut buffer).unwrap();
    assert_eq!(len, packet.len());
    assert_eq!(&buffer[16..20], &packet[16..20]);
}
