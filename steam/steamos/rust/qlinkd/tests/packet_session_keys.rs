use std::collections::VecDeque;

use qlink_core::packet_core::{FfiRouteMode, InstalledPeerSession, PeerSessionDirection};
use qlink_linux::{LoopbackTunDevice, TunDeviceConfig, TunPacketIo};
use qlink_proto::PathKind;
use qlinkd::data_plane::{
    packet_core_from_parts, DataPlaneError, DataPlaneRuntime, InboundTransportFrame,
    MeshFrameTransport,
};

#[derive(Debug)]
struct SessionAwareTransport {
    ready: bool,
    peer_session_ready: bool,
    last_error: Option<String>,
    frames: VecDeque<Vec<u8>>,
}

impl SessionAwareTransport {
    fn ready_without_peer_session() -> Self {
        Self {
            ready: true,
            peer_session_ready: false,
            last_error: Some("authenticated peer session keys are not installed".to_string()),
            frames: VecDeque::new(),
        }
    }

    fn ready_with_peer_session() -> Self {
        Self {
            ready: true,
            peer_session_ready: true,
            last_error: None,
            frames: VecDeque::new(),
        }
    }

    fn stale_peer_session() -> Self {
        Self {
            ready: true,
            peer_session_ready: false,
            last_error: Some("peer session is expired or revoked".to_string()),
            frames: VecDeque::new(),
        }
    }

    fn queued_frames(&self) -> usize {
        self.frames.len()
    }
}

impl MeshFrameTransport for SessionAwareTransport {
    fn is_ready(&self) -> bool {
        self.ready
    }

    fn path_kind(&self) -> PathKind {
        if self.ready {
            PathKind::Direct
        } else {
            PathKind::Unavailable
        }
    }

    fn peer_session_ready(&self) -> bool {
        self.peer_session_ready
    }

    fn installed_peer_session(&self) -> Option<InstalledPeerSession> {
        self.peer_session_ready.then(|| InstalledPeerSession {
            peer_id: "session-aware-peer".to_string(),
            direction: PeerSessionDirection::Outbound,
            generation: 1,
            transcript_binding: [0; 32],
            expires_at_unix: u64::MAX,
            rekey_after_bytes: 0,
        })
    }

    fn send_frame(&mut self, frame: Vec<u8>) -> Result<(), DataPlaneError> {
        if !self.ready || !self.peer_session_ready {
            return Err(DataPlaneError::Transport(
                self.last_error
                    .clone()
                    .unwrap_or_else(|| "peer session unavailable".to_string()),
            ));
        }
        self.frames.push_back(frame);
        Ok(())
    }

    fn try_receive_frame(&mut self) -> Option<InboundTransportFrame> {
        self.frames.pop_front().map(|frame| InboundTransportFrame {
            frame,
            peer_session: InstalledPeerSession {
                peer_id: "session-aware-peer".to_string(),
                direction: PeerSessionDirection::Inbound,
                generation: 1,
                transcript_binding: [0; 32],
                expires_at_unix: u64::MAX,
                rekey_after_bytes: 0,
            },
        })
    }

    fn last_transport_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }
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
    let mut packet = vec![0_u8; 28];
    packet[0] = 0x45;
    packet[3] = 28;
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[100, 64, 0, 2]);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&42000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&34197_u16.to_be_bytes());
    packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
    packet
}

#[test]
fn packet_session_keys_protected_packet_fails_closed_without_peer_session_keys() {
    let mut runtime = runtime();
    let packet = ipv4_packet([100, 64, 0, 9]);
    let mut transport = SessionAwareTransport::ready_without_peer_session();
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
    assert!(!status.peer_session_ready);
    assert!(status
        .last_transport_error
        .as_deref()
        .unwrap()
        .contains("peer session keys"));
}

#[test]
fn packet_session_keys_protected_packet_uses_installed_peer_session_keys() {
    let mut runtime = runtime();
    let packet = ipv4_packet([100, 64, 0, 9]);
    let mut transport = SessionAwareTransport::ready_with_peer_session();
    let mut buffer = [0_u8; 1280];

    runtime.tun_mut().write_packet(&packet).unwrap();
    let result = runtime
        .pump_tun_to_transport_once(&mut transport, &mut buffer)
        .unwrap();

    assert_eq!(result.queued_packets, 1);
    assert_eq!(result.emitted_packets, 1);
    assert_eq!(transport.queued_frames(), 1);
    assert!(runtime.status().transport_ready);
    assert!(runtime.status().peer_session_ready);
}

#[test]
fn packet_session_keys_stale_peer_session_is_rejected_before_frame_emission() {
    let mut runtime = runtime();
    let packet = ipv4_packet([100, 64, 0, 9]);
    let mut transport = SessionAwareTransport::stale_peer_session();
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
    assert!(status
        .last_transport_error
        .as_deref()
        .unwrap()
        .contains("expired or revoked"));
}
