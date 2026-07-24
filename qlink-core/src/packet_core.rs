use crate::{
    crypto::{validate_suite_name, SUITE_FIPS203},
    error::{QlinkError, Result},
    replay::ReplayWindow,
    routing::{RouteMode, RoutePolicy},
};
use serde::Deserialize;
use std::{
    collections::VecDeque,
    net::Ipv4Addr,
    time::{SystemTime, UNIX_EPOCH},
};

const FRAME_MAGIC: &[u8; 6] = b"QLPKT1";
const FRAME_HEADER_LEN: usize = 6 + 8 + 2 + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDisposition {
    QueuedForTransport,
    DroppedUnprotected,
    DroppedPeerSessionUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelPacket {
    pub protocol_family: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacketCoreMetrics {
    pub packets_from_tunnel: u64,
    pub packets_to_tunnel: u64,
    pub transport_frames_out: u64,
    pub transport_frames_in: u64,
    pub dropped_unprotected: u64,
    pub dropped_malformed: u64,
    pub dropped_peer_session_unavailable: u64,
    pub dropped_replay: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerSessionDirection {
    Outbound,
    Inbound,
}

#[derive(Clone, PartialEq, Eq)]
pub struct InstalledPeerSession {
    pub peer_id: String,
    pub direction: PeerSessionDirection,
    pub generation: u64,
    pub transcript_binding: [u8; 32],
    pub expires_at_unix: u64,
    pub rekey_after_bytes: u64,
}

impl std::fmt::Debug for InstalledPeerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstalledPeerSession")
            .field("peer_id", &self.peer_id)
            .field("direction", &self.direction)
            .field("generation", &self.generation)
            .field("transcript_binding", &"[redacted]")
            .field("expires_at_unix", &self.expires_at_unix)
            .field("rekey_after_bytes", &self.rekey_after_bytes)
            .finish()
    }
}

#[derive(Debug)]
pub struct PacketTunnelCore {
    policy: RoutePolicy,
    frame_codec: PacketFrameCodec,
    require_peer_session: bool,
    outbound_peer_session: Option<InstalledPeerSession>,
    inbound_peer_session: Option<InstalledPeerSession>,
    outbound_peer_session_bytes: u64,
    inbound_peer_session_bytes: u64,
    replay_window: ReplayWindow,
    next_packet_number: u64,
    transport_outbox: VecDeque<Vec<u8>>,
    tunnel_outbox: VecDeque<TunnelPacket>,
    metrics: PacketCoreMetrics,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketTunnelCoreConfig {
    pub protected_routes: Vec<String>,
    #[serde(default)]
    pub excluded_routes: Vec<String>,
    #[serde(default = "default_route_mode")]
    pub route_mode: FfiRouteMode,
    #[serde(default = "default_mtu")]
    pub mtu: usize,
    #[serde(default)]
    pub crypto: Option<FfiCryptoPolicy>,
    #[serde(default)]
    pub require_peer_session: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FfiCryptoPolicy {
    #[serde(default = "default_crypto_suite")]
    pub suite: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FfiRouteMode {
    SplitTunnel,
    ProtectedPrefixesOnly,
    FullTunnel,
}

impl Default for FfiRouteMode {
    fn default() -> Self {
        Self::SplitTunnel
    }
}

impl From<FfiRouteMode> for RouteMode {
    fn from(value: FfiRouteMode) -> Self {
        match value {
            FfiRouteMode::SplitTunnel => RouteMode::SplitTunnel,
            FfiRouteMode::ProtectedPrefixesOnly => RouteMode::ProtectedPrefixesOnly,
            FfiRouteMode::FullTunnel => RouteMode::FullTunnel,
        }
    }
}

impl PacketTunnelCore {
    pub fn new(config: PacketTunnelCoreConfig) -> Result<Self> {
        if config.mtu < 576 {
            return Err(QlinkError::Protocol(
                "MTU must be at least 576 bytes".into(),
            ));
        }

        let policy = RoutePolicy::new(
            config.route_mode.into(),
            &config.protected_routes,
            &config.excluded_routes,
        )?;
        let suite = config
            .crypto
            .as_ref()
            .map(|crypto| crypto.suite.as_str())
            .unwrap_or(SUITE_FIPS203);
        let frame_codec = PacketFrameCodec::new(suite)?;

        Ok(Self {
            policy,
            frame_codec,
            require_peer_session: config.require_peer_session,
            outbound_peer_session: None,
            inbound_peer_session: None,
            outbound_peer_session_bytes: 0,
            inbound_peer_session_bytes: 0,
            replay_window: ReplayWindow::new(),
            next_packet_number: 1,
            transport_outbox: VecDeque::new(),
            tunnel_outbox: VecDeque::new(),
            metrics: PacketCoreMetrics::default(),
        })
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let config = serde_json::from_slice(bytes)?;
        Self::new(config)
    }

    pub fn install_peer_session(&mut self, session: InstalledPeerSession) -> bool {
        let (slot, bytes) = match session.direction {
            PeerSessionDirection::Outbound => (
                &mut self.outbound_peer_session,
                &mut self.outbound_peer_session_bytes,
            ),
            PeerSessionDirection::Inbound => (
                &mut self.inbound_peer_session,
                &mut self.inbound_peer_session_bytes,
            ),
        };
        if let Some(current) = slot.as_ref() {
            if current == &session {
                return true;
            }
            if current.peer_id == session.peer_id && current.generation >= session.generation {
                return false;
            }
        }
        let reset_inbound_replay = session.direction == PeerSessionDirection::Inbound;
        *slot = Some(session);
        *bytes = 0;
        if reset_inbound_replay {
            self.replay_window = ReplayWindow::new();
        }
        true
    }

    pub fn clear_peer_sessions(&mut self) {
        self.outbound_peer_session = None;
        self.inbound_peer_session = None;
        self.outbound_peer_session_bytes = 0;
        self.inbound_peer_session_bytes = 0;
        self.replay_window = ReplayWindow::new();
    }

    pub fn clear_peer_session_direction(&mut self, direction: PeerSessionDirection) {
        match direction {
            PeerSessionDirection::Outbound => {
                self.outbound_peer_session = None;
                self.outbound_peer_session_bytes = 0;
            }
            PeerSessionDirection::Inbound => {
                self.inbound_peer_session = None;
                self.inbound_peer_session_bytes = 0;
                self.replay_window = ReplayWindow::new();
            }
        }
    }

    pub fn clear_peer_session(
        &mut self,
        peer_id: &str,
        direction: PeerSessionDirection,
        generation: u64,
    ) -> bool {
        let (slot, packets) = match direction {
            PeerSessionDirection::Outbound => (
                &mut self.outbound_peer_session,
                &mut self.outbound_peer_session_bytes,
            ),
            PeerSessionDirection::Inbound => (
                &mut self.inbound_peer_session,
                &mut self.inbound_peer_session_bytes,
            ),
        };
        let matches = slot
            .as_ref()
            .is_some_and(|session| session.peer_id == peer_id && session.generation == generation);
        if matches {
            *slot = None;
            *packets = 0;
            if direction == PeerSessionDirection::Inbound {
                self.replay_window = ReplayWindow::new();
            }
        }
        matches
    }

    pub fn peer_session_required(&self) -> bool {
        self.require_peer_session
    }

    pub fn peer_session_ready(&self) -> bool {
        self.peer_session_block_reason(PeerSessionDirection::Outbound)
            .is_none()
    }

    pub fn peer_session_error(&self) -> Option<String> {
        self.peer_session_block_reason(PeerSessionDirection::Outbound)
    }

    pub fn submit_tunnel_packet(
        &mut self,
        protocol_family: u32,
        packet: &[u8],
    ) -> Result<PacketDisposition> {
        self.metrics.packets_from_tunnel += 1;

        let Some(destination) = ipv4_destination(packet) else {
            self.metrics.dropped_malformed += 1;
            return Err(QlinkError::Protocol(
                "only IPv4 packets are accepted in this adapter".into(),
            ));
        };

        if !self.policy.protects(destination) {
            self.metrics.dropped_unprotected += 1;
            return Ok(PacketDisposition::DroppedUnprotected);
        }

        if self.require_peer_session {
            if self
                .peer_session_block_reason(PeerSessionDirection::Outbound)
                .is_some()
            {
                self.metrics.dropped_peer_session_unavailable += 1;
                return Ok(PacketDisposition::DroppedPeerSessionUnavailable);
            }
        }

        let mut normalized_packet = packet.to_vec();
        normalize_ipv4_packet(&mut normalized_packet)?;

        let frame = self.frame_codec.encode_transport_frame(
            self.next_packet_number,
            protocol_family,
            &normalized_packet,
        )?;
        self.next_packet_number += 1;
        if self.require_peer_session {
            self.outbound_peer_session_bytes = self
                .outbound_peer_session_bytes
                .saturating_add(frame.len() as u64);
        }
        self.metrics.transport_frames_out += 1;
        self.transport_outbox.push_back(frame);
        Ok(PacketDisposition::QueuedForTransport)
    }

    pub fn pop_transport_frame(&mut self) -> Option<Vec<u8>> {
        self.transport_outbox.pop_front()
    }

    pub fn accept_transport_frame(&mut self, frame: &[u8]) -> Result<()> {
        if self.require_peer_session {
            if let Some(reason) = self.peer_session_block_reason(PeerSessionDirection::Inbound) {
                self.metrics.dropped_peer_session_unavailable += 1;
                return Err(QlinkError::Protocol(reason));
            }
        }

        let (packet_number, protocol_family, packet) =
            match self.frame_codec.decode_transport_frame(frame) {
                Ok(decoded) => decoded,
                Err(error) => {
                    self.metrics.dropped_malformed += 1;
                    return Err(error);
                }
            };
        if !self.replay_window.observe(packet_number) {
            self.metrics.dropped_replay += 1;
            return Err(QlinkError::Protocol(
                "replayed transport frame rejected".into(),
            ));
        }
        self.metrics.transport_frames_in += 1;
        self.metrics.packets_to_tunnel += 1;
        if self.require_peer_session {
            self.inbound_peer_session_bytes = self
                .inbound_peer_session_bytes
                .saturating_add(frame.len() as u64);
        }
        self.tunnel_outbox.push_back(TunnelPacket {
            protocol_family,
            bytes: packet,
        });
        Ok(())
    }

    pub fn pop_tunnel_packet(&mut self) -> Option<TunnelPacket> {
        self.tunnel_outbox.pop_front()
    }

    pub fn metrics(&self) -> PacketCoreMetrics {
        self.metrics.clone()
    }

    fn peer_session_block_reason(&self, direction: PeerSessionDirection) -> Option<String> {
        if !self.require_peer_session {
            return None;
        }
        let (session, packets) = match direction {
            PeerSessionDirection::Outbound => (
                self.outbound_peer_session.as_ref(),
                self.outbound_peer_session_bytes,
            ),
            PeerSessionDirection::Inbound => (
                self.inbound_peer_session.as_ref(),
                self.inbound_peer_session_bytes,
            ),
        };
        let Some(session) = session else {
            return Some(format!(
                "authenticated {direction:?} peer session readiness is not installed"
            ));
        };
        let now = now_unix_seconds();
        if session.expires_at_unix <= now {
            return Some(format!("peer session for {} is expired", session.peer_id));
        }
        if session.rekey_after_bytes > 0 && packets >= session.rekey_after_bytes {
            return Some(format!(
                "peer session for {} requires rekey",
                session.peer_id
            ));
        }
        None
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn default_route_mode() -> FfiRouteMode {
    FfiRouteMode::SplitTunnel
}

fn default_mtu() -> usize {
    1280
}

fn default_crypto_suite() -> String {
    SUITE_FIPS203.to_string()
}

fn ipv4_destination(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

fn normalize_ipv4_packet(packet: &mut [u8]) -> Result<()> {
    if packet.len() < 20 {
        return Err(QlinkError::Protocol("IPv4 packet is too short".into()));
    }
    if packet[0] >> 4 != 4 {
        return Err(QlinkError::Protocol(
            "only IPv4 packets can be normalized".into(),
        ));
    }

    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if header_len < 20 || packet.len() < header_len {
        return Err(QlinkError::Protocol("invalid IPv4 header length".into()));
    }

    packet[1] = 0;
    let flags_and_fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if flags_and_fragment & 0x3fff == 0 {
        packet[4..6].copy_from_slice(&0_u16.to_be_bytes());
    }
    packet[8] = 64;
    packet[10..12].copy_from_slice(&0_u16.to_be_bytes());
    let checksum = ipv4_header_checksum(&packet[..header_len]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    Ok(())
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Debug, Clone)]
struct PacketFrameCodec;

impl PacketFrameCodec {
    fn new(suite: &str) -> Result<Self> {
        validate_suite_name(suite)?;
        Ok(Self)
    }

    fn encode_transport_frame(
        &self,
        packet_number: u64,
        protocol_family: u32,
        packet: &[u8],
    ) -> Result<Vec<u8>> {
        let family = u16::try_from(protocol_family)
            .map_err(|_| QlinkError::Protocol("protocol family does not fit in frame".into()))?;
        let packet_len = u32::try_from(packet.len())
            .map_err(|_| QlinkError::Protocol("packet is too large for frame".into()))?;

        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + packet.len());
        frame.extend_from_slice(FRAME_MAGIC);
        frame.extend_from_slice(&packet_number.to_be_bytes());
        frame.extend_from_slice(&family.to_be_bytes());
        frame.extend_from_slice(&packet_len.to_be_bytes());
        frame.extend_from_slice(packet);
        Ok(frame)
    }

    fn decode_transport_frame(&self, frame: &[u8]) -> Result<(u64, u32, Vec<u8>)> {
        if frame.len() < FRAME_HEADER_LEN {
            return Err(QlinkError::Protocol("transport frame too short".into()));
        }
        if &frame[..6] != FRAME_MAGIC {
            return Err(QlinkError::Protocol("invalid transport frame magic".into()));
        }

        let mut packet_number = [0_u8; 8];
        packet_number.copy_from_slice(&frame[6..14]);
        let packet_number = u64::from_be_bytes(packet_number);

        let mut family = [0_u8; 2];
        family.copy_from_slice(&frame[14..16]);

        let mut len = [0_u8; 4];
        len.copy_from_slice(&frame[16..20]);
        let packet_len = u32::from_be_bytes(len) as usize;

        let packet_start = FRAME_HEADER_LEN;
        let packet_end = packet_start + packet_len;
        if frame.len() != packet_end {
            return Err(QlinkError::Protocol(
                "transport frame length mismatch".into(),
            ));
        }

        Ok((
            packet_number,
            u16::from_be_bytes(family) as u32,
            frame[packet_start..packet_end].to_vec(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SUITE_FIPS203, SUITE_FIPS204, SUITE_FIPS205};

    #[test]
    fn protected_ipv4_packet_becomes_transport_frame() {
        let mut core = test_core(SUITE_FIPS203);

        let packet = test_ipv4_packet([100, 127, 0, 10]);
        assert_eq!(
            core.submit_tunnel_packet(2, &packet).unwrap(),
            PacketDisposition::QueuedForTransport
        );

        let frame = core.pop_transport_frame().unwrap();
        let mut expected_packet = packet.clone();
        normalize_ipv4_packet(&mut expected_packet).unwrap();
        assert!(
            contains_subslice(&frame, &expected_packet),
            "packet core must not apply a classical inner packet cipher; PQC mesh frame protection owns transport secrecy"
        );

        core.accept_transport_frame(&frame).unwrap();
        let restored = core.pop_tunnel_packet().unwrap();

        assert_eq!(restored.protocol_family, 2);
        assert_eq!(restored.bytes[16..20], packet[16..20]);
        assert_eq!(ipv4_header_checksum(&restored.bytes), 0);
        assert_eq!(core.metrics().transport_frames_out, 1);
        assert_eq!(core.metrics().transport_frames_in, 1);
    }

    #[test]
    fn unprotected_ipv4_packet_is_not_queued() {
        let mut core = test_core(SUITE_FIPS203);

        let packet = test_ipv4_packet([8, 8, 8, 8]);
        assert_eq!(
            core.submit_tunnel_packet(2, &packet).unwrap(),
            PacketDisposition::DroppedUnprotected
        );
        assert!(core.pop_transport_frame().is_none());
        assert_eq!(core.metrics().dropped_unprotected, 1);
    }

    #[test]
    fn malformed_transport_frame_is_rejected() {
        let mut core = test_core(SUITE_FIPS204);
        let packet = test_ipv4_packet([100, 127, 0, 10]);
        core.submit_tunnel_packet(2, &packet).unwrap();

        let mut frame = core.pop_transport_frame().unwrap();
        frame.pop();

        assert!(core.accept_transport_frame(&frame).is_err());
        assert!(core.pop_tunnel_packet().is_none());
    }

    #[test]
    fn malformed_transport_frames_are_rejected_without_queueing_packets() {
        let packet = test_ipv4_packet([100, 127, 0, 10]);
        let mut sender = test_core(SUITE_FIPS203);
        sender.submit_tunnel_packet(2, &packet).unwrap();
        let valid = sender.pop_transport_frame().unwrap();

        let mut bad_magic = valid.clone();
        bad_magic[0] ^= 0xff;

        let mut trailing_byte = valid.clone();
        trailing_byte.push(0);

        let mut truncated_packet = valid.clone();
        truncated_packet.pop();

        let mut length_too_large = valid.clone();
        length_too_large[FRAME_HEADER_LEN - 4..FRAME_HEADER_LEN]
            .copy_from_slice(&u32::MAX.to_be_bytes());

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            (
                "short header",
                valid[..FRAME_HEADER_LEN.saturating_sub(1)].to_vec(),
            ),
            ("bad magic", bad_magic),
            ("trailing byte", trailing_byte),
            ("truncated packet", truncated_packet),
            ("length too large", length_too_large),
        ];

        for (name, frame) in cases {
            let mut receiver = test_core(SUITE_FIPS203);
            assert!(
                receiver.accept_transport_frame(&frame).is_err(),
                "{name} frame should be rejected"
            );
            assert!(
                receiver.pop_tunnel_packet().is_none(),
                "{name} frame must not queue a packet"
            );
            assert_eq!(
                receiver.metrics().transport_frames_in,
                0,
                "{name} frame must not count as accepted"
            );
            assert_eq!(
                receiver.metrics().dropped_malformed,
                1,
                "{name} frame should increment malformed drops"
            );
        }
    }

    #[test]
    fn selected_pqc_suite_does_not_change_packet_frame_codec() {
        let packet = test_ipv4_packet([100, 127, 0, 10]);
        let mut fips203 = test_core(SUITE_FIPS203);
        let mut fips205 = test_core(SUITE_FIPS205);

        fips203.submit_tunnel_packet(2, &packet).unwrap();
        fips205.submit_tunnel_packet(2, &packet).unwrap();

        let fips203_frame = fips203.pop_transport_frame().unwrap();
        let fips205_frame = fips205.pop_transport_frame().unwrap();
        let mut expected_packet = packet.clone();
        normalize_ipv4_packet(&mut expected_packet).unwrap();

        assert_eq!(fips203_frame, fips205_frame);
        assert!(contains_subslice(&fips203_frame, &expected_packet));
        fips203.accept_transport_frame(&fips205_frame).unwrap();
    }

    #[test]
    fn packet_metadata_is_normalized_before_transport_framing() {
        let mut core = test_core(SUITE_FIPS203);
        let mut packet = test_ipv4_packet([100, 127, 0, 10]);
        packet[1] = 0xff;
        packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
        packet[8] = 255;
        packet[10..12].copy_from_slice(&0_u16.to_be_bytes());

        core.submit_tunnel_packet(2, &packet).unwrap();
        let frame = core.pop_transport_frame().unwrap();
        core.accept_transport_frame(&frame).unwrap();
        let restored = core.pop_tunnel_packet().unwrap().bytes;

        assert_eq!(restored[1], 0);
        assert_eq!(&restored[4..6], &0_u16.to_be_bytes());
        assert_eq!(restored[8], 64);
        assert_eq!(ipv4_header_checksum(&restored), 0);
    }

    #[test]
    fn unsupported_crypto_suite_is_rejected() {
        let config = PacketTunnelCoreConfig {
            protected_routes: vec!["100.127.0.0/16".to_string()],
            excluded_routes: vec![],
            route_mode: FfiRouteMode::SplitTunnel,
            mtu: 1280,
            crypto: Some(FfiCryptoPolicy {
                suite: "QLINK-UNKNOWN-v1".to_string(),
            }),
            require_peer_session: false,
        };

        assert!(PacketTunnelCore::new(config).is_err());
    }

    #[test]
    fn protected_packet_drops_when_peer_session_is_required_but_missing() {
        let mut core = test_core_requiring_peer_session();
        let packet = test_ipv4_packet([100, 127, 0, 10]);

        assert_eq!(
            core.submit_tunnel_packet(2, &packet).unwrap(),
            PacketDisposition::DroppedPeerSessionUnavailable
        );

        assert!(core.pop_transport_frame().is_none());
        assert!(!core.peer_session_ready());
        assert!(core
            .peer_session_error()
            .unwrap()
            .contains("Outbound peer session readiness is not installed"));
        assert_eq!(core.metrics().dropped_peer_session_unavailable, 1);
    }

    #[test]
    fn installed_peer_session_allows_packet_until_rekey_boundary() {
        let mut core = test_core_requiring_peer_session();
        core.install_peer_session(InstalledPeerSession {
            peer_id: "peer-a".to_string(),
            direction: PeerSessionDirection::Outbound,
            generation: 1,
            transcript_binding: [7; 32],
            expires_at_unix: now_unix_seconds() + 60,
            rekey_after_bytes: 1,
        });
        let packet = test_ipv4_packet([100, 127, 0, 10]);

        assert_eq!(
            core.submit_tunnel_packet(2, &packet).unwrap(),
            PacketDisposition::QueuedForTransport
        );
        assert!(core.pop_transport_frame().is_some());
        assert_eq!(
            core.submit_tunnel_packet(2, &packet).unwrap(),
            PacketDisposition::DroppedPeerSessionUnavailable
        );

        assert!(core
            .peer_session_error()
            .unwrap()
            .contains("requires rekey"));
        assert_eq!(core.metrics().transport_frames_out, 1);
        assert_eq!(core.metrics().dropped_peer_session_unavailable, 1);
    }

    #[test]
    fn inbound_transport_frame_drops_when_peer_session_required_but_missing() {
        let packet = test_ipv4_packet([100, 127, 0, 10]);
        let mut sender = test_core(SUITE_FIPS203);
        sender.submit_tunnel_packet(2, &packet).unwrap();
        let frame = sender.pop_transport_frame().unwrap();
        let mut receiver = test_core_requiring_peer_session();

        let error = receiver.accept_transport_frame(&frame).unwrap_err();

        assert!(error
            .to_string()
            .contains("Inbound peer session readiness is not installed"));
        assert!(receiver.pop_tunnel_packet().is_none());
        assert_eq!(receiver.metrics().transport_frames_in, 0);
        assert_eq!(receiver.metrics().packets_to_tunnel, 0);
        assert_eq!(receiver.metrics().dropped_peer_session_unavailable, 1);
    }

    #[test]
    fn inbound_lease_rotation_does_not_reset_outbound_rekey_budget() {
        let mut core = test_core_requiring_peer_session();
        let now = now_unix_seconds();
        assert!(core.install_peer_session(InstalledPeerSession {
            peer_id: "peer-a".to_string(),
            direction: PeerSessionDirection::Outbound,
            generation: 1,
            transcript_binding: [1; 32],
            expires_at_unix: now + 60,
            rekey_after_bytes: 1,
        }));
        let packet = test_ipv4_packet([100, 127, 0, 10]);
        assert_eq!(
            core.submit_tunnel_packet(2, &packet).unwrap(),
            PacketDisposition::QueuedForTransport
        );

        assert!(core.install_peer_session(InstalledPeerSession {
            peer_id: "peer-a".to_string(),
            direction: PeerSessionDirection::Inbound,
            generation: 2,
            transcript_binding: [2; 32],
            expires_at_unix: now + 60,
            rekey_after_bytes: 10,
        }));
        assert_eq!(
            core.submit_tunnel_packet(2, &packet).unwrap(),
            PacketDisposition::DroppedPeerSessionUnavailable
        );
    }

    #[test]
    fn stale_directional_clear_cannot_remove_newer_lease() {
        let mut core = test_core_requiring_peer_session();
        let session = InstalledPeerSession {
            peer_id: "peer-a".to_string(),
            direction: PeerSessionDirection::Outbound,
            generation: 2,
            transcript_binding: [3; 32],
            expires_at_unix: now_unix_seconds() + 60,
            rekey_after_bytes: 10,
        };
        assert!(core.install_peer_session(session));
        assert!(!core.clear_peer_session("peer-a", PeerSessionDirection::Outbound, 1));

        let packet = test_ipv4_packet([100, 127, 0, 10]);
        assert_eq!(
            core.submit_tunnel_packet(2, &packet).unwrap(),
            PacketDisposition::QueuedForTransport
        );
    }

    #[test]
    fn replayed_transport_frame_is_rejected() {
        let packet = test_ipv4_packet([100, 127, 0, 10]);
        let mut sender = test_core(SUITE_FIPS203);
        sender.submit_tunnel_packet(2, &packet).unwrap();
        let frame = sender.pop_transport_frame().unwrap();
        let mut receiver = test_core(SUITE_FIPS203);

        receiver.accept_transport_frame(&frame).unwrap();
        let error = receiver.accept_transport_frame(&frame).unwrap_err();

        assert!(error.to_string().contains("replayed transport frame"));
        assert_eq!(receiver.metrics().transport_frames_in, 1);
        assert_eq!(receiver.metrics().dropped_replay, 1);
    }

    #[test]
    fn authenticated_inbound_rotation_resets_replay_scope() {
        let packet = test_ipv4_packet([100, 127, 0, 10]);
        let mut sender = test_core(SUITE_FIPS203);
        sender.submit_tunnel_packet(2, &packet).unwrap();
        let frame = sender.pop_transport_frame().unwrap();
        let mut receiver = test_core_requiring_peer_session();
        let now = now_unix_seconds();

        for generation in [1, 2] {
            assert!(receiver.install_peer_session(InstalledPeerSession {
                peer_id: "peer-a".to_string(),
                direction: PeerSessionDirection::Inbound,
                generation,
                transcript_binding: [generation as u8; 32],
                expires_at_unix: now + 60,
                rekey_after_bytes: 1_024,
            }));
            receiver.accept_transport_frame(&frame).unwrap();
            assert!(receiver.pop_tunnel_packet().is_some());
        }
    }

    fn test_core(suite: &str) -> PacketTunnelCore {
        PacketTunnelCore::new(PacketTunnelCoreConfig {
            protected_routes: vec!["100.127.0.0/16".to_string()],
            excluded_routes: vec![],
            route_mode: FfiRouteMode::SplitTunnel,
            mtu: 1280,
            crypto: Some(FfiCryptoPolicy {
                suite: suite.to_string(),
            }),
            require_peer_session: false,
        })
        .unwrap()
    }

    fn test_core_requiring_peer_session() -> PacketTunnelCore {
        PacketTunnelCore::new(PacketTunnelCoreConfig {
            protected_routes: vec!["100.127.0.0/16".to_string()],
            excluded_routes: vec![],
            route_mode: FfiRouteMode::SplitTunnel,
            mtu: 1280,
            crypto: Some(FfiCryptoPolicy {
                suite: SUITE_FIPS203.to_string(),
            }),
            require_peer_session: true,
        })
        .unwrap()
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn ipv4_header_checksum(packet: &[u8]) -> u16 {
        let header_len = ((packet[0] & 0x0f) as usize) * 4;
        let mut sum = 0_u32;
        for chunk in packet[..header_len].chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn test_ipv4_packet(destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[2] = 0;
        packet[3] = 20;
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[100, 127, 0, 2]);
        packet[16..20].copy_from_slice(&destination);
        packet
    }
}
