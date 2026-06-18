use crate::{
    crypto::{validate_suite_name, SUITE_FIPS203},
    error::{QlinkError, Result},
    routing::{RouteMode, RoutePolicy},
};
use serde::Deserialize;
use std::{collections::VecDeque, net::Ipv4Addr};

const FRAME_MAGIC: &[u8; 6] = b"QLPKT1";
const FRAME_HEADER_LEN: usize = 6 + 8 + 2 + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDisposition {
    QueuedForTransport,
    DroppedUnprotected,
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
}

#[derive(Debug)]
pub struct PacketTunnelCore {
    policy: RoutePolicy,
    frame_codec: PacketFrameCodec,
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

        let mut normalized_packet = packet.to_vec();
        normalize_ipv4_packet(&mut normalized_packet)?;

        let frame = self.frame_codec.encode_transport_frame(
            self.next_packet_number,
            protocol_family,
            &normalized_packet,
        )?;
        self.next_packet_number += 1;
        self.metrics.transport_frames_out += 1;
        self.transport_outbox.push_back(frame);
        Ok(PacketDisposition::QueuedForTransport)
    }

    pub fn pop_transport_frame(&mut self) -> Option<Vec<u8>> {
        self.transport_outbox.pop_front()
    }

    pub fn accept_transport_frame(&mut self, frame: &[u8]) -> Result<()> {
        let (_packet_number, protocol_family, packet) =
            match self.frame_codec.decode_transport_frame(frame) {
                Ok(decoded) => decoded,
                Err(error) => {
                    self.metrics.dropped_malformed += 1;
                    return Err(error);
                }
            };
        self.metrics.transport_frames_in += 1;
        self.metrics.packets_to_tunnel += 1;
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
        };

        assert!(PacketTunnelCore::new(config).is_err());
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
