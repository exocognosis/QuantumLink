//! Outbound + inbound packet pump — Rust port of
//! `QuantumLinkKit/TunnelPacketPump.swift`, moved into the service so
//! macOS and Windows can converge on one shared tunnel-core contract.
//!
//! The pump is the **second** line of fail-closed defense against
//! protected-prefix traffic escaping the tunnel:
//!
//! 1. The OS forwards only protected-prefix packets into the Wintun
//!    adapter in the first place (routes programmed by `win::routes`,
//!    pinned by the WFP kill switch in `win::wfp`).
//! 2. Every packet observed by [`TunnelPacketPump::handle_packets`] is
//!    therefore presumed protected; the pump's only job is to refuse to
//!    forward it when the data plane is unhealthy (no core, or
//!    `TransportFrameSink::is_ready() == false`), rather than letting it
//!    fall through to the default interface.
//! 3. The Rust core (`packet_core::submit_tunnel_packet`) re-validates
//!    the destination against its own `protected_routes` policy.
//! 4. Encrypted transport frames are sent pop-then-send: a failed send
//!    loses the frame (counted in `failed_submissions`) — the bytes never
//!    fall back to plaintext routing. Worst case is a dropped packet,
//!    not a leaked one.

use qlink_core::packet_core::{
    PacketCoreMetrics, PacketDisposition, PacketTunnelCore, TunnelPacket,
};
use quantumlink_proto::models::PacketPumpMetrics;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PumpError {
    #[error("tunnel core is unavailable: {0}")]
    CoreUnavailable(String),
    #[error("core operation failed: {0}")]
    Core(#[from] qlink_core::QlinkError),
    #[error("transport send failed: {0}")]
    TransportSend(String),
}

/// Abstraction over the Rust packet core so tests can inject failures.
/// `PacketTunnelCore` implements this directly — no FFI hop on Windows.
pub trait TunnelCoreAdapting: Send {
    fn submit_tunnel_packet(
        &mut self,
        protocol_family: u32,
        packet: &[u8],
    ) -> Result<PacketDisposition, qlink_core::QlinkError>;
    fn pop_transport_frame(&mut self) -> Option<Vec<u8>>;
    fn accept_transport_frame(&mut self, frame: &[u8]) -> Result<(), qlink_core::QlinkError>;
    fn pop_tunnel_packet(&mut self) -> Option<TunnelPacket>;
    fn metrics(&self) -> PacketCoreMetrics;
}

impl TunnelCoreAdapting for PacketTunnelCore {
    fn submit_tunnel_packet(
        &mut self,
        protocol_family: u32,
        packet: &[u8],
    ) -> Result<PacketDisposition, qlink_core::QlinkError> {
        PacketTunnelCore::submit_tunnel_packet(self, protocol_family, packet)
    }

    fn pop_transport_frame(&mut self) -> Option<Vec<u8>> {
        PacketTunnelCore::pop_transport_frame(self)
    }

    fn accept_transport_frame(&mut self, frame: &[u8]) -> Result<(), qlink_core::QlinkError> {
        PacketTunnelCore::accept_transport_frame(self, frame)
    }

    fn pop_tunnel_packet(&mut self) -> Option<TunnelPacket> {
        PacketTunnelCore::pop_tunnel_packet(self)
    }

    fn metrics(&self) -> PacketCoreMetrics {
        PacketTunnelCore::metrics(self)
    }
}

/// Port of Swift `TransportFrameSink`.
pub trait TransportFrameSink {
    fn is_ready(&self) -> bool {
        true
    }
    fn send_transport_frame(&self, frame: Vec<u8>) -> Result<(), PumpError>;
}

/// Per-batch result, port of Swift `PacketPumpBatchResult`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PacketPumpBatchResult {
    pub packets_observed: usize,
    pub queued_for_transport: usize,
    pub dropped_unprotected: usize,
    pub dropped_fail_closed: usize,
    pub dropped_kill_switch: usize,
    pub failed_submissions: usize,
    pub transport_frames_emitted: usize,
}

/// Cumulative counters, port of Swift `PacketPumpCounters`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacketPumpCounters {
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
    /// Inbound frames accepted from each verified mesh peer. Frames
    /// without an attributed peer (loopback smoke, dev transports) are
    /// not counted here.
    pub transport_frames_accepted_per_peer: HashMap<String, u64>,
}

impl PacketPumpCounters {
    pub fn as_proto(&self) -> PacketPumpMetrics {
        PacketPumpMetrics {
            packets_observed: self.packets_observed,
            queued_for_transport: self.queued_for_transport,
            dropped_unprotected: self.dropped_unprotected,
            dropped_fail_closed: self.dropped_fail_closed,
            dropped_kill_switch: self.dropped_kill_switch,
            failed_submissions: self.failed_submissions,
            transport_frames_emitted: self.transport_frames_emitted,
            transport_frames_accepted: self.transport_frames_accepted,
            failed_inbound_frames: self.failed_inbound_frames,
            tunnel_packets_emitted: self.tunnel_packets_emitted,
        }
    }
}

pub struct TunnelPacketPump<C: TunnelCoreAdapting> {
    core: Option<C>,
    counters: PacketPumpCounters,
}

impl<C: TunnelCoreAdapting> TunnelPacketPump<C> {
    pub fn new(core: Option<C>) -> Self {
        Self {
            core,
            counters: PacketPumpCounters::default(),
        }
    }

    pub fn counters(&self) -> &PacketPumpCounters {
        &self.counters
    }

    pub fn core_metrics(&self) -> Option<PacketCoreMetrics> {
        self.core.as_ref().map(|core| core.metrics())
    }

    /// Drives the outbound half: tunnel packets in, encrypted transport
    /// frames out through `sink`. Mirrors Swift `handlePackets` exactly,
    /// including the order of the fail-closed and kill-switch gates.
    pub fn handle_packets(
        &mut self,
        packets: &[(u32, &[u8])],
        sink: &dyn TransportFrameSink,
    ) -> PacketPumpBatchResult {
        self.counters.packets_observed += packets.len() as u64;

        let Some(core) = self.core.as_mut() else {
            self.counters.dropped_fail_closed += packets.len() as u64;
            return PacketPumpBatchResult {
                packets_observed: packets.len(),
                dropped_fail_closed: packets.len(),
                ..Default::default()
            };
        };

        // Kill-switch gate: when the transport is not ready, do not even
        // submit packets to the core. No plaintext crosses the encode
        // boundary while the data plane is unhealthy.
        if !sink.is_ready() {
            self.counters.dropped_kill_switch += packets.len() as u64;
            return PacketPumpBatchResult {
                packets_observed: packets.len(),
                dropped_kill_switch: packets.len(),
                ..Default::default()
            };
        }

        let mut result = PacketPumpBatchResult {
            packets_observed: packets.len(),
            ..Default::default()
        };

        for (family, packet) in packets {
            match core.submit_tunnel_packet(*family, packet) {
                Ok(PacketDisposition::QueuedForTransport) => {
                    result.queued_for_transport += 1;
                    self.counters.queued_for_transport += 1;
                    while let Some(frame) = core.pop_transport_frame() {
                        match sink.send_transport_frame(frame) {
                            Ok(()) => result.transport_frames_emitted += 1,
                            Err(_) => {
                                result.failed_submissions += 1;
                                self.counters.failed_submissions += 1;
                            }
                        }
                    }
                }
                Ok(PacketDisposition::DroppedUnprotected) => {
                    result.dropped_unprotected += 1;
                    self.counters.dropped_unprotected += 1;
                }
                Err(_) => {
                    result.failed_submissions += 1;
                    self.counters.failed_submissions += 1;
                }
            }
        }

        self.counters.transport_frames_emitted += result.transport_frames_emitted as u64;
        result
    }

    /// Inbound half: accepts an encrypted transport frame from a verified
    /// peer. Decrypted packets become available via [`Self::pop_tunnel_packet`].
    pub fn accept_transport_frame(
        &mut self,
        frame: &[u8],
        peer_id: Option<&str>,
    ) -> Result<(), PumpError> {
        let Some(core) = self.core.as_mut() else {
            self.counters.failed_inbound_frames += 1;
            return Err(PumpError::CoreUnavailable(
                "Rust core is unavailable for inbound transport frame".into(),
            ));
        };
        match core.accept_transport_frame(frame) {
            Ok(()) => {
                self.counters.transport_frames_accepted += 1;
                if let Some(peer_id) = peer_id.filter(|p| !p.is_empty()) {
                    *self
                        .counters
                        .transport_frames_accepted_per_peer
                        .entry(peer_id.to_string())
                        .or_insert(0) += 1;
                }
                Ok(())
            }
            Err(error) => {
                self.counters.failed_inbound_frames += 1;
                Err(error.into())
            }
        }
    }

    pub fn pop_tunnel_packet(&mut self) -> Option<TunnelPacket> {
        let packet = self.core.as_mut()?.pop_tunnel_packet();
        if packet.is_some() {
            self.counters.tunnel_packets_emitted += 1;
        }
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct ClosureSink {
        ready: bool,
        sent: RefCell<Vec<Vec<u8>>>,
        fail_sends: bool,
    }

    impl ClosureSink {
        fn new(ready: bool) -> Self {
            Self {
                ready,
                sent: RefCell::new(Vec::new()),
                fail_sends: false,
            }
        }
    }

    impl TransportFrameSink for ClosureSink {
        fn is_ready(&self) -> bool {
            self.ready
        }
        fn send_transport_frame(&self, frame: Vec<u8>) -> Result<(), PumpError> {
            if self.fail_sends {
                return Err(PumpError::TransportSend("test sink failure".into()));
            }
            self.sent.borrow_mut().push(frame);
            Ok(())
        }
    }

    fn test_core() -> PacketTunnelCore {
        PacketTunnelCore::from_json(
            br#"{
                "protectedRoutes": ["100.127.0.0/16"],
                "excludedRoutes": [],
                "routeMode": "splitTunnel",
                "mtu": 1280
            }"#,
        )
        .expect("test core config")
    }

    fn ipv4_packet(destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[100, 127, 0, 2]);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    #[test]
    fn protected_packet_round_trips_through_pump() {
        let mut pump = TunnelPacketPump::new(Some(test_core()));
        let sink = ClosureSink::new(true);
        let packet = ipv4_packet([100, 127, 0, 9]);

        let result = pump.handle_packets(&[(2, &packet)], &sink);
        assert_eq!(result.queued_for_transport, 1);
        assert_eq!(result.transport_frames_emitted, 1);

        let frame = sink.sent.borrow()[0].clone();
        pump.accept_transport_frame(&frame, Some("qlink_peer"))
            .unwrap();
        let restored = pump.pop_tunnel_packet().expect("decrypted packet");
        assert_eq!(restored.protocol_family, 2);
        assert_eq!(&restored.bytes[16..20], &packet[16..20]);
        assert_eq!(
            pump.counters().transport_frames_accepted_per_peer["qlink_peer"],
            1
        );
    }

    #[test]
    fn missing_core_drops_fail_closed() {
        let mut pump: TunnelPacketPump<PacketTunnelCore> = TunnelPacketPump::new(None);
        let sink = ClosureSink::new(true);
        let packet = ipv4_packet([100, 127, 0, 9]);

        let result = pump.handle_packets(&[(2, &packet)], &sink);
        assert_eq!(result.dropped_fail_closed, 1);
        assert_eq!(result.queued_for_transport, 0);
        assert!(pump.accept_transport_frame(b"frame", None).is_err());
    }

    #[test]
    fn unready_sink_engages_kill_switch_before_encode() {
        let mut pump = TunnelPacketPump::new(Some(test_core()));
        let sink = ClosureSink::new(false);
        let packet = ipv4_packet([100, 127, 0, 9]);

        let result = pump.handle_packets(&[(2, &packet)], &sink);
        assert_eq!(result.dropped_kill_switch, 1);
        assert_eq!(result.queued_for_transport, 0);
        assert!(sink.sent.borrow().is_empty());
        // Nothing reached the core at all.
        assert_eq!(pump.core_metrics().unwrap().packets_from_tunnel, 0);
    }

    #[test]
    fn unprotected_destination_is_dropped_by_core_policy() {
        let mut pump = TunnelPacketPump::new(Some(test_core()));
        let sink = ClosureSink::new(true);
        let packet = ipv4_packet([8, 8, 8, 8]);

        let result = pump.handle_packets(&[(2, &packet)], &sink);
        assert_eq!(result.dropped_unprotected, 1);
        assert!(sink.sent.borrow().is_empty());
    }

    #[test]
    fn failed_sends_lose_frames_not_plaintext() {
        let mut pump = TunnelPacketPump::new(Some(test_core()));
        let mut sink = ClosureSink::new(true);
        sink.fail_sends = true;
        let packet = ipv4_packet([100, 127, 0, 9]);

        let result = pump.handle_packets(&[(2, &packet)], &sink);
        assert_eq!(result.queued_for_transport, 1);
        assert_eq!(result.transport_frames_emitted, 0);
        assert_eq!(result.failed_submissions, 1);
        assert!(sink.sent.borrow().is_empty());
    }
}
