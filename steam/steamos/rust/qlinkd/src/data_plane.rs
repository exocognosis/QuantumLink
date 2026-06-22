use qlink_core::packet_core::{FfiCryptoPolicy, FfiRouteMode};
use qlink_core::packet_core::{
    PacketDisposition, PacketTunnelCore, PacketTunnelCoreConfig, TunnelPacket,
};
use qlink_linux::{protocol_family_for_packet, TunDeviceConfig, TunPacketIo, TunPacketIoError};
use qlink_proto::{DataPlaneState, DataPlaneStatus, PacketPumpMetrics};
use std::{collections::VecDeque, error::Error, fmt, io::ErrorKind};

#[derive(Debug)]
pub enum DataPlaneError {
    Core(String),
    Tun(String),
    Transport(String),
    NetworkNotApplied(String),
}

impl DataPlaneError {
    pub fn message(&self) -> &str {
        match self {
            Self::Core(message)
            | Self::Tun(message)
            | Self::Transport(message)
            | Self::NetworkNotApplied(message) => message,
        }
    }
}

impl fmt::Display for DataPlaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl Error for DataPlaneError {}

impl From<qlink_core::QlinkError> for DataPlaneError {
    fn from(error: qlink_core::QlinkError) -> Self {
        Self::Core(error.to_string())
    }
}

impl From<TunPacketIoError> for DataPlaneError {
    fn from(error: TunPacketIoError) -> Self {
        Self::Tun(error.to_string())
    }
}

pub trait TunnelCoreAdapting {
    fn submit_tunnel_packet(
        &mut self,
        protocol_family: u32,
        packet: &[u8],
    ) -> Result<PacketDisposition, qlink_core::QlinkError>;
    fn pop_transport_frame(&mut self) -> Option<Vec<u8>>;
    fn accept_transport_frame(&mut self, frame: &[u8]) -> Result<(), qlink_core::QlinkError>;
    fn pop_tunnel_packet(&mut self) -> Option<TunnelPacket>;
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
}

pub trait TransportFrameSink {
    fn is_ready(&self) -> bool;
    fn send_transport_frame(&mut self, frame: Vec<u8>) -> Result<(), DataPlaneError>;
}

pub trait TransportFrameSource {
    fn is_ready(&self) -> bool;
    fn try_receive_frame(&mut self) -> Option<Vec<u8>>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PacketPumpBatchResult {
    pub observed_packets: u64,
    pub queued_packets: u64,
    pub dropped_packets: u64,
    pub emitted_packets: u64,
    pub accepted_packets: u64,
    pub rejected_packets: u64,
    pub transport_errors: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacketPumpCounters {
    pub observed_packets: u64,
    pub queued_packets: u64,
    pub dropped_packets: u64,
    pub emitted_packets: u64,
    pub accepted_packets: u64,
    pub rejected_packets: u64,
    pub transport_errors: u64,
}

impl PacketPumpCounters {
    pub fn as_proto(&self) -> PacketPumpMetrics {
        PacketPumpMetrics {
            observed_packets: self.observed_packets,
            queued_packets: self.queued_packets,
            dropped_packets: self.dropped_packets,
            emitted_packets: self.emitted_packets,
            accepted_packets: self.accepted_packets,
            rejected_packets: self.rejected_packets,
            transport_errors: self.transport_errors,
        }
    }

    fn add_batch(&mut self, batch: PacketPumpBatchResult) {
        self.observed_packets += batch.observed_packets;
        self.queued_packets += batch.queued_packets;
        self.dropped_packets += batch.dropped_packets;
        self.emitted_packets += batch.emitted_packets;
        self.accepted_packets += batch.accepted_packets;
        self.rejected_packets += batch.rejected_packets;
        self.transport_errors += batch.transport_errors;
    }
}

#[derive(Debug)]
pub struct TunnelPacketPump<C: TunnelCoreAdapting> {
    core: Option<C>,
    counters: PacketPumpCounters,
}

impl<C: TunnelCoreAdapting> TunnelPacketPump<C> {
    pub fn new(core: C) -> Self {
        Self {
            core: Some(core),
            counters: PacketPumpCounters::default(),
        }
    }

    pub fn counters(&self) -> &PacketPumpCounters {
        &self.counters
    }

    pub fn handle_packet(
        &mut self,
        packet: &[u8],
        sink: &mut dyn TransportFrameSink,
    ) -> PacketPumpBatchResult {
        let mut result = PacketPumpBatchResult {
            observed_packets: 1,
            ..Default::default()
        };

        let Some(core) = self.core.as_mut() else {
            result.dropped_packets = 1;
            self.counters.add_batch(result);
            return result;
        };

        if !sink.is_ready() {
            result.dropped_packets = 1;
            self.counters.add_batch(result);
            return result;
        }

        let Some(protocol_family) = protocol_family_for_packet(packet) else {
            result.rejected_packets = 1;
            self.counters.add_batch(result);
            return result;
        };

        match core.submit_tunnel_packet(protocol_family, packet) {
            Ok(PacketDisposition::QueuedForTransport) => {
                result.queued_packets = 1;
                while let Some(frame) = core.pop_transport_frame() {
                    match sink.send_transport_frame(frame) {
                        Ok(()) => result.emitted_packets += 1,
                        Err(_) => result.transport_errors += 1,
                    }
                }
            }
            Ok(PacketDisposition::DroppedUnprotected) => result.dropped_packets = 1,
            Err(_) => result.rejected_packets = 1,
        }

        self.counters.add_batch(result);
        result
    }

    pub fn accept_transport_frame(
        &mut self,
        frame: &[u8],
    ) -> Result<PacketPumpBatchResult, DataPlaneError> {
        let mut result = PacketPumpBatchResult::default();
        let Some(core) = self.core.as_mut() else {
            result.rejected_packets = 1;
            self.counters.add_batch(result);
            return Err(DataPlaneError::Core(
                "packet core is unavailable for inbound frame".to_string(),
            ));
        };

        match core.accept_transport_frame(frame) {
            Ok(()) => {
                result.accepted_packets = 1;
                self.counters.add_batch(result);
                Ok(result)
            }
            Err(error) => {
                result.rejected_packets = 1;
                self.counters.add_batch(result);
                Err(error.into())
            }
        }
    }

    pub fn pop_tunnel_packet(&mut self) -> Option<TunnelPacket> {
        self.core.as_mut()?.pop_tunnel_packet()
    }

    fn record_tunnel_packet_emitted(&mut self) {
        self.counters.emitted_packets += 1;
    }

    fn record_transport_error(&mut self) {
        self.counters.transport_errors += 1;
    }
}

pub struct BoxedTunDevice {
    inner: Box<dyn TunPacketIo + Send>,
}

impl BoxedTunDevice {
    pub fn new<T>(inner: T) -> Self
    where
        T: TunPacketIo + Send + 'static,
    {
        Self {
            inner: Box::new(inner),
        }
    }
}

impl fmt::Debug for BoxedTunDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoxedTunDevice")
            .field("config", self.config())
            .finish_non_exhaustive()
    }
}

impl TunPacketIo for BoxedTunDevice {
    fn config(&self) -> &TunDeviceConfig {
        self.inner.config()
    }

    fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, TunPacketIoError> {
        self.inner.read_packet(buffer)
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunPacketIoError> {
        self.inner.write_packet(packet)
    }
}

#[derive(Debug)]
pub struct DataPlaneRuntime<T: TunPacketIo, C: TunnelCoreAdapting> {
    tun: T,
    pump: TunnelPacketPump<C>,
    last_error: Option<String>,
    transport_ready: bool,
}

impl<T, C> DataPlaneRuntime<T, C>
where
    T: TunPacketIo,
    C: TunnelCoreAdapting,
{
    pub fn new(tun: T, core: C) -> Self {
        Self {
            tun,
            pump: TunnelPacketPump::new(core),
            last_error: None,
            transport_ready: false,
        }
    }

    pub fn status(&self) -> DataPlaneStatus {
        DataPlaneStatus {
            interface_name: Some(self.tun.config().name.clone()),
            state: if self.last_error.is_some() {
                DataPlaneState::Degraded
            } else if !self.transport_ready {
                DataPlaneState::Starting
            } else {
                DataPlaneState::Ready
            },
            packet_io_available: true,
            transport_ready: self.transport_ready,
            metrics: self.pump.counters().as_proto(),
            error: self.last_error.clone(),
        }
    }

    pub fn pump_tun_to_transport_once(
        &mut self,
        sink: &mut dyn TransportFrameSink,
        buffer: &mut [u8],
    ) -> Result<PacketPumpBatchResult, DataPlaneError> {
        self.transport_ready = sink.is_ready();
        let packet_len = match self.tun.read_packet(buffer) {
            Ok(packet_len) => packet_len,
            Err(TunPacketIoError::Io(error)) if error.kind() == ErrorKind::WouldBlock => {
                return Ok(PacketPumpBatchResult::default());
            }
            Err(error) => {
                let error = DataPlaneError::from(error);
                self.last_error = Some(error.to_string());
                return Err(error);
            }
        };

        let result = self.pump.handle_packet(&buffer[..packet_len], sink);
        if result.transport_errors > 0 {
            let error = DataPlaneError::Transport(format!(
                "transport send failed for {} frame(s)",
                result.transport_errors
            ));
            self.last_error = Some(error.to_string());
            return Err(error);
        }
        Ok(result)
    }

    pub fn pump_transport_to_tun_once(
        &mut self,
        source: &mut dyn TransportFrameSource,
    ) -> Result<PacketPumpBatchResult, DataPlaneError> {
        self.transport_ready = source.is_ready();
        let Some(frame) = source.try_receive_frame() else {
            return Ok(PacketPumpBatchResult::default());
        };

        let mut result = self.pump.accept_transport_frame(&frame)?;
        while let Some(packet) = self.pump.pop_tunnel_packet() {
            if let Err(error) = self.tun.write_packet(&packet.bytes) {
                let error = DataPlaneError::from(error);
                self.pump.record_transport_error();
                self.last_error = Some(error.to_string());
                return Err(error);
            }
            self.pump.record_tunnel_packet_emitted();
            result.emitted_packets += 1;
        }
        Ok(result)
    }

    pub fn tun_mut(&mut self) -> &mut T {
        &mut self.tun
    }

    pub fn counters(&self) -> &PacketPumpCounters {
        self.pump.counters()
    }
}

#[derive(Debug, Clone, Default)]
pub struct LocalFrameQueue {
    ready: bool,
    frames: VecDeque<Vec<u8>>,
}

impl LocalFrameQueue {
    pub fn ready() -> Self {
        Self {
            ready: true,
            frames: VecDeque::new(),
        }
    }

    pub fn unavailable() -> Self {
        Self {
            ready: false,
            frames: VecDeque::new(),
        }
    }

    pub fn queued_frames(&self) -> usize {
        self.frames.len()
    }
}

impl TransportFrameSink for LocalFrameQueue {
    fn is_ready(&self) -> bool {
        self.ready
    }

    fn send_transport_frame(&mut self, frame: Vec<u8>) -> Result<(), DataPlaneError> {
        if !self.ready {
            return Err(DataPlaneError::Transport(
                "transport is not ready".to_string(),
            ));
        }
        self.frames.push_back(frame);
        Ok(())
    }
}

impl TransportFrameSource for LocalFrameQueue {
    fn is_ready(&self) -> bool {
        self.ready
    }

    fn try_receive_frame(&mut self) -> Option<Vec<u8>> {
        self.frames.pop_front()
    }
}

pub fn packet_core_from_parts(
    protected_cidr: String,
    route_mode: FfiRouteMode,
    mtu: usize,
) -> Result<PacketTunnelCore, DataPlaneError> {
    PacketTunnelCore::new(PacketTunnelCoreConfig {
        protected_routes: vec![protected_cidr],
        excluded_routes: Vec::new(),
        route_mode,
        mtu,
        crypto: Some(FfiCryptoPolicy {
            suite: qlink_core::crypto::SUITE_FIPS203.to_string(),
        }),
    })
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlink_linux::{LoopbackTunDevice, TunDeviceConfig};

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
    fn packet_pump_drops_when_transport_is_unavailable() {
        let mut runtime = runtime();
        let packet = ipv4_packet([100, 64, 0, 9]);
        runtime.tun_mut().write_packet(&packet).unwrap();
        let mut sink = LocalFrameQueue::unavailable();
        let mut buffer = [0_u8; 1280];

        let result = runtime
            .pump_tun_to_transport_once(&mut sink, &mut buffer)
            .unwrap();

        assert_eq!(result.observed_packets, 1);
        assert_eq!(result.dropped_packets, 1);
        assert_eq!(result.queued_packets, 0);
        assert_eq!(sink.queued_frames(), 0);
        assert!(!runtime.status().transport_ready);
    }

    #[test]
    fn packet_pump_tun_to_transport_uses_packet_core() {
        let mut runtime = runtime();
        let packet = ipv4_packet([100, 64, 0, 9]);
        runtime.tun_mut().write_packet(&packet).unwrap();
        let mut sink = LocalFrameQueue::ready();
        let mut buffer = [0_u8; 1280];

        let result = runtime
            .pump_tun_to_transport_once(&mut sink, &mut buffer)
            .unwrap();

        assert_eq!(result.observed_packets, 1);
        assert_eq!(result.queued_packets, 1);
        assert_eq!(result.emitted_packets, 1);
        assert_eq!(sink.queued_frames(), 1);
        assert!(runtime.status().packet_io_available);
        assert!(runtime.status().transport_ready);
    }

    #[test]
    fn packet_pump_transport_send_failure_degrades_status() {
        struct FailingSink;

        impl TransportFrameSink for FailingSink {
            fn is_ready(&self) -> bool {
                true
            }

            fn send_transport_frame(&mut self, _frame: Vec<u8>) -> Result<(), DataPlaneError> {
                Err(DataPlaneError::Transport(
                    "synthetic send failure".to_string(),
                ))
            }
        }

        let mut runtime = runtime();
        let packet = ipv4_packet([100, 64, 0, 9]);
        runtime.tun_mut().write_packet(&packet).unwrap();
        let mut sink = FailingSink;
        let mut buffer = [0_u8; 1280];

        let error = runtime
            .pump_tun_to_transport_once(&mut sink, &mut buffer)
            .unwrap_err();
        let status = runtime.status();

        assert!(error.to_string().contains("transport send failed"));
        assert_eq!(status.state, DataPlaneState::Degraded);
        assert_eq!(status.metrics.transport_errors, 1);
        assert!(status.error.as_deref().unwrap().contains("transport send"));
    }

    #[test]
    fn packet_pump_mesh_to_tun_accepts_frame_and_writes_restored_packet() {
        let mut runtime = runtime();
        let packet = ipv4_packet([100, 64, 0, 9]);
        runtime.tun_mut().write_packet(&packet).unwrap();
        let mut transport = LocalFrameQueue::ready();
        let mut buffer = [0_u8; 1280];
        runtime
            .pump_tun_to_transport_once(&mut transport, &mut buffer)
            .unwrap();

        let result = runtime.pump_transport_to_tun_once(&mut transport).unwrap();

        assert_eq!(result.accepted_packets, 1);
        assert_eq!(result.emitted_packets, 1);
        let len = runtime.tun_mut().read_packet(&mut buffer).unwrap();
        assert_eq!(&buffer[16..20], &packet[16..20]);
        assert_eq!(len, packet.len());
    }

    #[test]
    fn packet_pump_drops_unprotected_tun_packet_without_transport_send() {
        let mut runtime = runtime();
        let packet = ipv4_packet([203, 0, 113, 9]);
        runtime.tun_mut().write_packet(&packet).unwrap();
        let mut sink = LocalFrameQueue::ready();
        let mut buffer = [0_u8; 1280];

        let result = runtime
            .pump_tun_to_transport_once(&mut sink, &mut buffer)
            .unwrap();

        assert_eq!(result.observed_packets, 1);
        assert_eq!(result.dropped_packets, 1);
        assert_eq!(result.queued_packets, 0);
        assert_eq!(sink.queued_frames(), 0);
    }
}
