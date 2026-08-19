use qlink_core::flow_stability::{
    FlowPathController, PacketDecision, PathChangeReason, PathId, PathMetrics,
    PathMtuProbeState as CorePathMtuProbeState, StablePathKind,
};
use qlink_core::packet_core::{
    FfiCryptoPolicy, FfiRouteMode, InstalledPeerSession, PeerSessionDirection,
};
use qlink_core::packet_core::{
    PacketDisposition, PacketTunnelCore, PacketTunnelCoreConfig, TunnelPacket,
};
use qlink_linux::{protocol_family_for_packet, TunDeviceConfig, TunPacketIo, TunPacketIoError};
use qlink_proto::{
    DataPlanePathChangeReason, DataPlaneState, DataPlaneStatus, FlowStabilityStatus,
    PacketPumpMetrics, PathKind, PathMtuProbeState,
};
use std::{collections::VecDeque, error::Error, fmt, io::ErrorKind, time::Instant};

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
    fn install_peer_session(&mut self, session: InstalledPeerSession);
    fn clear_peer_session(
        &mut self,
        peer_id: &str,
        direction: PeerSessionDirection,
        generation: u64,
    );
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
    fn install_peer_session(&mut self, session: InstalledPeerSession) {
        let _ = PacketTunnelCore::install_peer_session(self, session);
    }

    fn clear_peer_session(
        &mut self,
        peer_id: &str,
        direction: PeerSessionDirection,
        generation: u64,
    ) {
        let _ = PacketTunnelCore::clear_peer_session(self, peer_id, direction, generation);
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundTransportFrame {
    pub frame: Vec<u8>,
    pub peer_session: InstalledPeerSession,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerSessionUpdate {
    Ready(InstalledPeerSession),
    Cleared {
        peer_id: String,
        direction: PeerSessionDirection,
        generation: u64,
    },
}

pub trait TransportFrameSink {
    fn is_ready(&self) -> bool;
    fn path_kind(&self) -> PathKind {
        if self.is_ready() {
            PathKind::Probing
        } else {
            PathKind::Unavailable
        }
    }
    fn peer_session_ready(&self) -> bool {
        false
    }
    fn path_generation(&self) -> Option<u64> {
        None
    }
    fn installed_peer_session(&self) -> Option<InstalledPeerSession> {
        None
    }
    fn take_peer_session_updates(&self) -> Vec<PeerSessionUpdate> {
        Vec::new()
    }
    fn last_transport_error(&self) -> Option<&str> {
        None
    }
    fn send_transport_frame(&mut self, frame: Vec<u8>) -> Result<(), DataPlaneError>;
}

pub trait TransportFrameSource {
    fn is_ready(&self) -> bool;
    fn path_kind(&self) -> PathKind {
        if self.is_ready() {
            PathKind::Probing
        } else {
            PathKind::Unavailable
        }
    }
    fn peer_session_ready(&self) -> bool {
        false
    }
    fn path_generation(&self) -> Option<u64> {
        None
    }
    fn take_peer_session_updates(&self) -> Vec<PeerSessionUpdate> {
        Vec::new()
    }
    fn last_transport_error(&self) -> Option<&str> {
        None
    }
    fn try_receive_frame(&mut self) -> Option<InboundTransportFrame>;
}

pub trait MeshFrameTransport {
    fn is_ready(&self) -> bool;
    fn path_kind(&self) -> PathKind;
    fn peer_session_ready(&self) -> bool;
    fn path_generation(&self) -> Option<u64> {
        None
    }
    fn installed_peer_session(&self) -> Option<InstalledPeerSession>;
    fn take_peer_session_updates(&self) -> Vec<PeerSessionUpdate> {
        Vec::new()
    }
    fn send_frame(&mut self, frame: Vec<u8>) -> Result<(), DataPlaneError>;
    fn try_receive_frame(&mut self) -> Option<InboundTransportFrame>;
    fn last_transport_error(&self) -> Option<&str> {
        None
    }
}

impl<T> TransportFrameSink for T
where
    T: MeshFrameTransport + ?Sized,
{
    fn is_ready(&self) -> bool {
        MeshFrameTransport::is_ready(self)
    }

    fn path_kind(&self) -> PathKind {
        MeshFrameTransport::path_kind(self)
    }

    fn peer_session_ready(&self) -> bool {
        MeshFrameTransport::peer_session_ready(self)
    }

    fn path_generation(&self) -> Option<u64> {
        MeshFrameTransport::path_generation(self)
    }

    fn installed_peer_session(&self) -> Option<InstalledPeerSession> {
        MeshFrameTransport::installed_peer_session(self).map(|mut session| {
            session.direction = PeerSessionDirection::Outbound;
            session
        })
    }

    fn take_peer_session_updates(&self) -> Vec<PeerSessionUpdate> {
        MeshFrameTransport::take_peer_session_updates(self)
    }

    fn last_transport_error(&self) -> Option<&str> {
        MeshFrameTransport::last_transport_error(self)
    }

    fn send_transport_frame(&mut self, frame: Vec<u8>) -> Result<(), DataPlaneError> {
        self.send_frame(frame)
    }
}

impl<T> TransportFrameSource for T
where
    T: MeshFrameTransport + ?Sized,
{
    fn is_ready(&self) -> bool {
        MeshFrameTransport::is_ready(self)
    }

    fn path_kind(&self) -> PathKind {
        MeshFrameTransport::path_kind(self)
    }

    fn peer_session_ready(&self) -> bool {
        MeshFrameTransport::peer_session_ready(self)
    }

    fn path_generation(&self) -> Option<u64> {
        MeshFrameTransport::path_generation(self)
    }

    fn take_peer_session_updates(&self) -> Vec<PeerSessionUpdate> {
        MeshFrameTransport::take_peer_session_updates(self)
    }

    fn last_transport_error(&self) -> Option<&str> {
        MeshFrameTransport::last_transport_error(self)
    }

    fn try_receive_frame(&mut self) -> Option<InboundTransportFrame> {
        MeshFrameTransport::try_receive_frame(self)
    }
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

        if !sink.is_ready() || !sink.peer_session_ready() {
            result.dropped_packets = 1;
            self.counters.add_batch(result);
            return result;
        }
        let Some(session) = sink.installed_peer_session() else {
            result.dropped_packets = 1;
            self.counters.add_batch(result);
            return result;
        };
        core.install_peer_session(session);

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
            Ok(PacketDisposition::DroppedUnprotected)
            | Ok(PacketDisposition::DroppedPeerSessionUnavailable) => result.dropped_packets = 1,
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

    pub fn install_peer_session(&mut self, session: InstalledPeerSession) {
        if let Some(core) = self.core.as_mut() {
            core.install_peer_session(session);
        }
    }

    pub fn clear_peer_session(
        &mut self,
        peer_id: &str,
        direction: PeerSessionDirection,
        generation: u64,
    ) {
        if let Some(core) = self.core.as_mut() {
            core.clear_peer_session(peer_id, direction, generation);
        }
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
    transport_path: Option<PathKind>,
    peer_session_ready: bool,
    last_transport_error: Option<String>,
    flow_stability: FlowPathController,
    observed_path: Option<PathId>,
    path_generation: u64,
    started_at: Instant,
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
            transport_path: None,
            peer_session_ready: false,
            last_transport_error: None,
            flow_stability: FlowPathController::default(),
            observed_path: None,
            path_generation: 0,
            started_at: Instant::now(),
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
            transport_path: self.transport_path,
            peer_session_ready: self.peer_session_ready,
            last_transport_error: self.last_transport_error.clone(),
            metrics: self.pump.counters().as_proto(),
            flow_stability: flow_stability_status(self.flow_stability.snapshot()),
            error: self.last_error.clone(),
        }
    }

    pub fn pump_tun_to_transport_once(
        &mut self,
        sink: &mut dyn TransportFrameSink,
        buffer: &mut [u8],
    ) -> Result<PacketPumpBatchResult, DataPlaneError> {
        self.apply_peer_session_updates(sink.take_peer_session_updates());
        self.record_transport_status_from_sink(sink);
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

        let packet = &buffer[..packet_len];
        let result = match self.current_path_id() {
            Some(path) => match self.flow_stability.authorize_ipv4_packet(
                packet,
                path,
                self.started_at.elapsed().as_millis() as u64,
            ) {
                Ok(PacketDecision::Allowed { .. }) => self.pump.handle_packet(packet, sink),
                Ok(
                    PacketDecision::DroppedNoPath
                    | PacketDecision::DroppedPathMismatch
                    | PacketDecision::DroppedOversize { .. },
                ) => {
                    let result = PacketPumpBatchResult {
                        observed_packets: 1,
                        dropped_packets: 1,
                        ..Default::default()
                    };
                    self.pump.counters.add_batch(result);
                    result
                }
                Err(_) => {
                    let result = PacketPumpBatchResult {
                        observed_packets: 1,
                        rejected_packets: 1,
                        ..Default::default()
                    };
                    self.pump.counters.add_batch(result);
                    result
                }
            },
            None => {
                let result = PacketPumpBatchResult {
                    observed_packets: 1,
                    dropped_packets: 1,
                    ..Default::default()
                };
                self.pump.counters.add_batch(result);
                result
            }
        };
        if result.transport_errors > 0 {
            let error = DataPlaneError::Transport(format!(
                "transport send failed for {} frame(s)",
                result.transport_errors
            ));
            self.last_transport_error = Some(error.to_string());
            self.last_error = Some(error.to_string());
            return Err(error);
        }
        Ok(result)
    }

    pub fn pump_transport_to_tun_once(
        &mut self,
        source: &mut dyn TransportFrameSource,
    ) -> Result<PacketPumpBatchResult, DataPlaneError> {
        self.apply_peer_session_updates(source.take_peer_session_updates());
        self.record_transport_status_from_source(source);
        let Some(inbound) = source.try_receive_frame() else {
            return Ok(PacketPumpBatchResult::default());
        };
        self.pump.install_peer_session(inbound.peer_session);

        let mut result = self.pump.accept_transport_frame(&inbound.frame)?;
        while let Some(packet) = self.pump.pop_tunnel_packet() {
            if let Err(error) = self.tun.write_packet(&packet.bytes) {
                let error = DataPlaneError::from(error);
                self.pump.record_transport_error();
                self.last_transport_error = Some(error.to_string());
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

    pub fn handle_network_change(&mut self) {
        self.flow_stability.invalidate_for_network_change();
        self.observed_path = None;
        self.transport_ready = false;
        self.transport_path = Some(PathKind::Probing);
    }

    fn record_transport_status_from_sink(&mut self, sink: &dyn TransportFrameSink) {
        self.peer_session_ready = sink.peer_session_ready();
        self.transport_ready = sink.is_ready() && self.peer_session_ready;
        self.transport_path = Some(sink.path_kind());
        self.last_transport_error = sink.last_transport_error().map(str::to_string);
        self.observe_transport_path(sink.path_generation());
    }

    fn record_transport_status_from_source(&mut self, source: &dyn TransportFrameSource) {
        self.peer_session_ready = source.peer_session_ready();
        self.transport_ready = source.is_ready() && self.peer_session_ready;
        self.transport_path = Some(source.path_kind());
        self.last_transport_error = source.last_transport_error().map(str::to_string);
        self.observe_transport_path(source.path_generation());
    }

    fn observe_transport_path(&mut self, reported_generation: Option<u64>) {
        if !self.transport_ready {
            return;
        }
        let Some(kind) = stable_path_kind(self.transport_path) else {
            return;
        };
        let generation = reported_generation
            .filter(|value| *value > 0)
            .unwrap_or_else(|| {
                self.observed_path
                    .filter(|path| path.kind == kind)
                    .map(|path| path.generation)
                    .unwrap_or_else(|| self.path_generation.saturating_add(1).max(1))
            });
        let path = PathId::new(kind, generation);
        if self.observed_path == Some(path) {
            return;
        }
        self.path_generation = self.path_generation.max(generation);
        if self.observed_path.is_some() {
            self.flow_stability
                .switch_after_failure(path, PathMetrics::unknown());
        } else {
            self.flow_stability
                .activate_initial(path, PathMetrics::unknown());
        }
        self.observed_path = Some(path);
        let _ = self.flow_stability.next_mtu_probe();
    }

    fn current_path_id(&self) -> Option<PathId> {
        self.observed_path
    }

    fn apply_peer_session_updates(&mut self, updates: Vec<PeerSessionUpdate>) {
        for update in updates {
            match update {
                PeerSessionUpdate::Ready(session) => self.pump.install_peer_session(session),
                PeerSessionUpdate::Cleared {
                    peer_id,
                    direction,
                    generation,
                } => self
                    .pump
                    .clear_peer_session(&peer_id, direction, generation),
            }
        }
    }
}

fn stable_path_kind(path: Option<PathKind>) -> Option<StablePathKind> {
    match path {
        Some(PathKind::Direct) => Some(StablePathKind::Direct),
        Some(PathKind::Relay) => Some(StablePathKind::Relay),
        Some(PathKind::Probing | PathKind::Unavailable) | None => None,
    }
}

fn flow_stability_status(
    snapshot: qlink_core::flow_stability::FlowPathSnapshot,
) -> FlowStabilityStatus {
    FlowStabilityStatus {
        active_flow_count: snapshot.active_flow_count as u64,
        path_generation: snapshot.active_path.map(|path| path.generation),
        last_path_change_reason: snapshot.last_change_reason.map(|reason| match reason {
            PathChangeReason::Initial => DataPlanePathChangeReason::Initial,
            PathChangeReason::PathFailure => DataPlanePathChangeReason::PathFailure,
            PathChangeReason::SustainedImprovement => {
                DataPlanePathChangeReason::SustainedImprovement
            }
            PathChangeReason::NetworkChange => DataPlanePathChangeReason::NetworkChange,
        }),
        path_mtu: Some(snapshot.path_mtu.confirmed_mtu),
        next_mtu_probe: snapshot.path_mtu.next_probe_mtu,
        mtu_probe_state: match snapshot.path_mtu.state {
            CorePathMtuProbeState::BaseOnly => PathMtuProbeState::BaseOnly,
            CorePathMtuProbeState::Searching => PathMtuProbeState::Searching,
            CorePathMtuProbeState::Confirmed => PathMtuProbeState::Confirmed,
        },
        median_rtt_ms: snapshot.median_rtt_ms,
        jitter_ms: snapshot.jitter_ms,
        packet_loss_basis_points: snapshot.packet_loss_basis_points,
    }
}

#[derive(Debug, Clone, Default)]
pub struct LocalFrameQueue {
    ready: bool,
    generation: u64,
    frames: VecDeque<Vec<u8>>,
}

impl LocalFrameQueue {
    pub fn ready() -> Self {
        Self {
            ready: true,
            generation: 1,
            frames: VecDeque::new(),
        }
    }

    pub fn unavailable() -> Self {
        Self {
            ready: false,
            generation: 0,
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

    fn peer_session_ready(&self) -> bool {
        self.ready
    }

    fn path_kind(&self) -> PathKind {
        if self.ready {
            PathKind::Direct
        } else {
            PathKind::Unavailable
        }
    }

    fn path_generation(&self) -> Option<u64> {
        self.ready.then_some(self.generation)
    }

    fn installed_peer_session(&self) -> Option<InstalledPeerSession> {
        self.ready.then(|| InstalledPeerSession {
            peer_id: "local-loopback-peer".to_string(),
            direction: PeerSessionDirection::Outbound,
            generation: 1,
            transcript_binding: [0; 32],
            expires_at_unix: u64::MAX,
            rekey_after_bytes: 0,
        })
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

    fn peer_session_ready(&self) -> bool {
        self.ready
    }

    fn path_kind(&self) -> PathKind {
        if self.ready {
            PathKind::Direct
        } else {
            PathKind::Unavailable
        }
    }

    fn path_generation(&self) -> Option<u64> {
        self.ready.then_some(self.generation)
    }

    fn try_receive_frame(&mut self) -> Option<InboundTransportFrame> {
        self.frames.pop_front().map(|frame| InboundTransportFrame {
            frame,
            peer_session: InstalledPeerSession {
                peer_id: "local-loopback-peer".to_string(),
                direction: PeerSessionDirection::Inbound,
                generation: 1,
                transcript_binding: [0; 32],
                expires_at_unix: u64::MAX,
                rekey_after_bytes: 0,
            },
        })
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
        require_peer_session: true,
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
        assert_eq!(runtime.status().flow_stability.active_flow_count, 1);
        assert_eq!(runtime.status().flow_stability.path_generation, Some(1));
        assert_eq!(runtime.status().flow_stability.path_mtu, Some(1280));
        assert_eq!(runtime.status().flow_stability.next_mtu_probe, Some(1312));
        assert_eq!(
            runtime.status().flow_stability.mtu_probe_state,
            PathMtuProbeState::Searching
        );
    }

    #[test]
    fn packet_pump_transport_send_failure_degrades_status() {
        struct FailingSink;

        impl TransportFrameSink for FailingSink {
            fn is_ready(&self) -> bool {
                true
            }

            fn peer_session_ready(&self) -> bool {
                true
            }

            fn path_kind(&self) -> PathKind {
                PathKind::Direct
            }

            fn installed_peer_session(&self) -> Option<InstalledPeerSession> {
                Some(InstalledPeerSession {
                    peer_id: "failing-sink-peer".to_string(),
                    direction: PeerSessionDirection::Outbound,
                    generation: 1,
                    transcript_binding: [0; 32],
                    expires_at_unix: u64::MAX,
                    rekey_after_bytes: 0,
                })
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

    #[test]
    fn network_change_clears_flow_bindings_and_requires_revalidation() {
        let mut runtime = runtime();
        let packet = ipv4_packet([100, 64, 0, 9]);
        runtime.tun_mut().write_packet(&packet).unwrap();
        let mut sink = LocalFrameQueue::ready();
        let mut buffer = [0_u8; 1280];
        runtime
            .pump_tun_to_transport_once(&mut sink, &mut buffer)
            .unwrap();
        assert_eq!(runtime.status().flow_stability.active_flow_count, 1);

        runtime.handle_network_change();

        let status = runtime.status();
        assert_eq!(status.flow_stability.active_flow_count, 0);
        assert_eq!(status.flow_stability.path_generation, None);
        assert_eq!(
            status.flow_stability.last_path_change_reason,
            Some(DataPlanePathChangeReason::NetworkChange)
        );
        assert!(!status.transport_ready);
    }

    #[test]
    fn same_kind_session_reconnect_advances_the_bound_path_generation() {
        let mut runtime = runtime();
        let packet = ipv4_packet([100, 64, 0, 9]);
        let mut sink = LocalFrameQueue::ready();
        let mut buffer = [0_u8; 1280];
        runtime.tun_mut().write_packet(&packet).unwrap();
        runtime
            .pump_tun_to_transport_once(&mut sink, &mut buffer)
            .unwrap();
        assert_eq!(runtime.status().flow_stability.path_generation, Some(1));

        sink.generation = 2;
        runtime.tun_mut().write_packet(&packet).unwrap();
        runtime
            .pump_tun_to_transport_once(&mut sink, &mut buffer)
            .unwrap();

        let status = runtime.status();
        assert_eq!(status.flow_stability.path_generation, Some(2));
        assert_eq!(
            status.flow_stability.last_path_change_reason,
            Some(DataPlanePathChangeReason::PathFailure)
        );
        assert_eq!(status.flow_stability.active_flow_count, 1);
    }
}
