use std::{collections::HashMap, net::Ipv4Addr};

pub const MIN_IPV4_PATH_MTU: u16 = 576;
pub const DEFAULT_SAFE_PATH_MTU: u16 = 1280;
pub const DEFAULT_MAX_PATH_MTU: u16 = 1472;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StablePathKind {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathId {
    pub kind: StablePathKind,
    pub generation: u64,
}

impl PathId {
    pub const fn new(kind: StablePathKind, generation: u64) -> Self {
        Self { kind, generation }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathChangeReason {
    Initial,
    PathFailure,
    SustainedImprovement,
    NetworkChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathMetrics {
    pub median_rtt_ms: u32,
    pub jitter_ms: u32,
    pub packet_loss_basis_points: u32,
    pub nat_penalty_ms: u32,
}

impl PathMetrics {
    pub const fn unknown() -> Self {
        Self {
            median_rtt_ms: 0,
            jitter_ms: 0,
            packet_loss_basis_points: 0,
            nat_penalty_ms: 0,
        }
    }

    pub fn score(self, kind: StablePathKind) -> u64 {
        let relay_penalty = match kind {
            StablePathKind::Direct => 0,
            StablePathKind::Relay => 30,
        };
        u64::from(self.median_rtt_ms)
            .saturating_add(u64::from(self.jitter_ms).saturating_mul(4))
            .saturating_add(u64::from(self.packet_loss_basis_points).saturating_mul(25) / 100)
            .saturating_add(u64::from(self.nat_penalty_ms))
            .saturating_add(relay_penalty)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowStabilityConfig {
    pub minimum_score_improvement: u64,
    pub required_better_samples: u8,
    pub flow_idle_timeout_ms: u64,
    pub base_path_mtu: u16,
    pub maximum_path_mtu: u16,
    pub mtu_probe_step: u16,
}

impl Default for FlowStabilityConfig {
    fn default() -> Self {
        Self {
            minimum_score_improvement: 15,
            required_better_samples: 3,
            flow_idle_timeout_ms: 120_000,
            base_path_mtu: DEFAULT_SAFE_PATH_MTU,
            maximum_path_mtu: DEFAULT_MAX_PATH_MTU,
            mtu_probe_step: 32,
        }
    }
}

impl FlowStabilityConfig {
    pub fn validate(self) -> Result<Self, FlowStabilityError> {
        if self.required_better_samples == 0 {
            return Err(FlowStabilityError::InvalidConfiguration(
                "required_better_samples must be greater than zero",
            ));
        }
        if self.flow_idle_timeout_ms == 0 {
            return Err(FlowStabilityError::InvalidConfiguration(
                "flow_idle_timeout_ms must be greater than zero",
            ));
        }
        if self.base_path_mtu < MIN_IPV4_PATH_MTU {
            return Err(FlowStabilityError::InvalidConfiguration(
                "base_path_mtu is below the IPv4 minimum",
            ));
        }
        if self.maximum_path_mtu < self.base_path_mtu {
            return Err(FlowStabilityError::InvalidConfiguration(
                "maximum_path_mtu is below base_path_mtu",
            ));
        }
        if self.mtu_probe_step == 0 {
            return Err(FlowStabilityError::InvalidConfiguration(
                "mtu_probe_step must be greater than zero",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn from_ipv4_packet(packet: &[u8]) -> Result<Self, FlowStabilityError> {
        if packet.len() < 20 || packet[0] >> 4 != 4 {
            return Err(FlowStabilityError::InvalidPacket(
                "packet is not a complete IPv4 header",
            ));
        }
        let header_len = usize::from(packet[0] & 0x0f).saturating_mul(4);
        if header_len < 20 || packet.len() < header_len {
            return Err(FlowStabilityError::InvalidPacket(
                "packet has an invalid IPv4 header length",
            ));
        }
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if total_len < header_len || total_len > packet.len() {
            return Err(FlowStabilityError::InvalidPacket(
                "packet has an invalid IPv4 total length",
            ));
        }
        let fragment = u16::from_be_bytes([packet[6], packet[7]]);
        if fragment & 0x3fff != 0 {
            return Err(FlowStabilityError::FragmentedPacket);
        }

        let protocol = packet[9];
        let (source_port, destination_port) = if matches!(protocol, 6 | 17) {
            if total_len < header_len + 4 {
                return Err(FlowStabilityError::InvalidPacket(
                    "TCP or UDP packet does not contain complete ports",
                ));
            }
            (
                u16::from_be_bytes([packet[header_len], packet[header_len + 1]]),
                u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]),
            )
        } else {
            (0, 0)
        };

        Ok(Self {
            source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
            destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
            source_port,
            destination_port,
            protocol,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMtuProbeState {
    BaseOnly,
    Searching,
    Confirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathMtuSnapshot {
    pub confirmed_mtu: u16,
    pub next_probe_mtu: Option<u16>,
    pub state: PathMtuProbeState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathMtuController {
    base: u16,
    maximum: u16,
    step: u16,
    confirmed: u16,
    upper_bound: u16,
    outstanding_probe: Option<u16>,
    state: PathMtuProbeState,
}

impl PathMtuController {
    fn new(config: FlowStabilityConfig) -> Self {
        Self {
            base: config.base_path_mtu,
            maximum: config.maximum_path_mtu,
            step: config.mtu_probe_step,
            confirmed: config.base_path_mtu,
            upper_bound: config.maximum_path_mtu,
            outstanding_probe: None,
            state: PathMtuProbeState::BaseOnly,
        }
    }

    fn reset(&mut self) {
        self.confirmed = self.base;
        self.upper_bound = self.maximum;
        self.outstanding_probe = None;
        self.state = PathMtuProbeState::BaseOnly;
    }

    fn next_probe(&mut self) -> Option<u16> {
        if let Some(probe) = self.outstanding_probe {
            return Some(probe);
        }
        if self.confirmed >= self.upper_bound {
            self.state = PathMtuProbeState::Confirmed;
            return None;
        }
        let probe = self
            .confirmed
            .saturating_add(self.step)
            .min(self.upper_bound);
        self.outstanding_probe = Some(probe);
        self.state = PathMtuProbeState::Searching;
        Some(probe)
    }

    fn record_probe_result(
        &mut self,
        probe_mtu: u16,
        succeeded: bool,
    ) -> Result<(), FlowStabilityError> {
        if self.outstanding_probe != Some(probe_mtu) {
            return Err(FlowStabilityError::UnexpectedMtuProbe);
        }
        self.outstanding_probe = None;
        if succeeded {
            self.confirmed = probe_mtu;
            if self.confirmed >= self.maximum {
                self.state = PathMtuProbeState::Confirmed;
            }
        } else {
            self.upper_bound = probe_mtu.saturating_sub(1).max(self.confirmed);
            self.state = PathMtuProbeState::Confirmed;
        }
        Ok(())
    }

    fn snapshot(self) -> PathMtuSnapshot {
        PathMtuSnapshot {
            confirmed_mtu: self.confirmed,
            next_probe_mtu: self.outstanding_probe,
            state: self.state,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowPathSnapshot {
    pub active_path: Option<PathId>,
    pub active_flow_count: usize,
    pub last_change_reason: Option<PathChangeReason>,
    pub path_mtu: PathMtuSnapshot,
    pub median_rtt_ms: Option<u32>,
    pub jitter_ms: Option<u32>,
    pub packet_loss_basis_points: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateDecision {
    KeptCurrent,
    Pending { observed: u8, required: u8 },
    Switched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDecision {
    Allowed { flow: FlowKey, path: PathId },
    DroppedNoPath,
    DroppedPathMismatch,
    DroppedOversize { packet_len: usize, path_mtu: u16 },
}

#[derive(Debug, Clone, Copy)]
struct FlowBinding {
    path: PathId,
    last_seen_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct CandidateObservation {
    path: PathId,
    consecutive_better_samples: u8,
}

#[derive(Debug)]
pub struct FlowPathController {
    config: FlowStabilityConfig,
    active_path: Option<PathId>,
    active_metrics: Option<PathMetrics>,
    pending_candidate: Option<CandidateObservation>,
    flows: HashMap<FlowKey, FlowBinding>,
    last_change_reason: Option<PathChangeReason>,
    path_mtu: PathMtuController,
}

impl Default for FlowPathController {
    fn default() -> Self {
        Self::new(FlowStabilityConfig::default()).expect("default flow stability config is valid")
    }
}

impl FlowPathController {
    pub fn new(config: FlowStabilityConfig) -> Result<Self, FlowStabilityError> {
        let config = config.validate()?;
        Ok(Self {
            config,
            active_path: None,
            active_metrics: None,
            pending_candidate: None,
            flows: HashMap::new(),
            last_change_reason: None,
            path_mtu: PathMtuController::new(config),
        })
    }

    pub fn activate_initial(&mut self, path: PathId, metrics: PathMetrics) {
        let reason = if self.last_change_reason == Some(PathChangeReason::NetworkChange) {
            PathChangeReason::NetworkChange
        } else {
            PathChangeReason::Initial
        };
        self.switch_path(path, metrics, reason);
    }

    pub fn observe_candidate(
        &mut self,
        candidate: PathId,
        metrics: PathMetrics,
    ) -> CandidateDecision {
        let Some(active) = self.active_path else {
            self.activate_initial(candidate, metrics);
            return CandidateDecision::Switched;
        };
        if active == candidate {
            self.active_metrics = Some(metrics);
            self.pending_candidate = None;
            return CandidateDecision::KeptCurrent;
        }

        let active_score = self
            .active_metrics
            .unwrap_or_else(PathMetrics::unknown)
            .score(active.kind);
        let candidate_score = metrics.score(candidate.kind);
        if candidate_score.saturating_add(self.config.minimum_score_improvement) > active_score {
            self.pending_candidate = None;
            return CandidateDecision::KeptCurrent;
        }

        let observed = match self.pending_candidate {
            Some(observation) if observation.path == candidate => {
                observation.consecutive_better_samples.saturating_add(1)
            }
            _ => 1,
        };
        if observed < self.config.required_better_samples {
            self.pending_candidate = Some(CandidateObservation {
                path: candidate,
                consecutive_better_samples: observed,
            });
            return CandidateDecision::Pending {
                observed,
                required: self.config.required_better_samples,
            };
        }

        self.switch_path(candidate, metrics, PathChangeReason::SustainedImprovement);
        CandidateDecision::Switched
    }

    pub fn switch_after_failure(&mut self, path: PathId, metrics: PathMetrics) {
        self.switch_path(path, metrics, PathChangeReason::PathFailure);
    }

    pub fn invalidate_for_network_change(&mut self) {
        self.active_path = None;
        self.active_metrics = None;
        self.pending_candidate = None;
        self.flows.clear();
        self.last_change_reason = Some(PathChangeReason::NetworkChange);
        self.path_mtu.reset();
    }

    pub fn authorize_ipv4_packet(
        &mut self,
        packet: &[u8],
        path: PathId,
        now_ms: u64,
    ) -> Result<PacketDecision, FlowStabilityError> {
        self.expire_idle_flows(now_ms);
        if self.active_path.is_none() {
            return Ok(PacketDecision::DroppedNoPath);
        }
        if self.active_path != Some(path) {
            return Ok(PacketDecision::DroppedPathMismatch);
        }
        let path_mtu = self.path_mtu.confirmed;
        if packet.len() > usize::from(path_mtu) {
            return Ok(PacketDecision::DroppedOversize {
                packet_len: packet.len(),
                path_mtu,
            });
        }
        let flow = FlowKey::from_ipv4_packet(packet)?;
        match self.flows.get_mut(&flow) {
            Some(binding) if binding.path != path => Ok(PacketDecision::DroppedPathMismatch),
            Some(binding) => {
                binding.last_seen_ms = now_ms;
                Ok(PacketDecision::Allowed { flow, path })
            }
            None => {
                self.flows.insert(
                    flow,
                    FlowBinding {
                        path,
                        last_seen_ms: now_ms,
                    },
                );
                Ok(PacketDecision::Allowed { flow, path })
            }
        }
    }

    pub fn next_mtu_probe(&mut self) -> Option<u16> {
        self.path_mtu.next_probe()
    }

    pub fn record_mtu_probe_result(
        &mut self,
        probe_mtu: u16,
        succeeded: bool,
    ) -> Result<(), FlowStabilityError> {
        self.path_mtu.record_probe_result(probe_mtu, succeeded)
    }

    pub fn snapshot(&self) -> FlowPathSnapshot {
        FlowPathSnapshot {
            active_path: self.active_path,
            active_flow_count: self.flows.len(),
            last_change_reason: self.last_change_reason,
            path_mtu: self.path_mtu.snapshot(),
            median_rtt_ms: self.active_metrics.map(|metrics| metrics.median_rtt_ms),
            jitter_ms: self.active_metrics.map(|metrics| metrics.jitter_ms),
            packet_loss_basis_points: self
                .active_metrics
                .map(|metrics| metrics.packet_loss_basis_points),
        }
    }

    fn switch_path(&mut self, path: PathId, metrics: PathMetrics, reason: PathChangeReason) {
        self.active_path = Some(path);
        self.active_metrics = Some(metrics);
        self.pending_candidate = None;
        for binding in self.flows.values_mut() {
            binding.path = path;
        }
        self.last_change_reason = Some(reason);
        self.path_mtu.reset();
    }

    fn expire_idle_flows(&mut self, now_ms: u64) {
        let idle_timeout = self.config.flow_idle_timeout_ms;
        self.flows
            .retain(|_, binding| now_ms.saturating_sub(binding.last_seen_ms) <= idle_timeout);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FlowStabilityError {
    #[error("invalid flow stability configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("invalid packet for flow classification: {0}")]
    InvalidPacket(&'static str),
    #[error("fragmented IPv4 packets are not accepted on the game flow path")]
    FragmentedPacket,
    #[error("path MTU probe result does not match the outstanding probe")]
    UnexpectedMtuProbe,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_packet(source_port: u16, destination_port: u16, len: usize) -> Vec<u8> {
        let len = len.max(28);
        let mut packet = vec![0_u8; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[100, 64, 0, 2]);
        packet[16..20].copy_from_slice(&[100, 64, 0, 9]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet
    }

    fn metrics(rtt: u32) -> PathMetrics {
        PathMetrics {
            median_rtt_ms: rtt,
            jitter_ms: 2,
            packet_loss_basis_points: 0,
            nat_penalty_ms: 0,
        }
    }

    #[test]
    fn five_tuple_keeps_one_path_until_an_approved_switch() {
        let direct = PathId::new(StablePathKind::Direct, 1);
        let relay = PathId::new(StablePathKind::Relay, 2);
        let mut controller = FlowPathController::default();
        controller.activate_initial(direct, metrics(30));
        let packet = udp_packet(42000, 34197, 100);

        assert!(matches!(
            controller.authorize_ipv4_packet(&packet, direct, 1),
            Ok(PacketDecision::Allowed { path, .. }) if path == direct
        ));
        assert_eq!(
            controller.authorize_ipv4_packet(&packet, relay, 2).unwrap(),
            PacketDecision::DroppedPathMismatch
        );
    }

    #[test]
    fn score_noise_does_not_move_an_active_flow() {
        let direct = PathId::new(StablePathKind::Direct, 1);
        let alternate = PathId::new(StablePathKind::Direct, 2);
        let mut controller = FlowPathController::default();
        controller.activate_initial(direct, metrics(30));

        for rtt in [29, 28, 27, 29] {
            assert_eq!(
                controller.observe_candidate(alternate, metrics(rtt)),
                CandidateDecision::KeptCurrent
            );
        }
        assert_eq!(controller.snapshot().active_path, Some(direct));
    }

    #[test]
    fn sustained_improvement_switches_once_after_threshold() {
        let direct = PathId::new(StablePathKind::Direct, 1);
        let alternate = PathId::new(StablePathKind::Direct, 2);
        let mut controller = FlowPathController::default();
        controller.activate_initial(direct, metrics(80));

        assert!(matches!(
            controller.observe_candidate(alternate, metrics(20)),
            CandidateDecision::Pending { observed: 1, .. }
        ));
        assert!(matches!(
            controller.observe_candidate(alternate, metrics(20)),
            CandidateDecision::Pending { observed: 2, .. }
        ));
        assert_eq!(
            controller.observe_candidate(alternate, metrics(20)),
            CandidateDecision::Switched
        );
        assert_eq!(controller.snapshot().active_path, Some(alternate));
        assert_eq!(
            controller.snapshot().last_change_reason,
            Some(PathChangeReason::SustainedImprovement)
        );
    }

    #[test]
    fn hard_failure_rebinds_existing_flows_and_resets_mtu() {
        let direct = PathId::new(StablePathKind::Direct, 1);
        let relay = PathId::new(StablePathKind::Relay, 2);
        let mut controller = FlowPathController::default();
        controller.activate_initial(direct, metrics(20));
        let packet = udp_packet(42000, 34197, 100);
        controller
            .authorize_ipv4_packet(&packet, direct, 1)
            .unwrap();
        let probe = controller.next_mtu_probe().unwrap();
        controller.record_mtu_probe_result(probe, true).unwrap();

        controller.switch_after_failure(relay, metrics(45));

        assert!(matches!(
            controller.authorize_ipv4_packet(&packet, relay, 2),
            Ok(PacketDecision::Allowed { path, .. }) if path == relay
        ));
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.path_mtu.confirmed_mtu, DEFAULT_SAFE_PATH_MTU);
        assert_eq!(
            snapshot.last_change_reason,
            Some(PathChangeReason::PathFailure)
        );
    }

    #[test]
    fn mtu_probe_advances_and_oversize_packets_fail_closed() {
        let path = PathId::new(StablePathKind::Direct, 1);
        let mut controller = FlowPathController::default();
        controller.activate_initial(path, metrics(20));
        let first_probe = controller.next_mtu_probe().unwrap();
        assert_eq!(first_probe, 1312);
        controller
            .record_mtu_probe_result(first_probe, true)
            .unwrap();
        assert_eq!(controller.snapshot().path_mtu.confirmed_mtu, 1312);

        let packet = udp_packet(42000, 34197, 1313);
        assert_eq!(
            controller.authorize_ipv4_packet(&packet, path, 1).unwrap(),
            PacketDecision::DroppedOversize {
                packet_len: 1313,
                path_mtu: 1312,
            }
        );
    }

    #[test]
    fn network_change_clears_flows_and_requires_a_new_path() {
        let path = PathId::new(StablePathKind::Direct, 1);
        let mut controller = FlowPathController::default();
        controller.activate_initial(path, metrics(20));
        let packet = udp_packet(42000, 34197, 100);
        controller.authorize_ipv4_packet(&packet, path, 1).unwrap();

        controller.invalidate_for_network_change();

        let snapshot = controller.snapshot();
        assert_eq!(snapshot.active_flow_count, 0);
        assert_eq!(snapshot.active_path, None);
        assert_eq!(
            snapshot.last_change_reason,
            Some(PathChangeReason::NetworkChange)
        );
        assert_eq!(
            controller.authorize_ipv4_packet(&packet, path, 2).unwrap(),
            PacketDecision::DroppedNoPath
        );
    }

    #[test]
    fn fragmented_ipv4_packet_is_rejected() {
        let path = PathId::new(StablePathKind::Direct, 1);
        let mut controller = FlowPathController::default();
        controller.activate_initial(path, metrics(20));
        let mut packet = udp_packet(42000, 34197, 100);
        packet[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());

        assert_eq!(
            controller.authorize_ipv4_packet(&packet, path, 1),
            Err(FlowStabilityError::FragmentedPacket)
        );
    }
}
