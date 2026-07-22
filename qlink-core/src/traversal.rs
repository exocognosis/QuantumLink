#[cfg(feature = "turn-relay")]
use crate::turn::{gather_relay_candidates, TurnServer};
use crate::{
    discovery::{CandidateEndpoint, CandidateType},
    error::{QlinkError, Result},
    stun::gather_server_reflexive_candidate,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// RFC 8445 §5.1.2.2 — recommended type preferences (0..=126).
pub const TYPE_PREF_HOST: u32 = 126;
pub const TYPE_PREF_PEER_REFLEXIVE: u32 = 110;
pub const TYPE_PREF_SERVER_REFLEXIVE: u32 = 100;
pub const TYPE_PREF_RELAY: u32 = 0;

/// Default local preference for a single-stack agent (RFC 8445 §5.1.2.1).
/// IPv6 candidates would normally get a higher local preference than IPv4 to
/// prefer modern transport when both are available; QuantumLink v1 is IPv4
/// only, so the value is the maximum.
pub const DEFAULT_LOCAL_PREF: u32 = 65_535;

/// Component ID for a single-component flow (no RTCP/RTP split).
pub const COMPONENT_ID: u32 = 1;

/// RFC 8445 §5.1.2.1 candidate priority formula.
///
///   priority = (2^24)*(type pref) + (2^8)*(local pref) + (256 - component ID)
pub const fn ice_priority(type_pref: u32, local_pref: u32, component_id: u32) -> u32 {
    let bounded_component = if component_id > 256 {
        256
    } else {
        component_id
    };
    (type_pref << 24) | (local_pref << 8) | (256 - bounded_component)
}

/// RFC 8445 §6.1.2.3 candidate-pair priority formula.
///
///   pair_priority = 2^32 * MIN(G,D) + 2 * MAX(G,D) + (G > D ? 1 : 0)
///
/// where G is the controlling agent's candidate priority and D is the
/// controlled agent's candidate priority.
pub const fn pair_priority(controlling: u32, controlled: u32) -> u64 {
    let g = controlling as u64;
    let d = controlled as u64;
    let min = if g < d { g } else { d };
    let max = if g > d { g } else { d };
    let tiebreaker = if g > d { 1 } else { 0 };
    (min << 32) + (2 * max) + tiebreaker
}

pub const HOST_PRIORITY: u32 = ice_priority(TYPE_PREF_HOST, DEFAULT_LOCAL_PREF, COMPONENT_ID);
pub const SERVER_REFLEXIVE_PRIORITY: u32 =
    ice_priority(TYPE_PREF_SERVER_REFLEXIVE, DEFAULT_LOCAL_PREF, COMPONENT_ID);
pub const PEER_REFLEXIVE_PRIORITY: u32 =
    ice_priority(TYPE_PREF_PEER_REFLEXIVE, DEFAULT_LOCAL_PREF, COMPONENT_ID);
pub const RELAY_PRIORITY: u32 = ice_priority(TYPE_PREF_RELAY, DEFAULT_LOCAL_PREF, COMPONENT_ID);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePair {
    pub local: CandidateEndpoint,
    pub remote: CandidateEndpoint,
    pub score: u32,
}

#[derive(Debug, Clone)]
pub struct HostCandidateGatherer {
    bind_addresses: Vec<IpAddr>,
    port: u16,
}

impl HostCandidateGatherer {
    pub fn loopback(port: u16) -> Self {
        Self {
            bind_addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            port,
        }
    }

    pub fn new(bind_addresses: Vec<IpAddr>, port: u16) -> Self {
        Self {
            bind_addresses,
            port,
        }
    }

    pub fn gather(&self) -> Vec<CandidateEndpoint> {
        self.bind_addresses
            .iter()
            .map(|address| CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: address.to_string(),
                port: self.port,
                priority: HOST_PRIORITY,
            })
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct PathSelector;

impl PathSelector {
    pub fn nominate(
        &self,
        local: &[CandidateEndpoint],
        remote: &[CandidateEndpoint],
    ) -> Option<CandidatePair> {
        local
            .iter()
            .flat_map(|local| {
                remote.iter().map(move |remote| CandidatePair {
                    local: local.clone(),
                    remote: remote.clone(),
                    score: pair_score(local, remote),
                })
            })
            .max_by_key(|pair| pair.score)
    }
}

pub fn relay_candidate(address: SocketAddr) -> CandidateEndpoint {
    CandidateEndpoint {
        candidate_type: CandidateType::Relay,
        address: address.ip().to_string(),
        port: address.port(),
        priority: RELAY_PRIORITY,
    }
}

pub fn server_reflexive_candidate(address: SocketAddr) -> CandidateEndpoint {
    CandidateEndpoint {
        candidate_type: CandidateType::ServerReflexive,
        address: address.ip().to_string(),
        port: address.port(),
        priority: SERVER_REFLEXIVE_PRIORITY,
    }
}

/// Gathers the local agent's candidate set: a host candidate for the QUIC
/// socket, plus a server-reflexive candidate per supplied STUN server.
///
/// **Production caveat**: The STUN binding is sent from a fresh ephemeral UDP
/// socket because Quinn (v0.11) owns its bound socket and does not expose it
/// for sharing. Strictly speaking, the reflexive address learned from a
/// non-QUIC socket may map to a different external port behind symmetric NAT
/// (and would be classified as a peer-reflexive candidate per RFC 8445 §5.1.2
/// rather than server-reflexive). True per-connection srflx requires the
/// QUIC endpoint to be constructed from a caller-supplied socket and the
/// STUN binding to be sent from that same socket. Tracking that as a
/// follow-up.
///
/// STUN failures are recorded in `stun_failures` but do not abort the gather —
/// direct hosts and a relay path may still succeed.
#[derive(Debug, Default)]
pub struct GatherReport {
    pub stun_failures: Vec<(SocketAddr, String)>,
    pub turn_failures: Vec<(SocketAddr, String)>,
}

pub async fn gather_local_candidates(
    quic_local_addr: SocketAddr,
    stun_servers: &[SocketAddr],
) -> (Vec<CandidateEndpoint>, GatherReport) {
    let mut candidates: Vec<CandidateEndpoint> = Vec::new();
    let mut report = GatherReport::default();

    candidates.push(host_candidate(quic_local_addr));

    // Use an ephemeral bind for STUN so we don't EADDRINUSE-conflict with the
    // QUIC socket. See the production caveat above.
    let stun_bind: SocketAddr = match quic_local_addr.ip() {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };

    for server in stun_servers {
        match gather_server_reflexive_candidate(*server, stun_bind).await {
            Ok(mut candidate) => {
                candidate.priority = SERVER_REFLEXIVE_PRIORITY;
                if !candidates.iter().any(|existing| {
                    existing.address == candidate.address && existing.port == candidate.port
                }) {
                    candidates.push(candidate);
                }
            }
            Err(error) => {
                report.stun_failures.push((*server, error.to_string()));
            }
        }
    }

    (candidates, report)
}

/// Gathers a complete local candidate set for production rendezvous records:
/// host, server-reflexive, and TURN relay candidates. TURN support is feature
/// gated because standard TURN authentication requires classical RFC framing
/// primitives that are deliberately excluded from default PQC-only builds.
#[cfg(feature = "turn-relay")]
pub async fn gather_ice_candidates(
    quic_local_addr: SocketAddr,
    stun_servers: &[SocketAddr],
    turn_servers: &[TurnServer],
) -> (Vec<CandidateEndpoint>, GatherReport) {
    let (mut candidates, mut report) = gather_local_candidates(quic_local_addr, stun_servers).await;

    let turn_bind: SocketAddr = match quic_local_addr.ip() {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let (relay_candidates, failures) = gather_relay_candidates(turn_servers, turn_bind).await;
    report.turn_failures = failures;

    for mut candidate in relay_candidates {
        candidate.priority = RELAY_PRIORITY;
        if !candidates.iter().any(|existing| {
            existing.address == candidate.address && existing.port == candidate.port
        }) {
            candidates.push(candidate);
        }
    }

    (order_remote_candidates(&candidates), report)
}

fn host_candidate(addr: SocketAddr) -> CandidateEndpoint {
    CandidateEndpoint {
        candidate_type: CandidateType::Host,
        address: addr.ip().to_string(),
        port: addr.port(),
        priority: HOST_PRIORITY,
    }
}

/// Sort remote candidates by ICE priority (highest first), with relay
/// candidates always at the tail so direct paths get tried first regardless of
/// numeric priority overflow from external sources.
pub fn order_remote_candidates(candidates: &[CandidateEndpoint]) -> Vec<CandidateEndpoint> {
    let mut sorted: Vec<CandidateEndpoint> = candidates.to_vec();
    sorted.sort_by(|a, b| {
        let a_relay = matches!(a.candidate_type, CandidateType::Relay);
        let b_relay = matches!(b.candidate_type, CandidateType::Relay);
        match (a_relay, b_relay) {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => b.priority.cmp(&a.priority),
        }
    });
    sorted
}

/// Validates a CandidateEndpoint enough to extract a `SocketAddr`.
pub fn candidate_socket_addr(endpoint: &CandidateEndpoint) -> Result<SocketAddr> {
    let ip: IpAddr = endpoint
        .address
        .parse()
        .map_err(|err| QlinkError::Protocol(format!("invalid candidate address: {err}")))?;
    Ok(SocketAddr::new(ip, endpoint.port))
}

fn pair_score(local: &CandidateEndpoint, remote: &CandidateEndpoint) -> u32 {
    let base = local.priority.min(remote.priority);
    let type_bonus = match (&local.candidate_type, &remote.candidate_type) {
        (CandidateType::Host, CandidateType::Host) => 30,
        (CandidateType::Host, CandidateType::ServerReflexive)
        | (CandidateType::ServerReflexive, CandidateType::Host)
        | (CandidateType::ServerReflexive, CandidateType::ServerReflexive) => 15,
        _ => 0,
    };
    base + type_bonus
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ice_priority_matches_rfc_8445_formula() {
        // Spot-check a host candidate, single component:
        //   (126 << 24) | (65535 << 8) | (256 - 1)
        let expected = (126_u32 << 24) | (65535_u32 << 8) | (256 - 1);
        assert_eq!(
            ice_priority(TYPE_PREF_HOST, DEFAULT_LOCAL_PREF, COMPONENT_ID),
            expected
        );
        assert_eq!(HOST_PRIORITY, expected);
        assert!(HOST_PRIORITY > SERVER_REFLEXIVE_PRIORITY);
        assert!(SERVER_REFLEXIVE_PRIORITY > RELAY_PRIORITY);
    }

    #[test]
    fn pair_priority_orders_candidate_pairs_per_rfc() {
        // Stronger controlled side. Pair priority should be dominated by MIN(G,D).
        let weaker = pair_priority(HOST_PRIORITY, RELAY_PRIORITY);
        let stronger = pair_priority(HOST_PRIORITY, HOST_PRIORITY);
        assert!(stronger > weaker);

        // Symmetry tiebreak: G > D adds 1.
        let g_higher = pair_priority(HOST_PRIORITY, SERVER_REFLEXIVE_PRIORITY);
        let g_lower = pair_priority(SERVER_REFLEXIVE_PRIORITY, HOST_PRIORITY);
        assert_eq!(g_higher, g_lower + 1);
    }

    #[test]
    fn order_remote_candidates_puts_relays_last() {
        let candidates = vec![
            relay_candidate("1.2.3.4:5".parse().unwrap()),
            CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "1.2.3.4".to_string(),
                port: 4433,
                priority: HOST_PRIORITY,
            },
            CandidateEndpoint {
                candidate_type: CandidateType::ServerReflexive,
                address: "5.6.7.8".to_string(),
                port: 4434,
                priority: SERVER_REFLEXIVE_PRIORITY,
            },
        ];
        let ordered = order_remote_candidates(&candidates);
        assert_eq!(ordered[0].candidate_type, CandidateType::Host);
        assert_eq!(ordered[1].candidate_type, CandidateType::ServerReflexive);
        assert_eq!(ordered[2].candidate_type, CandidateType::Relay);
    }

    #[tokio::test]
    async fn gather_local_candidates_includes_host_and_srflx() {
        use crate::stun::spawn_dev_stun;
        let stun_server = spawn_dev_stun().await.unwrap();
        let quic_addr: SocketAddr = "127.0.0.1:14433".parse().unwrap();
        let (candidates, report) =
            gather_local_candidates(quic_addr, &[stun_server.local_addr()]).await;
        assert!(report.stun_failures.is_empty());
        // Host candidate first.
        assert_eq!(candidates[0].candidate_type, CandidateType::Host);
        // At least one server-reflexive candidate followed.
        assert!(candidates
            .iter()
            .any(|c| c.candidate_type == CandidateType::ServerReflexive));
    }

    #[tokio::test]
    async fn gather_local_candidates_records_stun_failures_without_aborting() {
        let unreachable: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let quic_addr: SocketAddr = "127.0.0.1:14434".parse().unwrap();
        let (candidates, report) = gather_local_candidates(quic_addr, &[unreachable]).await;
        // Host candidate still present.
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].candidate_type, CandidateType::Host);
        // Failure recorded.
        assert_eq!(report.stun_failures.len(), 1);
        assert_eq!(report.stun_failures[0].0, unreachable);
        assert!(report.turn_failures.is_empty());
    }

    #[cfg(feature = "turn-relay")]
    #[tokio::test]
    async fn gather_ice_candidates_includes_host_srflx_and_turn_relay() {
        use crate::{stun::spawn_dev_stun, turn::spawn_dev_turn};

        let stun_server = spawn_dev_stun().await.unwrap();
        let turn_server = spawn_dev_turn().await.unwrap();
        let quic_addr: SocketAddr = "127.0.0.1:14435".parse().unwrap();
        let turn_servers = vec![TurnServer::open(turn_server.local_addr())];

        let (candidates, report) =
            gather_ice_candidates(quic_addr, &[stun_server.local_addr()], &turn_servers).await;

        assert!(report.stun_failures.is_empty());
        assert!(report.turn_failures.is_empty());
        assert_eq!(candidates[0].candidate_type, CandidateType::Host);
        assert!(candidates
            .iter()
            .any(|candidate| candidate.candidate_type == CandidateType::ServerReflexive));
        assert!(candidates
            .iter()
            .any(|candidate| candidate.candidate_type == CandidateType::Relay));
        assert_eq!(
            candidates.last().map(|candidate| &candidate.candidate_type),
            Some(&CandidateType::Relay)
        );
    }

    #[test]
    fn host_gatherer_produces_loopback_candidate() {
        let candidates = HostCandidateGatherer::loopback(4433).gather();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].candidate_type, CandidateType::Host);
        assert_eq!(candidates[0].address, "127.0.0.1");
        assert_eq!(candidates[0].port, 4433);
    }

    #[test]
    fn path_selector_prefers_direct_candidate_pair_over_relay() {
        let local = vec![
            relay_candidate("127.0.0.1:9472".parse().unwrap()),
            CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "127.0.0.1".to_string(),
                port: 4433,
                priority: HOST_PRIORITY,
            },
        ];
        let remote = vec![
            relay_candidate("127.0.0.1:9472".parse().unwrap()),
            CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "127.0.0.1".to_string(),
                port: 4434,
                priority: HOST_PRIORITY,
            },
        ];

        let selected = PathSelector::default().nominate(&local, &remote).unwrap();
        assert_eq!(selected.local.candidate_type, CandidateType::Host);
        assert_eq!(selected.remote.candidate_type, CandidateType::Host);
    }
}
