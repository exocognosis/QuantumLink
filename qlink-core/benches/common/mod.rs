//! Shared bench fixtures: spin up a dev rendezvous + dev relay + a "remote
//! peer" QUIC server + accept loop. Returns a configured `MeshConnector`
//! ready to call `.connect(&remote_peer_id)` against.
//!
//! Used by all three bench targets; living in `benches/common/mod.rs` keeps
//! the per-bench files focused on what they actually measure.

#![allow(dead_code)]

use qlink_core::{
    carrier_transport::CarrierSession,
    crypto::DeviceKeypair,
    discovery::{CandidateEndpoint, CandidateType, PeerRecord, UnsignedPeerRecord},
    ice::IceCredentials,
    inbound_identity::{
        receive_and_evaluate_inbound, InboundDecision, DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS,
    },
    mesh_connection::{MeshConnector, MeshConnectorConfig},
    pqc_session_wire::run_pqc_session_responder,
    quic_transport::QuicEndpoint,
    relay::{spawn_dev_relay, RelayResponderListener},
    rendezvous::{spawn_dev_rendezvous, RendezvousClient},
    session_crypto::PqcSessionContext,
    synthetic_wan::{WanProfile, WanProxy},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::task::JoinHandle;

pub const MESH_ID: &str = "bench-mesh";

pub struct DirectEnv {
    pub connector: Arc<MeshConnector>,
    pub remote_peer_id: String,
    /// Held to keep the rendezvous + relay + accept loop alive for the
    /// duration of the bench group.
    _rendezvous: qlink_core::rendezvous::DevRendezvousServer,
    _relay: qlink_core::relay::DevRelayServer,
    _accept_loop: JoinHandle<()>,
    _relay_responder: JoinHandle<()>,
    /// Held when the environment is running through a synthetic WAN
    /// proxy. Drop tears down the forwarding tasks. `None` for plain
    /// loopback environments.
    _wan_proxy: Option<WanProxy>,
}

pub async fn build_direct_env(probe_ms: u64, deadline_ms: u64) -> DirectEnv {
    let rendezvous = spawn_dev_rendezvous().await.unwrap();
    let relay = spawn_dev_relay().await.unwrap();
    let relay_addr = relay.local_addr().to_string();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    let server_cert_der = server_cert.as_der().to_vec();
    let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
    let remote_peer_id = remote_key.public_key().peer_id();
    // Empty trust list — connector uses per-connect cert pulled from the
    // signed peer record below.
    let client_endpoint = QuicEndpoint::client(bind, &[]).unwrap();
    drop(server_cert);

    let accept_loop =
        spawn_pqc_drain_accept_loop(server_endpoint, remote_key.clone(), server_cert_der.clone());
    let relay_responder = spawn_relay_pqc_responder(
        relay_addr.clone(),
        remote_key.clone(),
        server_cert_der.clone(),
    );

    let unsigned = UnsignedPeerRecord::new(
        MESH_ID,
        "bench-remote",
        remote_key.public_key(),
        vec![CandidateEndpoint {
            candidate_type: CandidateType::Host,
            address: server_addr.ip().to_string(),
            port: server_addr.port(),
            priority: 120,
        }],
        vec!["100.127.0.10/32".to_string()],
        300,
        1,
    )
    .with_device_certificate(server_cert_der);
    let record = PeerRecord::signed(unsigned, remote_key.as_ref()).unwrap();
    let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
    publisher.publish(MESH_ID, record).await.unwrap();

    let local_key = Arc::new(DeviceKeypair::generate().unwrap());
    let local_peer_id = local_key.public_key().peer_id();
    let connector = Arc::new(MeshConnector::new(
        MeshConnectorConfig::new(MESH_ID, local_peer_id)
            .with_direct_probe_timeout(Duration::from_millis(probe_ms))
            .with_overall_deadline(Duration::from_millis(deadline_ms))
            .with_probe_pacing(Duration::from_millis(50))
            .with_relay_server(relay_addr)
            .with_local_device_keypair(local_key.clone()),
        RendezvousClient::new(rendezvous.local_addr().to_string()),
        client_endpoint,
    ));

    DirectEnv {
        connector,
        remote_peer_id,
        _rendezvous: rendezvous,
        _relay: relay,
        _accept_loop: accept_loop,
        _relay_responder: relay_responder,
        _wan_proxy: None,
    }
}

/// Same as `build_direct_env` but inserts a [`WanProxy`] between the
/// connector and the QUIC server. The candidate published in the
/// rendezvous record points at the proxy's client-facing port, so the
/// connector dials the proxy. The proxy then forwards (with delay / loss
/// / jitter per `profile`) to the actual QUIC server.
///
/// Use this for SLO scenarios that want realistic network conditions.
pub async fn build_direct_env_via_wan(
    probe_ms: u64,
    deadline_ms: u64,
    profile: WanProfile,
) -> DirectEnv {
    let rendezvous = spawn_dev_rendezvous().await.unwrap();
    let relay = spawn_dev_relay().await.unwrap();
    let relay_addr = relay.local_addr().to_string();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    let server_cert_der = server_cert.as_der().to_vec();
    let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
    let remote_peer_id = remote_key.public_key().peer_id();
    let client_endpoint = QuicEndpoint::client(bind, &[]).unwrap();
    drop(server_cert);

    // Stand up the impairment proxy between the connector and the QUIC
    // server. The proxy's `client_facing_addr` is what gets published in
    // the rendezvous record.
    let wan_proxy = WanProxy::between(server_addr, profile).await.unwrap();
    let advertised_addr = wan_proxy.client_facing_addr();

    let accept_loop =
        spawn_pqc_drain_accept_loop(server_endpoint, remote_key.clone(), server_cert_der.clone());
    let relay_responder = spawn_relay_pqc_responder(
        relay_addr.clone(),
        remote_key.clone(),
        server_cert_der.clone(),
    );

    let unsigned = UnsignedPeerRecord::new(
        MESH_ID,
        "bench-remote-wan",
        remote_key.public_key(),
        vec![CandidateEndpoint {
            candidate_type: CandidateType::Host,
            address: advertised_addr.ip().to_string(),
            port: advertised_addr.port(),
            priority: 120,
        }],
        vec!["100.127.0.10/32".to_string()],
        300,
        1,
    )
    .with_device_certificate(server_cert_der);
    let record = PeerRecord::signed(unsigned, remote_key.as_ref()).unwrap();
    let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
    publisher.publish(MESH_ID, record).await.unwrap();

    let local_key = Arc::new(DeviceKeypair::generate().unwrap());
    let local_peer_id = local_key.public_key().peer_id();
    let connector = Arc::new(MeshConnector::new(
        MeshConnectorConfig::new(MESH_ID, local_peer_id)
            .with_direct_probe_timeout(Duration::from_millis(probe_ms))
            .with_overall_deadline(Duration::from_millis(deadline_ms))
            .with_probe_pacing(Duration::from_millis(50))
            .with_relay_server(relay_addr)
            .with_local_device_keypair(local_key.clone()),
        RendezvousClient::new(rendezvous.local_addr().to_string()),
        client_endpoint,
    ));

    DirectEnv {
        connector,
        remote_peer_id,
        _rendezvous: rendezvous,
        _relay: relay,
        _accept_loop: accept_loop,
        _relay_responder: relay_responder,
        _wan_proxy: Some(wan_proxy),
    }
}

pub struct RelayOnlyEnv {
    pub connector: Arc<MeshConnector>,
    pub remote_peer_id: String,
    _rendezvous: qlink_core::rendezvous::DevRendezvousServer,
    _relay: qlink_core::relay::DevRelayServer,
    _relay_responder: JoinHandle<()>,
    _wan_proxy: Option<WanProxy>,
}

/// Environment where the advertised host candidate is unreachable, forcing
/// the connector to fall back to relay. The probe timeout intentionally
/// stays short so each iteration spends only ~direct_probe_timeout failing
/// the direct path before opening the relay link.
pub async fn build_relay_only_env(probe_ms: u64, deadline_ms: u64) -> RelayOnlyEnv {
    let rendezvous = spawn_dev_rendezvous().await.unwrap();
    let relay = spawn_dev_relay().await.unwrap();
    let relay_addr = relay.local_addr().to_string();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (_unused_server, server_cert) = QuicEndpoint::server(bind).unwrap();
    let server_cert_der = server_cert.as_der().to_vec();
    let client_endpoint = QuicEndpoint::client(bind, &[]).unwrap();

    let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
    let remote_peer_id = remote_key.public_key().peer_id();
    let relay_responder = spawn_relay_pqc_responder(
        relay_addr.clone(),
        remote_key.clone(),
        server_cert_der.clone(),
    );
    let unsigned = UnsignedPeerRecord::new(
        MESH_ID,
        "bench-remote-relay",
        remote_key.public_key(),
        vec![CandidateEndpoint {
            // Fast local refusal: the SLO measures relay activation, not
            // route-level timeout behavior for unroutable documentation IPs.
            candidate_type: CandidateType::Host,
            address: "127.0.0.1".to_string(),
            port: 1,
            priority: 120,
        }],
        vec!["100.127.0.20/32".to_string()],
        300,
        1,
    )
    .with_device_certificate(server_cert_der);
    let record = PeerRecord::signed(unsigned, remote_key.as_ref()).unwrap();
    let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
    publisher.publish(MESH_ID, record).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let local_key = Arc::new(DeviceKeypair::generate().unwrap());
    let connector = Arc::new(MeshConnector::new(
        MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
            .with_direct_probe_timeout(Duration::from_millis(probe_ms))
            .with_overall_deadline(Duration::from_millis(deadline_ms))
            .with_probe_pacing(Duration::from_millis(50))
            .with_relay_server(relay_addr)
            .with_local_device_keypair(local_key.clone()),
        RendezvousClient::new(rendezvous.local_addr().to_string()),
        client_endpoint,
    ));

    RelayOnlyEnv {
        connector,
        remote_peer_id,
        _rendezvous: rendezvous,
        _relay: relay,
        _relay_responder: relay_responder,
        _wan_proxy: None,
    }
}

/// `RelayOnlyEnv` variant whose direct candidate is exposed through a
/// `WanProxy`. The direct probe still fails (the candidate points at an
/// unreachable port via the proxy) but at realistic latency, so the
/// fallback timer behaves the way it would on a real WAN.
pub async fn build_relay_only_env_via_wan(
    probe_ms: u64,
    deadline_ms: u64,
    profile: WanProfile,
) -> RelayOnlyEnv {
    // Stand up a "blackhole" UDP socket that accepts but never replies.
    // Putting the proxy in front of it gives us delayed-then-dropped
    // probe behavior, mimicking a candidate behind a strict firewall.
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let blackhole_addr = blackhole.local_addr().unwrap();
    // Hold the socket alive for the lifetime of the env so the OS
    // doesn't reassign the port; we just never read or reply.
    std::mem::forget(blackhole);
    let wan_proxy = WanProxy::between(blackhole_addr, profile).await.unwrap();
    let advertised_addr = wan_proxy.client_facing_addr();

    let rendezvous = spawn_dev_rendezvous().await.unwrap();
    let relay = spawn_dev_relay().await.unwrap();
    let relay_addr = relay.local_addr().to_string();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (_unused_server, server_cert) = QuicEndpoint::server(bind).unwrap();
    let server_cert_der = server_cert.as_der().to_vec();
    let client_endpoint = QuicEndpoint::client(bind, &[]).unwrap();

    let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
    let remote_peer_id = remote_key.public_key().peer_id();
    let relay_responder = spawn_relay_pqc_responder(
        relay_addr.clone(),
        remote_key.clone(),
        server_cert_der.clone(),
    );
    let unsigned = UnsignedPeerRecord::new(
        MESH_ID,
        "bench-remote-relay-wan",
        remote_key.public_key(),
        vec![CandidateEndpoint {
            candidate_type: CandidateType::Host,
            address: advertised_addr.ip().to_string(),
            port: advertised_addr.port(),
            priority: 120,
        }],
        vec!["100.127.0.20/32".to_string()],
        300,
        1,
    )
    .with_device_certificate(server_cert_der);
    let record = PeerRecord::signed(unsigned, remote_key.as_ref()).unwrap();
    let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
    publisher.publish(MESH_ID, record).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let local_key = Arc::new(DeviceKeypair::generate().unwrap());
    let connector = Arc::new(MeshConnector::new(
        MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
            .with_direct_probe_timeout(Duration::from_millis(probe_ms))
            .with_overall_deadline(Duration::from_millis(deadline_ms))
            .with_probe_pacing(Duration::from_millis(50))
            .with_relay_server(relay_addr)
            .with_local_device_keypair(local_key.clone()),
        RendezvousClient::new(rendezvous.local_addr().to_string()),
        client_endpoint,
    ));

    RelayOnlyEnv {
        connector,
        remote_peer_id,
        _rendezvous: rendezvous,
        _relay: relay,
        _relay_responder: relay_responder,
        _wan_proxy: Some(wan_proxy),
    }
}

fn spawn_pqc_drain_accept_loop(
    server_endpoint: QuicEndpoint,
    responder_keypair: Arc<DeviceKeypair>,
    server_cert_der: Vec<u8>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match server_endpoint.accept_one().await {
                Ok(session) => {
                    let session = CarrierSession::from(session);
                    let responder_keypair = responder_keypair.clone();
                    let server_cert_der = server_cert_der.clone();
                    tokio::spawn(async move {
                        let Ok((InboundDecision::Accepted, assertion)) =
                            receive_and_evaluate_inbound(
                                &session,
                                MESH_ID,
                                DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS,
                                None,
                            )
                            .await
                        else {
                            session.close(b"");
                            return;
                        };
                        let context = PqcSessionContext::new(
                            MESH_ID,
                            assertion.peer_id,
                            responder_keypair.public_key().peer_id(),
                            server_cert_der,
                        );
                        if run_pqc_session_responder(&session, context, responder_keypair.as_ref())
                            .await
                            .is_err()
                        {
                            session.close(b"");
                            return;
                        }
                        // Bench scenarios stop at connection establishment.
                        // Returning here drops this responder-side session so
                        // repeated connects from the same local peer get a
                        // fresh demux session instead of reusing stale state.
                    });
                }
                Err(_) => break,
            }
        }
    })
}

fn spawn_relay_pqc_responder(
    relay_addr: String,
    responder_keypair: Arc<DeviceKeypair>,
    server_cert_der: Vec<u8>,
) -> JoinHandle<()> {
    let local_peer_id = responder_keypair.public_key().peer_id();
    tokio::spawn(async move {
        let _ = RelayResponderListener::run(&relay_addr, local_peer_id.clone(), move |session| {
            let responder_keypair = responder_keypair.clone();
            let server_cert_der = server_cert_der.clone();
            let local_peer_id = local_peer_id.clone();
            tokio::spawn(async move {
                let session = CarrierSession::from(session);
                let Ok((InboundDecision::Accepted, assertion)) = receive_and_evaluate_inbound(
                    &session,
                    MESH_ID,
                    DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS,
                    None,
                )
                .await
                else {
                    session.close(b"");
                    return;
                };
                let context = PqcSessionContext::new(
                    MESH_ID,
                    assertion.peer_id,
                    local_peer_id,
                    server_cert_der,
                );
                if run_pqc_session_responder(&session, context, responder_keypair.as_ref())
                    .await
                    .is_err()
                {
                    session.close(b"");
                }
            });
        })
        .await;
    })
}

/// Helper for SLO scenario harnesses: collects N samples, returns sorted
/// durations so callers can compute their own percentiles + assert SLOs.
pub fn percentiles(mut samples: Vec<Duration>) -> Percentiles {
    samples.sort();
    let n = samples.len();
    let p = |q: f64| -> Duration {
        if n == 0 {
            Duration::ZERO
        } else {
            let idx = ((n as f64 - 1.0) * q).round() as usize;
            samples[idx.min(n - 1)]
        }
    };
    Percentiles {
        p50: p(0.50),
        p90: p(0.90),
        p99: p(0.99),
        max: samples.last().copied().unwrap_or_default(),
        n,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Percentiles {
    pub p50: Duration,
    pub p90: Duration,
    pub p99: Duration,
    pub max: Duration,
    pub n: usize,
}

impl Percentiles {
    pub fn print(&self, label: &str) {
        println!(
            "{label}: n={} p50={:.1?} p90={:.1?} p99={:.1?} max={:.1?}",
            self.n, self.p50, self.p90, self.p99, self.max
        );
    }
}

/// Minimal IceCredentials helper for the ICE bench.
pub fn fresh_ice_credentials() -> IceCredentials {
    IceCredentials::generate().unwrap()
}
