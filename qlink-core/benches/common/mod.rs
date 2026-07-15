//! Shared bench fixtures: spin up a dev rendezvous + dev relay + a "remote
//! peer" QUIC server + accept loop. Returns a configured `MeshConnector`
//! ready to call `.connect(&remote_peer_id)` against.
//!
//! Used by all three bench targets; living in `benches/common/mod.rs` keeps
//! the per-bench files focused on what they actually measure.

#![allow(dead_code)]

use qlink_core::{
    crypto::DeviceKeypair,
    discovery::{CandidateEndpoint, CandidateType, PeerRecord, UnsignedPeerRecord},
    ice::IceCredentials,
    mesh_connection::{MeshConnector, MeshConnectorConfig},
    quic_transport::QuicEndpoint,
    relay::spawn_dev_relay,
    rendezvous::{spawn_dev_rendezvous, RendezvousClient},
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
    /// Held when the environment is running through a synthetic WAN
    /// proxy. Drop tears down the forwarding tasks. `None` for plain
    /// loopback environments.
    _wan_proxy: Option<WanProxy>,
}

pub async fn build_direct_env(probe_ms: u64, deadline_ms: u64) -> DirectEnv {
    let rendezvous = spawn_dev_rendezvous().await.unwrap();
    let relay = spawn_dev_relay().await.unwrap();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    let server_cert_der = server_cert.as_der().to_vec();
    // Empty trust list — connector uses per-connect cert pulled from the
    // signed peer record below.
    let client_endpoint = QuicEndpoint::client(bind, &[]).unwrap();
    drop(server_cert);

    // Accept loop: each incoming QUIC connection just reads frames so the
    // handshake completes; bench measurements stop at "connector returns a
    // live MeshLink", which already implies a successful QUIC handshake.
    let accept_loop = tokio::spawn(async move {
        loop {
            match server_endpoint.accept_one().await {
                Ok(session) => {
                    tokio::spawn(async move {
                        let _ = session.receive_frame().await;
                    });
                }
                Err(_) => break,
            }
        }
    });

    let remote_key = DeviceKeypair::generate().unwrap();
    let remote_peer_id = remote_key.public_key().peer_id();
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
    let record = PeerRecord::signed(unsigned, &remote_key).unwrap();
    let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
    publisher.publish(MESH_ID, record).await.unwrap();

    let local_key = Arc::new(DeviceKeypair::generate().unwrap());
    let local_peer_id = local_key.public_key().peer_id();
    let connector = Arc::new(MeshConnector::new(
        MeshConnectorConfig::new(MESH_ID, local_peer_id)
            .with_direct_probe_timeout(Duration::from_millis(probe_ms))
            .with_overall_deadline(Duration::from_millis(deadline_ms))
            .with_probe_pacing(Duration::from_millis(50))
            .with_relay_server(relay.local_addr().to_string())
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
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    let server_cert_der = server_cert.as_der().to_vec();
    let client_endpoint = QuicEndpoint::client(bind, &[]).unwrap();
    drop(server_cert);

    // Stand up the impairment proxy between the connector and the QUIC
    // server. The proxy's `client_facing_addr` is what gets published in
    // the rendezvous record.
    let wan_proxy = WanProxy::between(server_addr, profile).await.unwrap();
    let advertised_addr = wan_proxy.client_facing_addr();

    let accept_loop = tokio::spawn(async move {
        loop {
            match server_endpoint.accept_one().await {
                Ok(session) => {
                    tokio::spawn(async move {
                        let _ = session.receive_frame().await;
                    });
                }
                Err(_) => break,
            }
        }
    });

    let remote_key = DeviceKeypair::generate().unwrap();
    let remote_peer_id = remote_key.public_key().peer_id();
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
    let record = PeerRecord::signed(unsigned, &remote_key).unwrap();
    let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
    publisher.publish(MESH_ID, record).await.unwrap();

    let local_key = Arc::new(DeviceKeypair::generate().unwrap());
    let local_peer_id = local_key.public_key().peer_id();
    let connector = Arc::new(MeshConnector::new(
        MeshConnectorConfig::new(MESH_ID, local_peer_id)
            .with_direct_probe_timeout(Duration::from_millis(probe_ms))
            .with_overall_deadline(Duration::from_millis(deadline_ms))
            .with_probe_pacing(Duration::from_millis(50))
            .with_relay_server(relay.local_addr().to_string())
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
        _wan_proxy: Some(wan_proxy),
    }
}

pub struct RelayOnlyEnv {
    pub connector: Arc<MeshConnector>,
    pub remote_peer_id: String,
    _rendezvous: qlink_core::rendezvous::DevRendezvousServer,
    _relay: qlink_core::relay::DevRelayServer,
}

/// Environment where the advertised host candidate is unreachable, forcing
/// the connector to fall back to relay. The probe timeout intentionally
/// stays short so each iteration spends only ~direct_probe_timeout failing
/// the direct path before opening the relay link.
pub async fn build_relay_only_env(probe_ms: u64, deadline_ms: u64) -> RelayOnlyEnv {
    let rendezvous = spawn_dev_rendezvous().await.unwrap();
    let relay = spawn_dev_relay().await.unwrap();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (_unused_server, server_cert) = QuicEndpoint::server(bind).unwrap();
    let server_cert_der = server_cert.as_der().to_vec();
    let client_endpoint = QuicEndpoint::client(bind, &[]).unwrap();

    let remote_key = DeviceKeypair::generate().unwrap();
    let remote_peer_id = remote_key.public_key().peer_id();
    let unsigned = UnsignedPeerRecord::new(
        MESH_ID,
        "bench-remote-relay",
        remote_key.public_key(),
        vec![CandidateEndpoint {
            // RFC 5737 TEST-NET-1 — guaranteed unreachable.
            candidate_type: CandidateType::Host,
            address: "192.0.2.1".to_string(),
            port: 4433,
            priority: 120,
        }],
        vec!["100.127.0.20/32".to_string()],
        300,
        1,
    )
    .with_device_certificate(server_cert_der);
    let record = PeerRecord::signed(unsigned, &remote_key).unwrap();
    let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
    publisher.publish(MESH_ID, record).await.unwrap();

    let local_key = Arc::new(DeviceKeypair::generate().unwrap());
    let connector = Arc::new(MeshConnector::new(
        MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
            .with_direct_probe_timeout(Duration::from_millis(probe_ms))
            .with_overall_deadline(Duration::from_millis(deadline_ms))
            .with_probe_pacing(Duration::from_millis(50))
            .with_relay_server(relay.local_addr().to_string())
            .with_local_device_keypair(local_key.clone()),
        RendezvousClient::new(rendezvous.local_addr().to_string()),
        client_endpoint,
    ));

    RelayOnlyEnv {
        connector,
        remote_peer_id,
        _rendezvous: rendezvous,
        _relay: relay,
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
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (_unused_server, server_cert) = QuicEndpoint::server(bind).unwrap();
    let server_cert_der = server_cert.as_der().to_vec();
    let client_endpoint = QuicEndpoint::client(bind, &[]).unwrap();

    let remote_key = DeviceKeypair::generate().unwrap();
    let remote_peer_id = remote_key.public_key().peer_id();
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
    let record = PeerRecord::signed(unsigned, &remote_key).unwrap();
    let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
    publisher.publish(MESH_ID, record).await.unwrap();

    let local_key = Arc::new(DeviceKeypair::generate().unwrap());
    let connector = Arc::new(MeshConnector::new(
        MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
            .with_direct_probe_timeout(Duration::from_millis(probe_ms))
            .with_overall_deadline(Duration::from_millis(deadline_ms))
            .with_probe_pacing(Duration::from_millis(50))
            .with_relay_server(relay.local_addr().to_string())
            .with_local_device_keypair(local_key.clone()),
        RendezvousClient::new(rendezvous.local_addr().to_string()),
        client_endpoint,
    ));

    // Keep the proxy alive in the closure-captured scope. We don't have
    // a field for it on RelayOnlyEnv, so leak it — bench environments
    // are short-lived.
    Box::leak(Box::new(wan_proxy));

    RelayOnlyEnv {
        connector,
        remote_peer_id,
        _rendezvous: rendezvous,
        _relay: relay,
    }
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
