#![allow(dead_code)]

use qlink_core::{
    crypto::DeviceKeypair,
    discovery::{CandidateEndpoint, CandidateType, PeerRecord, UnsignedPeerRecord},
    error::Result,
    ice::IceCredentials,
    mesh_connection::{MeshConnector, MeshConnectorConfig},
    quic_transport::QuicEndpoint,
    relay::{spawn_dev_relay, DevRelayServer},
    rendezvous::{spawn_dev_rendezvous, DevRendezvousServer, RendezvousClient},
    synthetic_wan::{WanProfile, WanProxy},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{net::UdpSocket, task::JoinHandle};

const MESH_ID: &str = "devmesh";
const REMOTE_ROUTE: &str = "100.127.0.10/32";

pub struct BenchEnv {
    pub connector: MeshConnector,
    pub remote_peer_id: String,
    _rendezvous: DevRendezvousServer,
    _relay: Option<DevRelayServer>,
    _accept_loop: Option<JoinHandle<()>>,
    _wan_proxy: Option<WanProxy>,
    _blackhole_socket: Option<UdpSocket>,
}

pub struct Percentiles {
    n: usize,
    pub p50: Duration,
    p90: Duration,
    p99: Duration,
    max: Duration,
}

impl Percentiles {
    pub fn print(&self, label: &str) {
        println!(
            "{label}: n={} p50={:.1}ms p90={:.1}ms p99={:.1}ms max={:.1}ms",
            self.n,
            duration_ms(self.p50),
            duration_ms(self.p90),
            duration_ms(self.p99),
            duration_ms(self.max)
        );
    }
}

pub fn fresh_ice_credentials() -> IceCredentials {
    IceCredentials::generate().expect("ICE credential generation requires entropy")
}

pub fn percentiles(mut samples: Vec<Duration>) -> Percentiles {
    assert!(
        !samples.is_empty(),
        "cannot compute percentiles without samples"
    );
    samples.sort_unstable();
    let n = samples.len();
    Percentiles {
        n,
        p50: percentile(&samples, 0.50),
        p90: percentile(&samples, 0.90),
        p99: percentile(&samples, 0.99),
        max: samples[n - 1],
    }
}

pub async fn build_direct_env(probe_ms: u64, deadline_ms: u64) -> BenchEnv {
    build_direct_env_inner(probe_ms, deadline_ms, None).await
}

pub async fn build_direct_env_via_wan(
    probe_ms: u64,
    deadline_ms: u64,
    profile: WanProfile,
) -> BenchEnv {
    build_direct_env_inner(probe_ms, deadline_ms, Some(profile)).await
}

pub async fn build_relay_only_env(probe_ms: u64, deadline_ms: u64) -> BenchEnv {
    build_relay_only_env_inner(probe_ms, deadline_ms, None).await
}

pub async fn build_relay_only_env_via_wan(
    probe_ms: u64,
    deadline_ms: u64,
    profile: WanProfile,
) -> BenchEnv {
    build_relay_only_env_inner(probe_ms, deadline_ms, Some(profile)).await
}

async fn build_direct_env_inner(
    probe_ms: u64,
    deadline_ms: u64,
    wan_profile: Option<WanProfile>,
) -> BenchEnv {
    let rendezvous = spawn_dev_rendezvous().await.expect("dev rendezvous");
    let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());
    let bind = loopback_ephemeral();
    let (server_endpoint, server_cert) = QuicEndpoint::server(bind).expect("QUIC server");
    let server_addr = server_endpoint.local_addr().expect("QUIC server address");
    let certificate_der = server_cert.as_der().to_vec();
    let accept_loop = spawn_accept_loop(server_endpoint);
    let (candidate_addr, wan_proxy) = match wan_profile {
        Some(profile) => {
            let proxy = WanProxy::between(server_addr, profile)
                .await
                .expect("WAN proxy");
            (proxy.client_facing_addr(), Some(proxy))
        }
        None => (server_addr, None),
    };

    let (connector, remote_peer_id) = publish_env_connector(
        rendezvous_client,
        candidate_addr,
        certificate_der,
        probe_ms,
        deadline_ms,
        None,
    )
    .await
    .expect("direct benchmark environment");

    BenchEnv {
        connector,
        remote_peer_id,
        _rendezvous: rendezvous,
        _relay: None,
        _accept_loop: Some(accept_loop),
        _wan_proxy: wan_proxy,
        _blackhole_socket: None,
    }
}

async fn build_relay_only_env_inner(
    probe_ms: u64,
    deadline_ms: u64,
    wan_profile: Option<WanProfile>,
) -> BenchEnv {
    let rendezvous = spawn_dev_rendezvous().await.expect("dev rendezvous");
    let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());
    let relay = spawn_dev_relay().await.expect("dev relay");
    let relay_addr = relay.local_addr();

    let bind = loopback_ephemeral();
    let (throwaway_endpoint, throwaway_cert) =
        QuicEndpoint::server(bind).expect("throwaway QUIC cert");
    drop(throwaway_endpoint);
    let certificate_der = throwaway_cert.as_der().to_vec();

    let (candidate_addr, wan_proxy, blackhole_socket) = match wan_profile {
        Some(profile) => {
            let blackhole = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("blackhole UDP socket");
            let proxy =
                WanProxy::between(blackhole.local_addr().expect("blackhole address"), profile)
                    .await
                    .expect("WAN proxy");
            (proxy.client_facing_addr(), Some(proxy), Some(blackhole))
        }
        None => (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            None,
            None,
        ),
    };

    let (connector, remote_peer_id) = publish_env_connector(
        rendezvous_client,
        candidate_addr,
        certificate_der,
        probe_ms,
        deadline_ms,
        Some(relay_addr.to_string()),
    )
    .await
    .expect("relay benchmark environment");

    BenchEnv {
        connector,
        remote_peer_id,
        _rendezvous: rendezvous,
        _relay: Some(relay),
        _accept_loop: None,
        _wan_proxy: wan_proxy,
        _blackhole_socket: blackhole_socket,
    }
}

async fn publish_env_connector(
    rendezvous_client: RendezvousClient,
    candidate_addr: SocketAddr,
    certificate_der: Vec<u8>,
    probe_ms: u64,
    deadline_ms: u64,
    relay_server: Option<String>,
) -> Result<(MeshConnector, String)> {
    let local_key = DeviceKeypair::generate()?;
    let remote_key = DeviceKeypair::generate()?;
    let remote_peer_id = remote_key.public_key().peer_id();

    let record = signed_record_with_cert(
        &remote_key,
        vec![CandidateEndpoint {
            candidate_type: CandidateType::Host,
            address: candidate_addr.ip().to_string(),
            port: candidate_addr.port(),
            priority: 120,
        }],
        1,
        certificate_der,
    )?;
    rendezvous_client.publish(MESH_ID, record).await?;

    let mut config = MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
        .with_direct_probe_timeout(Duration::from_millis(probe_ms))
        .with_overall_deadline(Duration::from_millis(deadline_ms));
    if let Some(relay_server) = relay_server {
        config = config.with_relay_server(relay_server);
    }

    let client_endpoint = QuicEndpoint::client(loopback_ephemeral(), &[])?;
    Ok((
        MeshConnector::new(config, rendezvous_client, client_endpoint),
        remote_peer_id,
    ))
}

fn signed_record_with_cert(
    keypair: &DeviceKeypair,
    endpoints: Vec<CandidateEndpoint>,
    sequence: u64,
    certificate_der: Vec<u8>,
) -> Result<PeerRecord> {
    let unsigned = UnsignedPeerRecord::new(
        MESH_ID,
        "remote-peer",
        keypair.public_key(),
        endpoints,
        vec![REMOTE_ROUTE.to_string()],
        60,
        sequence,
    )
    .with_device_certificate(certificate_der);
    PeerRecord::signed(unsigned, keypair)
}

fn spawn_accept_loop(server_endpoint: QuicEndpoint) -> JoinHandle<()> {
    tokio::spawn(async move {
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
    })
}

fn loopback_ephemeral() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn percentile(samples: &[Duration], percentile: f64) -> Duration {
    let index = ((samples.len() as f64 - 1.0) * percentile).round() as usize;
    samples[index]
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}
