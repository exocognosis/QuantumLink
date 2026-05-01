use crate::{
    crypto::DeviceKeypair,
    discovery::{CandidateEndpoint, CandidateType, PeerRecord, UnsignedPeerRecord},
    error::{QlinkError, Result},
    packet_core::{FfiRouteMode, PacketTunnelCore, PacketTunnelCoreConfig},
    quic_transport::QuicEndpoint,
    relay::{spawn_dev_relay, RelayClient},
    rendezvous::{spawn_dev_rendezvous, RendezvousClient},
    traversal::{relay_candidate, PathSelector},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

const DEV_MESH_ID: &str = "devmesh";
const DEV_ROUTE: &str = "100.127.0.0/16";

#[derive(Debug, Clone)]
pub struct MeshLoopbackResult {
    pub rendezvous_addr: SocketAddr,
    pub local_peer_id: String,
    pub remote_peer_id: String,
    pub quic_server_addr: SocketAddr,
    pub selected_path_type: CandidateType,
    pub selected_path_score: u32,
    pub protocol_family: u32,
    pub packet_bytes: usize,
    pub packet_round_trip: bool,
}

#[derive(Debug, Clone)]
pub struct RelayLoopbackResult {
    pub relay_addr: SocketAddr,
    pub source_peer_id: String,
    pub destination_peer_id: String,
    pub protocol_family: u32,
    pub packet_bytes: usize,
    pub packet_round_trip: bool,
}

pub async fn run_local_mesh_loopback() -> Result<MeshLoopbackResult> {
    let rendezvous = spawn_dev_rendezvous().await?;
    let rendezvous_addr = rendezvous.local_addr();
    let rendezvous_client = RendezvousClient::new(rendezvous_addr.to_string());

    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (server_endpoint, server_cert) = QuicEndpoint::server(bind)?;
    let quic_server_addr = server_endpoint.local_addr()?;
    let client_endpoint = QuicEndpoint::client(bind, &[server_cert])?;
    let quic_client_addr = client_endpoint.local_addr()?;

    let local_key = DeviceKeypair::generate()?;
    let remote_key = DeviceKeypair::generate()?;
    let local_candidates = vec![relay_candidate(quic_client_addr)];
    let remote_candidates = vec![relay_candidate(quic_server_addr)];

    let local_record = signed_dev_record(
        "local-mac",
        &local_key,
        local_candidates.clone(),
        vec!["100.127.0.2/32".to_string()],
        1,
    )?;
    let remote_record = signed_dev_record(
        "remote-mac",
        &remote_key,
        remote_candidates,
        vec!["100.127.0.10/32".to_string()],
        1,
    )?;
    let local_peer_id = local_record.body.peer_id.clone();
    let remote_peer_id = remote_record.body.peer_id.clone();

    rendezvous_client
        .publish(DEV_MESH_ID, local_record.clone())
        .await?;
    rendezvous_client
        .publish(DEV_MESH_ID, remote_record)
        .await?;

    let found_remote = rendezvous_client
        .lookup(DEV_MESH_ID, &remote_peer_id)
        .await?
        .ok_or_else(|| QlinkError::Protocol("remote peer was not found in rendezvous".into()))?;
    found_remote.verify(DEV_MESH_ID)?;

    let selected = PathSelector::default()
        .nominate(&local_candidates, &found_remote.body.endpoints)
        .ok_or_else(|| QlinkError::Protocol("no candidate pair was nominated".into()))?;
    let selected_path_type = selected.remote.candidate_type.clone();
    let selected_path_score = selected.score;
    let remote_addr = endpoint_socket_addr(&selected.remote)?;

    let (client_session, server_session) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            client_endpoint.connect(remote_addr),
            server_endpoint.accept_one()
        )
    })
    .await
    .map_err(|_| QlinkError::Protocol("mesh loopback QUIC connection timed out".into()))?;
    let client_session = client_session?;
    let server_session = server_session?;

    let mut sender = dev_packet_core()?;
    let mut receiver = dev_packet_core()?;
    let packet = test_ipv4_packet([100, 127, 0, 10]);
    sender.submit_tunnel_packet(2, &packet)?;
    let frame = sender
        .pop_transport_frame()
        .ok_or_else(|| QlinkError::Protocol("packet core produced no transport frame".into()))?;

    client_session.send_frame(frame).await?;
    let received_frame = server_session.receive_frame().await?;
    receiver.accept_transport_frame(&received_frame)?;
    let restored = receiver
        .pop_tunnel_packet()
        .ok_or_else(|| QlinkError::Protocol("receiver produced no tunnel packet".into()))?;

    client_session.close(b"mesh loopback complete");
    server_session.close(b"mesh loopback complete");

    Ok(MeshLoopbackResult {
        rendezvous_addr,
        local_peer_id,
        remote_peer_id,
        quic_server_addr,
        selected_path_type,
        selected_path_score,
        protocol_family: restored.protocol_family,
        packet_bytes: restored.bytes.len(),
        packet_round_trip: normalized_packet_matches(&restored.bytes, &packet),
    })
}

pub async fn run_relay_loopback() -> Result<RelayLoopbackResult> {
    let relay = spawn_dev_relay().await?;
    let relay_addr = relay.local_addr();

    let alice_key = DeviceKeypair::generate()?;
    let bob_key = DeviceKeypair::generate()?;
    let source_peer_id = alice_key.public_key().peer_id();
    let destination_peer_id = bob_key.public_key().peer_id();

    let mut alice = RelayClient::connect(&relay_addr.to_string(), source_peer_id.clone()).await?;
    let mut bob =
        RelayClient::connect(&relay_addr.to_string(), destination_peer_id.clone()).await?;

    let mut sender = dev_packet_core()?;
    let mut receiver = dev_packet_core()?;
    let packet = test_ipv4_packet([100, 127, 0, 10]);
    sender.submit_tunnel_packet(2, &packet)?;
    let frame = sender
        .pop_transport_frame()
        .ok_or_else(|| QlinkError::Protocol("packet core produced no transport frame".into()))?;

    alice.send_datagram(&destination_peer_id, &frame).await?;
    let (relay_source, received_frame) =
        tokio::time::timeout(Duration::from_secs(5), bob.receive_datagram())
            .await
            .map_err(|_| QlinkError::Protocol("relay loopback timed out".into()))??
            .ok_or_else(|| QlinkError::Protocol("relay closed before delivering packet".into()))?;
    if relay_source != source_peer_id {
        return Err(QlinkError::Protocol(
            "relay datagram source mismatch".into(),
        ));
    }

    receiver.accept_transport_frame(&received_frame)?;
    let restored = receiver
        .pop_tunnel_packet()
        .ok_or_else(|| QlinkError::Protocol("receiver produced no tunnel packet".into()))?;

    Ok(RelayLoopbackResult {
        relay_addr,
        source_peer_id,
        destination_peer_id,
        protocol_family: restored.protocol_family,
        packet_bytes: restored.bytes.len(),
        packet_round_trip: normalized_packet_matches(&restored.bytes, &packet),
    })
}

fn signed_dev_record(
    alias: &str,
    keypair: &DeviceKeypair,
    endpoints: Vec<CandidateEndpoint>,
    routes: Vec<String>,
    sequence: u64,
) -> Result<PeerRecord> {
    PeerRecord::signed(
        UnsignedPeerRecord::new(
            DEV_MESH_ID,
            alias,
            keypair.public_key(),
            endpoints,
            routes,
            60,
            sequence,
        ),
        keypair,
    )
}

fn endpoint_socket_addr(endpoint: &CandidateEndpoint) -> Result<SocketAddr> {
    let ip = endpoint
        .address
        .parse()
        .map_err(|err| QlinkError::Protocol(format!("invalid candidate address: {err}")))?;
    Ok(SocketAddr::new(ip, endpoint.port))
}

fn normalized_packet_matches(restored: &[u8], original: &[u8]) -> bool {
    restored.len() == original.len()
        && restored.get(16..20) == original.get(16..20)
        && ipv4_header_checksum(restored) == 0
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

fn dev_packet_core() -> Result<PacketTunnelCore> {
    PacketTunnelCore::new(PacketTunnelCoreConfig {
        protected_routes: vec![DEV_ROUTE.to_string()],
        excluded_routes: vec![],
        route_mode: FfiRouteMode::SplitTunnel,
        mtu: 1280,
        crypto: None,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_mesh_loopback_moves_packet_via_rendezvous_and_quic() {
        let result = run_local_mesh_loopback().await.unwrap();
        assert_eq!(result.selected_path_type, CandidateType::Relay);
        assert_eq!(result.protocol_family, 2);
        assert_eq!(result.packet_bytes, 20);
        assert!(result.packet_round_trip);
    }

    #[tokio::test]
    async fn relay_loopback_moves_packet_frame() {
        let result = run_relay_loopback().await.unwrap();
        assert_eq!(result.protocol_family, 2);
        assert_eq!(result.packet_bytes, 20);
        assert!(result.packet_round_trip);
    }
}
