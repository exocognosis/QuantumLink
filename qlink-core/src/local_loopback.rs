use crate::{
    discovery::CandidateType,
    error::{QlinkError, Result},
};
use std::net::SocketAddr;

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
    Err(QlinkError::Protocol(
        "mesh loopback is disabled because the legacy local loopback bypasses the app-layer PQC frame session".into(),
    ))
}

pub async fn run_relay_loopback() -> Result<RelayLoopbackResult> {
    Err(QlinkError::Protocol(
        "relay loopback is disabled until relay has an end-to-end PQC session".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_mesh_loopback_fails_closed_without_pqc_session() {
        let error = run_local_mesh_loopback().await.unwrap_err();
        assert!(error.to_string().contains("mesh loopback is disabled"));
    }

    #[tokio::test]
    async fn relay_loopback_fails_closed_without_pqc_session() {
        let error = run_relay_loopback().await.unwrap_err();
        assert!(error.to_string().contains("relay loopback is disabled"));
    }
}
