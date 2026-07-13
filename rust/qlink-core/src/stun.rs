use crate::{
    error::{QlinkError, Result},
    traversal::server_reflexive_candidate,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::UdpSocket, task::JoinHandle};

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
pub(crate) const XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub(crate) const MAGIC_COOKIE: u32 = 0x2112_A442;
pub(crate) const HEADER_LEN: usize = 20;
pub(crate) const TRANSACTION_ID_LEN: usize = 12;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunBindingRequest {
    pub transaction_id: [u8; TRANSACTION_ID_LEN],
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunBindingResult {
    pub mapped_addr: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct StunClient {
    bind_addr: SocketAddr,
    timeout: Duration,
}

impl StunClient {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn binding_request(&self, server: SocketAddr) -> Result<StunBindingResult> {
        let request = build_binding_request()?;
        let socket = UdpSocket::bind(self.bind_addr).await?;
        socket.connect(server).await?;
        socket.send(&request.bytes).await?;

        let mut buffer = vec![0_u8; 1500];
        let received = tokio::time::timeout(self.timeout, socket.recv(&mut buffer))
            .await
            .map_err(|_| QlinkError::Protocol("STUN binding request timed out".into()))??;
        parse_binding_response(&buffer[..received], request.transaction_id)
    }
}

pub fn build_binding_request() -> Result<StunBindingRequest> {
    let mut transaction_id = [0_u8; TRANSACTION_ID_LEN];
    getrandom::fill(&mut transaction_id).map_err(|err| {
        QlinkError::Crypto(format!("failed to generate STUN transaction id: {err}"))
    })?;

    let mut bytes = Vec::with_capacity(HEADER_LEN);
    bytes.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    bytes.extend_from_slice(&transaction_id);

    Ok(StunBindingRequest {
        transaction_id,
        bytes,
    })
}

pub fn parse_binding_response(
    bytes: &[u8],
    transaction_id: [u8; TRANSACTION_ID_LEN],
) -> Result<StunBindingResult> {
    if bytes.len() < HEADER_LEN {
        return Err(QlinkError::Protocol("STUN response is too short".into()));
    }

    let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    if message_type != BINDING_SUCCESS_RESPONSE {
        return Err(QlinkError::Protocol(format!(
            "unexpected STUN message type: 0x{message_type:04x}"
        )));
    }

    let message_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let message_end = HEADER_LEN + message_len;
    if bytes.len() < message_end {
        return Err(QlinkError::Protocol("truncated STUN response body".into()));
    }

    let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(QlinkError::Protocol("invalid STUN magic cookie".into()));
    }

    if bytes[8..20] != transaction_id {
        return Err(QlinkError::Protocol("STUN transaction id mismatch".into()));
    }

    let mut offset = HEADER_LEN;
    while offset < message_end {
        if offset + 4 > message_end {
            return Err(QlinkError::Protocol(
                "truncated STUN attribute header".into(),
            ));
        }

        let attribute_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let attribute_len = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        let value_start = offset + 4;
        let value_end = value_start + attribute_len;
        let padded_end = value_end + padding_len(attribute_len);
        if value_end > message_end || padded_end > message_end {
            return Err(QlinkError::Protocol(
                "truncated STUN attribute value".into(),
            ));
        }

        if attribute_type == XOR_MAPPED_ADDRESS {
            return Ok(StunBindingResult {
                mapped_addr: parse_xor_mapped_address(
                    &bytes[value_start..value_end],
                    transaction_id,
                )?,
            });
        }

        offset = padded_end;
    }

    Err(QlinkError::Protocol(
        "STUN response did not include XOR-MAPPED-ADDRESS".into(),
    ))
}

pub async fn gather_server_reflexive_candidate(
    server: SocketAddr,
    bind_addr: SocketAddr,
) -> Result<crate::discovery::CandidateEndpoint> {
    let result = StunClient::new(bind_addr).binding_request(server).await?;
    Ok(server_reflexive_candidate(result.mapped_addr))
}

/// Minimal STUN binding-request server for tests and local development.
///
/// Reflects each binding request's source address back to the client as
/// `XOR-MAPPED-ADDRESS`. **Not** RFC-conformant for production: omits
/// authentication, fingerprint, message-integrity, and rate limiting. Use
/// `coturn` or a comparable production server in real deployments.
#[derive(Debug)]
pub struct DevStunServer {
    local_addr: SocketAddr,
    task: JoinHandle<()>,
}

impl DevStunServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for DevStunServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_dev_stun() -> Result<DevStunServer> {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let local_addr = socket.local_addr()?;
    let task = tokio::spawn(serve_dev_stun(socket));
    Ok(DevStunServer { local_addr, task })
}

async fn serve_dev_stun(socket: Arc<UdpSocket>) {
    let mut buffer = vec![0_u8; 1500];
    loop {
        let (received, peer) = match socket.recv_from(&mut buffer).await {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(?error, "dev STUN server stopped accepting datagrams");
                return;
            }
        };

        if received < HEADER_LEN {
            continue;
        }

        let message_type = u16::from_be_bytes([buffer[0], buffer[1]]);
        if message_type != BINDING_REQUEST {
            continue;
        }
        let cookie = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        if cookie != MAGIC_COOKIE {
            continue;
        }

        let mut transaction_id = [0_u8; TRANSACTION_ID_LEN];
        transaction_id.copy_from_slice(&buffer[8..20]);

        let response = build_binding_response(transaction_id, peer);
        if let Err(error) = socket.send_to(&response, peer).await {
            tracing::warn!(?error, ?peer, "dev STUN server failed to send response");
        }
    }
}

fn build_binding_response(
    transaction_id: [u8; TRANSACTION_ID_LEN],
    mapped_addr: SocketAddr,
) -> Vec<u8> {
    let attribute = encode_xor_mapped_address(transaction_id, mapped_addr);
    let mut response = Vec::with_capacity(HEADER_LEN + 4 + attribute.len());
    response.extend_from_slice(&BINDING_SUCCESS_RESPONSE.to_be_bytes());
    response.extend_from_slice(&((4_usize + attribute.len()) as u16).to_be_bytes());
    response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    response.extend_from_slice(&transaction_id);
    response.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
    response.extend_from_slice(&(attribute.len() as u16).to_be_bytes());
    response.extend_from_slice(&attribute);
    response
}

pub(crate) fn encode_xor_mapped_address(
    transaction_id: [u8; TRANSACTION_ID_LEN],
    mapped_addr: SocketAddr,
) -> Vec<u8> {
    let mut attribute = Vec::new();
    attribute.push(0);
    match mapped_addr.ip() {
        IpAddr::V4(ip) => {
            attribute.push(0x01);
            let port_xor = mapped_addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            attribute.extend_from_slice(&port_xor.to_be_bytes());
            let encoded = u32::from(ip) ^ MAGIC_COOKIE;
            attribute.extend_from_slice(&encoded.to_be_bytes());
        }
        IpAddr::V6(ip) => {
            attribute.push(0x02);
            let port_xor = mapped_addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            attribute.extend_from_slice(&port_xor.to_be_bytes());
            let mut mask = [0_u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(&transaction_id);
            let octets = ip.octets();
            for index in 0..16 {
                attribute.push(octets[index] ^ mask[index]);
            }
        }
    }
    attribute
}

pub(crate) fn parse_xor_mapped_address(
    value: &[u8],
    transaction_id: [u8; TRANSACTION_ID_LEN],
) -> Result<SocketAddr> {
    if value.len() < 4 || value[0] != 0 {
        return Err(QlinkError::Protocol(
            "invalid XOR-MAPPED-ADDRESS header".into(),
        ));
    }

    let port = u16::from_be_bytes([value[2], value[3]]) ^ ((MAGIC_COOKIE >> 16) as u16);
    match value[1] {
        0x01 => {
            if value.len() < 8 {
                return Err(QlinkError::Protocol(
                    "truncated IPv4 XOR-MAPPED-ADDRESS".into(),
                ));
            }
            let encoded = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(encoded ^ MAGIC_COOKIE)),
                port,
            ))
        }
        0x02 => {
            if value.len() < 20 {
                return Err(QlinkError::Protocol(
                    "truncated IPv6 XOR-MAPPED-ADDRESS".into(),
                ));
            }
            let mut mask = [0_u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(&transaction_id);

            let mut address = [0_u8; 16];
            for index in 0..16 {
                address[index] = value[4 + index] ^ mask[index];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(address)), port))
        }
        family => Err(QlinkError::Protocol(format!(
            "unsupported XOR-MAPPED-ADDRESS family: {family}"
        ))),
    }
}

pub(crate) fn padding_len(attribute_len: usize) -> usize {
    (4 - (attribute_len % 4)) % 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_request_has_stun_header() {
        let request = build_binding_request().unwrap();
        assert_eq!(request.bytes.len(), HEADER_LEN);
        assert_eq!(&request.bytes[0..2], &BINDING_REQUEST.to_be_bytes());
        assert_eq!(&request.bytes[2..4], &0_u16.to_be_bytes());
        assert_eq!(&request.bytes[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&request.bytes[8..20], &request.transaction_id);
    }

    #[test]
    fn parses_ipv4_xor_mapped_address() {
        let transaction_id = [7_u8; TRANSACTION_ID_LEN];
        let mapped_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 54321);
        let response = synthetic_success_response(transaction_id, mapped_addr);

        let parsed = parse_binding_response(&response, transaction_id).unwrap();
        assert_eq!(parsed.mapped_addr, mapped_addr);
    }

    #[tokio::test]
    async fn dev_stun_server_returns_xor_mapped_address_of_client() {
        let server = spawn_dev_stun().await.unwrap();
        let client = StunClient::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .with_timeout(Duration::from_secs(2));
        let result = client.binding_request(server.local_addr()).await.unwrap();
        assert!(matches!(result.mapped_addr.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST));
        assert!(result.mapped_addr.port() != 0);
    }

    #[tokio::test]
    async fn gather_server_reflexive_candidate_uses_dev_stun() {
        let server = spawn_dev_stun().await.unwrap();
        let candidate = gather_server_reflexive_candidate(
            server.local_addr(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .await
        .unwrap();
        assert_eq!(candidate.address, "127.0.0.1");
        assert!(candidate.port != 0);
    }

    #[test]
    fn rejects_transaction_id_mismatch() {
        let transaction_id = [7_u8; TRANSACTION_ID_LEN];
        let mapped_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 54321);
        let response = synthetic_success_response(transaction_id, mapped_addr);

        let error = parse_binding_response(&response, [8_u8; TRANSACTION_ID_LEN]).unwrap_err();
        assert!(error.to_string().contains("transaction id mismatch"));
    }

    fn synthetic_success_response(
        transaction_id: [u8; TRANSACTION_ID_LEN],
        mapped_addr: SocketAddr,
    ) -> Vec<u8> {
        let attribute = encode_xor_mapped_address(transaction_id, mapped_addr);
        let mut response = Vec::with_capacity(HEADER_LEN + 4 + attribute.len());
        response.extend_from_slice(&BINDING_SUCCESS_RESPONSE.to_be_bytes());
        response.extend_from_slice(&(4_u16 + attribute.len() as u16).to_be_bytes());
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&transaction_id);
        response.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&(attribute.len() as u16).to_be_bytes());
        response.extend_from_slice(&attribute);
        response
    }
}
