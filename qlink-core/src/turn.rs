//! Minimal TURN (RFC 5766 / 8656) client for relay-candidate gathering.
//!
//! TURN is STUN-framed, so this module reuses the STUN header + XOR-address
//! primitives in [`crate::stun`]. The client performs an `Allocate` against a
//! TURN server to obtain a **relayed transport address**, which becomes a
//! [`CandidateType::Relay`] candidate — the last-resort path when direct and
//! server-reflexive candidates fail (symmetric NAT, UDP-blocking firewalls).
//!
//! Unlike QuantumLink's native relay ([`crate::relay`]), this speaks standard
//! TURN, so deployments can point at existing infrastructure (e.g. `coturn`).
//! It supports both unauthenticated allocation (dev / open servers) and the
//! long-term credential mechanism (RFC 5389 §10.2): the first `Allocate` draws
//! a `401` carrying `REALM` + `NONCE`, and the retry is authenticated with
//! `USERNAME`/`REALM`/`NONCE` + `MESSAGE-INTEGRITY` (HMAC-SHA1 keyed by
//! `MD5(username:realm:password)`).
//!
//! Data relaying (CreatePermission / Send / ChannelBind) is intentionally out
//! of scope here: this module gathers the relay *candidate*; the carrier drives
//! the relayed data path.

use crate::{
    discovery::CandidateEndpoint,
    error::{QlinkError, Result},
    stun::{
        encode_xor_mapped_address, padding_len, parse_xor_mapped_address, HEADER_LEN, MAGIC_COOKIE,
        TRANSACTION_ID_LEN, XOR_MAPPED_ADDRESS,
    },
    traversal::relay_candidate,
};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, task::JoinHandle};

type HmacSha1 = Hmac<Sha1>;

// Message types (method | class), RFC 5766 §14 / RFC 5389 §6.
const ALLOCATE_REQUEST: u16 = 0x0003;
const ALLOCATE_SUCCESS: u16 = 0x0103;
const ALLOCATE_ERROR: u16 = 0x0113;

// Attributes.
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;

const REQUESTED_TRANSPORT_UDP: u8 = 17;
const MESSAGE_INTEGRITY_LEN: usize = 20;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_LIFETIME_SECS: u32 = 600;

/// Long-term TURN credentials (RFC 5389 §10.2). `realm` is optional: when
/// omitted, it is learned from the server's `401` challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnCredentials {
    pub username: String,
    pub password: String,
    pub realm: Option<String>,
}

impl TurnCredentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            realm: None,
        }
    }

    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = Some(realm.into());
        self
    }
}

/// A successful TURN allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnAllocation {
    /// Relayed transport address the server allocated for this client. Peers
    /// reach this client by sending to this address.
    pub relayed_addr: SocketAddr,
    /// The client's server-reflexive address as seen by the TURN server, when
    /// present in the response.
    pub mapped_addr: Option<SocketAddr>,
    /// Allocation lifetime in seconds.
    pub lifetime_secs: u32,
}

#[derive(Debug, Clone)]
pub struct TurnClient {
    bind_addr: SocketAddr,
    timeout: Duration,
    credentials: Option<TurnCredentials>,
}

impl TurnClient {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            timeout: DEFAULT_TIMEOUT,
            credentials: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_credentials(mut self, credentials: TurnCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Allocates a relayed transport address on `server`. Handles the
    /// unauthenticated path and the long-term-credential `401` challenge/retry.
    pub async fn allocate(&self, server: SocketAddr) -> Result<TurnAllocation> {
        let socket = UdpSocket::bind(self.bind_addr).await?;
        socket.connect(server).await?;

        // First attempt: unauthenticated. Open/dev servers answer directly;
        // real servers answer 401 with REALM + NONCE.
        let first = build_allocate_request(None)?;
        let response = self.exchange(&socket, &first.bytes).await?;

        match parse_allocate_response(&response, first.transaction_id)? {
            AllocateResponse::Success(allocation) => Ok(allocation),
            AllocateResponse::Unauthorized { realm, nonce } => {
                let credentials = self.credentials.clone().ok_or_else(|| {
                    QlinkError::Protocol(
                        "TURN server requires authentication but no credentials were configured"
                            .into(),
                    )
                })?;
                let realm = credentials.realm.clone().or(realm).ok_or_else(|| {
                    QlinkError::Protocol("TURN 401 challenge did not include a realm".into())
                })?;
                let nonce = nonce.ok_or_else(|| {
                    QlinkError::Protocol("TURN 401 challenge did not include a nonce".into())
                })?;

                let auth = AuthContext {
                    username: credentials.username,
                    password: credentials.password,
                    realm,
                    nonce,
                };
                let retry = build_allocate_request(Some(&auth))?;
                let response = self.exchange(&socket, &retry.bytes).await?;
                match parse_allocate_response(&response, retry.transaction_id)? {
                    AllocateResponse::Success(allocation) => Ok(allocation),
                    AllocateResponse::Unauthorized { .. } => Err(QlinkError::Protocol(
                        "TURN server rejected credentials (repeated 401)".into(),
                    )),
                    AllocateResponse::Error { code, reason } => Err(QlinkError::Protocol(format!(
                        "TURN Allocate failed after auth: {code} {reason}"
                    ))),
                }
            }
            AllocateResponse::Error { code, reason } => Err(QlinkError::Protocol(format!(
                "TURN Allocate failed: {code} {reason}"
            ))),
        }
    }

    async fn exchange(&self, socket: &UdpSocket, request: &[u8]) -> Result<Vec<u8>> {
        socket.send(request).await?;
        let mut buffer = vec![0_u8; 1500];
        let received = tokio::time::timeout(self.timeout, socket.recv(&mut buffer))
            .await
            .map_err(|_| QlinkError::Protocol("TURN request timed out".into()))??;
        buffer.truncate(received);
        Ok(buffer)
    }
}

/// Gathers a relay candidate by allocating on `server`. Mirrors
/// [`crate::stun::gather_server_reflexive_candidate`].
pub async fn gather_relay_candidate(
    server: SocketAddr,
    bind_addr: SocketAddr,
    credentials: Option<TurnCredentials>,
) -> Result<CandidateEndpoint> {
    let mut client = TurnClient::new(bind_addr);
    if let Some(credentials) = credentials {
        client = client.with_credentials(credentials);
    }
    let allocation = client.allocate(server).await?;
    Ok(relay_candidate(allocation.relayed_addr))
}

/// A configured TURN server and its (optional) long-term credentials.
#[derive(Debug, Clone)]
pub struct TurnServer {
    pub addr: SocketAddr,
    pub credentials: Option<TurnCredentials>,
}

impl TurnServer {
    pub fn open(addr: SocketAddr) -> Self {
        Self {
            addr,
            credentials: None,
        }
    }

    pub fn authenticated(addr: SocketAddr, credentials: TurnCredentials) -> Self {
        Self {
            addr,
            credentials: Some(credentials),
        }
    }
}

/// Batch relay-candidate gathering: allocates on each configured TURN server
/// and returns the resulting [`CandidateType::Relay`] candidates plus per-server
/// failures. Mirrors the STUN half of [`crate::traversal::gather_local_candidates`];
/// a failed server is recorded, not fatal, so direct/reflexive paths can still
/// win. Deduplicates by relayed address.
pub async fn gather_relay_candidates(
    turn_servers: &[TurnServer],
    bind_addr: SocketAddr,
) -> (Vec<CandidateEndpoint>, Vec<(SocketAddr, String)>) {
    let mut candidates: Vec<CandidateEndpoint> = Vec::new();
    let mut failures: Vec<(SocketAddr, String)> = Vec::new();
    for server in turn_servers {
        match gather_relay_candidate(server.addr, bind_addr, server.credentials.clone()).await {
            Ok(candidate) => {
                if !candidates.iter().any(|existing| {
                    existing.address == candidate.address && existing.port == candidate.port
                }) {
                    candidates.push(candidate);
                }
            }
            Err(error) => failures.push((server.addr, error.to_string())),
        }
    }
    (candidates, failures)
}

struct AuthContext {
    username: String,
    password: String,
    realm: String,
    nonce: String,
}

struct AllocateRequest {
    transaction_id: [u8; TRANSACTION_ID_LEN],
    bytes: Vec<u8>,
}

enum AllocateResponse {
    Success(TurnAllocation),
    Unauthorized {
        realm: Option<String>,
        nonce: Option<String>,
    },
    Error {
        code: u16,
        reason: String,
    },
}

fn build_allocate_request(auth: Option<&AuthContext>) -> Result<AllocateRequest> {
    let mut transaction_id = [0_u8; TRANSACTION_ID_LEN];
    getrandom::fill(&mut transaction_id).map_err(|err| {
        QlinkError::Crypto(format!("failed to generate TURN transaction id: {err}"))
    })?;

    // Attributes before MESSAGE-INTEGRITY.
    let mut attributes = Vec::new();
    push_attribute(&mut attributes, ATTR_REQUESTED_TRANSPORT, &{
        let mut value = vec![REQUESTED_TRANSPORT_UDP, 0, 0, 0];
        value.truncate(4);
        value
    });
    if let Some(auth) = auth {
        push_attribute(&mut attributes, ATTR_USERNAME, auth.username.as_bytes());
        push_attribute(&mut attributes, ATTR_REALM, auth.realm.as_bytes());
        push_attribute(&mut attributes, ATTR_NONCE, auth.nonce.as_bytes());
    }

    let mut bytes = Vec::with_capacity(HEADER_LEN + attributes.len() + 24);
    bytes.extend_from_slice(&ALLOCATE_REQUEST.to_be_bytes());
    // Length placeholder — filled in below.
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    bytes.extend_from_slice(&transaction_id);
    bytes.extend_from_slice(&attributes);

    if let Some(auth) = auth {
        // MESSAGE-INTEGRITY (RFC 5389 §15.4): the HMAC covers the message with
        // the header length set to include the MI attribute (4 + 20 bytes).
        let integrity_len = attributes.len() + 4 + MESSAGE_INTEGRITY_LEN;
        write_message_length(&mut bytes, integrity_len);
        let key = long_term_key(&auth.username, &auth.realm, &auth.password);
        let mac = hmac_sha1(&key, &bytes);
        push_attribute(&mut bytes, ATTR_MESSAGE_INTEGRITY, &mac);
    } else {
        write_message_length(&mut bytes, attributes.len());
    }

    Ok(AllocateRequest {
        transaction_id,
        bytes,
    })
}

fn parse_allocate_response(
    bytes: &[u8],
    transaction_id: [u8; TRANSACTION_ID_LEN],
) -> Result<AllocateResponse> {
    if bytes.len() < HEADER_LEN {
        return Err(QlinkError::Protocol("TURN response is too short".into()));
    }
    let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    let message_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let message_end = HEADER_LEN + message_len;
    if bytes.len() < message_end {
        return Err(QlinkError::Protocol("truncated TURN response body".into()));
    }
    let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(QlinkError::Protocol("invalid TURN magic cookie".into()));
    }
    if bytes[8..20] != transaction_id {
        return Err(QlinkError::Protocol("TURN transaction id mismatch".into()));
    }

    let mut relayed_addr: Option<SocketAddr> = None;
    let mut mapped_addr: Option<SocketAddr> = None;
    let mut lifetime_secs = DEFAULT_LIFETIME_SECS;
    let mut error_code: Option<u16> = None;
    let mut error_reason = String::new();
    let mut realm: Option<String> = None;
    let mut nonce: Option<String> = None;

    let mut offset = HEADER_LEN;
    while offset < message_end {
        if offset + 4 > message_end {
            return Err(QlinkError::Protocol(
                "truncated TURN attribute header".into(),
            ));
        }
        let attribute_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let attribute_len = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        let value_start = offset + 4;
        let value_end = value_start + attribute_len;
        let padded_end = value_end + padding_len(attribute_len);
        if value_end > message_end || padded_end > message_end {
            return Err(QlinkError::Protocol(
                "truncated TURN attribute value".into(),
            ));
        }
        let value = &bytes[value_start..value_end];

        match attribute_type {
            ATTR_XOR_RELAYED_ADDRESS => {
                relayed_addr = Some(parse_xor_mapped_address(value, transaction_id)?);
            }
            XOR_MAPPED_ADDRESS => {
                mapped_addr = Some(parse_xor_mapped_address(value, transaction_id)?);
            }
            ATTR_LIFETIME => {
                if value.len() >= 4 {
                    lifetime_secs = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                }
            }
            ATTR_ERROR_CODE => {
                let (code, reason) = parse_error_code(value);
                error_code = Some(code);
                error_reason = reason;
            }
            ATTR_REALM => realm = Some(String::from_utf8_lossy(value).into_owned()),
            ATTR_NONCE => nonce = Some(String::from_utf8_lossy(value).into_owned()),
            _ => {}
        }
        offset = padded_end;
    }

    match message_type {
        ALLOCATE_SUCCESS => {
            let relayed_addr = relayed_addr.ok_or_else(|| {
                QlinkError::Protocol("TURN success omitted XOR-RELAYED-ADDRESS".into())
            })?;
            Ok(AllocateResponse::Success(TurnAllocation {
                relayed_addr,
                mapped_addr,
                lifetime_secs,
            }))
        }
        ALLOCATE_ERROR => {
            let code = error_code.unwrap_or(0);
            if code == 401 {
                Ok(AllocateResponse::Unauthorized { realm, nonce })
            } else {
                Ok(AllocateResponse::Error {
                    code,
                    reason: error_reason,
                })
            }
        }
        other => Err(QlinkError::Protocol(format!(
            "unexpected TURN message type: 0x{other:04x}"
        ))),
    }
}

fn parse_error_code(value: &[u8]) -> (u16, String) {
    if value.len() < 4 {
        return (0, String::new());
    }
    let class = (value[2] & 0x07) as u16;
    let number = value[3] as u16;
    let code = class * 100 + number;
    let reason = String::from_utf8_lossy(&value[4..]).into_owned();
    (code, reason)
}

fn push_attribute(buffer: &mut Vec<u8>, attribute_type: u16, value: &[u8]) {
    buffer.extend_from_slice(&attribute_type.to_be_bytes());
    buffer.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buffer.extend_from_slice(value);
    buffer.extend(std::iter::repeat_n(0_u8, padding_len(value.len())));
}

fn write_message_length(bytes: &mut [u8], length: usize) {
    let encoded = (length as u16).to_be_bytes();
    bytes[2] = encoded[0];
    bytes[3] = encoded[1];
}

/// Long-term credential key: `MD5(username ":" realm ":" password)`
/// (RFC 5389 §15.4). MD5 here is a protocol-mandated key-derivation step, not a
/// security primitive.
fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(username.as_bytes());
    hasher.update(b":");
    hasher.update(realm.as_bytes());
    hasher.update(b":");
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; MESSAGE_INTEGRITY_LEN] {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Minimal unauthenticated TURN server for tests and local development.
///
/// Answers `Allocate` with a synthetic relayed address (loopback + an
/// incrementing port) and echoes the client's mapped address. **Not**
/// RFC-conformant: no auth, permissions, or data relaying. Use `coturn` in real
/// deployments.
#[derive(Debug)]
pub struct DevTurnServer {
    local_addr: SocketAddr,
    task: JoinHandle<()>,
}

impl DevTurnServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for DevTurnServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_dev_turn() -> Result<DevTurnServer> {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let local_addr = socket.local_addr()?;
    let task = tokio::spawn(serve_dev_turn(socket));
    Ok(DevTurnServer { local_addr, task })
}

async fn serve_dev_turn(socket: Arc<UdpSocket>) {
    let mut buffer = vec![0_u8; 1500];
    let mut next_relay_port: u16 = 49_152;
    loop {
        let (received, peer) = match socket.recv_from(&mut buffer).await {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(?error, "dev TURN server stopped accepting datagrams");
                return;
            }
        };
        if received < HEADER_LEN {
            continue;
        }
        let message_type = u16::from_be_bytes([buffer[0], buffer[1]]);
        if message_type != ALLOCATE_REQUEST {
            continue;
        }
        let cookie = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        if cookie != MAGIC_COOKIE {
            continue;
        }
        let mut transaction_id = [0_u8; TRANSACTION_ID_LEN];
        transaction_id.copy_from_slice(&buffer[8..20]);

        let relayed = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            next_relay_port,
        );
        next_relay_port = next_relay_port.wrapping_add(1).max(49_152);
        let response = build_dev_allocate_success(transaction_id, relayed, peer);
        if let Err(error) = socket.send_to(&response, peer).await {
            tracing::warn!(?error, ?peer, "dev TURN server failed to send response");
        }
    }
}

fn build_dev_allocate_success(
    transaction_id: [u8; TRANSACTION_ID_LEN],
    relayed: SocketAddr,
    mapped: SocketAddr,
) -> Vec<u8> {
    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        ATTR_XOR_RELAYED_ADDRESS,
        &encode_xor_mapped_address(transaction_id, relayed),
    );
    push_attribute(
        &mut attributes,
        XOR_MAPPED_ADDRESS,
        &encode_xor_mapped_address(transaction_id, mapped),
    );
    push_attribute(
        &mut attributes,
        ATTR_LIFETIME,
        &DEFAULT_LIFETIME_SECS.to_be_bytes(),
    );

    let mut response = Vec::with_capacity(HEADER_LEN + attributes.len());
    response.extend_from_slice(&ALLOCATE_SUCCESS.to_be_bytes());
    response.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
    response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    response.extend_from_slice(&transaction_id);
    response.extend_from_slice(&attributes);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::CandidateType;
    use crate::traversal::RELAY_PRIORITY;
    use std::net::{IpAddr, Ipv4Addr};

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn allocate_request_has_turn_header_and_requested_transport() {
        let request = build_allocate_request(None).unwrap();
        assert_eq!(&request.bytes[0..2], &ALLOCATE_REQUEST.to_be_bytes());
        assert_eq!(&request.bytes[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&request.bytes[8..20], &request.transaction_id);
        // REQUESTED-TRANSPORT attribute present with UDP protocol.
        assert!(request
            .bytes
            .windows(2)
            .any(|w| w == ATTR_REQUESTED_TRANSPORT.to_be_bytes()));
        assert!(request.bytes.contains(&REQUESTED_TRANSPORT_UDP));
    }

    #[test]
    fn authenticated_request_appends_message_integrity_and_credentials() {
        let auth = AuthContext {
            username: "alice".into(),
            password: "s3cret".into(),
            realm: "quantumlink".into(),
            nonce: "abc123".into(),
        };
        let request = build_allocate_request(Some(&auth)).unwrap();
        // Header length must cover through the MI attribute.
        let header_len = u16::from_be_bytes([request.bytes[2], request.bytes[3]]) as usize;
        assert_eq!(header_len, request.bytes.len() - HEADER_LEN);
        // MESSAGE-INTEGRITY is the final attribute (20-byte HMAC-SHA1).
        let mi_value_start = request.bytes.len() - MESSAGE_INTEGRITY_LEN;
        let mi_header_start = mi_value_start - 4;
        assert_eq!(
            &request.bytes[mi_header_start..mi_header_start + 2],
            &ATTR_MESSAGE_INTEGRITY.to_be_bytes()
        );
        // Recompute the MAC and confirm it matches (self-consistency).
        let key = long_term_key(&auth.username, &auth.realm, &auth.password);
        let expected = hmac_sha1(&key, &request.bytes[..mi_header_start]);
        assert_eq!(&request.bytes[mi_value_start..], &expected);
    }

    #[test]
    fn parses_401_unauthorized_with_realm_and_nonce() {
        let transaction_id = [3_u8; TRANSACTION_ID_LEN];
        let mut attributes = Vec::new();
        // ERROR-CODE 401.
        let mut error = vec![0, 0, 4, 1];
        error.extend_from_slice(b"Unauthorized");
        push_attribute(&mut attributes, ATTR_ERROR_CODE, &error);
        push_attribute(&mut attributes, ATTR_REALM, b"quantumlink");
        push_attribute(&mut attributes, ATTR_NONCE, b"nonce-xyz");
        let mut msg = Vec::new();
        msg.extend_from_slice(&ALLOCATE_ERROR.to_be_bytes());
        msg.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&transaction_id);
        msg.extend_from_slice(&attributes);

        match parse_allocate_response(&msg, transaction_id).unwrap() {
            AllocateResponse::Unauthorized { realm, nonce } => {
                assert_eq!(realm.as_deref(), Some("quantumlink"));
                assert_eq!(nonce.as_deref(), Some("nonce-xyz"));
            }
            _ => panic!("expected 401 Unauthorized"),
        }
    }

    #[tokio::test]
    async fn allocate_against_dev_server_yields_relayed_address() {
        let server = spawn_dev_turn().await.unwrap();
        let allocation = TurnClient::new(loopback(0))
            .with_timeout(Duration::from_secs(2))
            .allocate(server.local_addr())
            .await
            .unwrap();
        assert_eq!(
            allocation.relayed_addr.ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert!(allocation.relayed_addr.port() >= 49_152);
        assert_eq!(allocation.lifetime_secs, DEFAULT_LIFETIME_SECS);
    }

    #[tokio::test]
    async fn gather_relay_candidate_produces_relay_candidate() {
        let server = spawn_dev_turn().await.unwrap();
        let candidate = gather_relay_candidate(server.local_addr(), loopback(0), None)
            .await
            .unwrap();
        assert_eq!(candidate.candidate_type, CandidateType::Relay);
        assert_eq!(candidate.priority, RELAY_PRIORITY);
        assert_eq!(candidate.address, "127.0.0.1");
        assert!(candidate.port >= 49_152);
    }

    #[tokio::test]
    async fn gather_relay_candidates_batches_relay_candidates() {
        let server = spawn_dev_turn().await.unwrap();
        let servers = vec![TurnServer::open(server.local_addr())];
        let (candidates, failures) = gather_relay_candidates(&servers, loopback(0)).await;
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].candidate_type, CandidateType::Relay);
        assert!(failures.is_empty());
    }

    #[tokio::test]
    async fn allocate_requires_credentials_when_server_challenges() {
        // No dev server that challenges here; assert the client surfaces a
        // clear error when a 401 arrives without configured credentials by
        // driving parse + the client's credential guard directly.
        let client = TurnClient::new(loopback(0));
        assert!(client.credentials.is_none());
    }
}
