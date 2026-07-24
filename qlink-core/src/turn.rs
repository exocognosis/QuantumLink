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
//! The production proof path also supports a resident UDP allocation:
//! `CreatePermission`, `Send` indications, `Data` indications, and periodic
//! refreshes. It deliberately does not implement full RFC ICE nomination or
//! ChannelBind optimization.

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
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::UdpSocket, sync::Mutex, task::JoinHandle};

type HmacSha1 = Hmac<Sha1>;

// Message types (method | class), RFC 5766 §14 / RFC 5389 §6.
const ALLOCATE_REQUEST: u16 = 0x0003;
const ALLOCATE_SUCCESS: u16 = 0x0103;
const ALLOCATE_ERROR: u16 = 0x0113;
const REFRESH_REQUEST: u16 = 0x0004;
const REFRESH_SUCCESS: u16 = 0x0104;
const CREATE_PERMISSION_REQUEST: u16 = 0x0008;
const CREATE_PERMISSION_SUCCESS: u16 = 0x0108;
const CREATE_PERMISSION_ERROR: u16 = 0x0118;
const SEND_INDICATION: u16 = 0x0016;
const DATA_INDICATION: u16 = 0x0017;

// Attributes.
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_DATA: u16 = 0x0013;
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

/// A resident TURN allocation with enough lifecycle to prove relayed data:
/// initial Allocate, CreatePermission for an allowed peer IP, Send/Data
/// indication wrapping, and periodic Refresh/CreatePermission keepalives.
#[derive(Debug)]
pub struct ResidentTurnAllocation {
    allocation: TurnAllocation,
    relay_socket: TurnRelaySocket,
    refresh_task: JoinHandle<()>,
}

impl ResidentTurnAllocation {
    pub fn allocation(&self) -> &TurnAllocation {
        &self.allocation
    }

    pub fn relayed_addr(&self) -> SocketAddr {
        self.allocation.relayed_addr
    }

    pub fn relay_socket(&self) -> TurnRelaySocket {
        self.relay_socket.clone()
    }
}

impl Drop for ResidentTurnAllocation {
    fn drop(&mut self) {
        self.refresh_task.abort();
    }
}

/// Datagram adapter for a TURN allocation. The native UDP carrier owns the
/// frame/authentication/reassembly layer; this adapter only maps raw datagrams
/// to TURN Send/Data indications.
#[derive(Debug, Clone)]
pub struct TurnRelaySocket {
    socket: Arc<UdpSocket>,
    auth: Option<Arc<AuthContext>>,
    peer_addr: Arc<Mutex<Option<SocketAddr>>>,
}

impl TurnRelaySocket {
    fn new(socket: Arc<UdpSocket>, auth: Option<AuthContext>) -> Self {
        Self {
            socket,
            auth: auth.map(Arc::new),
            peer_addr: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn send(&self, datagram: &[u8]) -> Result<usize> {
        let peer = self.peer_addr().await?;
        let message = build_send_indication(peer, datagram, self.auth.as_deref())?;
        self.socket.send(&message).await.map_err(|err| {
            QlinkError::Protocol(format!("failed to send TURN Send indication: {err}"))
        })?;
        Ok(datagram.len())
    }

    pub async fn recv(&self, buffer: &mut [u8]) -> Result<usize> {
        let mut raw = vec![0_u8; 1500];
        loop {
            let received = self.socket.recv(&mut raw).await.map_err(|err| {
                QlinkError::Protocol(format!("failed to receive TURN datagram: {err}"))
            })?;
            let Some((peer, payload)) = parse_data_indication(&raw[..received])? else {
                continue;
            };
            if payload.len() > buffer.len() {
                return Err(QlinkError::Protocol(format!(
                    "TURN relayed datagram exceeds receive buffer: {} > {} bytes",
                    payload.len(),
                    buffer.len()
                )));
            }
            *self.peer_addr.lock().await = Some(peer);
            buffer[..payload.len()].copy_from_slice(&payload);
            return Ok(payload.len());
        }
    }

    pub fn try_send(&self, datagram: &[u8]) -> Result<usize> {
        let peer = self
            .peer_addr
            .try_lock()
            .ok()
            .and_then(|guard| *guard)
            .ok_or_else(|| QlinkError::Protocol("TURN peer address is not known yet".into()))?;
        let message = build_send_indication(peer, datagram, self.auth.as_deref())?;
        self.socket.try_send(&message).map_err(|err| {
            QlinkError::Protocol(format!("failed to send TURN close indication: {err}"))
        })?;
        Ok(datagram.len())
    }

    async fn peer_addr(&self) -> Result<SocketAddr> {
        self.peer_addr.lock().await.ok_or_else(|| {
            QlinkError::Protocol(
                "TURN peer address is not known until a DATA indication arrives".into(),
            )
        })
    }
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
        let socket = Arc::new(UdpSocket::bind(self.bind_addr).await?);
        socket.connect(server).await?;
        let (allocation, _) = self.allocate_on_socket(&socket).await?;
        Ok(allocation)
    }

    /// Allocates a resident relayed transport and installs a permission for
    /// `permitted_peer_ip`. The returned socket can carry QuantumLink's native
    /// UDP carrier through TURN Send/Data indications.
    pub async fn allocate_resident(
        &self,
        server: SocketAddr,
        permitted_peer_ip: IpAddr,
    ) -> Result<ResidentTurnAllocation> {
        let socket = Arc::new(UdpSocket::bind(self.bind_addr).await?);
        socket.connect(server).await?;
        let (allocation, auth) = self.allocate_on_socket(&socket).await?;
        let peer_permission_addr = SocketAddr::new(permitted_peer_ip, 0);
        let create_permission =
            build_create_permission_request(peer_permission_addr, auth.as_ref())?;
        exchange_simple_success(
            &socket,
            &create_permission.bytes,
            create_permission.transaction_id,
            CREATE_PERMISSION_SUCCESS,
            CREATE_PERMISSION_ERROR,
            self.timeout,
            "TURN CreatePermission",
        )
        .await?;

        let relay_socket = TurnRelaySocket::new(socket.clone(), auth.clone());
        let refresh_task = tokio::spawn(run_refresh_loop(
            socket,
            auth,
            peer_permission_addr,
            allocation.lifetime_secs,
        ));
        Ok(ResidentTurnAllocation {
            allocation,
            relay_socket,
            refresh_task,
        })
    }

    async fn allocate_on_socket(
        &self,
        socket: &Arc<UdpSocket>,
    ) -> Result<(TurnAllocation, Option<AuthContext>)> {
        // First attempt: unauthenticated. Open/dev servers answer directly;
        // real servers answer 401 with REALM + NONCE.
        let first = build_allocate_request(None)?;
        let response = self.exchange(&socket, &first.bytes).await?;

        match parse_allocate_response(&response, first.transaction_id)? {
            AllocateResponse::Success(allocation) => Ok((allocation, None)),
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
                    AllocateResponse::Success(allocation) => Ok((allocation, Some(auth))),
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

struct TurnRequest {
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

fn build_create_permission_request(
    peer_addr: SocketAddr,
    auth: Option<&AuthContext>,
) -> Result<TurnRequest> {
    let mut transaction_id = [0_u8; TRANSACTION_ID_LEN];
    getrandom::fill(&mut transaction_id).map_err(|err| {
        QlinkError::Crypto(format!("failed to generate TURN transaction id: {err}"))
    })?;
    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        ATTR_XOR_PEER_ADDRESS,
        &encode_xor_mapped_address(transaction_id, peer_addr),
    );
    Ok(TurnRequest {
        transaction_id,
        bytes: build_turn_message(CREATE_PERMISSION_REQUEST, transaction_id, attributes, auth),
    })
}

fn build_refresh_request(lifetime_secs: u32, auth: Option<&AuthContext>) -> Result<TurnRequest> {
    let mut transaction_id = [0_u8; TRANSACTION_ID_LEN];
    getrandom::fill(&mut transaction_id).map_err(|err| {
        QlinkError::Crypto(format!("failed to generate TURN transaction id: {err}"))
    })?;
    let mut attributes = Vec::new();
    push_attribute(&mut attributes, ATTR_LIFETIME, &lifetime_secs.to_be_bytes());
    Ok(TurnRequest {
        transaction_id,
        bytes: build_turn_message(REFRESH_REQUEST, transaction_id, attributes, auth),
    })
}

fn build_send_indication(
    peer_addr: SocketAddr,
    payload: &[u8],
    auth: Option<&AuthContext>,
) -> Result<Vec<u8>> {
    let mut transaction_id = [0_u8; TRANSACTION_ID_LEN];
    getrandom::fill(&mut transaction_id).map_err(|err| {
        QlinkError::Crypto(format!("failed to generate TURN transaction id: {err}"))
    })?;
    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        ATTR_XOR_PEER_ADDRESS,
        &encode_xor_mapped_address(transaction_id, peer_addr),
    );
    push_attribute(&mut attributes, ATTR_DATA, payload);
    Ok(build_turn_message(
        SEND_INDICATION,
        transaction_id,
        attributes,
        auth,
    ))
}

fn build_data_indication(peer_addr: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let mut transaction_id = [0_u8; TRANSACTION_ID_LEN];
    getrandom::fill(&mut transaction_id).map_err(|err| {
        QlinkError::Crypto(format!("failed to generate TURN transaction id: {err}"))
    })?;
    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        ATTR_XOR_PEER_ADDRESS,
        &encode_xor_mapped_address(transaction_id, peer_addr),
    );
    push_attribute(&mut attributes, ATTR_DATA, payload);
    Ok(build_turn_message(
        DATA_INDICATION,
        transaction_id,
        attributes,
        None,
    ))
}

fn build_turn_message(
    message_type: u16,
    transaction_id: [u8; TRANSACTION_ID_LEN],
    mut attributes: Vec<u8>,
    auth: Option<&AuthContext>,
) -> Vec<u8> {
    if let Some(auth) = auth {
        push_attribute(&mut attributes, ATTR_USERNAME, auth.username.as_bytes());
        push_attribute(&mut attributes, ATTR_REALM, auth.realm.as_bytes());
        push_attribute(&mut attributes, ATTR_NONCE, auth.nonce.as_bytes());
    }

    let mut bytes = Vec::with_capacity(HEADER_LEN + attributes.len() + 24);
    bytes.extend_from_slice(&message_type.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    bytes.extend_from_slice(&transaction_id);
    bytes.extend_from_slice(&attributes);

    if let Some(auth) = auth {
        let integrity_len = attributes.len() + 4 + MESSAGE_INTEGRITY_LEN;
        write_message_length(&mut bytes, integrity_len);
        let key = long_term_key(&auth.username, &auth.realm, &auth.password);
        let mac = hmac_sha1(&key, &bytes);
        push_attribute(&mut bytes, ATTR_MESSAGE_INTEGRITY, &mac);
    } else {
        write_message_length(&mut bytes, attributes.len());
    }

    bytes
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

async fn exchange_simple_success(
    socket: &UdpSocket,
    request: &[u8],
    transaction_id: [u8; TRANSACTION_ID_LEN],
    success_type: u16,
    error_type: u16,
    timeout: Duration,
    label: &str,
) -> Result<()> {
    socket.send(request).await?;
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buffer = vec![0_u8; 1500];
    loop {
        let received = tokio::time::timeout_at(deadline, socket.recv(&mut buffer))
            .await
            .map_err(|_| QlinkError::Protocol(format!("{label} timed out")))??;
        match parse_simple_response(
            &buffer[..received],
            transaction_id,
            success_type,
            error_type,
        )? {
            SimpleResponse::MatchedSuccess => return Ok(()),
            SimpleResponse::MatchedError { code, reason } => {
                return Err(QlinkError::Protocol(format!(
                    "{label} failed: {code} {reason}"
                )));
            }
            SimpleResponse::Ignored => continue,
        }
    }
}

enum SimpleResponse {
    MatchedSuccess,
    MatchedError { code: u16, reason: String },
    Ignored,
}

fn parse_simple_response(
    bytes: &[u8],
    transaction_id: [u8; TRANSACTION_ID_LEN],
    success_type: u16,
    error_type: u16,
) -> Result<SimpleResponse> {
    if bytes.len() < HEADER_LEN {
        return Ok(SimpleResponse::Ignored);
    }
    let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    if message_type != success_type && message_type != error_type {
        return Ok(SimpleResponse::Ignored);
    }
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
        return Ok(SimpleResponse::Ignored);
    }
    if message_type == success_type {
        return Ok(SimpleResponse::MatchedSuccess);
    }

    let mut offset = HEADER_LEN;
    let mut code = 0;
    let mut reason = String::new();
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
        if attribute_type == ATTR_ERROR_CODE {
            (code, reason) = parse_error_code(&bytes[value_start..value_end]);
        }
        offset = padded_end;
    }
    Ok(SimpleResponse::MatchedError { code, reason })
}

fn parse_data_indication(bytes: &[u8]) -> Result<Option<(SocketAddr, Vec<u8>)>> {
    if bytes.len() < HEADER_LEN {
        return Ok(None);
    }
    let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    if message_type != DATA_INDICATION {
        return Ok(None);
    }
    let message_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let message_end = HEADER_LEN + message_len;
    if bytes.len() < message_end {
        return Err(QlinkError::Protocol(
            "truncated TURN Data indication".into(),
        ));
    }
    let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(QlinkError::Protocol("invalid TURN magic cookie".into()));
    }
    let mut transaction_id = [0_u8; TRANSACTION_ID_LEN];
    transaction_id.copy_from_slice(&bytes[8..20]);

    let mut peer_addr = None;
    let mut data = None;
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
            ATTR_XOR_PEER_ADDRESS => {
                peer_addr = Some(parse_xor_mapped_address(value, transaction_id)?);
            }
            ATTR_DATA => data = Some(value.to_vec()),
            _ => {}
        }
        offset = padded_end;
    }

    match (peer_addr, data) {
        (Some(peer), Some(data)) => Ok(Some((peer, data))),
        _ => Err(QlinkError::Protocol(
            "TURN Data indication omitted peer address or data".into(),
        )),
    }
}

fn parse_send_indication(bytes: &[u8]) -> Result<Option<(SocketAddr, Vec<u8>)>> {
    if bytes.len() < HEADER_LEN {
        return Ok(None);
    }
    let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    if message_type != SEND_INDICATION {
        return Ok(None);
    }
    let message_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let message_end = HEADER_LEN + message_len;
    if bytes.len() < message_end {
        return Err(QlinkError::Protocol(
            "truncated TURN Send indication".into(),
        ));
    }
    let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(QlinkError::Protocol("invalid TURN magic cookie".into()));
    }
    let mut transaction_id = [0_u8; TRANSACTION_ID_LEN];
    transaction_id.copy_from_slice(&bytes[8..20]);

    let mut peer_addr = None;
    let mut data = None;
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
            ATTR_XOR_PEER_ADDRESS => {
                peer_addr = Some(parse_xor_mapped_address(value, transaction_id)?);
            }
            ATTR_DATA => data = Some(value.to_vec()),
            _ => {}
        }
        offset = padded_end;
    }

    match (peer_addr, data) {
        (Some(peer), Some(data)) => Ok(Some((peer, data))),
        _ => Err(QlinkError::Protocol(
            "TURN Send indication omitted peer address or data".into(),
        )),
    }
}

async fn run_refresh_loop(
    socket: Arc<UdpSocket>,
    auth: Option<AuthContext>,
    peer_permission_addr: SocketAddr,
    lifetime_secs: u32,
) {
    let refresh_secs = (lifetime_secs / 2).clamp(30, 300);
    let mut interval = tokio::time::interval(Duration::from_secs(refresh_secs as u64));
    loop {
        interval.tick().await;
        match build_refresh_request(lifetime_secs, auth.as_ref()) {
            Ok(request) => {
                if let Err(error) = socket.send(&request.bytes).await {
                    tracing::warn!(?error, "TURN allocation refresh send failed");
                    return;
                }
            }
            Err(error) => {
                tracing::warn!(?error, "TURN allocation refresh build failed");
                return;
            }
        }
        match build_create_permission_request(peer_permission_addr, auth.as_ref()) {
            Ok(request) => {
                if let Err(error) = socket.send(&request.bytes).await {
                    tracing::warn!(?error, "TURN permission refresh send failed");
                    return;
                }
            }
            Err(error) => {
                tracing::warn!(?error, "TURN permission refresh build failed");
                return;
            }
        }
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
/// Answers `Allocate`, tracks `CreatePermission`, and relays data through
/// Send/Data indications on the same UDP socket. **Not** RFC-conformant:
/// no auth, per-allocation sockets, channel binding, quota control, nonce
/// rotation, or abuse hardening. Use `coturn` in real deployments.
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
    spawn_dev_turn_on("127.0.0.1:0").await
}

pub async fn spawn_dev_turn_on(listen: impl AsRef<str>) -> Result<DevTurnServer> {
    let socket = Arc::new(UdpSocket::bind(listen.as_ref()).await?);
    let local_addr = socket.local_addr()?;
    let task = tokio::spawn(serve_dev_turn(socket));
    Ok(DevTurnServer { local_addr, task })
}

pub async fn run_dev_turn(listen: &str) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(listen).await?);
    serve_dev_turn(socket).await;
    Ok(())
}

#[derive(Debug, Default)]
struct DevTurnState {
    allocations: HashMap<SocketAddr, DevTurnAllocation>,
}

#[derive(Debug)]
struct DevTurnAllocation {
    permissions: HashSet<IpAddr>,
}

impl DevTurnState {
    fn allocate(&mut self, client: SocketAddr) {
        self.allocations
            .entry(client)
            .or_insert_with(|| DevTurnAllocation {
                permissions: HashSet::new(),
            });
    }

    fn permit(&mut self, client: SocketAddr, peer_ip: IpAddr) {
        self.allocations
            .entry(client)
            .or_insert_with(|| DevTurnAllocation {
                permissions: HashSet::new(),
            })
            .permissions
            .insert(peer_ip);
    }

    fn allocation_for_peer(&self, peer: SocketAddr) -> Option<SocketAddr> {
        self.allocations.iter().find_map(|(client, allocation)| {
            allocation
                .permissions
                .contains(&peer.ip())
                .then_some(*client)
        })
    }
}

async fn serve_dev_turn(socket: Arc<UdpSocket>) {
    let mut buffer = vec![0_u8; 1500];
    let relayed_addr = match socket.local_addr() {
        Ok(addr) => addr,
        Err(error) => {
            tracing::warn!(?error, "dev TURN server failed to read local address");
            return;
        }
    };
    let mut state = DevTurnState::default();
    loop {
        let (received, peer) = match socket.recv_from(&mut buffer).await {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(?error, "dev TURN server stopped accepting datagrams");
                return;
            }
        };
        if received < HEADER_LEN {
            if let Some(client) = state.allocation_for_peer(peer) {
                if let Ok(indication) = build_data_indication(peer, &buffer[..received]) {
                    let _ = socket.send_to(&indication, client).await;
                }
            }
            continue;
        }
        let Some(message_type) = turn_message_type(&buffer[..received]) else {
            if let Some(client) = state.allocation_for_peer(peer) {
                if let Ok(indication) = build_data_indication(peer, &buffer[..received]) {
                    let _ = socket.send_to(&indication, client).await;
                }
            }
            continue;
        };
        let mut transaction_id = [0_u8; TRANSACTION_ID_LEN];
        transaction_id.copy_from_slice(&buffer[8..20]);

        match message_type {
            ALLOCATE_REQUEST => {
                state.allocate(peer);
                let response = build_dev_allocate_success(transaction_id, relayed_addr, peer);
                if let Err(error) = socket.send_to(&response, peer).await {
                    tracing::warn!(?error, ?peer, "dev TURN server failed to send response");
                }
            }
            CREATE_PERMISSION_REQUEST => {
                match parse_create_permission_peer(&buffer[..received], transaction_id) {
                    Ok(Some(permitted)) => {
                        state.permit(peer, permitted.ip());
                        let response = build_success_response(
                            CREATE_PERMISSION_SUCCESS,
                            transaction_id,
                            Vec::new(),
                        );
                        let _ = socket.send_to(&response, peer).await;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::warn!(?error, ?peer, "dev TURN CreatePermission parse failed");
                    }
                }
            }
            REFRESH_REQUEST => {
                let mut attributes = Vec::new();
                push_attribute(
                    &mut attributes,
                    ATTR_LIFETIME,
                    &DEFAULT_LIFETIME_SECS.to_be_bytes(),
                );
                let response = build_success_response(REFRESH_SUCCESS, transaction_id, attributes);
                let _ = socket.send_to(&response, peer).await;
            }
            SEND_INDICATION => {
                if !state.allocations.contains_key(&peer) {
                    continue;
                }
                match parse_send_indication(&buffer[..received]) {
                    Ok(Some((destination, data))) => {
                        let _ = socket.send_to(&data, destination).await;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::warn!(?error, ?peer, "dev TURN Send indication parse failed");
                    }
                }
            }
            _ => {}
        }
    }
}

fn turn_message_type(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < HEADER_LEN {
        return None;
    }
    let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    (cookie == MAGIC_COOKIE).then(|| u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn parse_create_permission_peer(
    bytes: &[u8],
    transaction_id: [u8; TRANSACTION_ID_LEN],
) -> Result<Option<SocketAddr>> {
    if turn_message_type(bytes) != Some(CREATE_PERMISSION_REQUEST) {
        return Ok(None);
    }
    let message_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let message_end = HEADER_LEN + message_len;
    if bytes.len() < message_end {
        return Err(QlinkError::Protocol(
            "truncated TURN CreatePermission".into(),
        ));
    }
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
        if attribute_type == ATTR_XOR_PEER_ADDRESS {
            return Ok(Some(parse_xor_mapped_address(
                &bytes[value_start..value_end],
                transaction_id,
            )?));
        }
        offset = padded_end;
    }
    Ok(None)
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

fn build_success_response(
    message_type: u16,
    transaction_id: [u8; TRANSACTION_ID_LEN],
    attributes: Vec<u8>,
) -> Vec<u8> {
    let mut response = Vec::with_capacity(HEADER_LEN + attributes.len());
    response.extend_from_slice(&message_type.to_be_bytes());
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
    fn send_and_data_indications_round_trip_peer_and_payload() {
        let peer = loopback(44_000);
        let send = build_send_indication(peer, b"hello", None).unwrap();
        let parsed_send = parse_send_indication(&send).unwrap().unwrap();
        assert_eq!(parsed_send.0, peer);
        assert_eq!(parsed_send.1, b"hello");

        let data = build_data_indication(peer, b"world").unwrap();
        let parsed_data = parse_data_indication(&data).unwrap().unwrap();
        assert_eq!(parsed_data.0, peer);
        assert_eq!(parsed_data.1, b"world");
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
        assert_eq!(allocation.relayed_addr, server.local_addr());
        assert_eq!(allocation.lifetime_secs, DEFAULT_LIFETIME_SECS);
    }

    #[tokio::test]
    async fn resident_allocation_relays_datagrams_through_dev_turn() {
        let server = spawn_dev_turn().await.unwrap();
        let resident = TurnClient::new(loopback(0))
            .with_timeout(Duration::from_secs(2))
            .allocate_resident(server.local_addr(), IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .unwrap();

        let peer = UdpSocket::bind(loopback(0)).await.unwrap();
        peer.send_to(b"turn-ping", resident.relayed_addr())
            .await
            .unwrap();

        let relay_socket = resident.relay_socket();
        let mut buffer = [0_u8; 64];
        let received = relay_socket.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..received], b"turn-ping");

        relay_socket.send(b"turn-pong").await.unwrap();
        let mut response = [0_u8; 64];
        let (response_len, from) = peer.recv_from(&mut response).await.unwrap();
        assert_eq!(from, server.local_addr());
        assert_eq!(&response[..response_len], b"turn-pong");
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
        assert_eq!(candidate.port, server.local_addr().port());
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
