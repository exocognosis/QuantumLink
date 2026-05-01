//! RFC 8445 ICE connectivity checks with RFC 5389 / RFC 8489 short-term
//! credential authentication.
//!
//! This module is the protocol layer for ICE checks. It exposes:
//!
//! - [`StunMessage`] / [`StunAttribute`]: full encode/decode of the STUN
//!   binding request and binding success/error responses with the ICE
//!   attributes the connector needs (USERNAME, MESSAGE-INTEGRITY, FINGERPRINT,
//!   PRIORITY, ICE-CONTROLLING, ICE-CONTROLLED, USE-CANDIDATE,
//!   XOR-MAPPED-ADDRESS, ERROR-CODE).
//! - [`IceCredentials`]: the short-term `ufrag`/`password` pair exchanged via
//!   the signed rendezvous record.
//! - [`perform_ice_check`]: client-side connectivity check that builds and
//!   sends an authenticated binding request, validates the response (MI +
//!   fingerprint + transaction id), and returns the peer-reported reflexive
//!   address.
//! - [`spawn_dev_ice_responder`]: the responder side, used for tests and
//!   local-only scenarios — receives binding requests, validates MI with the
//!   *responding* peer's password, and replies with an authenticated success
//!   response.
//!
//! ## Production caveat: shared socket with the QUIC data plane
//!
//! RFC 8445 expects connectivity checks to run on the same UDP socket as the
//! data plane so that ICE-verified candidate pairs map directly to the data
//! path. Quinn 0.11 owns its socket and does not expose it for STUN/QUIC
//! demultiplexing (RFC 7983 demux is feasible since STUN's first byte is in
//! 0x00-0x3f and QUIC's fixed bit makes it 0x80+, but it requires implementing
//! Quinn's `AsyncUdpSocket` trait — tracked as a follow-up).
//!
//! v1 runs ICE checks on a dedicated UDP socket per local candidate. Behind
//! cone NATs (most consumer routers) the external port mapping is the same
//! for any socket from the same device, so ICE-verified == QUIC-verified.
//! Behind symmetric NATs the mappings diverge and ICE may incorrectly green
//! a path that QUIC cannot then reach; the connector falls back to relay if
//! the post-ICE QUIC connect fails.

use crate::error::{QlinkError, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, task::JoinHandle};

type HmacSha1 = Hmac<Sha1>;

// Header constants (RFC 5389 §6).
const HEADER_LEN: usize = 20;
const TRANSACTION_ID_LEN: usize = 12;
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

// The STUN message-type field encodes class+method per RFC 5389 §6 Figure 3:
// type = (M[11..7] << 9) | (C[1] << 8) | (M[6..4] << 5) | (C[0] << 4) | M[3..0]
// For binding (method=0x001) and small classes the result simplifies to:
//   request           = 0x0001
//   indication        = 0x0011
//   success response  = 0x0101
//   error response    = 0x0111
const MSG_TYPE_BINDING_REQUEST: u16 = 0x0001;
const MSG_TYPE_BINDING_INDICATION: u16 = 0x0011;
const MSG_TYPE_BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
const MSG_TYPE_BINDING_ERROR_RESPONSE: u16 = 0x0111;

// Attribute type codes (RFC 5389 §18.2 + RFC 8445).
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_PRIORITY: u16 = 0x0024;
const ATTR_USE_CANDIDATE: u16 = 0x0025;
const ATTR_FINGERPRINT: u16 = 0x8028;
const ATTR_ICE_CONTROLLED: u16 = 0x8029;
const ATTR_ICE_CONTROLLING: u16 = 0x802A;

const FINGERPRINT_XOR: u32 = 0x5354_554E;
const MESSAGE_INTEGRITY_LEN: usize = 20;
const FINGERPRINT_LEN: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceCredentials {
    pub ufrag: String,
    pub password: String,
}

impl IceCredentials {
    /// Generates RFC 8445 §5.3 compliant credentials: ufrag of at least 24
    /// bits of entropy (we use 64 bits, base64-urlsafe encoded), password of
    /// at least 128 bits of entropy (we use 192 bits).
    pub fn generate() -> Result<Self> {
        let mut ufrag_bytes = [0_u8; 8];
        getrandom::fill(&mut ufrag_bytes)
            .map_err(|err| QlinkError::Crypto(format!("ICE ufrag entropy unavailable: {err}")))?;
        let mut password_bytes = [0_u8; 24];
        getrandom::fill(&mut password_bytes).map_err(|err| {
            QlinkError::Crypto(format!("ICE password entropy unavailable: {err}"))
        })?;
        Ok(Self {
            ufrag: base64_url_encode(&ufrag_bytes),
            password: base64_url_encode(&password_bytes),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

impl StunClass {
    fn message_type(self) -> u16 {
        match self {
            StunClass::Request => MSG_TYPE_BINDING_REQUEST,
            StunClass::Indication => MSG_TYPE_BINDING_INDICATION,
            StunClass::SuccessResponse => MSG_TYPE_BINDING_SUCCESS_RESPONSE,
            StunClass::ErrorResponse => MSG_TYPE_BINDING_ERROR_RESPONSE,
        }
    }

    fn from_message_type(value: u16) -> Result<Self> {
        match value {
            MSG_TYPE_BINDING_REQUEST => Ok(StunClass::Request),
            MSG_TYPE_BINDING_INDICATION => Ok(StunClass::Indication),
            MSG_TYPE_BINDING_SUCCESS_RESPONSE => Ok(StunClass::SuccessResponse),
            MSG_TYPE_BINDING_ERROR_RESPONSE => Ok(StunClass::ErrorResponse),
            other => Err(QlinkError::Protocol(format!(
                "unsupported STUN message type 0x{other:04x}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunAttribute {
    Username(String),
    MessageIntegrity([u8; MESSAGE_INTEGRITY_LEN]),
    Fingerprint(u32),
    Priority(u32),
    IceControlling(u64),
    IceControlled(u64),
    UseCandidate,
    XorMappedAddress(SocketAddr),
    ErrorCode {
        code: u16,
        reason: String,
    },
    /// Captures forward-compatible attributes that the codec doesn't recognize
    /// but should still round-trip. The `comprehension_required` bit (RFC 5389
    /// §15) is preserved via the type code itself.
    Unknown {
        type_code: u16,
        value: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMessage {
    pub class: StunClass,
    pub transaction_id: [u8; TRANSACTION_ID_LEN],
    pub attributes: Vec<StunAttribute>,
}

impl StunMessage {
    pub fn new_binding_request(transaction_id: [u8; TRANSACTION_ID_LEN]) -> Self {
        Self {
            class: StunClass::Request,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    pub fn new_binding_success_response(transaction_id: [u8; TRANSACTION_ID_LEN]) -> Self {
        Self {
            class: StunClass::SuccessResponse,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    pub fn new_binding_error_response(transaction_id: [u8; TRANSACTION_ID_LEN]) -> Self {
        Self {
            class: StunClass::ErrorResponse,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    pub fn add(&mut self, attr: StunAttribute) -> &mut Self {
        self.attributes.push(attr);
        self
    }

    pub fn find_xor_mapped_address(&self) -> Option<SocketAddr> {
        self.attributes.iter().find_map(|attr| match attr {
            StunAttribute::XorMappedAddress(addr) => Some(*addr),
            _ => None,
        })
    }

    pub fn find_error_code(&self) -> Option<(u16, &str)> {
        self.attributes.iter().find_map(|attr| match attr {
            StunAttribute::ErrorCode { code, reason } => Some((*code, reason.as_str())),
            _ => None,
        })
    }

    pub fn find_username(&self) -> Option<&str> {
        self.attributes.iter().find_map(|attr| match attr {
            StunAttribute::Username(value) => Some(value.as_str()),
            _ => None,
        })
    }

    /// Encodes the message. If `mi_password` is `Some`, a MESSAGE-INTEGRITY
    /// attribute is appended (computed over the message with the header length
    /// adjusted to include the MI attribute itself). A FINGERPRINT attribute
    /// is always appended last (RFC 5389 §15.5).
    ///
    /// Existing MessageIntegrity / Fingerprint attributes in `self.attributes`
    /// are ignored — the encoder always produces fresh ones.
    pub fn encode(&self, mi_password: Option<&str>) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(HEADER_LEN + 64);
        // Reserve the header slot; we'll fill the length once attributes are
        // serialized.
        buffer.extend_from_slice(&self.class.message_type().to_be_bytes());
        buffer.extend_from_slice(&0_u16.to_be_bytes()); // length placeholder
        buffer.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buffer.extend_from_slice(&self.transaction_id);

        for attr in &self.attributes {
            match attr {
                StunAttribute::MessageIntegrity(_) | StunAttribute::Fingerprint(_) => {
                    // Always recomputed below.
                    continue;
                }
                _ => encode_attribute(&mut buffer, attr, &self.transaction_id),
            }
        }

        // RFC 5389 §15.4: when computing MI, the length field of the STUN
        // header MUST include the MI attribute (4-byte header + 20-byte value
        // = 24 bytes), but the buffer fed to HMAC must NOT yet contain MI.
        if let Some(password) = mi_password {
            let body_len_with_mi = (buffer.len() - HEADER_LEN + 4 + MESSAGE_INTEGRITY_LEN) as u16;
            buffer[2..4].copy_from_slice(&body_len_with_mi.to_be_bytes());

            let digest = compute_message_integrity(&buffer, password);
            // Append MI attribute itself.
            buffer.extend_from_slice(&ATTR_MESSAGE_INTEGRITY.to_be_bytes());
            buffer.extend_from_slice(&(MESSAGE_INTEGRITY_LEN as u16).to_be_bytes());
            buffer.extend_from_slice(&digest);
        }

        // RFC 5389 §15.5: FINGERPRINT, if present, MUST be the last attribute.
        // The header length when computing fingerprint must include the
        // fingerprint attribute (4-byte header + 4-byte value = 8 bytes).
        let body_len_with_fp = (buffer.len() - HEADER_LEN + 4 + FINGERPRINT_LEN) as u16;
        buffer[2..4].copy_from_slice(&body_len_with_fp.to_be_bytes());

        let crc = crc32fast::hash(&buffer) ^ FINGERPRINT_XOR;
        buffer.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
        buffer.extend_from_slice(&(FINGERPRINT_LEN as u16).to_be_bytes());
        buffer.extend_from_slice(&crc.to_be_bytes());

        buffer
    }

    /// Decodes a STUN message. If `mi_password` is `Some`, MESSAGE-INTEGRITY
    /// is verified against the supplied password. FINGERPRINT (when present)
    /// is always verified.
    pub fn decode(bytes: &[u8], mi_password: Option<&str>) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(QlinkError::Protocol("STUN message too short".into()));
        }

        let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let class = StunClass::from_message_type(message_type)?;

        let body_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let total_len = HEADER_LEN + body_len;
        if bytes.len() < total_len {
            return Err(QlinkError::Protocol(format!(
                "STUN body claims {body_len} bytes but message is {} bytes",
                bytes.len() - HEADER_LEN
            )));
        }

        let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(QlinkError::Protocol("invalid STUN magic cookie".into()));
        }

        let mut transaction_id = [0_u8; TRANSACTION_ID_LEN];
        transaction_id.copy_from_slice(&bytes[8..20]);

        let mut attributes: Vec<StunAttribute> = Vec::new();
        let mut offset = HEADER_LEN;
        let mut mi_offset: Option<usize> = None;
        let mut fingerprint_offset: Option<usize> = None;

        while offset < total_len {
            if offset + 4 > total_len {
                return Err(QlinkError::Protocol(
                    "truncated STUN attribute header".into(),
                ));
            }
            let attr_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let attr_len = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            let value_start = offset + 4;
            let value_end = value_start + attr_len;
            let padded_end = value_end + padding_len(attr_len);
            if value_end > total_len {
                return Err(QlinkError::Protocol(
                    "truncated STUN attribute value".into(),
                ));
            }
            // Padding may extend up to total_len exactly; some senders omit
            // trailing padding when the attribute is the last in the message.
            let value = &bytes[value_start..value_end];

            match attr_type {
                ATTR_USERNAME => {
                    let username = String::from_utf8(value.to_vec())
                        .map_err(|_| QlinkError::Protocol("STUN USERNAME is not UTF-8".into()))?;
                    attributes.push(StunAttribute::Username(username));
                }
                ATTR_MESSAGE_INTEGRITY => {
                    if value.len() != MESSAGE_INTEGRITY_LEN {
                        return Err(QlinkError::Protocol(
                            "MESSAGE-INTEGRITY length must be 20 bytes".into(),
                        ));
                    }
                    let mut digest = [0_u8; MESSAGE_INTEGRITY_LEN];
                    digest.copy_from_slice(value);
                    mi_offset = Some(offset);
                    attributes.push(StunAttribute::MessageIntegrity(digest));
                }
                ATTR_FINGERPRINT => {
                    if value.len() != FINGERPRINT_LEN {
                        return Err(QlinkError::Protocol(
                            "FINGERPRINT length must be 4 bytes".into(),
                        ));
                    }
                    let crc = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                    fingerprint_offset = Some(offset);
                    attributes.push(StunAttribute::Fingerprint(crc));
                }
                ATTR_PRIORITY => {
                    if value.len() != 4 {
                        return Err(QlinkError::Protocol(
                            "PRIORITY length must be 4 bytes".into(),
                        ));
                    }
                    let prio = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                    attributes.push(StunAttribute::Priority(prio));
                }
                ATTR_USE_CANDIDATE => {
                    if attr_len != 0 {
                        return Err(QlinkError::Protocol("USE-CANDIDATE must be empty".into()));
                    }
                    attributes.push(StunAttribute::UseCandidate);
                }
                ATTR_ICE_CONTROLLING | ATTR_ICE_CONTROLLED => {
                    if value.len() != 8 {
                        return Err(QlinkError::Protocol(
                            "ICE-CONTROLLING/CONTROLLED must be 8 bytes".into(),
                        ));
                    }
                    let mut bytes8 = [0_u8; 8];
                    bytes8.copy_from_slice(value);
                    let tiebreaker = u64::from_be_bytes(bytes8);
                    attributes.push(if attr_type == ATTR_ICE_CONTROLLING {
                        StunAttribute::IceControlling(tiebreaker)
                    } else {
                        StunAttribute::IceControlled(tiebreaker)
                    });
                }
                ATTR_XOR_MAPPED_ADDRESS => {
                    let addr = parse_xor_mapped_address(value, transaction_id)?;
                    attributes.push(StunAttribute::XorMappedAddress(addr));
                }
                ATTR_ERROR_CODE => {
                    if value.len() < 4 {
                        return Err(QlinkError::Protocol("ERROR-CODE too short".into()));
                    }
                    let class = (value[2] & 0b0000_0111) as u16;
                    let number = value[3] as u16;
                    let code = class * 100 + number;
                    let reason = String::from_utf8(value[4..].to_vec())
                        .map_err(|_| QlinkError::Protocol("ERROR-CODE reason not UTF-8".into()))?;
                    attributes.push(StunAttribute::ErrorCode { code, reason });
                }
                _ => {
                    attributes.push(StunAttribute::Unknown {
                        type_code: attr_type,
                        value: value.to_vec(),
                    });
                }
            }

            offset = padded_end.min(total_len);
        }

        // Fingerprint validation (when present).
        if let Some(fp_offset) = fingerprint_offset {
            // The buffer used for CRC must have header.length set to span up
            // to and including the FINGERPRINT attribute (i.e. exactly the
            // observed total_len) and exclude the FINGERPRINT attribute body
            // itself.
            let fp_body_len = (fp_offset + 4 + FINGERPRINT_LEN - HEADER_LEN) as u16;
            let mut crc_buffer = bytes[..fp_offset].to_vec();
            crc_buffer[2..4].copy_from_slice(&fp_body_len.to_be_bytes());
            let expected_crc = crc32fast::hash(&crc_buffer) ^ FINGERPRINT_XOR;
            let observed_crc = match attributes.iter().rev().find_map(|attr| match attr {
                StunAttribute::Fingerprint(value) => Some(*value),
                _ => None,
            }) {
                Some(value) => value,
                None => {
                    return Err(QlinkError::Protocol(
                        "FINGERPRINT attribute missing despite offset".into(),
                    ))
                }
            };
            if expected_crc != observed_crc {
                return Err(QlinkError::Protocol(
                    "STUN FINGERPRINT validation failed".into(),
                ));
            }
        }

        // Message-integrity validation when caller demands it.
        if let Some(password) = mi_password {
            let mi_offset = mi_offset.ok_or_else(|| {
                QlinkError::Protocol(
                    "STUN message has no MESSAGE-INTEGRITY attribute but caller required one"
                        .into(),
                )
            })?;
            // Reconstruct the buffer the sender hashed: bytes up to the MI
            // attribute, with header length set to (mi_offset - HEADER_LEN +
            // 4 + 20).
            let mi_body_len = (mi_offset + 4 + MESSAGE_INTEGRITY_LEN - HEADER_LEN) as u16;
            let mut mi_buffer = bytes[..mi_offset].to_vec();
            mi_buffer[2..4].copy_from_slice(&mi_body_len.to_be_bytes());
            let expected = compute_message_integrity(&mi_buffer, password);
            let observed = match attributes.iter().find_map(|attr| match attr {
                StunAttribute::MessageIntegrity(value) => Some(*value),
                _ => None,
            }) {
                Some(value) => value,
                None => {
                    return Err(QlinkError::Protocol(
                        "MESSAGE-INTEGRITY attribute missing despite offset".into(),
                    ))
                }
            };
            if !constant_time_eq(&expected, &observed) {
                return Err(QlinkError::Protocol(
                    "STUN MESSAGE-INTEGRITY verification failed".into(),
                ));
            }
        }

        Ok(Self {
            class,
            transaction_id,
            attributes,
        })
    }
}

fn encode_attribute(
    buffer: &mut Vec<u8>,
    attr: &StunAttribute,
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) {
    match attr {
        StunAttribute::Username(name) => {
            let bytes = name.as_bytes();
            push_attribute(buffer, ATTR_USERNAME, bytes);
        }
        StunAttribute::Priority(value) => {
            push_attribute(buffer, ATTR_PRIORITY, &value.to_be_bytes());
        }
        StunAttribute::IceControlling(tiebreaker) => {
            push_attribute(buffer, ATTR_ICE_CONTROLLING, &tiebreaker.to_be_bytes());
        }
        StunAttribute::IceControlled(tiebreaker) => {
            push_attribute(buffer, ATTR_ICE_CONTROLLED, &tiebreaker.to_be_bytes());
        }
        StunAttribute::UseCandidate => {
            push_attribute(buffer, ATTR_USE_CANDIDATE, &[]);
        }
        StunAttribute::XorMappedAddress(addr) => {
            let value = encode_xor_mapped_address(*addr, *transaction_id);
            push_attribute(buffer, ATTR_XOR_MAPPED_ADDRESS, &value);
        }
        StunAttribute::ErrorCode { code, reason } => {
            let class = (*code / 100) as u8;
            let number = (*code % 100) as u8;
            let mut value = Vec::with_capacity(4 + reason.len());
            value.extend_from_slice(&[0, 0, class & 0b0000_0111, number]);
            value.extend_from_slice(reason.as_bytes());
            push_attribute(buffer, ATTR_ERROR_CODE, &value);
        }
        StunAttribute::Unknown { type_code, value } => {
            push_attribute(buffer, *type_code, value);
        }
        StunAttribute::MessageIntegrity(_) | StunAttribute::Fingerprint(_) => {
            // These are emitted directly by `encode` after computing fresh
            // values; never re-emit a stored copy.
        }
    }
}

fn push_attribute(buffer: &mut Vec<u8>, type_code: u16, value: &[u8]) {
    buffer.extend_from_slice(&type_code.to_be_bytes());
    buffer.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buffer.extend_from_slice(value);
    let pad = padding_len(value.len());
    for _ in 0..pad {
        buffer.push(0);
    }
}

fn padding_len(value_len: usize) -> usize {
    (4 - (value_len % 4)) % 4
}

fn encode_xor_mapped_address(
    addr: SocketAddr,
    transaction_id: [u8; TRANSACTION_ID_LEN],
) -> Vec<u8> {
    let mut value = Vec::new();
    value.push(0); // reserved
    let port_xor = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
    match addr.ip() {
        IpAddr::V4(ip) => {
            value.push(0x01);
            value.extend_from_slice(&port_xor.to_be_bytes());
            let encoded = u32::from(ip) ^ MAGIC_COOKIE;
            value.extend_from_slice(&encoded.to_be_bytes());
        }
        IpAddr::V6(ip) => {
            value.push(0x02);
            value.extend_from_slice(&port_xor.to_be_bytes());
            let mut mask = [0_u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(&transaction_id);
            let octets = ip.octets();
            let mut xored = [0_u8; 16];
            for index in 0..16 {
                xored[index] = octets[index] ^ mask[index];
            }
            value.extend_from_slice(&xored);
        }
    }
    value
}

fn parse_xor_mapped_address(
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
            let mut decoded = [0_u8; 16];
            for index in 0..16 {
                decoded[index] = value[4 + index] ^ mask[index];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(decoded)), port))
        }
        family => Err(QlinkError::Protocol(format!(
            "unsupported XOR-MAPPED-ADDRESS family: {family}"
        ))),
    }
}

fn compute_message_integrity(buffer: &[u8], password: &str) -> [u8; MESSAGE_INTEGRITY_LEN] {
    let mut mac = HmacSha1::new_from_slice(password.as_bytes())
        .expect("HMAC-SHA1 accepts arbitrary key length");
    mac.update(buffer);
    let result = mac.finalize().into_bytes();
    let mut out = [0_u8; MESSAGE_INTEGRITY_LEN];
    out.copy_from_slice(&result);
    out
}

fn constant_time_eq(a: &[u8; MESSAGE_INTEGRITY_LEN], b: &[u8; MESSAGE_INTEGRITY_LEN]) -> bool {
    let mut diff = 0_u8;
    for index in 0..MESSAGE_INTEGRITY_LEN {
        diff |= a[index] ^ b[index];
    }
    diff == 0
}

fn base64_url_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(bytes)
}

// === Connectivity check client ===

#[derive(Debug, Clone)]
pub struct IceCheckRequest {
    pub remote_credentials: IceCredentials,
    pub local_ufrag: String,
    pub local_priority: u32,
    pub controlling_tiebreaker: u64,
    pub use_candidate: bool,
}

#[derive(Debug, Clone)]
pub struct IceCheckResult {
    pub mapped_address: Option<SocketAddr>,
    pub round_trip: Duration,
}

/// Sends a single ICE connectivity check (binding request) and waits for the
/// authenticated response. Does NOT retransmit — a higher-level retry policy
/// can wrap this for production.
pub async fn perform_ice_check(
    socket: &UdpSocket,
    remote_addr: SocketAddr,
    request: IceCheckRequest,
    timeout: Duration,
) -> Result<IceCheckResult> {
    let mut transaction_id = [0_u8; TRANSACTION_ID_LEN];
    getrandom::fill(&mut transaction_id).map_err(|err| {
        QlinkError::Crypto(format!("ICE transaction id entropy unavailable: {err}"))
    })?;

    let username = format!(
        "{}:{}",
        request.remote_credentials.ufrag, request.local_ufrag
    );

    let mut message = StunMessage::new_binding_request(transaction_id);
    message.add(StunAttribute::Username(username));
    message.add(StunAttribute::Priority(request.local_priority));
    message.add(StunAttribute::IceControlling(
        request.controlling_tiebreaker,
    ));
    if request.use_candidate {
        message.add(StunAttribute::UseCandidate);
    }
    let bytes = message.encode(Some(&request.remote_credentials.password));

    let started = Instant::now();
    socket.send_to(&bytes, remote_addr).await?;

    let mut buffer = vec![0_u8; 1500];
    let received = tokio::time::timeout(timeout, socket.recv_from(&mut buffer))
        .await
        .map_err(|_| QlinkError::Protocol("ICE connectivity check timed out".into()))?;
    let (n, _from) = received?;

    let response = StunMessage::decode(&buffer[..n], Some(&request.remote_credentials.password))?;

    if response.transaction_id != transaction_id {
        return Err(QlinkError::Protocol(
            "ICE response transaction id mismatch".into(),
        ));
    }

    match response.class {
        StunClass::SuccessResponse => Ok(IceCheckResult {
            mapped_address: response.find_xor_mapped_address(),
            round_trip: started.elapsed(),
        }),
        StunClass::ErrorResponse => {
            let (code, reason) = response
                .find_error_code()
                .unwrap_or((0, "unspecified error"));
            Err(QlinkError::Protocol(format!(
                "ICE error response: {code} {reason}"
            )))
        }
        other => Err(QlinkError::Protocol(format!(
            "unexpected ICE response class {other:?}"
        ))),
    }
}

// === Connectivity check responder (test/dev) ===

#[derive(Debug)]
pub struct DevIceResponder {
    local_addr: SocketAddr,
    task: JoinHandle<()>,
}

impl DevIceResponder {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for DevIceResponder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Spawns an ICE responder on a fresh UDP socket. Validates incoming binding
/// requests against the responder's password, replies with an authenticated
/// success response carrying XOR-MAPPED-ADDRESS = the requester's source.
///
/// Production caveat: this is a test helper. A real responder runs in-process
/// alongside the data plane, sharing the QUIC socket via STUN/QUIC demux.
pub async fn spawn_dev_ice_responder(
    bind: SocketAddr,
    credentials: IceCredentials,
) -> Result<DevIceResponder> {
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    let local_addr = socket.local_addr()?;
    let task = tokio::spawn(serve_dev_ice_responder(socket, credentials));
    Ok(DevIceResponder { local_addr, task })
}

async fn serve_dev_ice_responder(socket: Arc<UdpSocket>, credentials: IceCredentials) {
    let mut buffer = vec![0_u8; 1500];
    loop {
        let (received, peer) = match socket.recv_from(&mut buffer).await {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(?error, "dev ICE responder stopped accepting datagrams");
                return;
            }
        };

        // First validate the message structure with FINGERPRINT only.
        let request = match StunMessage::decode(&buffer[..received], None) {
            Ok(request) => request,
            Err(error) => {
                tracing::debug!(?error, ?peer, "dev ICE responder rejecting malformed input");
                continue;
            }
        };

        if request.class != StunClass::Request {
            continue;
        }

        // The USERNAME format is `${responder.ufrag}:${requester.ufrag}`;
        // verify the responder's ufrag matches what we serve.
        let Some(username) = request.find_username() else {
            send_error(
                &socket,
                peer,
                request.transaction_id,
                &credentials,
                400,
                "no USERNAME",
            )
            .await;
            continue;
        };
        let mut split = username.splitn(2, ':');
        let target_ufrag = split.next().unwrap_or("");
        if target_ufrag != credentials.ufrag {
            send_error(
                &socket,
                peer,
                request.transaction_id,
                &credentials,
                401,
                "bad ufrag",
            )
            .await;
            continue;
        }

        // Now re-decode with MI verification using our password.
        if let Err(error) = StunMessage::decode(&buffer[..received], Some(&credentials.password)) {
            tracing::debug!(?error, ?peer, "dev ICE responder MI verification failed");
            send_error(
                &socket,
                peer,
                request.transaction_id,
                &credentials,
                401,
                "MESSAGE-INTEGRITY verification failed",
            )
            .await;
            continue;
        }

        // Build authenticated success response.
        let mut response = StunMessage::new_binding_success_response(request.transaction_id);
        response.add(StunAttribute::XorMappedAddress(peer));
        let bytes = response.encode(Some(&credentials.password));
        if let Err(error) = socket.send_to(&bytes, peer).await {
            tracing::warn!(?error, ?peer, "dev ICE responder failed to send response");
        }
    }
}

async fn send_error(
    socket: &UdpSocket,
    peer: SocketAddr,
    transaction_id: [u8; TRANSACTION_ID_LEN],
    credentials: &IceCredentials,
    code: u16,
    reason: &str,
) {
    let mut response = StunMessage::new_binding_error_response(transaction_id);
    response.add(StunAttribute::ErrorCode {
        code,
        reason: reason.to_string(),
    });
    let bytes = response.encode(Some(&credentials.password));
    if let Err(error) = socket.send_to(&bytes, peer).await {
        tracing::warn!(
            ?error,
            ?peer,
            "dev ICE responder failed to send error response"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn loopback_v4() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    fn fixed_transaction_id() -> [u8; TRANSACTION_ID_LEN] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ]
    }

    #[test]
    fn binding_request_round_trips_without_authentication() {
        let mut message = StunMessage::new_binding_request(fixed_transaction_id());
        message.add(StunAttribute::Username("audience:author".into()));
        message.add(StunAttribute::Priority(0x7eff_ffff));
        message.add(StunAttribute::IceControlling(0xaa55_aa55_aa55_aa55));
        message.add(StunAttribute::UseCandidate);
        let bytes = message.encode(None);
        let decoded = StunMessage::decode(&bytes, None).unwrap();
        assert_eq!(decoded.class, StunClass::Request);
        assert_eq!(decoded.transaction_id, fixed_transaction_id());
        assert!(decoded
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::Username(_))));
        assert!(decoded
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::Priority(_))));
        assert!(decoded
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::IceControlling(_))));
        assert!(decoded
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::UseCandidate)));
        // FINGERPRINT is always appended.
        assert!(decoded
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::Fingerprint(_))));
    }

    #[test]
    fn message_integrity_authenticates_with_correct_password() {
        let mut message = StunMessage::new_binding_request(fixed_transaction_id());
        message.add(StunAttribute::Username("audience:author".into()));
        let bytes = message.encode(Some("super-secret-password"));
        StunMessage::decode(&bytes, Some("super-secret-password")).unwrap();
    }

    #[test]
    fn message_integrity_rejects_wrong_password() {
        let mut message = StunMessage::new_binding_request(fixed_transaction_id());
        message.add(StunAttribute::Username("audience:author".into()));
        let bytes = message.encode(Some("right-password"));
        let result = StunMessage::decode(&bytes, Some("wrong-password"));
        match result {
            Err(QlinkError::Protocol(reason)) => {
                assert!(reason.contains("MESSAGE-INTEGRITY"));
            }
            other => panic!("expected MI failure, got {other:?}"),
        }
    }

    #[test]
    fn fingerprint_detects_corruption() {
        let mut message = StunMessage::new_binding_request(fixed_transaction_id());
        message.add(StunAttribute::Username("audience:author".into()));
        let mut bytes = message.encode(Some("password"));
        // Flip a bit in the username area (after the 20-byte header).
        bytes[24] ^= 0x01;
        let result = StunMessage::decode(&bytes, None);
        match result {
            Err(QlinkError::Protocol(reason)) => {
                assert!(
                    reason.contains("FINGERPRINT"),
                    "expected FINGERPRINT failure, got {reason}"
                );
            }
            other => panic!("expected FINGERPRINT failure, got {other:?}"),
        }
    }

    #[test]
    fn xor_mapped_address_round_trips_ipv4() {
        let addr: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let mut message = StunMessage::new_binding_success_response(fixed_transaction_id());
        message.add(StunAttribute::XorMappedAddress(addr));
        let bytes = message.encode(Some("password"));
        let decoded = StunMessage::decode(&bytes, Some("password")).unwrap();
        assert_eq!(decoded.find_xor_mapped_address(), Some(addr));
    }

    #[test]
    fn error_response_round_trips_with_code_and_reason() {
        let mut response = StunMessage::new_binding_error_response(fixed_transaction_id());
        response.add(StunAttribute::ErrorCode {
            code: 401,
            reason: "Unauthorized".into(),
        });
        let bytes = response.encode(Some("password"));
        let decoded = StunMessage::decode(&bytes, Some("password")).unwrap();
        let (code, reason) = decoded.find_error_code().unwrap();
        assert_eq!(code, 401);
        assert_eq!(reason, "Unauthorized");
    }

    #[tokio::test]
    async fn dev_ice_responder_authenticates_valid_check() {
        let credentials = IceCredentials::generate().unwrap();
        let responder = spawn_dev_ice_responder(loopback_v4(), credentials.clone())
            .await
            .unwrap();

        let local_credentials = IceCredentials::generate().unwrap();
        let socket = UdpSocket::bind(loopback_v4()).await.unwrap();
        let local_addr = socket.local_addr().unwrap();

        let request = IceCheckRequest {
            remote_credentials: credentials,
            local_ufrag: local_credentials.ufrag.clone(),
            local_priority: 0x7eff_ffff,
            controlling_tiebreaker: 0xdead_beef_cafe_d00d,
            use_candidate: true,
        };
        let result = perform_ice_check(
            &socket,
            responder.local_addr(),
            request,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        // The responder echoes back our source address.
        let mapped = result.mapped_address.unwrap();
        assert_eq!(mapped.ip(), local_addr.ip());
        assert_eq!(mapped.port(), local_addr.port());
    }

    #[tokio::test]
    async fn dev_ice_responder_rejects_wrong_credentials() {
        let server_credentials = IceCredentials::generate().unwrap();
        let responder = spawn_dev_ice_responder(loopback_v4(), server_credentials.clone())
            .await
            .unwrap();

        let attacker_belief = IceCredentials {
            ufrag: server_credentials.ufrag.clone(),
            password: "this-is-not-the-real-password".to_string(),
        };
        let local_credentials = IceCredentials::generate().unwrap();
        let socket = UdpSocket::bind(loopback_v4()).await.unwrap();

        let request = IceCheckRequest {
            remote_credentials: attacker_belief,
            local_ufrag: local_credentials.ufrag.clone(),
            local_priority: 0x7eff_ffff,
            controlling_tiebreaker: 1,
            use_candidate: false,
        };
        let result = perform_ice_check(
            &socket,
            responder.local_addr(),
            request,
            Duration::from_millis(800),
        )
        .await;
        // The responder either ignores the request (so we time out) or sends
        // an error response signed with its real password (which we can't
        // verify). Both yield Err.
        assert!(result.is_err());
    }
}
