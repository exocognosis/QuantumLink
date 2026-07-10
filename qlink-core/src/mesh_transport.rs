//! Live data-plane transport that ties the [`MeshConnector`] to the Swift
//! tunnel pump.
//!
//! Architecture:
//!
//! ```text
//!   Swift PacketTunnelProvider          Rust mesh_transport
//!   ┌──────────────────────┐            ┌────────────────────────┐
//!   │   send_transport_*   │  outbound  │  manager task          │
//!   │   ─────────────────► │ ─────────► │  ┌─ MeshConnector      │
//!   │                      │   queue    │  │  • rendezvous       │
//!   │                      │            │  │  • paced ICE probes │
//!   │   recv_transport_*   │  inbound   │  │  • relay fallback   │
//!   │   ◄───────────────── │ ◄───────── │  └─ MeshLink           │
//!   │                      │   queue    │     (active session)   │
//!   │  network_event(code) │            │                        │
//!   │   ─────────────────► │ ─────────► │  reconnect on path     │
//!   │                      │            │  changed / wake        │
//!   └──────────────────────┘            └────────────────────────┘
//! ```
//!
//! The Swift side calls FFI on its packet-pump thread. The Rust side runs a
//! single tokio runtime that hosts a "session manager" task: it loops over
//! `connector.connect()` and drives the resulting `MeshLink` until either
//! (a) the link dies, (b) a network event demands reconnect, or (c) the
//! handle is dropped.

#![cfg_attr(not(feature = "dev-quic-carrier"), allow(dead_code, unused_imports))]

#[cfg(feature = "dev-quic-carrier")]
use crate::quic_transport::QuicEndpoint;
use crate::{
    carrier_transport::CarrierSession,
    crypto::{shake256_xof, DeviceKeypair},
    discovery::{now_unix, CandidateEndpoint, CandidateType, PeerRecord, UnsignedPeerRecord},
    dytallix_identity::{
        verify_inbound_registry_assertion, DytallixIdentityRegistry, DytallixRegistryLookupConfig,
        MeshTrustPolicy, RegistryDecision,
    },
    error::{QlinkError, Result},
    ice::IceCredentials,
    inbound_identity::{
        receive_and_evaluate_inbound, InboundDecision, DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS,
    },
    mesh_connection::{
        IdentityRegistryLookup, MeshConnector, MeshConnectorConfig, NetworkEvent,
        NetworkEventResponse, PathKind, PeerRecordSource,
    },
    metrics_endpoint::{spawn_metrics_endpoint, MetricsEndpoint, MetricsSnapshot},
    peer_acl::PeerAcl,
    peer_store::{
        open_file_peer_store, open_file_peer_store_with_key, InMemoryPeerStore, PeerStore,
    },
    pqc_frame::PqcFrameProtector,
    pqc_session_wire::run_pqc_session_responder,
    rendezvous::RendezvousClient,
    session_crypto::{derive_packet_session_binding, PqcSessionContext, PqcSessionRole},
    traversal::HOST_PRIORITY,
};
#[cfg(not(feature = "dev-quic-carrier"))]
use crate::{carrier_transport::NativeUdpListener, mesh_connection::native_udp_carrier_binding};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::Duration,
};
#[cfg(not(feature = "dev-quic-carrier"))]
use tokio::net::UdpSocket;
use tokio::{
    runtime::Runtime,
    sync::{mpsc, Mutex as TokioMutex},
    task::JoinHandle,
};

const DEFAULT_PACKET_SESSION_LIFETIME_SECONDS: u64 = 3_600;
const DEFAULT_PACKET_SESSION_REKEY_AFTER_BYTES: u64 = 1_073_741_824;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketSessionDirection {
    Outbound,
    Inbound,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PacketSessionLease {
    pub peer_id: String,
    pub direction: PacketSessionDirection,
    pub generation: u64,
    pub transcript_binding: [u8; 32],
    pub expires_at_unix: u64,
    pub rekey_after_bytes: u64,
}

impl std::fmt::Debug for PacketSessionLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketSessionLease")
            .field("peer_id", &self.peer_id)
            .field("direction", &self.direction)
            .field("generation", &self.generation)
            .field("transcript_binding", &"[redacted]")
            .field("expires_at_unix", &self.expires_at_unix)
            .field("rekey_after_bytes", &self.rekey_after_bytes)
            .finish()
    }
}

impl PacketSessionLease {
    fn is_current(&self) -> bool {
        self.expires_at_unix > now_unix()
    }
}

fn next_packet_session_generation(counter: &AtomicU64) -> Option<u64> {
    counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            current.checked_add(1)
        })
        .ok()
        .and_then(|previous| previous.checked_add(1))
}

fn packet_session_lease(
    peer_id: String,
    direction: PacketSessionDirection,
    generation: u64,
    authenticated_binding: [u8; 32],
    lifetime_seconds: u64,
    rekey_after_bytes: u64,
) -> PacketSessionLease {
    let expires_at_unix = now_unix().saturating_add(lifetime_seconds);
    let direction_label = match direction {
        PacketSessionDirection::Outbound => b"outbound".as_slice(),
        PacketSessionDirection::Inbound => b"inbound".as_slice(),
    };
    let generation_bytes = generation.to_be_bytes();
    let expiry_bytes = expires_at_unix.to_be_bytes();
    let byte_limit_bytes = rekey_after_bytes.to_be_bytes();
    let transcript_binding = shake256_xof::<32>(
        b"QuantumLink packet session readiness lease v1",
        &[
            &authenticated_binding,
            peer_id.as_bytes(),
            direction_label,
            &generation_bytes,
            &expiry_bytes,
            &byte_limit_bytes,
        ],
    );
    PacketSessionLease {
        peer_id,
        direction,
        generation,
        transcript_binding,
        expires_at_unix,
        rekey_after_bytes,
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum PacketSessionEvent {
    Ready(PacketSessionLease),
    Cleared {
        peer_id: String,
        direction: PacketSessionDirection,
        generation: u64,
    },
}

impl std::fmt::Debug for PacketSessionEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready(lease) => f.debug_tuple("Ready").field(lease).finish(),
            Self::Cleared {
                peer_id,
                direction,
                generation,
            } => f
                .debug_struct("Cleared")
                .field("peer_id", peer_id)
                .field("direction", direction)
                .field("generation", generation)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshTransportState {
    Connecting,
    Ready,
    Failed,
    Stopped,
}

impl MeshTransportState {
    pub fn as_code(self) -> u32 {
        match self {
            MeshTransportState::Connecting => 0,
            MeshTransportState::Ready => 1,
            MeshTransportState::Failed => 2,
            MeshTransportState::Stopped => 3,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MeshTransportRawMetrics {
    pub frames_sent: u64,
    pub frames_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub send_failures: u64,
    pub receive_failures: u64,
    pub network_event_count: u64,
    pub reconnect_count: u64,
}

pub const PEER_TRUST_DECISION_UNKNOWN: u32 = 0;
pub const PEER_TRUST_DECISION_ACCEPTED: u32 = 1;
pub const PEER_TRUST_DECISION_ACCEPTED_WITHOUT_REGISTRY_PRIVATE: u32 = 2;
pub const PEER_TRUST_DECISION_ACCEPTED_WITHOUT_REGISTRY_DEVELOPMENT: u32 = 3;
pub const PEER_TRUST_FAILURE_NONE: u32 = 0;
pub const PEER_TRUST_FAILURE_REGISTRY_REQUIRED: u32 = 1;
pub const PEER_TRUST_FAILURE_REGISTRY_REVOKED: u32 = 2;
pub const PEER_TRUST_FAILURE_REGISTRY_SUSPENDED: u32 = 3;
pub const PEER_TRUST_FAILURE_REGISTRY_EXPIRED: u32 = 4;
pub const PEER_TRUST_FAILURE_REGISTRY_MISMATCH: u32 = 5;
pub const PEER_TRUST_FAILURE_REGISTRY_LOOKUP: u32 = 6;
pub const PEER_TRUST_FAILURE_REGISTRY_VERIFICATION: u32 = 7;
pub const PEER_TRUST_FAILURE_REGISTRY_KEY_MISMATCH: u32 = 8;
pub const PEER_TRUST_FAILURE_REGISTRY_RECORD_HASH_MISMATCH: u32 = 9;
pub const PEER_TRUST_FAILURE_REGISTRY_STAKE_OR_REPUTATION: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedPeerDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockedPeerHistoryEntry {
    pub peer_id: String,
    pub direction: BlockedPeerDirection,
    pub failure_code: u32,
    pub failure_reason: String,
    pub observed_at_unix: u64,
    pub checked_at_unix: u64,
}

#[derive(Debug, Default)]
pub struct BlockedPeerHistory {
    entries: StdMutex<HashMap<(String, BlockedPeerDirection), BlockedPeerHistoryEntry>>,
}

impl BlockedPeerHistory {
    pub fn new() -> Self {
        Self {
            entries: StdMutex::new(HashMap::new()),
        }
    }

    pub fn record(
        &self,
        peer_id: &str,
        direction: BlockedPeerDirection,
        failure_code: u32,
        failure_reason: &str,
        checked_at_unix: Option<u64>,
    ) {
        let observed_at_unix = now_unix();
        let entry = BlockedPeerHistoryEntry {
            peer_id: peer_id.to_string(),
            direction,
            failure_code,
            failure_reason: failure_reason.to_string(),
            observed_at_unix,
            checked_at_unix: checked_at_unix.unwrap_or(observed_at_unix),
        };
        if let Ok(mut guard) = self.entries.lock() {
            guard.insert((entry.peer_id.clone(), direction), entry);
        }
    }

    pub fn snapshot(&self) -> Vec<BlockedPeerHistoryEntry> {
        let mut entries: Vec<BlockedPeerHistoryEntry> = self
            .entries
            .lock()
            .map(|guard| guard.values().cloned().collect())
            .unwrap_or_default();
        entries.sort_by(|lhs, rhs| {
            lhs.peer_id
                .cmp(&rhs.peer_id)
                .then_with(|| lhs.direction.cmp(&rhs.direction))
        });
        entries
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PeerTrustStatusRaw {
    pub decision_code: u32,
    pub failure_code: u32,
    pub checked_at_unix: u64,
    pub source_code: u32,
}

impl PeerTrustStatusRaw {
    fn from_registry_decision(decision: RegistryDecision, source: PeerRecordSource) -> Self {
        Self {
            decision_code: registry_decision_code(decision),
            failure_code: PEER_TRUST_FAILURE_NONE,
            checked_at_unix: now_unix(),
            source_code: source.trust_source_code(),
        }
    }

    fn from_failure_message(message: &str) -> Option<Self> {
        let failure_code = registry_failure_code(message)?;
        Some(Self {
            decision_code: PEER_TRUST_DECISION_UNKNOWN,
            failure_code,
            checked_at_unix: now_unix(),
            source_code: PEER_TRUST_SOURCE_UNKNOWN,
        })
    }
}

const PEER_TRUST_SOURCE_UNKNOWN: u32 = 0;

fn registry_decision_code(decision: RegistryDecision) -> u32 {
    match decision {
        RegistryDecision::Accepted => PEER_TRUST_DECISION_ACCEPTED,
        RegistryDecision::AcceptedWithoutRegistryPrivate => {
            PEER_TRUST_DECISION_ACCEPTED_WITHOUT_REGISTRY_PRIVATE
        }
        RegistryDecision::AcceptedWithoutRegistryDevelopment => {
            PEER_TRUST_DECISION_ACCEPTED_WITHOUT_REGISTRY_DEVELOPMENT
        }
    }
}

fn registry_failure_code(message: &str) -> Option<u32> {
    if message.contains("registry record required by public mesh trust policy") {
        return Some(PEER_TRUST_FAILURE_REGISTRY_REQUIRED);
    }
    if message.contains("registry record has expired") {
        return Some(PEER_TRUST_FAILURE_REGISTRY_EXPIRED);
    }
    if message.contains("registry record is revoked") {
        return Some(PEER_TRUST_FAILURE_REGISTRY_REVOKED);
    }
    if message.contains("registry record is suspended")
        || message.contains("registry record is not active")
    {
        return Some(PEER_TRUST_FAILURE_REGISTRY_SUSPENDED);
    }
    if message.contains("identity registry lookup failed")
        || message.contains("registry unavailable")
    {
        return Some(PEER_TRUST_FAILURE_REGISTRY_LOOKUP);
    }
    if message.contains("stake or reputation")
        || (message.contains("stake") && message.contains("reputation"))
    {
        return Some(PEER_TRUST_FAILURE_REGISTRY_STAKE_OR_REPUTATION);
    }
    if message.contains("latest_peer_record_hash_hex mismatch") {
        return Some(PEER_TRUST_FAILURE_REGISTRY_RECORD_HASH_MISMATCH);
    }
    let registry_key_mismatch = [
        "device_public_key_hash_hex mismatch",
        "pqc_binding_hash_hex mismatch",
        "node_signing_public_key_hash_hex mismatch",
        "transport_public_key_hash_hex mismatch",
    ]
    .iter()
    .any(|pattern| message.contains(pattern));
    if registry_key_mismatch {
        return Some(PEER_TRUST_FAILURE_REGISTRY_KEY_MISMATCH);
    }
    let registry_binding_mismatch = message.contains("peer_id mismatch");
    if registry_binding_mismatch || (message.contains("registry") && message.contains("mismatch")) {
        return Some(PEER_TRUST_FAILURE_REGISTRY_MISMATCH);
    }
    if message.contains("registry") {
        return Some(PEER_TRUST_FAILURE_REGISTRY_VERIFICATION);
    }
    None
}

pub fn peer_trust_failure_code_label(failure_code: u32) -> Option<&'static str> {
    match failure_code {
        PEER_TRUST_FAILURE_REGISTRY_REQUIRED => Some("rejected_missing_registry"),
        PEER_TRUST_FAILURE_REGISTRY_REVOKED => Some("rejected_revoked"),
        PEER_TRUST_FAILURE_REGISTRY_SUSPENDED => Some("rejected_suspended"),
        PEER_TRUST_FAILURE_REGISTRY_EXPIRED => Some("rejected_expired"),
        PEER_TRUST_FAILURE_REGISTRY_MISMATCH | PEER_TRUST_FAILURE_REGISTRY_KEY_MISMATCH => {
            Some("rejected_key_mismatch")
        }
        PEER_TRUST_FAILURE_REGISTRY_RECORD_HASH_MISMATCH => Some("rejected_record_hash_mismatch"),
        PEER_TRUST_FAILURE_REGISTRY_STAKE_OR_REPUTATION => Some("rejected_stake_or_reputation"),
        PEER_TRUST_FAILURE_REGISTRY_LOOKUP => Some("registry_unavailable"),
        PEER_TRUST_FAILURE_REGISTRY_VERIFICATION => Some("registry_unavailable"),
        PEER_TRUST_FAILURE_NONE => None,
        _ => None,
    }
}

pub fn peer_trust_failure_summary(failure_code: u32) -> Option<&'static str> {
    match failure_code {
        PEER_TRUST_FAILURE_REGISTRY_REQUIRED => {
            Some("Public mesh requires a matching Dytallix registry record.")
        }
        PEER_TRUST_FAILURE_REGISTRY_REVOKED => Some("Dytallix registry record is revoked."),
        PEER_TRUST_FAILURE_REGISTRY_SUSPENDED => Some("Dytallix registry record is suspended."),
        PEER_TRUST_FAILURE_REGISTRY_EXPIRED => Some("Dytallix registry record has expired."),
        PEER_TRUST_FAILURE_REGISTRY_MISMATCH | PEER_TRUST_FAILURE_REGISTRY_KEY_MISMATCH => {
            Some("Dytallix registry key binding does not match the peer assertion.")
        }
        PEER_TRUST_FAILURE_REGISTRY_RECORD_HASH_MISMATCH => {
            Some("Dytallix registry record hash does not match the signed peer record.")
        }
        PEER_TRUST_FAILURE_REGISTRY_STAKE_OR_REPUTATION => {
            Some("Dytallix registry stake or reputation requirement was not met.")
        }
        PEER_TRUST_FAILURE_REGISTRY_LOOKUP | PEER_TRUST_FAILURE_REGISTRY_VERIFICATION => {
            Some("Dytallix registry validation is unavailable.")
        }
        PEER_TRUST_FAILURE_NONE => None,
        _ => None,
    }
}

/// Per-peer session state. One instance per active remote peer.
///
/// The fields that matter to operators (state, path_kind, last_error,
/// frame/byte counters, reconnect_count) are per-peer because each peer
/// reconnects, fails, and carries traffic independently. Transport-level
/// counts that span all peers (most notably `network_event_count`) live
/// on [`AggregateState`].
#[derive(Debug)]
struct SharedState {
    state: StdMutex<MeshTransportState>,
    path_kind: StdMutex<Option<PathKind>>,
    last_error: StdMutex<Option<String>>,
    peer_trust: StdMutex<PeerTrustStatusRaw>,
    frames_sent: AtomicU64,
    frames_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    send_failures: AtomicU64,
    receive_failures: AtomicU64,
    reconnect_count: AtomicU64,
    packet_session: StdMutex<Option<PacketSessionLease>>,
}

impl SharedState {
    fn new() -> Self {
        Self {
            state: StdMutex::new(MeshTransportState::Connecting),
            path_kind: StdMutex::new(None),
            last_error: StdMutex::new(None),
            peer_trust: StdMutex::new(PeerTrustStatusRaw::default()),
            frames_sent: AtomicU64::new(0),
            frames_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            send_failures: AtomicU64::new(0),
            receive_failures: AtomicU64::new(0),
            reconnect_count: AtomicU64::new(0),
            packet_session: StdMutex::new(None),
        }
    }

    fn set_state(&self, state: MeshTransportState) {
        if let Ok(mut guard) = self.state.lock() {
            *guard = state;
        }
    }

    fn state_code(&self) -> u32 {
        self.state
            .lock()
            .map(|guard| guard.as_code())
            .unwrap_or(MeshTransportState::Failed.as_code())
    }

    fn set_path_kind(&self, kind: Option<PathKind>) {
        if let Ok(mut guard) = self.path_kind.lock() {
            *guard = kind;
        }
    }

    fn path_kind_code(&self) -> u32 {
        match self.path_kind.lock().ok().and_then(|guard| *guard) {
            None => 0,
            Some(PathKind::Direct) => 1,
            Some(PathKind::Relay) => 2,
        }
    }

    fn set_last_error(&self, error: Option<String>) {
        if let Ok(mut guard) = self.last_error.lock() {
            *guard = error;
        }
    }

    fn set_peer_trust_decision(&self, decision: RegistryDecision, source: PeerRecordSource) {
        if let Ok(mut guard) = self.peer_trust.lock() {
            *guard = PeerTrustStatusRaw::from_registry_decision(decision, source);
        }
    }

    fn set_peer_trust_failure_message(&self, message: &str) -> Option<PeerTrustStatusRaw> {
        let Some(status) = PeerTrustStatusRaw::from_failure_message(message) else {
            return None;
        };
        if let Ok(mut guard) = self.peer_trust.lock() {
            *guard = status;
        }
        Some(status)
    }

    fn peer_trust_status(&self) -> PeerTrustStatusRaw {
        self.peer_trust
            .lock()
            .map(|guard| *guard)
            .unwrap_or_default()
    }

    fn publish_packet_session(&self, session: PacketSessionLease) {
        if let Ok(mut guard) = self.packet_session.lock() {
            *guard = Some(session);
        }
    }

    fn current_packet_session(&self) -> Option<PacketSessionLease> {
        self.packet_session
            .lock()
            .ok()?
            .as_ref()
            .filter(|session| session.is_current())
            .cloned()
    }

    fn clear_packet_session(&self, generation: u64) -> Option<PacketSessionLease> {
        let mut guard = self.packet_session.lock().ok()?;
        if guard.as_ref().map(|session| session.generation) != Some(generation) {
            return None;
        }
        guard.take()
    }

    fn take_packet_session(&self) -> Option<PacketSessionLease> {
        self.packet_session.lock().ok()?.take()
    }

    /// Per-peer metrics only. Transport-level fields like
    /// `network_event_count` are populated by the caller from
    /// [`AggregateState`].
    fn snapshot_per_peer_metrics(&self) -> PerPeerMetricsRaw {
        PerPeerMetricsRaw {
            frames_sent: self.frames_sent.load(Ordering::Relaxed),
            frames_received: self.frames_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            send_failures: self.send_failures.load(Ordering::Relaxed),
            receive_failures: self.receive_failures.load(Ordering::Relaxed),
            reconnect_count: self.reconnect_count.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct PerPeerMetricsRaw {
    frames_sent: u64,
    frames_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    send_failures: u64,
    receive_failures: u64,
    reconnect_count: u64,
}

/// Transport-level counters that aren't tied to a specific peer.
#[derive(Debug)]
struct AggregateState {
    network_event_count: AtomicU64,
}

impl AggregateState {
    fn new() -> Self {
        Self {
            network_event_count: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeshTransportConfig {
    pub mesh_id: String,
    pub local_peer_id: String,
    pub remote_peer_id: String,
    pub rendezvous_url: String,
    #[serde(default)]
    pub relay_url: Option<String>,
    /// Local QUIC bind address, e.g. "127.0.0.1:0" or "0.0.0.0:0".
    pub bind_addr: String,
    #[serde(default = "default_overall_deadline_ms")]
    pub overall_deadline_ms: u64,
    #[serde(default = "default_direct_probe_timeout_ms")]
    pub direct_probe_timeout_ms: u64,
    #[serde(default = "default_probe_pacing_ms")]
    pub probe_pacing_ms: u64,
    #[serde(default)]
    pub enable_ice: bool,
    /// Initial sleep between reconnect attempts after a connect failure.
    /// Doubles on each consecutive failure up to `reconnect_max_backoff_ms`,
    /// then plateaus. Resets on a successful connect or any
    /// reachability-restoring network event.
    #[serde(default = "default_reconnect_initial_backoff_ms")]
    pub reconnect_initial_backoff_ms: u64,
    #[serde(default = "default_reconnect_max_backoff_ms")]
    pub reconnect_max_backoff_ms: u64,
    /// Maximum authenticated packet-session lifetime before a fresh PQC
    /// handshake is required.
    #[serde(default = "default_packet_session_lifetime_seconds")]
    pub packet_session_lifetime_seconds: u64,
    /// Maximum protected payload bytes across the live session before a fresh
    /// PQC handshake is required.
    #[serde(default = "default_packet_session_rekey_after_bytes")]
    pub packet_session_rekey_after_bytes: u64,
    /// Optional bind address for the OpenMetrics HTTP endpoint. When set,
    /// the transport spawns the metrics exporter on this address and
    /// publishes its live state at `GET /metrics` in OpenMetrics text
    /// format. Off by default per the privacy spec — operators must
    /// explicitly opt in.
    #[serde(default)]
    pub metrics_endpoint_bind_addr: Option<String>,
    /// Inbound peer authorization list. When set, the responder loop
    /// rejects any peer whose `InboundIdentityAssertion` falls outside
    /// the ACL — the QUIC connection is closed without a response so the
    /// rejection reason isn't leaked over the wire. When `None`, every
    /// peer that produces a valid assertion (correct mesh_id, fresh
    /// timestamp, valid ML-DSA signature) is accepted.
    #[serde(default)]
    pub inbound_acl: Option<PeerAcl>,
    /// Kill-switch for the inbound responder loop. When `true`,
    /// `MeshTransportHandle::new` skips binding a server endpoint and
    /// the transport behaves like the pre-responder world (outbound
    /// only). Useful in environments where binding a server port is
    /// blocked or unwanted (e.g. some CI sandboxes). Default `false`.
    #[serde(default)]
    pub disable_inbound_responder: bool,
    /// Filesystem path for a `FilePeerStore` that persists signed
    /// peer records across process restarts. When set, the connector
    /// uses the store as a fallback for rendezvous lookups (graceful
    /// degradation under rendezvous outage) and writes through to it
    /// on every successful lookup. The parent directory MUST exist
    /// when the handle is constructed; the handle does not auto-
    /// create directory trees. When `None`, the connector keeps an
    /// in-memory-only store that's lost on restart.
    #[serde(default)]
    pub peer_store_path: Option<String>,
    /// Optional base64 (standard alphabet, with padding) of a
    /// 32-byte SHAKE256 envelope key. When set together with
    /// `peer_store_path`, the on-disk file is protected in the v3
    /// envelope; without it the file is plaintext JSON. The host
    /// (Swift app) is expected to mint + persist this key in the
    /// macOS Keychain. `qlinkctl` deployments without a Keychain
    /// can leave this `None` and rely on file mode 0o600.
    #[serde(default)]
    pub peer_store_key_b64: Option<String>,
    #[serde(default = "default_mesh_trust_policy")]
    pub mesh_trust_policy: MeshTrustPolicy,
    #[serde(default)]
    pub dytallix_identity: Option<DytallixRegistryLookupConfig>,
}

fn default_overall_deadline_ms() -> u64 {
    3_000
}
fn default_direct_probe_timeout_ms() -> u64 {
    750
}
fn default_probe_pacing_ms() -> u64 {
    50
}
fn default_reconnect_initial_backoff_ms() -> u64 {
    250
}
fn default_reconnect_max_backoff_ms() -> u64 {
    30_000
}
fn default_packet_session_lifetime_seconds() -> u64 {
    DEFAULT_PACKET_SESSION_LIFETIME_SECONDS
}
fn default_packet_session_rekey_after_bytes() -> u64 {
    DEFAULT_PACKET_SESSION_REKEY_AFTER_BYTES
}
fn default_mesh_trust_policy() -> MeshTrustPolicy {
    MeshTrustPolicy::DevelopmentOptional
}

fn validate_packet_session_policy(config: &MeshTransportConfig) -> Result<()> {
    if config.packet_session_lifetime_seconds == 0 {
        return Err(QlinkError::Protocol(
            "packet_session_lifetime_seconds must be greater than zero".into(),
        ));
    }
    if config.packet_session_rekey_after_bytes == 0 {
        return Err(QlinkError::Protocol(
            "packet_session_rekey_after_bytes must be greater than zero".into(),
        ));
    }
    Ok(())
}

fn validate_public_dytallix_registry_pins(
    policy: MeshTrustPolicy,
    config: Option<&DytallixRegistryLookupConfig>,
) -> Result<()> {
    if policy != MeshTrustPolicy::PublicRequired {
        return Ok(());
    }
    let Some(config) = config else {
        return Err(QlinkError::Protocol(
            "public Dytallix registry trust requires dytallixIdentity config".into(),
        ));
    };
    if config
        .network_id
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(QlinkError::Protocol(
            "public Dytallix registry trust requires networkId".into(),
        ));
    }
    if config
        .chain_id
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(QlinkError::Protocol(
            "public Dytallix registry trust requires chainId".into(),
        ));
    }
    if config.allowed_rpc_endpoints.is_empty() {
        return Err(QlinkError::Protocol(
            "public Dytallix registry trust requires allowedRpcEndpoints".into(),
        ));
    }
    Ok(())
}

/// A frame received from a specific remote peer. Multi-peer transports
/// preserve the source peer ID so callers can route inbound traffic.
#[derive(Debug, Clone)]
pub struct InboundFrame {
    pub peer_id: String,
    pub frame: Vec<u8>,
    pub packet_session: PacketSessionLease,
}

/// Per-peer session state held inside `MeshTransportHandle`. Each entry
/// drives one independent session manager loop with its own outbound
/// queue, network-event channel, and shared state.
struct PerPeerSession {
    outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    event_tx: mpsc::UnboundedSender<NetworkEvent>,
    shutdown_tx: mpsc::UnboundedSender<()>,
    shared: Arc<SharedState>,
    packet_session_event_tx: mpsc::UnboundedSender<PacketSessionEvent>,
    manager_task: Option<JoinHandle<()>>,
}

impl PerPeerSession {
    /// Tears down this peer's session. Called both when the operator
    /// removes the peer and when the whole transport is dropped.
    fn shutdown(&mut self) {
        if let Some(session) = self.shared.take_packet_session() {
            let peer_id = session.peer_id.clone();
            let generation = session.generation;
            let _ = self
                .packet_session_event_tx
                .send(PacketSessionEvent::Cleared {
                    peer_id: session.peer_id,
                    direction: session.direction,
                    generation,
                });
            let _ = self
                .packet_session_event_tx
                .send(PacketSessionEvent::Cleared {
                    peer_id,
                    direction: PacketSessionDirection::Inbound,
                    generation,
                });
        }
        let _ = self.shutdown_tx.send(());
        if let Some(handle) = self.manager_task.take() {
            handle.abort();
        }
        self.shared.set_state(MeshTransportState::Stopped);
    }
}

pub struct MeshTransportHandle {
    /// Wrapped in `Option` so `Drop` can take it out and call
    /// `Runtime::shutdown_background()`. Letting a `Runtime` drop normally
    /// inside an async context panics with "Cannot drop a runtime in a
    /// context where blocking is not allowed".
    runtime: Option<Runtime>,
    /// Shared mesh connector — one rendezvous + QUIC endpoint serves all
    /// peers. The connector itself is multi-peer-friendly: its caches
    /// (last-good, mDNS) are keyed by remote peer ID.
    connector: Arc<MeshConnector>,
    /// Backoff policy applied uniformly across all peers. (Per-peer
    /// backoff state lives inside each session manager.)
    backoff: BackoffConfig,
    /// Active peers, keyed by remote peer ID. `add_peer` inserts;
    /// `remove_peer` extracts and shuts down the entry. Wrapped in `Arc`
    /// so the OpenMetrics provider closure can read it without
    /// holding the handle.
    peers: Arc<StdMutex<HashMap<String, PerPeerSession>>>,
    /// Default peer for the legacy single-peer API. Set from the config's
    /// `remote_peer_id` at construction so the existing
    /// `send_frame` / `try_receive_frame` / `state_code` keep working.
    default_peer_id: StdMutex<Option<String>>,
    /// Shared inbound channel: every per-peer session manager forwards
    /// received frames here (wrapped with the source peer ID).
    inbound_tx: mpsc::UnboundedSender<InboundFrame>,
    inbound_rx: TokioMutex<mpsc::UnboundedReceiver<InboundFrame>>,
    packet_session_generation: Arc<AtomicU64>,
    packet_session_event_tx: mpsc::UnboundedSender<PacketSessionEvent>,
    packet_session_event_rx: TokioMutex<mpsc::UnboundedReceiver<PacketSessionEvent>>,
    packet_session_lifetime_seconds: u64,
    packet_session_rekey_after_bytes: u64,
    /// Transport-level counters that aren't per-peer (today: just the
    /// network-event count).
    aggregate: Arc<AggregateState>,
    /// Retained trust/ACL rejection history. Kept outside `peers` so
    /// rejected or removed peers remain visible to diagnostics.
    blocked_peer_history: Arc<BlockedPeerHistory>,
    /// Held only when the operator opted into the OpenMetrics endpoint via
    /// `metrics_endpoint_bind_addr`. Drop aborts the listener task.
    metrics_endpoint: StdMutex<Option<MetricsEndpoint>>,
    /// QUIC server certificate for the inbound responder, in DER. Callers
    /// minting peer records (Swift app, qlinkctl) must publish this DER
    /// in `device_certificate_der` so dialing peers can pin our cert via
    /// `connect_with_trusted_cert`. `None` when the responder is disabled.
    server_certificate_der: Option<Vec<u8>>,
    /// Address the inbound responder is bound to, captured at endpoint
    /// creation. Needed by callers that publish peer records (host
    /// candidate addresses) and by tests that dial the responder. `None`
    /// when the responder is disabled.
    responder_local_addr: Option<SocketAddr>,
    /// Responder accept-loop task. Aborted on `Drop`. `None` when the
    /// responder is disabled via `disable_inbound_responder`.
    responder_task: StdMutex<Option<JoinHandle<()>>>,
}

impl MeshTransportHandle {
    pub fn from_json_config(bytes: &[u8]) -> Result<Self> {
        let config: MeshTransportConfig = serde_json::from_slice(bytes)?;
        Self::new(config)
    }

    pub fn new(config: MeshTransportConfig) -> Result<Self> {
        Self::new_with_keypair(config, None)
    }

    /// Variant of `new` that also installs a local device keypair on
    /// the connector. When set, the connector signs and sends an
    /// `InboundIdentityAssertion` over a fresh uni-stream immediately
    /// after each successful QUIC handshake — this is what lets the
    /// remote peer's responder loop verify our peer_id and run its
    /// inbound ACL. Without it, remote responders that require
    /// assertions (the production responder this crate now ships) close
    /// our connection silently.
    ///
    /// The keypair's `public_key().peer_id()` MUST match
    /// `config.local_peer_id` for the same reason `publish_self`
    /// requires the match: a connector that asserts a different
    /// identity than its published peer_id is unauthenticatable.
    #[cfg(not(feature = "dev-quic-carrier"))]
    pub fn new_with_keypair(
        config: MeshTransportConfig,
        local_device_keypair: Option<Arc<DeviceKeypair>>,
    ) -> Result<Self> {
        validate_packet_session_policy(&config)?;
        if let Some(local_device_keypair) = local_device_keypair.as_ref() {
            let keypair_peer_id = local_device_keypair.public_key().peer_id();
            if keypair_peer_id != config.local_peer_id {
                return Err(QlinkError::Protocol(format!(
                    "MeshTransportHandle local_device_keypair peer_id {keypair_peer_id} \
                     does not match config.local_peer_id {}",
                    config.local_peer_id
                )));
            }
        } else {
            if config.relay_url.is_none() {
                return Err(QlinkError::Protocol(
                    "MeshTransportHandle direct transport requires local_device_keypair for PQC"
                        .into(),
                ));
            }
            if !config.disable_inbound_responder {
                return Err(QlinkError::Protocol(
                    "MeshTransportHandle inbound responder requires local_device_keypair for PQC"
                        .into(),
                ));
            }
        }
        validate_public_dytallix_registry_pins(
            config.mesh_trust_policy,
            config.dytallix_identity.as_ref(),
        )?;

        let runtime = Runtime::new().map_err(|err| {
            QlinkError::Protocol(format!("failed to create mesh transport runtime: {err}"))
        })?;

        let bind_addr: SocketAddr = config
            .bind_addr
            .parse()
            .map_err(|err| QlinkError::Protocol(format!("invalid bind_addr: {err}")))?;

        let _runtime_guard = runtime.enter();

        let (server_socket, responder_local_addr) = if config.disable_inbound_responder {
            (None, None)
        } else {
            let socket = runtime
                .block_on(UdpSocket::bind(bind_addr))
                .map_err(|err| {
                    QlinkError::Protocol(format!("failed to bind native UDP responder: {err}"))
                })?;
            let local_addr = socket.local_addr().map_err(|err| {
                QlinkError::Protocol(format!("failed to read native UDP responder addr: {err}"))
            })?;
            (Some(socket), Some(local_addr))
        };

        let rendezvous_client = RendezvousClient::new(config.rendezvous_url.clone());
        let local_credentials = IceCredentials::generate()?;

        let mut connector_config =
            MeshConnectorConfig::new(config.mesh_id.clone(), config.local_peer_id.clone())
                .with_overall_deadline(Duration::from_millis(config.overall_deadline_ms))
                .with_direct_probe_timeout(Duration::from_millis(config.direct_probe_timeout_ms))
                .with_probe_pacing(Duration::from_millis(config.probe_pacing_ms))
                .with_mesh_trust_policy(config.mesh_trust_policy);
        if let Some(relay) = config.relay_url.clone() {
            connector_config = connector_config.with_relay_server(relay);
        }
        if config.enable_ice {
            connector_config = connector_config.with_local_ice_credentials(local_credentials);
        }
        if let Some(local_device_keypair) = local_device_keypair.clone() {
            connector_config = connector_config.with_local_device_keypair(local_device_keypair);
        }
        if let Some(registry_config) = config.dytallix_identity.clone() {
            let registry = DytallixIdentityRegistry::from_lookup_config(registry_config)?;
            connector_config = connector_config.with_identity_registry_lookup(Arc::new(registry));
        }
        let inbound_mesh_trust_policy = connector_config.mesh_trust_policy;
        let inbound_identity_registry_lookup = connector_config.identity_registry_lookup.clone();

        let peer_store: Arc<dyn PeerStore> = match config.peer_store_path.as_deref() {
            None => Arc::new(InMemoryPeerStore::new()),
            Some(path) => match config.peer_store_key_b64.as_deref() {
                None => Arc::new(open_file_peer_store(path)?),
                Some(b64) => {
                    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
                    let key_bytes = B64.decode(b64).map_err(|err| {
                        QlinkError::Protocol(format!(
                            "peer_store_key_b64 is not valid base64: {err}"
                        ))
                    })?;
                    if key_bytes.len() != 32 {
                        return Err(QlinkError::Protocol(format!(
                            "peer_store_key_b64 must decode to exactly 32 bytes; got {}",
                            key_bytes.len()
                        )));
                    }
                    let mut key = [0_u8; 32];
                    key.copy_from_slice(&key_bytes);
                    Arc::new(open_file_peer_store_with_key(path, key)?)
                }
            },
        };

        let connector = Arc::new(
            MeshConnector::new(connector_config, rendezvous_client).with_peer_store(peer_store),
        );

        let backoff = BackoffConfig {
            initial: Duration::from_millis(config.reconnect_initial_backoff_ms.max(1)),
            max: Duration::from_millis(config.reconnect_max_backoff_ms.max(1)),
        };

        let aggregate = Arc::new(AggregateState::new());
        let blocked_peer_history = Arc::new(BlockedPeerHistory::new());
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<InboundFrame>();
        let packet_session_generation = Arc::new(AtomicU64::new(0));
        let (packet_session_event_tx, packet_session_event_rx) =
            mpsc::unbounded_channel::<PacketSessionEvent>();
        let peers: Arc<StdMutex<HashMap<String, PerPeerSession>>> =
            Arc::new(StdMutex::new(HashMap::new()));

        let metrics_endpoint = match config.metrics_endpoint_bind_addr.as_ref() {
            Some(addr_str) => {
                let bind: SocketAddr = addr_str.parse().map_err(|err| {
                    QlinkError::Protocol(format!("invalid metrics_endpoint_bind_addr: {err}"))
                })?;
                let peers_provider = peers.clone();
                let aggregate_provider = aggregate.clone();
                let provider: crate::metrics_endpoint::MetricsSnapshotProvider =
                    Arc::new(move || mesh_transport_snapshot(&peers_provider, &aggregate_provider));
                Some(runtime.block_on(spawn_metrics_endpoint(bind, provider))?)
            }
            None => None,
        };

        let responder_task = match server_socket {
            Some(socket) => {
                let inbound_acl = config.inbound_acl.clone().map(Arc::new);
                let mesh_id = config.mesh_id.clone();
                let local_peer_id = config.local_peer_id.clone();
                let local_keypair = local_device_keypair
                    .clone()
                    .expect("inbound responder requires a local device keypair");
                let local_addr = responder_local_addr
                    .expect("native UDP responder local address must exist when enabled");
                let inbound_tx_responder = inbound_tx.clone();
                let packet_session_generation_responder = packet_session_generation.clone();
                let packet_session_event_tx_responder = packet_session_event_tx.clone();
                let blocked_peer_history_responder = blocked_peer_history.clone();
                Some(runtime.spawn(run_native_udp_responder_loop(
                    socket,
                    local_addr,
                    mesh_id,
                    local_peer_id,
                    local_keypair,
                    inbound_acl,
                    inbound_mesh_trust_policy,
                    inbound_identity_registry_lookup,
                    inbound_tx_responder,
                    packet_session_generation_responder,
                    packet_session_event_tx_responder,
                    blocked_peer_history_responder,
                    config.packet_session_lifetime_seconds,
                    config.packet_session_rekey_after_bytes,
                )))
            }
            None => None,
        };

        let handle = Self {
            runtime: Some(runtime),
            connector,
            backoff,
            peers,
            default_peer_id: StdMutex::new(Some(config.remote_peer_id.clone())),
            inbound_tx,
            inbound_rx: TokioMutex::new(inbound_rx),
            packet_session_generation,
            packet_session_event_tx,
            packet_session_event_rx: TokioMutex::new(packet_session_event_rx),
            packet_session_lifetime_seconds: config.packet_session_lifetime_seconds,
            packet_session_rekey_after_bytes: config.packet_session_rekey_after_bytes,
            aggregate,
            blocked_peer_history,
            metrics_endpoint: StdMutex::new(metrics_endpoint),
            server_certificate_der: None,
            responder_local_addr,
            responder_task: StdMutex::new(responder_task),
        };

        handle.add_peer(&config.remote_peer_id)?;

        Ok(handle)
    }

    #[cfg(feature = "dev-quic-carrier")]
    pub fn new_with_keypair(
        config: MeshTransportConfig,
        local_device_keypair: Option<Arc<DeviceKeypair>>,
    ) -> Result<Self> {
        validate_packet_session_policy(&config)?;
        if let Some(local_device_keypair) = local_device_keypair.as_ref() {
            let keypair_peer_id = local_device_keypair.public_key().peer_id();
            if keypair_peer_id != config.local_peer_id {
                return Err(QlinkError::Protocol(format!(
                    "MeshTransportHandle local_device_keypair peer_id {keypair_peer_id} \
                     does not match config.local_peer_id {}",
                    config.local_peer_id
                )));
            }
        } else {
            if config.relay_url.is_none() {
                return Err(QlinkError::Protocol(
                    "MeshTransportHandle direct transport requires local_device_keypair for PQC"
                        .into(),
                ));
            }
            if !config.disable_inbound_responder {
                return Err(QlinkError::Protocol(
                    "MeshTransportHandle inbound responder requires local_device_keypair for PQC"
                        .into(),
                ));
            }
        }
        validate_public_dytallix_registry_pins(
            config.mesh_trust_policy,
            config.dytallix_identity.as_ref(),
        )?;

        let runtime = Runtime::new().map_err(|err| {
            QlinkError::Protocol(format!("failed to create mesh transport runtime: {err}"))
        })?;

        let bind_addr: SocketAddr = config
            .bind_addr
            .parse()
            .map_err(|err| QlinkError::Protocol(format!("invalid bind_addr: {err}")))?;

        let _runtime_guard = runtime.enter();

        // The inbound responder owns the operator-supplied `bind_addr`
        // (it's the port peers will dial). The outbound client runs on a
        // distinct ephemeral socket on the same interface — quinn's
        // `Endpoint` doesn't multiplex client + server roles cleanly, and
        // peers shouldn't see our outbound source port advertised via
        // rendezvous (we publish the responder's address, not the
        // client's).
        let (server_endpoint, server_certificate_der, responder_local_addr) =
            if config.disable_inbound_responder {
                (None, None, None)
            } else {
                let (endpoint, certificate) = QuicEndpoint::server(bind_addr)?;
                let local_addr = endpoint.local_addr()?;
                let cert_der = certificate.as_der().to_vec();
                (Some(endpoint), Some(cert_der), Some(local_addr))
            };

        let client_bind_addr = if config.disable_inbound_responder {
            // No server bound — let the client take the operator's
            // address as before.
            bind_addr
        } else {
            // Same interface, ephemeral port.
            SocketAddr::new(bind_addr.ip(), 0)
        };

        // The connector learns each peer's QUIC server cert from the
        // signed rendezvous record and uses `connect_with_trusted_cert`
        // for per-connection trust. The endpoint-level trust list is
        // empty — any direct `connect()` would fail by design.
        let quic_endpoint = QuicEndpoint::client(client_bind_addr, &[])?;

        let rendezvous_client = RendezvousClient::new(config.rendezvous_url.clone());
        let local_credentials = IceCredentials::generate()?;

        let mut connector_config =
            MeshConnectorConfig::new(config.mesh_id.clone(), config.local_peer_id.clone())
                .with_overall_deadline(Duration::from_millis(config.overall_deadline_ms))
                .with_direct_probe_timeout(Duration::from_millis(config.direct_probe_timeout_ms))
                .with_probe_pacing(Duration::from_millis(config.probe_pacing_ms))
                .with_mesh_trust_policy(config.mesh_trust_policy);
        if let Some(relay) = config.relay_url.clone() {
            connector_config = connector_config.with_relay_server(relay);
        }
        if config.enable_ice {
            connector_config = connector_config.with_local_ice_credentials(local_credentials);
        }
        if let Some(local_device_keypair) = local_device_keypair.clone() {
            connector_config = connector_config.with_local_device_keypair(local_device_keypair);
        }
        if let Some(registry_config) = config.dytallix_identity.clone() {
            let registry = DytallixIdentityRegistry::from_lookup_config(registry_config)?;
            connector_config = connector_config.with_identity_registry_lookup(Arc::new(registry));
        }
        let inbound_mesh_trust_policy = connector_config.mesh_trust_policy;
        let inbound_identity_registry_lookup = connector_config.identity_registry_lookup.clone();

        // Resolve the configured persistence path, if any, into a
        // `FilePeerStore`. Construction errors (missing parent dir,
        // unreadable file) are surfaced up — we'd rather refuse to
        // start than silently degrade to ephemeral storage when the
        // operator asked for persistence. When `peer_store_key_b64`
        // is set, the file is wrapped in the v3 SHAKE256 envelope;
        // the key MUST decode to exactly 32 bytes.
        let peer_store: Arc<dyn PeerStore> = match config.peer_store_path.as_deref() {
            None => Arc::new(InMemoryPeerStore::new()),
            Some(path) => match config.peer_store_key_b64.as_deref() {
                None => Arc::new(open_file_peer_store(path)?),
                Some(b64) => {
                    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
                    let key_bytes = B64.decode(b64).map_err(|err| {
                        QlinkError::Protocol(format!(
                            "peer_store_key_b64 is not valid base64: {err}"
                        ))
                    })?;
                    if key_bytes.len() != 32 {
                        return Err(QlinkError::Protocol(format!(
                            "peer_store_key_b64 must decode to exactly 32 bytes; got {}",
                            key_bytes.len()
                        )));
                    }
                    let mut key = [0_u8; 32];
                    key.copy_from_slice(&key_bytes);
                    Arc::new(open_file_peer_store_with_key(path, key)?)
                }
            },
        };

        let connector = Arc::new(
            MeshConnector::new(connector_config, rendezvous_client, quic_endpoint)
                .with_peer_store(peer_store),
        );

        let backoff = BackoffConfig {
            initial: Duration::from_millis(config.reconnect_initial_backoff_ms.max(1)),
            max: Duration::from_millis(config.reconnect_max_backoff_ms.max(1)),
        };

        let aggregate = Arc::new(AggregateState::new());
        let blocked_peer_history = Arc::new(BlockedPeerHistory::new());
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<InboundFrame>();
        let packet_session_generation = Arc::new(AtomicU64::new(0));
        let (packet_session_event_tx, packet_session_event_rx) =
            mpsc::unbounded_channel::<PacketSessionEvent>();
        let peers: Arc<StdMutex<HashMap<String, PerPeerSession>>> =
            Arc::new(StdMutex::new(HashMap::new()));

        // Optional OpenMetrics endpoint. Off by default; only spawned
        // when the operator explicitly sets a bind address. The provider
        // closure clones the `peers` and `aggregate` Arcs and walks them
        // on every scrape — newly added peers surface automatically.
        let metrics_endpoint = match config.metrics_endpoint_bind_addr.as_ref() {
            Some(addr_str) => {
                let bind: SocketAddr = addr_str.parse().map_err(|err| {
                    QlinkError::Protocol(format!("invalid metrics_endpoint_bind_addr: {err}"))
                })?;
                let peers_provider = peers.clone();
                let aggregate_provider = aggregate.clone();
                let provider: crate::metrics_endpoint::MetricsSnapshotProvider =
                    Arc::new(move || mesh_transport_snapshot(&peers_provider, &aggregate_provider));
                Some(runtime.block_on(spawn_metrics_endpoint(bind, provider))?)
            }
            None => None,
        };

        // Spawn the responder loop now that the inbound channel exists.
        // The loop accepts QUIC connections on the server endpoint, runs
        // identity + ACL evaluation, and routes accepted frames into
        // `inbound_tx` tagged with the verified peer_id. Disabled paths
        // simply skip the spawn.
        let responder_task = match server_endpoint {
            Some(endpoint) => {
                let inbound_acl = config.inbound_acl.clone().map(Arc::new);
                let mesh_id = config.mesh_id.clone();
                let local_peer_id = config.local_peer_id.clone();
                let local_keypair = local_device_keypair
                    .clone()
                    .expect("inbound responder requires a local device keypair");
                let server_cert_der = server_certificate_der
                    .clone()
                    .expect("server certificate DER must exist when responder is enabled");
                let inbound_tx_responder = inbound_tx.clone();
                let packet_session_generation_responder = packet_session_generation.clone();
                let packet_session_event_tx_responder = packet_session_event_tx.clone();
                let blocked_peer_history_responder = blocked_peer_history.clone();
                let task = runtime.spawn(run_responder_loop(
                    endpoint,
                    mesh_id,
                    local_peer_id,
                    local_keypair,
                    server_cert_der,
                    inbound_acl,
                    inbound_mesh_trust_policy,
                    inbound_identity_registry_lookup,
                    inbound_tx_responder,
                    packet_session_generation_responder,
                    packet_session_event_tx_responder,
                    blocked_peer_history_responder,
                    config.packet_session_lifetime_seconds,
                    config.packet_session_rekey_after_bytes,
                ));
                Some(task)
            }
            None => None,
        };

        let handle = Self {
            runtime: Some(runtime),
            connector,
            backoff,
            peers,
            default_peer_id: StdMutex::new(Some(config.remote_peer_id.clone())),
            inbound_tx,
            inbound_rx: TokioMutex::new(inbound_rx),
            packet_session_generation,
            packet_session_event_tx,
            packet_session_event_rx: TokioMutex::new(packet_session_event_rx),
            packet_session_lifetime_seconds: config.packet_session_lifetime_seconds,
            packet_session_rekey_after_bytes: config.packet_session_rekey_after_bytes,
            aggregate,
            blocked_peer_history,
            metrics_endpoint: StdMutex::new(metrics_endpoint),
            server_certificate_der,
            responder_local_addr,
            responder_task: StdMutex::new(responder_task),
        };

        // Auto-add the configured peer for back-compat with the
        // single-peer API.
        handle.add_peer(&config.remote_peer_id)?;

        Ok(handle)
    }

    // (continued below — public API)
}

impl MeshTransportHandle {
    /// Local address of the OpenMetrics endpoint, when one is bound.
    pub fn metrics_endpoint_addr(&self) -> Option<SocketAddr> {
        self.metrics_endpoint
            .lock()
            .ok()?
            .as_ref()
            .map(|endpoint| endpoint.local_addr())
    }

    /// DER-encoded QUIC certificate the inbound responder presents.
    /// Callers that mint signed peer records must publish this DER as
    /// `device_certificate_der` so dialing peers can pin our cert.
    /// Returns `None` when the responder is disabled.
    pub fn server_certificate_der(&self) -> Option<&[u8]> {
        self.server_certificate_der.as_deref()
    }

    /// Local address the inbound responder is bound to. `None` when the
    /// responder is disabled. Stable for the lifetime of the handle.
    pub fn responder_local_addr(&self) -> Option<SocketAddr> {
        self.responder_local_addr
    }

    /// Synchronous wrapper for `publish_self` that drives the async
    /// publish on the handle's internal runtime. Intended for FFI
    /// callers (Swift) that don't have their own async context.
    ///
    /// MUST NOT be called from inside a tokio runtime (would deadlock
    /// on `block_on`). Use the async `publish_self` from Rust async
    /// code; use this from synchronous FFI entry points.
    pub fn publish_self_blocking(
        &self,
        keypair: &DeviceKeypair,
        rendezvous_url: &str,
        ttl_seconds: u64,
        sequence: u64,
        overlay_routes: Vec<String>,
    ) -> Result<PeerRecord> {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| QlinkError::Protocol("mesh transport runtime is shut down".into()))?;
        runtime.block_on(self.publish_self(
            keypair,
            rendezvous_url,
            ttl_seconds,
            sequence,
            overlay_routes,
        ))
    }

    /// Mints + signs a `PeerRecord` for the local node and publishes it
    /// to the rendezvous server, advertising the responder's bound
    /// address as a Host candidate and the responder's QUIC server
    /// certificate as the dialer's trust anchor.
    ///
    /// `keypair.public_key().peer_id()` MUST equal the `local_peer_id`
    /// passed to `MeshTransportHandle::new` — otherwise the record will
    /// publish a peer ID that doesn't match the identity the connector
    /// asserts on dial-out, and remote peers' inbound responders will
    /// reject our assertions.
    ///
    /// Returns the signed record on success so callers can republish it
    /// (verbatim or with a fresh sequence) to refresh TTL.
    ///
    /// Errors when:
    /// - the responder is disabled (no cert / addr to publish)
    /// - the supplied keypair's peer_id doesn't match the handle's
    ///   `local_peer_id`
    /// - the rendezvous publish call fails (network, server-side)
    pub async fn publish_self(
        &self,
        keypair: &DeviceKeypair,
        rendezvous_url: &str,
        ttl_seconds: u64,
        sequence: u64,
        overlay_routes: Vec<String>,
    ) -> Result<PeerRecord> {
        let cert_der = self.server_certificate_der.clone().unwrap_or_default();
        let local_addr = self.responder_local_addr.ok_or_else(|| {
            QlinkError::Protocol(
                "publish_self requires the inbound responder; bound \
                 local address is unavailable"
                    .into(),
            )
        })?;

        let connector_config = self.connector.config();
        let expected_peer_id = &connector_config.local_peer_id;
        let keypair_peer_id = keypair.public_key().peer_id();
        if &keypair_peer_id != expected_peer_id {
            return Err(QlinkError::Protocol(format!(
                "publish_self keypair peer_id {keypair_peer_id} does not match \
                 handle local_peer_id {expected_peer_id}; the wrong key would \
                 publish a record peers can't authenticate"
            )));
        }
        let mesh_id = connector_config.mesh_id.clone();

        let endpoints = vec![CandidateEndpoint {
            candidate_type: CandidateType::Host,
            address: local_addr.ip().to_string(),
            port: local_addr.port(),
            priority: HOST_PRIORITY,
        }];
        let body = UnsignedPeerRecord::new(
            mesh_id.clone(),
            // The alias gets replaced inside `UnsignedPeerRecord::new`
            // with a privacy-preserving derivative of the peer_id +
            // sequence; passing a placeholder here keeps the call site
            // self-explanatory.
            "qlink",
            keypair.public_key(),
            endpoints,
            overlay_routes,
            ttl_seconds,
            sequence,
        )
        .with_device_certificate(cert_der);
        let record = PeerRecord::signed(body, keypair)?;

        // The rendezvous publish is a single short-lived TCP request;
        // it doesn't need the handle's specialized runtime. Awaiting on
        // the caller's runtime keeps `publish_self` callable from any
        // async context (tests, `qlinkctl`, future FFI bridges).
        let client = RendezvousClient::new(rendezvous_url.to_string());
        client.publish(&mesh_id, record.clone()).await?;

        Ok(record)
    }

    /// Spawns a session manager for a new remote peer. Idempotent: if
    /// the peer is already active, this is a no-op.
    pub fn add_peer(&self, remote_peer_id: &str) -> Result<()> {
        let mut peers = self
            .peers
            .lock()
            .map_err(|_| QlinkError::Protocol("mesh transport peers mutex poisoned".into()))?;
        if peers.contains_key(remote_peer_id) {
            return Ok(());
        }

        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| QlinkError::Protocol("mesh transport runtime is shut down".into()))?;

        let shared = Arc::new(SharedState::new());
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<NetworkEvent>();
        let (shutdown_tx, shutdown_rx) = mpsc::unbounded_channel::<()>();

        let manager_task = runtime.spawn(run_session_manager(
            self.connector.clone(),
            remote_peer_id.to_string(),
            outbound_rx,
            self.inbound_tx.clone(),
            event_rx,
            shutdown_rx,
            shared.clone(),
            self.backoff,
            self.packet_session_generation.clone(),
            self.packet_session_event_tx.clone(),
            self.blocked_peer_history.clone(),
            self.packet_session_lifetime_seconds,
            self.packet_session_rekey_after_bytes,
        ));

        peers.insert(
            remote_peer_id.to_string(),
            PerPeerSession {
                outbound_tx,
                event_tx,
                shutdown_tx,
                shared,
                packet_session_event_tx: self.packet_session_event_tx.clone(),
                manager_task: Some(manager_task),
            },
        );
        Ok(())
    }

    /// Tears down a peer's session. Idempotent: removing a peer that
    /// isn't active is a no-op.
    pub fn remove_peer(&self, remote_peer_id: &str) {
        if let Ok(mut peers) = self.peers.lock() {
            if let Some(mut session) = peers.remove(remote_peer_id) {
                session.shutdown();
            }
        }
        // If the removed peer was the default, pick another active peer
        // (or None) so the legacy single-peer API doesn't dangle.
        if let Ok(mut default_guard) = self.default_peer_id.lock() {
            if default_guard.as_deref() == Some(remote_peer_id) {
                let next = self
                    .peers
                    .lock()
                    .ok()
                    .and_then(|peers| peers.keys().next().cloned());
                *default_guard = next;
            }
        }
    }

    /// Lists the peers currently being managed by this transport.
    pub fn peer_ids(&self) -> Vec<String> {
        self.peers
            .lock()
            .map(|peers| peers.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Replaces the legacy/default packet peer. The packet core is
    /// intentionally single-peer, so the replacement clears the previous
    /// lease before the new manager can publish readiness.
    pub fn replace_default_peer(&self, remote_peer_id: &str) -> Result<()> {
        let existing = self.default_peer_id_or_err().ok();
        if existing.as_deref() == Some(remote_peer_id) {
            return Ok(());
        }
        if let Some(existing) = existing {
            self.remove_peer(&existing);
        }
        self.add_peer(remote_peer_id)?;
        *self
            .default_peer_id
            .lock()
            .map_err(|_| QlinkError::Protocol("default peer id mutex poisoned".into()))? =
            Some(remote_peer_id.to_string());
        Ok(())
    }

    /// Returns the exact authenticated lease for the selected outbound peer.
    /// Multi-peer maps are rejected because `PacketTunnelCore` has one route
    /// target and cannot safely infer which peer owns a protected packet.
    pub fn default_packet_session(&self) -> Result<Option<PacketSessionLease>> {
        let default = self.default_peer_id_or_err()?;
        let peers = self
            .peers
            .lock()
            .map_err(|_| QlinkError::Protocol("mesh transport peers mutex poisoned".into()))?;
        if peers.len() != 1 {
            return Err(QlinkError::Protocol(format!(
                "single-peer packet routing requires exactly one mesh peer; found {}",
                peers.len()
            )));
        }
        let session = peers.get(&default).ok_or_else(|| {
            QlinkError::Protocol(format!(
                "default packet peer {default} is not an active mesh peer"
            ))
        })?;
        Ok(session.shared.current_packet_session())
    }

    pub fn try_receive_packet_session_event(&self) -> Option<PacketSessionEvent> {
        let mut rx = self.packet_session_event_rx.try_lock().ok()?;
        rx.try_recv().ok()
    }

    /// Snapshot of retained trust/ACL rejection history. Entries are
    /// owned values so callers can serialize or inspect them after the
    /// history mutex has been released.
    pub fn blocked_peer_history(&self) -> Vec<BlockedPeerHistoryEntry> {
        self.blocked_peer_history.snapshot()
    }

    /// Sends a frame to a specific peer. Errors if the peer isn't active
    /// (call `add_peer` first) or if its outbound channel is closed.
    pub fn send_frame_to(&self, remote_peer_id: &str, frame: Vec<u8>) -> Result<()> {
        let len = frame.len() as u64;
        let peers = self
            .peers
            .lock()
            .map_err(|_| QlinkError::Protocol("mesh transport peers mutex poisoned".into()))?;
        let session = peers.get(remote_peer_id).ok_or_else(|| {
            QlinkError::Protocol(format!(
                "mesh transport has no active session for peer {remote_peer_id}"
            ))
        })?;
        match session.outbound_tx.send(frame) {
            Ok(()) => {
                session.shared.frames_sent.fetch_add(1, Ordering::Relaxed);
                session.shared.bytes_sent.fetch_add(len, Ordering::Relaxed);
                Ok(())
            }
            Err(_) => {
                session.shared.send_failures.fetch_add(1, Ordering::Relaxed);
                Err(QlinkError::Protocol(format!(
                    "outbound channel for peer {remote_peer_id} is closed"
                )))
            }
        }
    }

    /// Pulls the next inbound frame from any active peer, with the
    /// source peer ID attached. Returns `None` if no frame is queued.
    pub fn try_receive_frame_from_any(&self) -> Option<InboundFrame> {
        let mut rx = self.inbound_rx.try_lock().ok()?;
        rx.try_recv().ok()
    }

    /// Per-peer state code: 0=connecting, 1=ready, 2=failed, 3=stopped.
    /// Returns `None` if the peer isn't active.
    pub fn peer_state_code(&self, remote_peer_id: &str) -> Option<u32> {
        self.peers
            .lock()
            .ok()?
            .get(remote_peer_id)
            .map(|session| session.shared.state_code())
    }

    pub fn peer_path_kind_code(&self, remote_peer_id: &str) -> Option<u32> {
        self.peers
            .lock()
            .ok()?
            .get(remote_peer_id)
            .map(|session| session.shared.path_kind_code())
    }

    pub fn peer_last_error(&self, remote_peer_id: &str) -> Option<String> {
        let peers = self.peers.lock().ok()?;
        let session = peers.get(remote_peer_id)?;
        let guard = session.shared.last_error.lock().ok()?;
        guard.clone()
    }

    pub fn peer_trust_status(&self, remote_peer_id: &str) -> Option<PeerTrustStatusRaw> {
        self.peers
            .lock()
            .ok()?
            .get(remote_peer_id)
            .map(|session| session.shared.peer_trust_status())
    }

    pub fn peer_metrics(&self, remote_peer_id: &str) -> Option<MeshTransportRawMetrics> {
        let peers = self.peers.lock().ok()?;
        let session = peers.get(remote_peer_id)?;
        let raw = session.shared.snapshot_per_peer_metrics();
        Some(MeshTransportRawMetrics {
            frames_sent: raw.frames_sent,
            frames_received: raw.frames_received,
            bytes_sent: raw.bytes_sent,
            bytes_received: raw.bytes_received,
            send_failures: raw.send_failures,
            receive_failures: raw.receive_failures,
            // The aggregate `network_event_count` is reported even on a
            // per-peer query because every active peer saw the same
            // events fan out from `handle_network_event`.
            network_event_count: self.aggregate.network_event_count.load(Ordering::Relaxed),
            reconnect_count: raw.reconnect_count,
        })
    }

    // === Legacy single-peer API (back-compat) ===

    /// Sends a frame to the configured default peer (the
    /// `remote_peer_id` from `MeshTransportConfig`). Equivalent to
    /// `send_frame_to(default_peer_id, frame)` for callers who haven't
    /// migrated to the multi-peer API yet.
    pub fn send_frame(&self, frame: Vec<u8>) -> Result<()> {
        let default = self.default_peer_id_or_err()?;
        self.send_frame_to(&default, frame)
    }

    /// Pulls the next inbound frame from any peer; the source peer ID is
    /// dropped because the legacy API has no field to carry it. New code
    /// should use `try_receive_frame_from_any()` instead.
    pub fn try_receive_frame(&self) -> Option<Vec<u8>> {
        self.try_receive_frame_from_any()
            .map(|inbound| inbound.frame)
    }

    /// Fans the event out to every active per-peer session manager.
    /// Returns the static policy mapping (matches what each session
    /// would report individually).
    pub fn handle_network_event(&self, event: NetworkEvent) -> NetworkEventResponse {
        self.aggregate
            .network_event_count
            .fetch_add(1, Ordering::Relaxed);
        if let Ok(peers) = self.peers.lock() {
            for session in peers.values() {
                let _ = session.event_tx.send(event);
            }
        }
        match event {
            NetworkEvent::PathChanged | NetworkEvent::PostWake => NetworkEventResponse {
                cache_entries_invalidated: 0,
                reprobe_recommended: true,
            },
            NetworkEvent::PreSleep => NetworkEventResponse {
                cache_entries_invalidated: 0,
                reprobe_recommended: false,
            },
            NetworkEvent::ReachabilityChanged { reachable } => NetworkEventResponse {
                cache_entries_invalidated: 0,
                reprobe_recommended: reachable,
            },
        }
    }

    /// Aggregate metrics across every active peer plus transport-level
    /// counters (network_event_count). Per-peer breakdowns are
    /// available via `peer_metrics(peer_id)`.
    pub fn metrics(&self) -> MeshTransportRawMetrics {
        let mut totals = PerPeerMetricsRaw::default();
        if let Ok(peers) = self.peers.lock() {
            for session in peers.values() {
                let raw = session.shared.snapshot_per_peer_metrics();
                totals.frames_sent += raw.frames_sent;
                totals.frames_received += raw.frames_received;
                totals.bytes_sent += raw.bytes_sent;
                totals.bytes_received += raw.bytes_received;
                totals.send_failures += raw.send_failures;
                totals.receive_failures += raw.receive_failures;
                totals.reconnect_count += raw.reconnect_count;
            }
        }
        MeshTransportRawMetrics {
            frames_sent: totals.frames_sent,
            frames_received: totals.frames_received,
            bytes_sent: totals.bytes_sent,
            bytes_received: totals.bytes_received,
            send_failures: totals.send_failures,
            receive_failures: totals.receive_failures,
            network_event_count: self.aggregate.network_event_count.load(Ordering::Relaxed),
            reconnect_count: totals.reconnect_count,
        }
    }

    /// State code of the configured default peer, for back-compat with
    /// the single-peer FFI. Returns Failed if there's no default peer.
    pub fn state_code(&self) -> u32 {
        self.default_peer_id
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
            .and_then(|peer_id| self.peer_state_code(&peer_id))
            .unwrap_or_else(|| MeshTransportState::Failed.as_code())
    }

    pub fn path_kind_code(&self) -> u32 {
        self.default_peer_id
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
            .and_then(|peer_id| self.peer_path_kind_code(&peer_id))
            .unwrap_or(0)
    }

    pub fn last_error(&self) -> Option<String> {
        let default = self.default_peer_id.lock().ok().and_then(|g| g.clone())?;
        self.peer_last_error(&default)
    }

    pub fn shutdown(&self) {
        if let Ok(mut peers) = self.peers.lock() {
            for (_, mut session) in peers.drain() {
                session.shutdown();
            }
        }
        if let Ok(mut guard) = self.metrics_endpoint.lock() {
            if let Some(endpoint) = guard.take() {
                endpoint.shutdown();
            }
        }
    }

    fn default_peer_id_or_err(&self) -> Result<String> {
        self.default_peer_id
            .lock()
            .map_err(|_| QlinkError::Protocol("default peer id mutex poisoned".into()))?
            .clone()
            .ok_or_else(|| {
                QlinkError::Protocol(
                    "no default peer configured for legacy single-peer send_frame".into(),
                )
            })
    }
}

impl Drop for MeshTransportHandle {
    fn drop(&mut self) {
        if let Ok(mut peers) = self.peers.lock() {
            for (_, mut session) in peers.drain() {
                session.shutdown();
            }
        }
        if let Ok(mut guard) = self.responder_task.lock() {
            if let Some(task) = guard.take() {
                task.abort();
            }
        }
        if let Ok(mut guard) = self.metrics_endpoint.lock() {
            // Drop on MetricsEndpoint already aborts the listener task.
            guard.take();
        }
        // Take the runtime and shutdown asynchronously so this Drop is
        // safe to call from any context (including from within another
        // tokio runtime, which is what tests do).
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// Inbound responder: accepts QUIC connections, verifies the assertion +
/// ACL, and forwards accepted frames into the shared inbound queue
/// tagged with the verified peer_id. Runs until the server endpoint
/// stops accepting (Drop on the endpoint, runtime shutdown, etc).
#[cfg(not(feature = "dev-quic-carrier"))]
async fn run_native_udp_responder_loop(
    socket: UdpSocket,
    local_addr: SocketAddr,
    expected_mesh_id: String,
    local_peer_id: String,
    local_device_keypair: Arc<DeviceKeypair>,
    inbound_acl: Option<Arc<PeerAcl>>,
    mesh_trust_policy: MeshTrustPolicy,
    identity_registry_lookup: Option<Arc<dyn IdentityRegistryLookup>>,
    inbound_tx: mpsc::UnboundedSender<InboundFrame>,
    packet_session_generation: Arc<AtomicU64>,
    packet_session_event_tx: mpsc::UnboundedSender<PacketSessionEvent>,
    _blocked_peer_history: Arc<BlockedPeerHistory>,
    packet_session_lifetime_seconds: u64,
    packet_session_rekey_after_bytes: u64,
) {
    let listener = NativeUdpListener::new(socket);
    loop {
        let (session, _remote_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(?error, "native UDP responder stopped");
                break;
            }
        };
        let session = CarrierSession::from(session);
        let mesh_id = expected_mesh_id.clone();
        let local_peer_id = local_peer_id.clone();
        let local_device_keypair = local_device_keypair.clone();
        let carrier_binding = native_udp_carrier_binding(&mesh_id, &local_peer_id, local_addr);
        let acl = inbound_acl.clone();
        let identity_registry_lookup = identity_registry_lookup.clone();
        let inbound_tx = inbound_tx.clone();
        let packet_session_generation = packet_session_generation.clone();
        let packet_session_event_tx = packet_session_event_tx.clone();
        tokio::spawn(async move {
            let acl_ref = acl.as_deref();
            let evaluation = receive_and_evaluate_inbound(
                &session,
                &mesh_id,
                DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS,
                acl_ref,
            )
            .await;
            match evaluation {
                Ok((InboundDecision::Accepted, assertion)) => {
                    let registry_record = match identity_registry_lookup.as_ref() {
                        Some(registry) => match registry.lookup(&assertion.peer_id).await {
                            Ok(record) => record,
                            Err(error) => match mesh_trust_policy {
                                MeshTrustPolicy::PublicRequired => {
                                    tracing::warn!(
                                        peer_id = %assertion.peer_id,
                                        error = %error,
                                        "inbound identity registry lookup failed"
                                    );
                                    session.close(b"");
                                    return;
                                }
                                MeshTrustPolicy::PrivatePreferred
                                | MeshTrustPolicy::DevelopmentOptional => {
                                    tracing::warn!(
                                        peer_id = %assertion.peer_id,
                                        error = %error,
                                        policy = ?mesh_trust_policy,
                                        "inbound identity registry lookup failed; continuing without registry verification"
                                    );
                                    None
                                }
                            },
                        },
                        None => None,
                    };
                    if let Err(error) = verify_inbound_registry_assertion(
                        &assertion,
                        registry_record.as_ref(),
                        mesh_trust_policy,
                    ) {
                        tracing::warn!(
                            peer_id = %assertion.peer_id,
                            error = %error,
                            "inbound identity registry policy rejected assertion"
                        );
                        session.close(b"");
                        return;
                    }

                    let peer_id = assertion.peer_id;
                    let pqc_context = PqcSessionContext::new(
                        mesh_id.clone(),
                        peer_id.clone(),
                        local_peer_id.clone(),
                        carrier_binding,
                    );
                    let handshake_timeout = pqc_responder_handshake_timeout();
                    let session_keys = match tokio::time::timeout(
                        handshake_timeout,
                        run_pqc_session_responder(
                            &session,
                            pqc_context,
                            local_device_keypair.as_ref(),
                        ),
                    )
                    .await
                    {
                        Ok(Ok(session_keys)) => session_keys,
                        Ok(Err(error)) => {
                            tracing::warn!(
                                ?error,
                                peer_id = %peer_id,
                                "inbound PQC session failed"
                            );
                            session.close(b"");
                            return;
                        }
                        Err(_) => {
                            tracing::warn!(
                                timeout_ms = handshake_timeout.as_millis() as u64,
                                peer_id = %peer_id,
                                "inbound PQC session timed out"
                            );
                            session.close(b"");
                            return;
                        }
                    };
                    let authenticated_binding = derive_packet_session_binding(
                        &session_keys.suite,
                        &session_keys.handshake_hash,
                        &mesh_id,
                        &peer_id,
                        &local_peer_id,
                        PqcSessionRole::Responder,
                    );
                    let Some(generation) =
                        next_packet_session_generation(&packet_session_generation)
                    else {
                        session.close(b"");
                        return;
                    };
                    let packet_session = packet_session_lease(
                        peer_id.clone(),
                        PacketSessionDirection::Inbound,
                        generation,
                        authenticated_binding,
                        packet_session_lifetime_seconds,
                        packet_session_rekey_after_bytes,
                    );
                    let _ = packet_session_event_tx
                        .send(PacketSessionEvent::Ready(packet_session.clone()));
                    let mut frame_protector = PqcFrameProtector::new(session_keys);
                    let deadline = tokio::time::Instant::now()
                        + Duration::from_secs(packet_session_lifetime_seconds);
                    let mut protected_bytes = 0_u64;
                    loop {
                        let protected_frame = tokio::select! {
                            received = session.receive_frame() => match received {
                                Ok(frame) => frame,
                                Err(_) => break,
                            },
                            _ = tokio::time::sleep_until(deadline) => break,
                        };
                        protected_bytes =
                            protected_bytes.saturating_add(protected_frame.len() as u64);
                        let frame = match frame_protector.open(&protected_frame) {
                            Ok(frame) => frame,
                            Err(_) => break,
                        };
                        let inbound_frame = InboundFrame {
                            peer_id: peer_id.clone(),
                            frame,
                            packet_session: packet_session.clone(),
                        };
                        if inbound_tx.send(inbound_frame).is_err() {
                            break;
                        }
                        if protected_bytes >= packet_session.rekey_after_bytes {
                            break;
                        }
                    }
                    let _ = packet_session_event_tx.send(PacketSessionEvent::Cleared {
                        peer_id,
                        direction: PacketSessionDirection::Inbound,
                        generation,
                    });
                    session.close(b"");
                }
                _ => {
                    session.close(b"");
                }
            }
        });
    }
}

#[cfg(feature = "dev-quic-carrier")]
async fn run_responder_loop(
    server: QuicEndpoint,
    expected_mesh_id: String,
    local_peer_id: String,
    local_device_keypair: Arc<DeviceKeypair>,
    local_server_certificate_der: Vec<u8>,
    inbound_acl: Option<Arc<PeerAcl>>,
    mesh_trust_policy: MeshTrustPolicy,
    identity_registry_lookup: Option<Arc<dyn IdentityRegistryLookup>>,
    inbound_tx: mpsc::UnboundedSender<InboundFrame>,
    packet_session_generation: Arc<AtomicU64>,
    packet_session_event_tx: mpsc::UnboundedSender<PacketSessionEvent>,
    _blocked_peer_history: Arc<BlockedPeerHistory>,
    packet_session_lifetime_seconds: u64,
    packet_session_rekey_after_bytes: u64,
) {
    loop {
        let session = match server.accept_one().await {
            Ok(session) => session,
            Err(_) => break,
        };
        let session = CarrierSession::from(session);
        let mesh_id = expected_mesh_id.clone();
        let local_peer_id = local_peer_id.clone();
        let local_device_keypair = local_device_keypair.clone();
        let carrier_binding = local_server_certificate_der.clone();
        let acl = inbound_acl.clone();
        let identity_registry_lookup = identity_registry_lookup.clone();
        let inbound_tx = inbound_tx.clone();
        let packet_session_generation = packet_session_generation.clone();
        let packet_session_event_tx = packet_session_event_tx.clone();
        tokio::spawn(async move {
            let acl_ref = acl.as_deref();
            let evaluation = receive_and_evaluate_inbound(
                &session,
                &mesh_id,
                DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS,
                acl_ref,
            )
            .await;
            match evaluation {
                Ok((InboundDecision::Accepted, assertion)) => {
                    let registry_record = match identity_registry_lookup.as_ref() {
                        Some(registry) => match registry.lookup(&assertion.peer_id).await {
                            Ok(record) => record,
                            Err(error) => match mesh_trust_policy {
                                MeshTrustPolicy::PublicRequired => {
                                    tracing::warn!(
                                        peer_id = %assertion.peer_id,
                                        error = %error,
                                        "inbound identity registry lookup failed"
                                    );
                                    session.close(b"");
                                    return;
                                }
                                MeshTrustPolicy::PrivatePreferred
                                | MeshTrustPolicy::DevelopmentOptional => {
                                    tracing::warn!(
                                        peer_id = %assertion.peer_id,
                                        error = %error,
                                        policy = ?mesh_trust_policy,
                                        "inbound identity registry lookup failed; continuing without registry verification"
                                    );
                                    None
                                }
                            },
                        },
                        None => None,
                    };
                    if let Err(error) = verify_inbound_registry_assertion(
                        &assertion,
                        registry_record.as_ref(),
                        mesh_trust_policy,
                    ) {
                        tracing::warn!(
                            peer_id = %assertion.peer_id,
                            error = %error,
                            "inbound identity registry policy rejected assertion"
                        );
                        session.close(b"");
                        return;
                    }

                    let peer_id = assertion.peer_id;
                    let pqc_context = PqcSessionContext::new(
                        mesh_id.clone(),
                        peer_id.clone(),
                        local_peer_id.clone(),
                        carrier_binding,
                    );
                    let handshake_timeout = pqc_responder_handshake_timeout();
                    let session_keys = match tokio::time::timeout(
                        handshake_timeout,
                        run_pqc_session_responder(
                            &session,
                            pqc_context,
                            local_device_keypair.as_ref(),
                        ),
                    )
                    .await
                    {
                        Ok(Ok(session_keys)) => session_keys,
                        Ok(Err(error)) => {
                            tracing::warn!(
                                ?error,
                                peer_id = %peer_id,
                                "inbound PQC session failed"
                            );
                            session.close(b"");
                            return;
                        }
                        Err(_) => {
                            tracing::warn!(
                                timeout_ms = handshake_timeout.as_millis() as u64,
                                peer_id = %peer_id,
                                "inbound PQC session timed out"
                            );
                            session.close(b"");
                            return;
                        }
                    };
                    let authenticated_binding = derive_packet_session_binding(
                        &session_keys.suite,
                        &session_keys.handshake_hash,
                        &mesh_id,
                        &peer_id,
                        &local_peer_id,
                        PqcSessionRole::Responder,
                    );
                    let Some(generation) =
                        next_packet_session_generation(&packet_session_generation)
                    else {
                        session.close(b"");
                        return;
                    };
                    let packet_session = packet_session_lease(
                        peer_id.clone(),
                        PacketSessionDirection::Inbound,
                        generation,
                        authenticated_binding,
                        packet_session_lifetime_seconds,
                        packet_session_rekey_after_bytes,
                    );
                    let _ = packet_session_event_tx
                        .send(PacketSessionEvent::Ready(packet_session.clone()));
                    let mut frame_protector = PqcFrameProtector::new(session_keys);
                    let deadline = tokio::time::Instant::now()
                        + Duration::from_secs(packet_session_lifetime_seconds);
                    let mut protected_bytes = 0_u64;
                    loop {
                        let protected_frame = tokio::select! {
                            received = session.receive_frame() => match received {
                                Ok(frame) => frame,
                                Err(_) => break,
                            },
                            _ = tokio::time::sleep_until(deadline) => break,
                        };
                        protected_bytes =
                            protected_bytes.saturating_add(protected_frame.len() as u64);
                        let frame = match frame_protector.open(&protected_frame) {
                            Ok(frame) => frame,
                            Err(_) => break,
                        };
                        let inbound_frame = InboundFrame {
                            peer_id: peer_id.clone(),
                            frame,
                            packet_session: packet_session.clone(),
                        };
                        if inbound_tx.send(inbound_frame).is_err() {
                            break;
                        }
                        if protected_bytes >= packet_session.rekey_after_bytes {
                            break;
                        }
                    }
                    let _ = packet_session_event_tx.send(PacketSessionEvent::Cleared {
                        peer_id,
                        direction: PacketSessionDirection::Inbound,
                        generation,
                    });
                    session.close(b"");
                }
                _ => {
                    // Closing without a reason is intentional: echoing
                    // the rejection (`acl: peer is on the deny list`)
                    // would let an attacker probe the ACL contents. The
                    // peer just sees a generic close.
                    session.close(b"");
                }
            }
        });
    }
}

#[cfg(test)]
fn pqc_responder_handshake_timeout() -> Duration {
    Duration::from_millis(500)
}

#[cfg(not(test))]
fn pqc_responder_handshake_timeout() -> Duration {
    Duration::from_secs(5)
}

fn mesh_transport_snapshot(
    peers: &Arc<StdMutex<HashMap<String, PerPeerSession>>>,
    aggregate: &Arc<AggregateState>,
) -> MetricsSnapshot {
    let mut snapshot = MetricsSnapshot::default();

    // Aggregate counters across every active peer. v2 should add
    // per-peer labels (`{peer="..."}`) so dashboards can break this down;
    // for v1 the aggregate matches the existing single-peer scrape
    // shape exactly.
    let mut totals = PerPeerMetricsRaw::default();
    let mut state_code = MeshTransportState::Failed.as_code();
    let mut path_kind_code: u32 = 0;
    let mut peer_count: u64 = 0;

    if let Ok(guard) = peers.lock() {
        peer_count = guard.len() as u64;
        for session in guard.values() {
            let raw = session.shared.snapshot_per_peer_metrics();
            totals.frames_sent += raw.frames_sent;
            totals.frames_received += raw.frames_received;
            totals.bytes_sent += raw.bytes_sent;
            totals.bytes_received += raw.bytes_received;
            totals.send_failures += raw.send_failures;
            totals.receive_failures += raw.receive_failures;
            totals.reconnect_count += raw.reconnect_count;

            // Surface the "best" state across peers so a dashboard's
            // single gauge says something useful: Ready beats
            // Connecting beats Failed beats Stopped.
            let session_state = session.shared.state_code();
            state_code = better_state(state_code, session_state);

            // Same for path kind: Direct (1) beats Relay (2) beats
            // None (0). (Numerically inverse, so we pick the smallest
            // non-zero value.)
            let session_path = session.shared.path_kind_code();
            path_kind_code = better_path_kind(path_kind_code, session_path);
        }
    }

    snapshot.push_gauge(
        "qlink_mesh_transport_peers",
        "Number of active peer sessions managed by this transport",
        peer_count as f64,
    );
    snapshot.push_gauge(
        "qlink_mesh_transport_state",
        "Best state across active peers: 0=connecting, 1=ready, 2=failed, 3=stopped",
        state_code as f64,
    );
    snapshot.push_gauge(
        "qlink_mesh_transport_path_kind",
        "Best path kind across active peers: 0=none, 1=direct, 2=relay",
        path_kind_code as f64,
    );

    snapshot.push_counter(
        "qlink_mesh_transport_frames_sent_total",
        "Frames sent across all peers",
        totals.frames_sent as f64,
    );
    snapshot.push_counter(
        "qlink_mesh_transport_frames_received_total",
        "Frames received across all peers",
        totals.frames_received as f64,
    );
    snapshot.push_counter(
        "qlink_mesh_transport_bytes_sent_total",
        "Bytes sent across all peers",
        totals.bytes_sent as f64,
    );
    snapshot.push_counter(
        "qlink_mesh_transport_bytes_received_total",
        "Bytes received across all peers",
        totals.bytes_received as f64,
    );
    snapshot.push_counter(
        "qlink_mesh_transport_send_failures_total",
        "Send-frame errors across all peers",
        totals.send_failures as f64,
    );
    snapshot.push_counter(
        "qlink_mesh_transport_receive_failures_total",
        "Receive-frame errors across all peers",
        totals.receive_failures as f64,
    );
    snapshot.push_counter(
        "qlink_mesh_transport_network_events_total",
        "Transport-level network events handled (fanned out to all peers)",
        aggregate.network_event_count.load(Ordering::Relaxed) as f64,
    );
    snapshot.push_counter(
        "qlink_mesh_transport_reconnects_total",
        "Reconnect attempts across all peers",
        totals.reconnect_count as f64,
    );

    snapshot
}

/// "Best of two" ordering for the aggregate state gauge:
/// Ready (1) beats Connecting (0) beats Failed (2) beats Stopped (3).
/// Returns whichever input is "more useful" for the dashboard.
fn better_state(a: u32, b: u32) -> u32 {
    let rank = |code: u32| match code {
        1 => 0, // Ready — best
        0 => 1, // Connecting
        2 => 2, // Failed
        3 => 3, // Stopped
        _ => 4,
    };
    if rank(a) <= rank(b) {
        a
    } else {
        b
    }
}

/// Direct (1) beats Relay (2) beats None (0). Picks the most-preferred
/// path-kind across active peers.
fn better_path_kind(a: u32, b: u32) -> u32 {
    let rank = |code: u32| match code {
        1 => 0, // Direct — best
        2 => 1, // Relay
        0 => 2, // None
        _ => 3,
    };
    if rank(a) <= rank(b) {
        a
    } else {
        b
    }
}

#[derive(Debug, Clone, Copy)]
struct BackoffConfig {
    initial: Duration,
    max: Duration,
}

impl BackoffConfig {
    /// Returns the sleep duration for `consecutive_failures` (1-indexed).
    /// Doubles each step up to `max`. We deliberately omit jitter for v1 —
    /// the calling pattern already has natural jitter from rendezvous +
    /// QUIC handshake variance, and deterministic backoff is easier to
    /// reason about for operators reading the reconnect_count metric.
    fn delay_for(&self, consecutive_failures: u32) -> Duration {
        if consecutive_failures == 0 {
            return Duration::ZERO;
        }
        // Multiplier is 2^(n-1), saturating at u32::MAX so we don't panic
        // on huge failure counts.
        let multiplier = 1u32
            .checked_shl(consecutive_failures.saturating_sub(1))
            .unwrap_or(u32::MAX);
        let candidate = self.initial.checked_mul(multiplier).unwrap_or(self.max);
        candidate.min(self.max)
    }
}

async fn run_session_manager(
    connector: Arc<MeshConnector>,
    remote_peer_id: String,
    mut outbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    inbound_tx: mpsc::UnboundedSender<InboundFrame>,
    mut event_rx: mpsc::UnboundedReceiver<NetworkEvent>,
    mut shutdown_rx: mpsc::UnboundedReceiver<()>,
    shared: Arc<SharedState>,
    backoff: BackoffConfig,
    packet_session_generation: Arc<AtomicU64>,
    packet_session_event_tx: mpsc::UnboundedSender<PacketSessionEvent>,
    blocked_peer_history: Arc<BlockedPeerHistory>,
    packet_session_lifetime_seconds: u64,
    packet_session_rekey_after_bytes: u64,
) {
    let mut first_attempt = true;
    let mut consecutive_failures: u32 = 0;
    loop {
        if !first_attempt {
            shared.reconnect_count.fetch_add(1, Ordering::Relaxed);
        }
        first_attempt = false;
        shared.set_state(MeshTransportState::Connecting);
        shared.set_path_kind(None);

        let (mut link, path_kind) = match connector.connect(&remote_peer_id).await {
            Ok((link, outcome)) => {
                shared.set_last_error(None);
                shared
                    .set_peer_trust_decision(outcome.registry_decision, outcome.peer_record_source);
                consecutive_failures = 0;
                (link, outcome.path_kind)
            }
            Err(error) => {
                let error_message = error.to_string();
                if let Some(status) = shared.set_peer_trust_failure_message(&error_message) {
                    blocked_peer_history.record(
                        &remote_peer_id,
                        BlockedPeerDirection::Outbound,
                        status.failure_code,
                        &error_message,
                        Some(status.checked_at_unix),
                    );
                }
                shared.set_last_error(Some(error_message));
                shared.set_state(MeshTransportState::Failed);
                consecutive_failures = consecutive_failures.saturating_add(1);
                // Sleep for the backoff window OR until a reachability-
                // restoring event arrives, whichever is sooner. Pre-sleep
                // and reachability-lost events do *not* short-circuit the
                // wait — they signal worse conditions, not better.
                let delay = backoff.delay_for(consecutive_failures);
                tokio::select! {
                    _ = tokio::time::sleep(delay) => continue,
                    event = event_rx.recv() => {
                        match event {
                            Some(NetworkEvent::PathChanged)
                            | Some(NetworkEvent::PostWake)
                            | Some(NetworkEvent::ReachabilityChanged { reachable: true }) => {
                                // Network conditions changed for the better
                                // (or at least changed). Reset backoff and
                                // retry immediately — no point waiting out a
                                // long delay on stale assumptions.
                                consecutive_failures = 0;
                                continue;
                            }
                            Some(_) => continue, // pre-sleep / offline → finish backoff cycle
                            None => return,
                        }
                    }
                    _ = shutdown_rx.recv() => return,
                }
            }
        };

        let Some(generation) = next_packet_session_generation(&packet_session_generation) else {
            shared.set_last_error(Some("packet session generation exhausted".to_string()));
            shared.set_state(MeshTransportState::Failed);
            link.close(b"packet session generation exhausted");
            return;
        };
        let packet_session = packet_session_lease(
            remote_peer_id.clone(),
            PacketSessionDirection::Outbound,
            generation,
            link.packet_session_binding(),
            packet_session_lifetime_seconds,
            packet_session_rekey_after_bytes,
        );
        let manager_carries_inbound =
            path_kind == PathKind::Relay || cfg!(feature = "dev-quic-carrier");
        let inbound_packet_session = manager_carries_inbound.then(|| {
            packet_session_lease(
                remote_peer_id.clone(),
                PacketSessionDirection::Inbound,
                generation,
                link.packet_session_binding(),
                packet_session_lifetime_seconds,
                packet_session_rekey_after_bytes,
            )
        });
        shared.publish_packet_session(packet_session.clone());
        let _ = packet_session_event_tx.send(PacketSessionEvent::Ready(packet_session.clone()));
        if let Some(inbound_packet_session) = inbound_packet_session.as_ref() {
            let _ = packet_session_event_tx
                .send(PacketSessionEvent::Ready(inbound_packet_session.clone()));
        }
        shared.set_path_kind(Some(path_kind));
        shared.set_state(MeshTransportState::Ready);

        // Drive the link until it dies or we get an event that demands
        // reconnect.
        enum SessionLoopExit {
            Reconnect,
            Stop,
        }
        let rotation_deadline =
            tokio::time::Instant::now() + Duration::from_secs(packet_session_lifetime_seconds);
        let mut session_bytes = 0_u64;
        let exit = loop {
            tokio::select! {
                outbound = outbound_rx.recv() => {
                    let Some(frame) = outbound else { break SessionLoopExit::Stop; };
                    let frame_len = frame.len() as u64;
                    if let Err(error) = link.send_frame(frame).await {
                        shared.send_failures.fetch_add(1, Ordering::Relaxed);
                        shared.set_last_error(Some(error.to_string()));
                        break SessionLoopExit::Reconnect;
                    }
                    session_bytes = session_bytes.saturating_add(frame_len);
                }
                inbound = link.receive_frame() => {
                    match inbound {
                        Ok(frame) => {
                            let Some(inbound_packet_session) = inbound_packet_session.as_ref() else {
                                shared.receive_failures.fetch_add(1, Ordering::Relaxed);
                                shared.set_last_error(Some(
                                    "unexpected inbound frame on direct outbound session".to_string(),
                                ));
                                break SessionLoopExit::Reconnect;
                            };
                            let len = frame.len() as u64;
                            shared.frames_received.fetch_add(1, Ordering::Relaxed);
                            shared.bytes_received.fetch_add(len, Ordering::Relaxed);
                            let envelope = InboundFrame {
                                peer_id: remote_peer_id.clone(),
                                frame,
                                packet_session: inbound_packet_session.clone(),
                            };
                            if inbound_tx.send(envelope).is_err() {
                                break SessionLoopExit::Stop;
                            }
                            session_bytes = session_bytes.saturating_add(len);
                        }
                        Err(error) => {
                            shared.receive_failures.fetch_add(1, Ordering::Relaxed);
                            shared.set_last_error(Some(error.to_string()));
                            break SessionLoopExit::Reconnect;
                        }
                    }
                }
                event = event_rx.recv() => {
                    match event {
                        Some(NetworkEvent::PathChanged) | Some(NetworkEvent::PostWake) => {
                            connector.handle_network_event(NetworkEvent::PathChanged);
                            break SessionLoopExit::Reconnect;
                        }
                        Some(NetworkEvent::ReachabilityChanged { reachable: true }) => {
                            // Back online: re-probe to validate the path.
                            break SessionLoopExit::Reconnect;
                        }
                        Some(_) => {
                            // PreSleep / Offline: keep the link, just record.
                        }
                        None => break SessionLoopExit::Stop,
                    }
                }
                _ = shutdown_rx.recv() => {
                    break SessionLoopExit::Stop;
                }
                _ = tokio::time::sleep_until(rotation_deadline) => {
                    break SessionLoopExit::Reconnect;
                }
            }
            if session_bytes >= packet_session.rekey_after_bytes {
                break SessionLoopExit::Reconnect;
            }
        };

        if let Some(cleared) = shared.clear_packet_session(generation) {
            let _ = packet_session_event_tx.send(PacketSessionEvent::Cleared {
                peer_id: cleared.peer_id,
                direction: cleared.direction,
                generation: cleared.generation,
            });
            if inbound_packet_session.is_some() {
                let _ = packet_session_event_tx.send(PacketSessionEvent::Cleared {
                    peer_id: remote_peer_id.clone(),
                    direction: PacketSessionDirection::Inbound,
                    generation,
                });
            }
        }
        match exit {
            SessionLoopExit::Reconnect => link.close(b"reconnecting"),
            SessionLoopExit::Stop => {
                link.close(b"transport shutdown");
                shared.set_state(MeshTransportState::Stopped);
                return;
            }
        }
    }
}

#[cfg(all(test, not(feature = "dev-quic-carrier")))]
mod native_udp_tests {
    use super::*;
    use crate::rendezvous::spawn_dev_rendezvous;
    use std::time::Instant;

    #[tokio::test(flavor = "multi_thread")]
    async fn publish_self_then_two_peers_exchange_and_rotate_authenticated_sessions() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let key_a = Arc::new(DeviceKeypair::generate().unwrap());
        let key_b = Arc::new(DeviceKeypair::generate().unwrap());
        let peer_a = key_a.public_key().peer_id();
        let peer_b = key_b.public_key().peer_id();

        let handle_a = tokio::task::spawn_blocking({
            let peer_a = peer_a.clone();
            let peer_b = peer_b.clone();
            let rendezvous_url = rendezvous_url.clone();
            let key_a = key_a.clone();
            move || {
                let mut config = test_config(&peer_a, &peer_b, &rendezvous_url);
                config.packet_session_rekey_after_bytes = 64;
                MeshTransportHandle::new_with_keypair(config, Some(key_a))
            }
        })
        .await
        .unwrap()
        .unwrap();
        let handle_b = tokio::task::spawn_blocking({
            let peer_a = peer_a.clone();
            let peer_b = peer_b.clone();
            let rendezvous_url = rendezvous_url.clone();
            let key_b = key_b.clone();
            move || {
                let mut config = test_config(&peer_b, &peer_a, &rendezvous_url);
                config.packet_session_rekey_after_bytes = 64;
                MeshTransportHandle::new_with_keypair(config, Some(key_b))
            }
        })
        .await
        .unwrap()
        .unwrap();

        handle_a
            .publish_self(key_a.as_ref(), &rendezvous_url, 120, 1, vec![])
            .await
            .unwrap();
        handle_b
            .publish_self(key_b.as_ref(), &rendezvous_url, 120, 1, vec![])
            .await
            .unwrap();

        let lease_a = wait_for_outbound_lease(&handle_a, None).await;
        let lease_b = wait_for_outbound_lease(&handle_b, None).await;
        assert_eq!(lease_a.direction, PacketSessionDirection::Outbound);
        assert_eq!(lease_b.direction, PacketSessionDirection::Outbound);
        assert_ne!(lease_a.transcript_binding, [0; 32]);
        assert_ne!(lease_b.transcript_binding, [0; 32]);
        assert_eq!(handle_a.peer_path_kind_code(&peer_b), Some(1));

        let frame_a = vec![0x41; 96];
        handle_a.send_frame_to(&peer_b, frame_a.clone()).unwrap();

        let deadline = Instant::now() + Duration::from_secs(3);
        let received = loop {
            if let Some(frame) = handle_b.try_receive_frame_from_any() {
                break frame;
            }
            if Instant::now() >= deadline {
                panic!("timed out waiting for native UDP inbound frame");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };

        assert_eq!(received.peer_id, peer_a);
        assert_eq!(received.frame, frame_a);
        assert_eq!(
            received.packet_session.direction,
            PacketSessionDirection::Inbound
        );
        assert_ne!(received.packet_session.transcript_binding, [0; 32]);

        let rotated_a = wait_for_outbound_lease(&handle_a, Some(lease_a.generation)).await;
        assert!(rotated_a.generation > lease_a.generation);

        let frame_b = vec![0x42; 96];
        handle_b.send_frame_to(&peer_a, frame_b.clone()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let received = loop {
            if let Some(frame) = handle_a.try_receive_frame_from_any() {
                break frame;
            }
            if Instant::now() >= deadline {
                panic!("timed out waiting for reverse native UDP inbound frame");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        assert_eq!(received.peer_id, peer_b);
        assert_eq!(received.frame, frame_b);
        assert_eq!(
            received.packet_session.direction,
            PacketSessionDirection::Inbound
        );

        let rotated_b = wait_for_outbound_lease(&handle_b, Some(lease_b.generation)).await;
        assert!(rotated_b.generation > lease_b.generation);
    }

    async fn wait_for_outbound_lease(
        handle: &MeshTransportHandle,
        generation_greater_than: Option<u64>,
    ) -> PacketSessionLease {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(Some(lease)) = handle.default_packet_session() {
                if generation_greater_than.is_none_or(|generation| lease.generation > generation) {
                    return lease;
                }
            }
            if Instant::now() >= deadline {
                panic!(
                    "timed out waiting for authenticated outbound packet session; state={} metrics={:?} error={:?}",
                    handle.state_code(),
                    handle.metrics(),
                    handle
                        .default_peer_id_or_err()
                        .ok()
                        .and_then(|peer_id| handle.peer_last_error(&peer_id))
                );
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    #[test]
    fn default_native_udp_public_mesh_rejects_unpinned_dytallix_registry_config() {
        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();
        let config: MeshTransportConfig = serde_json::from_value(serde_json::json!({
            "meshId": "public-mesh",
            "localPeerId": local_peer_id,
            "remotePeerId": "qlink_remote",
            "rendezvousUrl": "127.0.0.1:1",
            "bindAddr": "127.0.0.1:0",
            "disableInboundResponder": true,
            "meshTrustPolicy": "public_required",
            "dytallixIdentity": {
                "endpoint": "https://dytallix.example",
                "contractAddress": "1111111111111111111111111111111111111111"
            }
        }))
        .unwrap();

        let err = match MeshTransportHandle::new_with_keypair(config, Some(local_key)) {
            Ok(_) => panic!("public mesh accepted unpinned Dytallix registry config"),
            Err(error) => error,
        };

        assert!(err
            .to_string()
            .contains("public Dytallix registry trust requires networkId"));
    }

    fn test_config(
        local_peer_id: &str,
        remote_peer_id: &str,
        rendezvous_url: &str,
    ) -> MeshTransportConfig {
        MeshTransportConfig {
            mesh_id: "native-udp-handle-mesh".to_string(),
            local_peer_id: local_peer_id.to_string(),
            remote_peer_id: remote_peer_id.to_string(),
            rendezvous_url: rendezvous_url.to_string(),
            relay_url: None,
            bind_addr: "127.0.0.1:0".to_string(),
            overall_deadline_ms: 3_000,
            direct_probe_timeout_ms: 1_000,
            probe_pacing_ms: 50,
            enable_ice: false,
            reconnect_initial_backoff_ms: 100,
            reconnect_max_backoff_ms: 1_000,
            packet_session_lifetime_seconds: DEFAULT_PACKET_SESSION_LIFETIME_SECONDS,
            packet_session_rekey_after_bytes: DEFAULT_PACKET_SESSION_REKEY_AFTER_BYTES,
            metrics_endpoint_bind_addr: None,
            inbound_acl: None,
            disable_inbound_responder: false,
            peer_store_path: None,
            peer_store_key_b64: None,
            mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
            dytallix_identity: None,
        }
    }
}

#[cfg(all(test, feature = "dev-quic-carrier"))]
mod tests {
    use super::*;
    use crate::{
        crypto::DeviceKeypair,
        discovery::{CandidateEndpoint, CandidateType, PeerRecord, UnsignedPeerRecord},
        inbound_identity::send_inbound_assertion,
        pqc_session_wire::run_pqc_session_initiator,
        quic_transport::QuicCertificate,
        rendezvous::spawn_dev_rendezvous,
    };
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Instant,
    };

    const MESH_ID: &str = "devmesh";

    async fn wait_for_peer_state(
        handle: &MeshTransportHandle,
        peer_id: &str,
        state: MeshTransportState,
        timeout: Duration,
    ) {
        let started = Instant::now();
        loop {
            if handle.peer_state_code(peer_id) == Some(state.as_code()) {
                return;
            }

            if started.elapsed() >= timeout {
                panic!(
                    "peer {peer_id} did not reach {:?}; current state code={:?}",
                    state,
                    handle.peer_state_code(peer_id)
                );
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_for_peer_reconnect_count_above(
        handle: &MeshTransportHandle,
        peer_id: &str,
        previous: u64,
        timeout: Duration,
    ) -> u64 {
        let started = Instant::now();
        loop {
            let current = handle.peer_metrics(peer_id).unwrap().reconnect_count;
            if current > previous {
                return current;
            }

            if started.elapsed() >= timeout {
                panic!(
                    "peer {peer_id} reconnect_count did not advance above {previous}; current={current}"
                );
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn spawn_pqc_remote_accept_loop(
        server_endpoint: QuicEndpoint,
        responder_keypair: Arc<DeviceKeypair>,
        server_cert_der: Vec<u8>,
        echo_prefix: Option<&'static [u8]>,
    ) -> tokio::task::JoinHandle<()> {
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
                            let session_keys = match run_pqc_session_responder(
                                &session,
                                context,
                                responder_keypair.as_ref(),
                            )
                            .await
                            {
                                Ok(session_keys) => session_keys,
                                Err(_) => {
                                    session.close(b"");
                                    return;
                                }
                            };
                            let mut frame_protector = PqcFrameProtector::new(session_keys);

                            while let Ok(protected_frame) = session.receive_frame().await {
                                let frame = match frame_protector.open(&protected_frame) {
                                    Ok(frame) => frame,
                                    Err(_) => {
                                        session.close(b"");
                                        return;
                                    }
                                };
                                if let Some(prefix) = echo_prefix {
                                    let mut out = prefix.to_vec();
                                    out.extend_from_slice(&frame);
                                    let Ok(protected_out) = frame_protector.protect(&out) else {
                                        session.close(b"");
                                        return;
                                    };
                                    let _ = session.send_frame(protected_out).await;
                                }
                            }
                        });
                    }
                    Err(_) => break,
                }
            }
        })
    }

    async fn run_initiator_pqc_against_responder(
        handle: &MeshTransportHandle,
        session: &CarrierSession,
        mesh_id: &str,
        initiator_keypair: &DeviceKeypair,
        responder_peer_id: String,
    ) -> crate::crypto::SessionKeys {
        let cert_der = handle
            .server_certificate_der()
            .expect("responder must be enabled")
            .to_vec();
        let context = PqcSessionContext::new(
            mesh_id,
            initiator_keypair.public_key().peer_id(),
            responder_peer_id,
            cert_der,
        );
        run_pqc_session_initiator(session, context, initiator_keypair)
            .await
            .expect("PQC initiator session against responder must succeed")
    }

    #[test]
    fn backoff_doubles_until_cap() {
        let cfg = BackoffConfig {
            initial: Duration::from_millis(100),
            max: Duration::from_millis(1_000),
        };
        // Zero failures = no wait; one failure = initial; thereafter doubles.
        assert_eq!(cfg.delay_for(0), Duration::ZERO);
        assert_eq!(cfg.delay_for(1), Duration::from_millis(100));
        assert_eq!(cfg.delay_for(2), Duration::from_millis(200));
        assert_eq!(cfg.delay_for(3), Duration::from_millis(400));
        assert_eq!(cfg.delay_for(4), Duration::from_millis(800));
        // Capped at max; further failures plateau there.
        assert_eq!(cfg.delay_for(5), Duration::from_millis(1_000));
        assert_eq!(cfg.delay_for(6), Duration::from_millis(1_000));
        assert_eq!(cfg.delay_for(20), Duration::from_millis(1_000));
    }

    #[test]
    fn backoff_handles_pathological_failure_counts_without_panic() {
        let cfg = BackoffConfig {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(60),
        };
        // u32::MAX failures should saturate at the cap, not panic.
        assert_eq!(cfg.delay_for(u32::MAX), Duration::from_secs(60));
    }

    #[test]
    fn shared_state_retains_registry_decision_for_status_export() {
        let shared = SharedState::new();

        assert_eq!(
            shared.peer_trust_status().decision_code,
            PEER_TRUST_DECISION_UNKNOWN
        );

        shared
            .set_peer_trust_decision(RegistryDecision::Accepted, PeerRecordSource::RendezvousLive);
        let status = shared.peer_trust_status();

        assert_eq!(status.decision_code, PEER_TRUST_DECISION_ACCEPTED);
        assert_eq!(status.failure_code, PEER_TRUST_FAILURE_NONE);
        assert!(status.checked_at_unix > 0);
        assert_eq!(
            status.source_code,
            PeerRecordSource::RendezvousLive.trust_source_code()
        );
    }

    #[test]
    fn shared_state_retains_registry_failure_for_status_export() {
        let shared = SharedState::new();

        shared.set_peer_trust_failure_message("registry record has expired");
        let status = shared.peer_trust_status();

        assert_eq!(status.decision_code, PEER_TRUST_DECISION_UNKNOWN);
        assert_eq!(status.failure_code, PEER_TRUST_FAILURE_REGISTRY_EXPIRED);
        assert!(status.checked_at_unix > 0);
    }

    #[test]
    fn registry_failure_code_classifies_operator_visible_registry_failures() {
        let cases = [
            (
                "registry record required by public mesh trust policy",
                PEER_TRUST_FAILURE_REGISTRY_REQUIRED,
            ),
            (
                "registry record is revoked",
                PEER_TRUST_FAILURE_REGISTRY_REVOKED,
            ),
            (
                "registry record is suspended",
                PEER_TRUST_FAILURE_REGISTRY_SUSPENDED,
            ),
            (
                "registry record is not active",
                PEER_TRUST_FAILURE_REGISTRY_SUSPENDED,
            ),
            (
                "registry record has expired",
                PEER_TRUST_FAILURE_REGISTRY_EXPIRED,
            ),
            (
                "device_public_key_hash_hex mismatch",
                PEER_TRUST_FAILURE_REGISTRY_KEY_MISMATCH,
            ),
            (
                "latest_peer_record_hash_hex mismatch",
                PEER_TRUST_FAILURE_REGISTRY_RECORD_HASH_MISMATCH,
            ),
            (
                "registry binding mismatch",
                PEER_TRUST_FAILURE_REGISTRY_MISMATCH,
            ),
            (
                "identity registry lookup failed: node not found",
                PEER_TRUST_FAILURE_REGISTRY_LOOKUP,
            ),
            (
                "registry response failed verification",
                PEER_TRUST_FAILURE_REGISTRY_VERIFICATION,
            ),
            (
                "registry stake or reputation requirement failed",
                PEER_TRUST_FAILURE_REGISTRY_STAKE_OR_REPUTATION,
            ),
        ];

        for (message, expected) in cases {
            assert_eq!(registry_failure_code(message), Some(expected), "{message}");
        }
        assert_eq!(registry_failure_code("ordinary transport failure"), None);
    }

    #[test]
    fn registry_failure_code_exports_stable_operator_reason_strings() {
        let cases = [
            (
                PEER_TRUST_FAILURE_REGISTRY_REQUIRED,
                "rejected_missing_registry",
            ),
            (PEER_TRUST_FAILURE_REGISTRY_REVOKED, "rejected_revoked"),
            (PEER_TRUST_FAILURE_REGISTRY_SUSPENDED, "rejected_suspended"),
            (
                PEER_TRUST_FAILURE_REGISTRY_KEY_MISMATCH,
                "rejected_key_mismatch",
            ),
            (
                PEER_TRUST_FAILURE_REGISTRY_RECORD_HASH_MISMATCH,
                "rejected_record_hash_mismatch",
            ),
            (
                PEER_TRUST_FAILURE_REGISTRY_STAKE_OR_REPUTATION,
                "rejected_stake_or_reputation",
            ),
            (PEER_TRUST_FAILURE_REGISTRY_LOOKUP, "registry_unavailable"),
        ];

        for (failure_code, expected) in cases {
            assert_eq!(peer_trust_failure_code_label(failure_code), Some(expected));
            assert!(!peer_trust_failure_summary(failure_code).unwrap().is_empty());
        }
    }

    #[test]
    fn blocked_peer_history_records_outbound_registry_failure() {
        let history = BlockedPeerHistory::new();

        history.record(
            "qlink_remote",
            BlockedPeerDirection::Outbound,
            PEER_TRUST_FAILURE_REGISTRY_REVOKED,
            "registry record is revoked",
            None,
        );
        let snapshot = history.snapshot();

        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].peer_id, "qlink_remote");
        assert_eq!(snapshot[0].direction, BlockedPeerDirection::Outbound);
        assert_eq!(
            snapshot[0].failure_code,
            PEER_TRUST_FAILURE_REGISTRY_REVOKED
        );
        assert_eq!(snapshot[0].failure_reason, "registry record is revoked");
        assert!(snapshot[0].observed_at_unix > 0);
        assert!(snapshot[0].checked_at_unix > 0);
    }

    #[test]
    fn blocked_peer_history_keeps_latest_entry_for_peer_direction() {
        let history = BlockedPeerHistory::new();

        history.record(
            "qlink_remote",
            BlockedPeerDirection::Inbound,
            PEER_TRUST_FAILURE_REGISTRY_REQUIRED,
            "first rejection",
            Some(10),
        );
        history.record(
            "qlink_remote",
            BlockedPeerDirection::Inbound,
            PEER_TRUST_FAILURE_REGISTRY_EXPIRED,
            "latest rejection",
            Some(20),
        );
        let snapshot = history.snapshot();

        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].direction, BlockedPeerDirection::Inbound);
        assert_eq!(
            snapshot[0].failure_code,
            PEER_TRUST_FAILURE_REGISTRY_EXPIRED
        );
        assert_eq!(snapshot[0].failure_reason, "latest rejection");
        assert_eq!(snapshot[0].checked_at_unix, 20);
    }

    #[test]
    fn mesh_transport_config_decodes_identity_defaults() {
        let config: MeshTransportConfig = serde_json::from_value(serde_json::json!({
            "meshId": "devmesh",
            "localPeerId": "qlink_local",
            "remotePeerId": "qlink_remote",
            "rendezvousUrl": "127.0.0.1:9471",
            "bindAddr": "127.0.0.1:0"
        }))
        .unwrap();

        assert_eq!(
            config.mesh_trust_policy,
            crate::dytallix_identity::MeshTrustPolicy::DevelopmentOptional
        );
        assert!(config.dytallix_identity.is_none());
    }

    #[test]
    fn mesh_transport_config_decodes_registry_and_wires_connector() {
        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();
        let config: MeshTransportConfig = serde_json::from_value(serde_json::json!({
            "meshId": "public-mesh",
            "localPeerId": local_peer_id,
            "remotePeerId": "qlink_remote",
            "rendezvousUrl": "127.0.0.1:1",
            "bindAddr": "127.0.0.1:0",
            "overallDeadlineMs": 1,
            "directProbeTimeoutMs": 1,
            "probePacingMs": 1,
            "reconnectInitialBackoffMs": 1,
            "reconnectMaxBackoffMs": 1,
            "disableInboundResponder": true,
            "meshTrustPolicy": "public_required",
            "dytallixIdentity": {
                "endpoint": "https://dytallix.example",
                "contractAddress": "1111111111111111111111111111111111111111",
                "publishWalletAddress": false,
                "networkId": "dytallix-testnet",
                "chainId": "dytallix-testnet-1",
                "allowedRpcEndpoints": ["https://dytallix.example"]
            }
        }))
        .unwrap();

        let identity = config.dytallix_identity.as_ref().unwrap();
        assert_eq!(
            identity.contract_address,
            "0x1111111111111111111111111111111111111111"
        );
        assert_eq!(identity.network_id.as_deref(), Some("dytallix-testnet"));
        assert_eq!(identity.chain_id.as_deref(), Some("dytallix-testnet-1"));
        assert_eq!(
            identity.allowed_rpc_endpoints,
            vec!["https://dytallix.example".to_string()]
        );

        let handle = MeshTransportHandle::new_with_keypair(config, Some(local_key)).unwrap();

        assert_eq!(
            handle.connector.config().mesh_trust_policy,
            crate::dytallix_identity::MeshTrustPolicy::PublicRequired
        );
        assert!(handle.connector.config().identity_registry_lookup.is_some());
    }

    #[test]
    fn public_mesh_rejects_unpinned_dytallix_registry_config() {
        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();
        let config: MeshTransportConfig = serde_json::from_value(serde_json::json!({
            "meshId": "public-mesh",
            "localPeerId": local_peer_id,
            "remotePeerId": "qlink_remote",
            "rendezvousUrl": "127.0.0.1:1",
            "bindAddr": "127.0.0.1:0",
            "disableInboundResponder": true,
            "meshTrustPolicy": "public_required",
            "dytallixIdentity": {
                "endpoint": "https://dytallix.example",
                "contractAddress": "1111111111111111111111111111111111111111"
            }
        }))
        .unwrap();

        let err = match MeshTransportHandle::new_with_keypair(config, Some(local_key)) {
            Ok(_) => panic!("public mesh accepted unpinned Dytallix registry config"),
            Err(error) => error,
        };

        assert!(err
            .to_string()
            .contains("public Dytallix registry trust requires networkId"));
    }

    #[test]
    fn mesh_transport_config_rejects_registry_wallet_fields() {
        let err = serde_json::from_value::<MeshTransportConfig>(serde_json::json!({
            "meshId": "public-mesh",
            "localPeerId": "qlink_local",
            "remotePeerId": "qlink_remote",
            "rendezvousUrl": "127.0.0.1:1",
            "bindAddr": "127.0.0.1:0",
            "meshTrustPolicy": "public_required",
            "dytallixIdentity": {
                "endpoint": "https://dytallix.example",
                "contractAddress": "0x1111111111111111111111111111111111111111",
                "keystorePath": "/tmp/qlink-dytallix-keystore",
                "walletName": "default"
            }
        }))
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn keyless_constructor_allows_relay_only_when_responder_disabled() {
        let handle = MeshTransportHandle::new(MeshTransportConfig {
            mesh_id: MESH_ID.to_string(),
            local_peer_id: "qlink_keyless-local".to_string(),
            remote_peer_id: "qlink_keyless-remote".to_string(),
            rendezvous_url: "127.0.0.1:9".to_string(),
            relay_url: Some("127.0.0.1:9".to_string()),
            bind_addr: "127.0.0.1:0".to_string(),
            overall_deadline_ms: 100,
            direct_probe_timeout_ms: 50,
            probe_pacing_ms: 10,
            enable_ice: false,
            reconnect_initial_backoff_ms: 60_000,
            reconnect_max_backoff_ms: 60_000,
            packet_session_lifetime_seconds: DEFAULT_PACKET_SESSION_LIFETIME_SECONDS,
            packet_session_rekey_after_bytes: DEFAULT_PACKET_SESSION_REKEY_AFTER_BYTES,
            metrics_endpoint_bind_addr: None,
            inbound_acl: None,
            disable_inbound_responder: true,
            peer_store_path: None,
            peer_store_key_b64: None,
            mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
            dytallix_identity: None,
        })
        .expect("relay-only keyless construction must remain available");

        assert!(handle.server_certificate_der().is_none());
        assert!(handle.responder_local_addr().is_none());
    }

    #[test]
    fn keyless_constructor_rejects_direct_only_transport() {
        let err = match MeshTransportHandle::new(MeshTransportConfig {
            mesh_id: MESH_ID.to_string(),
            local_peer_id: "qlink_keyless-local".to_string(),
            remote_peer_id: "qlink_keyless-remote".to_string(),
            rendezvous_url: "127.0.0.1:9".to_string(),
            relay_url: None,
            bind_addr: "127.0.0.1:0".to_string(),
            overall_deadline_ms: 100,
            direct_probe_timeout_ms: 50,
            probe_pacing_ms: 10,
            enable_ice: false,
            reconnect_initial_backoff_ms: 60_000,
            reconnect_max_backoff_ms: 60_000,
            packet_session_lifetime_seconds: DEFAULT_PACKET_SESSION_LIFETIME_SECONDS,
            packet_session_rekey_after_bytes: DEFAULT_PACKET_SESSION_REKEY_AFTER_BYTES,
            metrics_endpoint_bind_addr: None,
            inbound_acl: None,
            disable_inbound_responder: true,
            peer_store_path: None,
            peer_store_key_b64: None,
            mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
            dytallix_identity: None,
        }) {
            Ok(_) => panic!("direct keyless construction must still be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("local_device_keypair"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mesh_transport_connects_and_round_trips_a_frame() {
        // Stand up a dev rendezvous + a "remote peer" QUIC server.
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_cert_der = server_cert.as_der().to_vec();

        let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_peer_id = remote_key.public_key().peer_id();
        // Spawn an accept loop on the "remote" side that completes identity +
        // PQC, then echoes any frame it receives back to the sender.
        let _accept_loop = spawn_pqc_remote_accept_loop(
            server_endpoint,
            remote_key.clone(),
            server_cert_der.clone(),
            Some(b""),
        );
        let unsigned = UnsignedPeerRecord::new(
            MESH_ID,
            "remote",
            remote_key.public_key(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: server_addr.ip().to_string(),
                port: server_addr.port(),
                priority: 120,
            }],
            vec!["100.127.0.10/32".to_string()],
            120,
            1,
        )
        .with_device_certificate(server_cert_der);
        let record = PeerRecord::signed(unsigned, remote_key.as_ref()).unwrap();
        let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
        publisher.publish(MESH_ID, record).await.unwrap();

        // MeshTransportHandle::new_with_keypair() spins up its own runtime; we must call
        // it from a context that doesn't already own one. Spawn-blocking
        // gets us a thread free of tokio context.
        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new_with_keypair(
                MeshTransportConfig {
                    mesh_id: MESH_ID.to_string(),
                    local_peer_id,
                    remote_peer_id,
                    rendezvous_url,
                    relay_url: None,
                    bind_addr: "127.0.0.1:0".to_string(),
                    overall_deadline_ms: 2_000,
                    direct_probe_timeout_ms: 500,
                    probe_pacing_ms: 50,
                    enable_ice: false,
                    reconnect_initial_backoff_ms: 250,
                    reconnect_max_backoff_ms: 30_000,
                    packet_session_lifetime_seconds: DEFAULT_PACKET_SESSION_LIFETIME_SECONDS,
                    packet_session_rekey_after_bytes: DEFAULT_PACKET_SESSION_REKEY_AFTER_BYTES,
                    metrics_endpoint_bind_addr: None,
                    inbound_acl: None,
                    disable_inbound_responder: true,
                    peer_store_path: None,
                    peer_store_key_b64: None,
                    mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
                    dytallix_identity: None,
                },
                Some(local_key),
            )
            .expect("transport construction must succeed")
        })
        .await
        .unwrap();

        // Wait for ready (manager runs connect on its runtime).
        let mut waited = 0_u64;
        while handle.state_code() != MeshTransportState::Ready.as_code() {
            if waited > 3_000 {
                panic!(
                    "mesh transport did not reach Ready (state_code={}, last_error={:?})",
                    handle.state_code(),
                    handle.last_error()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited += 50;
        }
        assert_eq!(handle.path_kind_code(), 1, "expected direct path");

        // Round-trip a frame through the live session.
        handle.send_frame(b"hello mesh".to_vec()).unwrap();
        let mut received: Option<Vec<u8>> = None;
        for _ in 0..40 {
            if let Some(frame) = handle.try_receive_frame() {
                received = Some(frame);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            received.as_deref(),
            Some(b"hello mesh".as_ref()),
            "mesh transport must echo the sent frame via the remote QUIC server"
        );

        let metrics = handle.metrics();
        assert!(metrics.frames_sent >= 1);
        assert!(metrics.frames_received >= 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mesh_transport_records_failure_when_peer_record_is_missing() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new_with_keypair(
                MeshTransportConfig {
                    mesh_id: MESH_ID.to_string(),
                    local_peer_id,
                    remote_peer_id: "qlink_does-not-exist".to_string(),
                    rendezvous_url,
                    relay_url: None,
                    bind_addr: "127.0.0.1:0".to_string(),
                    overall_deadline_ms: 800,
                    direct_probe_timeout_ms: 200,
                    probe_pacing_ms: 50,
                    enable_ice: false,
                    // Long backoff so we observe the FIRST failure cleanly
                    // before any retry kicks in.
                    reconnect_initial_backoff_ms: 60_000,
                    reconnect_max_backoff_ms: 60_000,
                    packet_session_lifetime_seconds: DEFAULT_PACKET_SESSION_LIFETIME_SECONDS,
                    packet_session_rekey_after_bytes: DEFAULT_PACKET_SESSION_REKEY_AFTER_BYTES,
                    metrics_endpoint_bind_addr: None,
                    inbound_acl: None,
                    disable_inbound_responder: true,
                    peer_store_path: None,
                    peer_store_key_b64: None,
                    mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
                    dytallix_identity: None,
                },
                Some(local_key),
            )
            .unwrap()
        })
        .await
        .unwrap();

        let mut waited = 0_u64;
        while handle.state_code() != MeshTransportState::Failed.as_code() {
            if waited > 3_000 {
                panic!(
                    "transport never reported Failed (state_code={})",
                    handle.state_code()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited += 50;
        }
        let last_error = handle.last_error().expect("failure must record an error");
        assert!(last_error.contains("not found in rendezvous"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mesh_transport_retries_with_backoff_after_persistent_failure() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new_with_keypair(
                MeshTransportConfig {
                    mesh_id: MESH_ID.to_string(),
                    local_peer_id,
                    remote_peer_id: "qlink_does-not-exist".to_string(),
                    rendezvous_url,
                    relay_url: None,
                    bind_addr: "127.0.0.1:0".to_string(),
                    overall_deadline_ms: 200,
                    direct_probe_timeout_ms: 100,
                    probe_pacing_ms: 50,
                    enable_ice: false,
                    // Short backoff so the test observes multiple retries fast.
                    // Initial 50ms doubles to 100ms then plateaus at 200ms.
                    reconnect_initial_backoff_ms: 50,
                    reconnect_max_backoff_ms: 200,
                    packet_session_lifetime_seconds: DEFAULT_PACKET_SESSION_LIFETIME_SECONDS,
                    packet_session_rekey_after_bytes: DEFAULT_PACKET_SESSION_REKEY_AFTER_BYTES,
                    metrics_endpoint_bind_addr: None,
                    inbound_acl: None,
                    disable_inbound_responder: true,
                    peer_store_path: None,
                    peer_store_key_b64: None,
                    mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
                    dytallix_identity: None,
                },
                Some(local_key),
            )
            .unwrap()
        })
        .await
        .unwrap();

        // Wait for the manager to cycle through several connect attempts.
        // Poll the metric instead of sleeping for a fixed window: on slower
        // Windows CI runners the first failed rendezvous attempt can consume
        // more of the nominal 50->100->200ms schedule than it does locally.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut metrics = handle.metrics();
        while metrics.reconnect_count < 2 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
            metrics = handle.metrics();
        }
        assert!(
            metrics.reconnect_count >= 2,
            "manager must retry instead of bailing — observed reconnect_count={}",
            metrics.reconnect_count
        );
        let state = handle.state_code();
        assert!(
            state == MeshTransportState::Failed.as_code()
                || state == MeshTransportState::Connecting.as_code(),
            "persistent failure should stay in the retry loop; observed state_code={state}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mesh_transport_publishes_live_counters_on_metrics_endpoint() {
        // Stand up a dev rendezvous + a "remote peer" QUIC server with an
        // echo loop, exactly like the round-trip test. The new wrinkle is
        // that we ask the transport to also bind a local OpenMetrics
        // endpoint and we scrape it to confirm the live counters are wired.
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_cert_der = server_cert.as_der().to_vec();

        let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_peer_id = remote_key.public_key().peer_id();
        let _accept_loop = spawn_pqc_remote_accept_loop(
            server_endpoint,
            remote_key.clone(),
            server_cert_der.clone(),
            Some(b""),
        );
        let unsigned = UnsignedPeerRecord::new(
            MESH_ID,
            "remote",
            remote_key.public_key(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: server_addr.ip().to_string(),
                port: server_addr.port(),
                priority: 120,
            }],
            vec!["100.127.0.10/32".to_string()],
            120,
            1,
        )
        .with_device_certificate(server_cert_der);
        let record = PeerRecord::signed(unsigned, remote_key.as_ref()).unwrap();
        let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
        publisher.publish(MESH_ID, record).await.unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new_with_keypair(
                MeshTransportConfig {
                    mesh_id: MESH_ID.to_string(),
                    local_peer_id,
                    remote_peer_id,
                    rendezvous_url,
                    relay_url: None,
                    bind_addr: "127.0.0.1:0".to_string(),
                    overall_deadline_ms: 2_000,
                    direct_probe_timeout_ms: 500,
                    probe_pacing_ms: 50,
                    enable_ice: false,
                    reconnect_initial_backoff_ms: 250,
                    reconnect_max_backoff_ms: 30_000,
                    packet_session_lifetime_seconds: DEFAULT_PACKET_SESSION_LIFETIME_SECONDS,
                    packet_session_rekey_after_bytes: DEFAULT_PACKET_SESSION_REKEY_AFTER_BYTES,
                    metrics_endpoint_bind_addr: Some("127.0.0.1:0".to_string()),
                    inbound_acl: None,
                    disable_inbound_responder: true,
                    peer_store_path: None,
                    peer_store_key_b64: None,
                    mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
                    dytallix_identity: None,
                },
                Some(local_key),
            )
            .expect("transport construction with metrics endpoint must succeed")
        })
        .await
        .unwrap();

        // Wait for the manager to reach Ready.
        let mut waited = 0_u64;
        while handle.state_code() != MeshTransportState::Ready.as_code() {
            if waited > 3_000 {
                panic!(
                    "mesh transport did not reach Ready (state_code={}, last_error={:?})",
                    handle.state_code(),
                    handle.last_error()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited += 50;
        }

        // Send a few frames and let the echo path bring them back so the
        // counters are non-zero before we scrape.
        for _ in 0..3 {
            handle.send_frame(b"metrics-probe".to_vec()).unwrap();
        }
        let mut received = 0;
        for _ in 0..40 {
            if handle.try_receive_frame().is_some() {
                received += 1;
            }
            if received >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(received, 3, "echo loop must round-trip the probe frames");

        let endpoint_addr = handle
            .metrics_endpoint_addr()
            .expect("metrics endpoint must be bound when configured");

        let body = http_get(endpoint_addr, "/metrics").await;
        assert!(
            body.contains("qlink_mesh_transport_state"),
            "metrics body missing state gauge: {body}"
        );
        assert!(
            body.contains("qlink_mesh_transport_path_kind 1"),
            "expected path_kind=direct (1) on a successful direct connect: {body}"
        );
        assert!(
            body.contains("qlink_mesh_transport_frames_sent_total 3"),
            "expected 3 frames sent: {body}"
        );
        assert!(
            body.contains("qlink_mesh_transport_frames_received_total 3"),
            "expected 3 frames received: {body}"
        );
        // Network-events counter should be zero on a clean run; assert the
        // metric is present even at zero so dashboards don't have to handle
        // missing series.
        assert!(
            body.contains("qlink_mesh_transport_network_events_total"),
            "network events counter must always be exposed: {body}"
        );
    }

    async fn http_get(addr: SocketAddr, path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.shutdown().await.ok();
        let mut buffer = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let raw = String::from_utf8_lossy(&buffer).to_string();
        raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mesh_transport_resets_backoff_after_path_changed_event() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new_with_keypair(
                MeshTransportConfig {
                    mesh_id: MESH_ID.to_string(),
                    local_peer_id,
                    remote_peer_id: "qlink_does-not-exist".to_string(),
                    rendezvous_url,
                    relay_url: None,
                    bind_addr: "127.0.0.1:0".to_string(),
                    overall_deadline_ms: 200,
                    direct_probe_timeout_ms: 100,
                    probe_pacing_ms: 50,
                    enable_ice: false,
                    // Long initial backoff: without an event the manager would
                    // wait 5s before retrying; the path-change event below
                    // should cut that short and force an immediate retry.
                    reconnect_initial_backoff_ms: 5_000,
                    reconnect_max_backoff_ms: 5_000,
                    packet_session_lifetime_seconds: DEFAULT_PACKET_SESSION_LIFETIME_SECONDS,
                    packet_session_rekey_after_bytes: DEFAULT_PACKET_SESSION_REKEY_AFTER_BYTES,
                    metrics_endpoint_bind_addr: None,
                    inbound_acl: None,
                    disable_inbound_responder: true,
                    peer_store_path: None,
                    peer_store_key_b64: None,
                    mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
                    dytallix_identity: None,
                },
                Some(local_key),
            )
            .unwrap()
        })
        .await
        .unwrap();

        // First connect fails fast (~200ms), then manager parks in backoff.
        tokio::time::sleep(Duration::from_millis(400)).await;
        let metrics_before_event = handle.metrics();

        // Path-changed should short-circuit the backoff and trigger a fresh
        // attempt immediately.
        handle.handle_network_event(NetworkEvent::PathChanged);

        // Give the manager time to come out of the wait, retry, and fail
        // again. We expect at least one new reconnect cycle.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let metrics_after_event = handle.metrics();
        assert!(
            metrics_after_event.reconnect_count > metrics_before_event.reconnect_count,
            "PathChanged must short-circuit backoff (before={}, after={})",
            metrics_before_event.reconnect_count,
            metrics_after_event.reconnect_count
        );
    }

    // === Multi-peer integration tests ===

    /// Stands up two distinct "remote peer" QUIC servers on different
    /// ports, publishes a record for each, and adds both to a single
    /// `MeshTransportHandle`. Verifies that frames sent to peer A go to
    /// the right server, and inbound frames are tagged with the source
    /// peer ID.
    #[tokio::test(flavor = "multi_thread")]
    async fn mesh_transport_routes_frames_per_peer_with_two_active_peers() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        // Peer A's "remote": echoes "A:<frame>"
        let (server_a, cert_a) = QuicEndpoint::server(bind).unwrap();
        let server_a_addr = server_a.local_addr().unwrap();
        let cert_a_der = cert_a.as_der().to_vec();

        // Peer B's "remote": echoes "B:<frame>"
        let (server_b, cert_b) = QuicEndpoint::server(bind).unwrap();
        let server_b_addr = server_b.local_addr().unwrap();
        let cert_b_der = cert_b.as_der().to_vec();

        // Publish records for each remote peer.
        let key_a = Arc::new(DeviceKeypair::generate().unwrap());
        let peer_a_id = key_a.public_key().peer_id();
        let _accept_a =
            spawn_pqc_remote_accept_loop(server_a, key_a.clone(), cert_a_der.clone(), Some(b"A:"));
        let record_a = PeerRecord::signed(
            UnsignedPeerRecord::new(
                "devmesh",
                "remote-a",
                key_a.public_key(),
                vec![CandidateEndpoint {
                    candidate_type: CandidateType::Host,
                    address: server_a_addr.ip().to_string(),
                    port: server_a_addr.port(),
                    priority: 120,
                }],
                vec!["100.127.0.10/32".to_string()],
                120,
                1,
            )
            .with_device_certificate(cert_a_der.clone()),
            key_a.as_ref(),
        )
        .unwrap();

        let key_b = Arc::new(DeviceKeypair::generate().unwrap());
        let peer_b_id = key_b.public_key().peer_id();
        let _accept_b =
            spawn_pqc_remote_accept_loop(server_b, key_b.clone(), cert_b_der.clone(), Some(b"B:"));
        let record_b = PeerRecord::signed(
            UnsignedPeerRecord::new(
                "devmesh",
                "remote-b",
                key_b.public_key(),
                vec![CandidateEndpoint {
                    candidate_type: CandidateType::Host,
                    address: server_b_addr.ip().to_string(),
                    port: server_b_addr.port(),
                    priority: 120,
                }],
                vec!["100.127.0.11/32".to_string()],
                120,
                1,
            )
            .with_device_certificate(cert_b_der.clone()),
            key_b.as_ref(),
        )
        .unwrap();

        let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
        publisher.publish("devmesh", record_a).await.unwrap();
        publisher.publish("devmesh", record_b).await.unwrap();

        // Build the transport with peer A as the default; then add peer B.
        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let peer_a_id_for_handle = peer_a_id.clone();
        let local_key_for_handle = local_key.clone();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new_with_keypair(
                MeshTransportConfig {
                    mesh_id: "devmesh".to_string(),
                    local_peer_id,
                    remote_peer_id: peer_a_id_for_handle,
                    rendezvous_url,
                    relay_url: None,
                    bind_addr: "127.0.0.1:0".to_string(),
                    overall_deadline_ms: 2_000,
                    direct_probe_timeout_ms: 500,
                    probe_pacing_ms: 50,
                    enable_ice: false,
                    reconnect_initial_backoff_ms: 250,
                    reconnect_max_backoff_ms: 30_000,
                    packet_session_lifetime_seconds: DEFAULT_PACKET_SESSION_LIFETIME_SECONDS,
                    packet_session_rekey_after_bytes: DEFAULT_PACKET_SESSION_REKEY_AFTER_BYTES,
                    metrics_endpoint_bind_addr: None,
                    inbound_acl: None,
                    disable_inbound_responder: true,
                    peer_store_path: None,
                    peer_store_key_b64: None,
                    mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
                    dytallix_identity: None,
                },
                Some(local_key_for_handle),
            )
            .expect("transport new")
        })
        .await
        .unwrap();

        handle.add_peer(&peer_b_id).unwrap();
        assert!(handle.peer_ids().contains(&peer_a_id));
        assert!(handle.peer_ids().contains(&peer_b_id));

        // Wait for both sessions to reach Ready.
        let mut waited = 0_u64;
        loop {
            let a_ready =
                handle.peer_state_code(&peer_a_id) == Some(MeshTransportState::Ready.as_code());
            let b_ready =
                handle.peer_state_code(&peer_b_id) == Some(MeshTransportState::Ready.as_code());
            if a_ready && b_ready {
                break;
            }
            if waited > 5_000 {
                panic!(
                    "peers did not reach Ready: a={:?} b={:?}",
                    handle.peer_state_code(&peer_a_id),
                    handle.peer_state_code(&peer_b_id)
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited += 50;
        }

        // Send "ping-A" to peer A and "ping-B" to peer B.
        handle
            .send_frame_to(&peer_a_id, b"ping-A".to_vec())
            .unwrap();
        handle
            .send_frame_to(&peer_b_id, b"ping-B".to_vec())
            .unwrap();

        // Collect echoes; expect each one back tagged with its source.
        let mut got_a = false;
        let mut got_b = false;
        for _ in 0..40 {
            if let Some(inbound) = handle.try_receive_frame_from_any() {
                if inbound.peer_id == peer_a_id && inbound.frame == b"A:ping-A" {
                    got_a = true;
                }
                if inbound.peer_id == peer_b_id && inbound.frame == b"B:ping-B" {
                    got_b = true;
                }
            }
            if got_a && got_b {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            got_a,
            "peer A's echo did not arrive tagged with its peer_id"
        );
        assert!(
            got_b,
            "peer B's echo did not arrive tagged with its peer_id"
        );

        // Aggregate metrics should sum traffic across both peers.
        let aggregate = handle.metrics();
        assert!(aggregate.frames_sent >= 2);
        assert!(aggregate.frames_received >= 2);

        // Per-peer metrics break it down.
        let per_a = handle.peer_metrics(&peer_a_id).unwrap();
        let per_b = handle.peer_metrics(&peer_b_id).unwrap();
        assert!(per_a.frames_sent >= 1);
        assert!(per_b.frames_sent >= 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remove_peer_shuts_down_session_and_send_to_errors() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server, cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server.local_addr().unwrap();
        let cert_der = cert.as_der().to_vec();

        let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_peer_id = remote_key.public_key().peer_id();
        let _accept =
            spawn_pqc_remote_accept_loop(server, remote_key.clone(), cert_der.clone(), None);
        let record = PeerRecord::signed(
            UnsignedPeerRecord::new(
                "devmesh",
                "remote",
                remote_key.public_key(),
                vec![CandidateEndpoint {
                    candidate_type: CandidateType::Host,
                    address: server_addr.ip().to_string(),
                    port: server_addr.port(),
                    priority: 120,
                }],
                vec!["100.127.0.10/32".to_string()],
                120,
                1,
            )
            .with_device_certificate(cert_der.clone()),
            remote_key.as_ref(),
        )
        .unwrap();
        let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
        publisher.publish("devmesh", record).await.unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let remote_peer_id_for_handle = remote_peer_id.clone();
        let local_key_for_handle = local_key.clone();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new_with_keypair(
                MeshTransportConfig {
                    mesh_id: "devmesh".to_string(),
                    local_peer_id,
                    remote_peer_id: remote_peer_id_for_handle,
                    rendezvous_url,
                    relay_url: None,
                    bind_addr: "127.0.0.1:0".to_string(),
                    overall_deadline_ms: 2_000,
                    direct_probe_timeout_ms: 500,
                    probe_pacing_ms: 50,
                    enable_ice: false,
                    reconnect_initial_backoff_ms: 250,
                    reconnect_max_backoff_ms: 30_000,
                    packet_session_lifetime_seconds: DEFAULT_PACKET_SESSION_LIFETIME_SECONDS,
                    packet_session_rekey_after_bytes: DEFAULT_PACKET_SESSION_REKEY_AFTER_BYTES,
                    metrics_endpoint_bind_addr: None,
                    inbound_acl: None,
                    disable_inbound_responder: true,
                    peer_store_path: None,
                    peer_store_key_b64: None,
                    mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
                    dytallix_identity: None,
                },
                Some(local_key_for_handle),
            )
            .expect("transport new")
        })
        .await
        .unwrap();

        // Wait for Ready then remove the peer.
        let mut waited = 0;
        while handle.peer_state_code(&remote_peer_id) != Some(MeshTransportState::Ready.as_code()) {
            if waited > 3_000 {
                panic!("peer did not reach Ready");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited += 50;
        }

        handle.remove_peer(&remote_peer_id);
        assert!(handle.peer_ids().is_empty());
        // Sending to the removed peer must error explicitly — the session
        // is gone, not just temporarily disconnected.
        let result = handle.send_frame_to(&remote_peer_id, b"after-remove".to_vec());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("no active session"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handle_network_event_fans_out_to_all_active_peers() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();

        // Two unknown peers on a healthy rendezvous server so they sit in
        // backoff. PathChanged should short-circuit the backoff for
        // BOTH peers — observed via per-peer reconnect_count both
        // bumping after the event.
        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let local_key_for_handle = local_key.clone();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new_with_keypair(
                MeshTransportConfig {
                    mesh_id: "devmesh".to_string(),
                    local_peer_id,
                    remote_peer_id: "qlink_does-not-exist-A".to_string(),
                    rendezvous_url,
                    relay_url: None,
                    bind_addr: "127.0.0.1:0".to_string(),
                    overall_deadline_ms: 200,
                    direct_probe_timeout_ms: 100,
                    probe_pacing_ms: 50,
                    enable_ice: false,
                    reconnect_initial_backoff_ms: 5_000, // long enough that natural retry won't fire
                    reconnect_max_backoff_ms: 5_000,
                    packet_session_lifetime_seconds: DEFAULT_PACKET_SESSION_LIFETIME_SECONDS,
                    packet_session_rekey_after_bytes: DEFAULT_PACKET_SESSION_REKEY_AFTER_BYTES,
                    metrics_endpoint_bind_addr: None,
                    inbound_acl: None,
                    disable_inbound_responder: true,
                    peer_store_path: None,
                    peer_store_key_b64: None,
                    mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
                    dytallix_identity: None,
                },
                Some(local_key_for_handle),
            )
            .expect("transport new")
        })
        .await
        .unwrap();

        handle.add_peer("qlink_does-not-exist-B").unwrap();

        // Wait for initial connect attempts to fail and the managers to park
        // in backoff before sending the event. Fixed sleeps race slower
        // Windows CI hosts.
        wait_for_peer_state(
            &handle,
            "qlink_does-not-exist-A",
            MeshTransportState::Failed,
            Duration::from_secs(5),
        )
        .await;
        wait_for_peer_state(
            &handle,
            "qlink_does-not-exist-B",
            MeshTransportState::Failed,
            Duration::from_secs(5),
        )
        .await;

        let a_before = handle
            .peer_metrics("qlink_does-not-exist-A")
            .unwrap()
            .reconnect_count;
        let b_before = handle
            .peer_metrics("qlink_does-not-exist-B")
            .unwrap()
            .reconnect_count;

        handle.handle_network_event(NetworkEvent::PathChanged);

        // Both peers should come out of backoff and retry.
        let a_after = wait_for_peer_reconnect_count_above(
            &handle,
            "qlink_does-not-exist-A",
            a_before,
            Duration::from_secs(5),
        )
        .await;
        let b_after = wait_for_peer_reconnect_count_above(
            &handle,
            "qlink_does-not-exist-B",
            b_before,
            Duration::from_secs(5),
        )
        .await;
        assert!(
            a_after > a_before,
            "peer A reconnect_count did not advance ({a_before} → {a_after})"
        );
        assert!(
            b_after > b_before,
            "peer B reconnect_count did not advance ({b_before} → {b_after})"
        );

        // Aggregate network_event_count bumps once per event, regardless
        // of how many peers it fans out to.
        let aggregate = handle.metrics();
        assert_eq!(aggregate.network_event_count, 1);
    }

    #[test]
    fn add_peer_is_idempotent() {
        // Construct a transport pointing at an unreachable rendezvous so
        // it doesn't actually do network IO during the test. We just
        // exercise the peer-map bookkeeping.
        let runtime = Runtime::new().unwrap();
        let handle = runtime.block_on(async {
            tokio::task::spawn_blocking(|| {
                let local_key = Arc::new(DeviceKeypair::generate().unwrap());
                MeshTransportHandle::new_with_keypair(
                    MeshTransportConfig {
                        mesh_id: "devmesh".to_string(),
                        local_peer_id: local_key.public_key().peer_id(),
                        remote_peer_id: "qlink_initial-peer".to_string(),
                        rendezvous_url: "127.0.0.1:1".to_string(),
                        relay_url: None,
                        bind_addr: "127.0.0.1:0".to_string(),
                        overall_deadline_ms: 200,
                        direct_probe_timeout_ms: 100,
                        probe_pacing_ms: 50,
                        enable_ice: false,
                        reconnect_initial_backoff_ms: 60_000,
                        reconnect_max_backoff_ms: 60_000,
                        packet_session_lifetime_seconds: DEFAULT_PACKET_SESSION_LIFETIME_SECONDS,
                        packet_session_rekey_after_bytes: DEFAULT_PACKET_SESSION_REKEY_AFTER_BYTES,
                        metrics_endpoint_bind_addr: None,
                        inbound_acl: None,
                        disable_inbound_responder: true,
                        peer_store_path: None,
                        peer_store_key_b64: None,
                        mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
                        dytallix_identity: None,
                    },
                    Some(local_key),
                )
                .unwrap()
            })
            .await
            .unwrap()
        });

        // The configured peer was auto-added.
        assert_eq!(handle.peer_ids(), vec!["qlink_initial-peer".to_string()]);
        // Adding it again is a no-op.
        handle.add_peer("qlink_initial-peer").unwrap();
        assert_eq!(handle.peer_ids().len(), 1);

        // Adding a second peer makes it 2.
        handle.add_peer("qlink_second-peer").unwrap();
        let mut ids = handle.peer_ids();
        ids.sort();
        assert_eq!(
            ids,
            vec![
                "qlink_initial-peer".to_string(),
                "qlink_second-peer".to_string()
            ]
        );
    }

    /// Helper for the responder tests: build a `MeshTransportHandle`
    /// with the responder enabled and an arbitrary `inbound_acl`. The
    /// rendezvous URL is real but unused for the simpler tests — the
    /// dialer in those connects directly to the responder address, so
    /// the connector's outbound path stays idle (it'll fail-and-backoff
    /// in the background, which is harmless for those assertions).
    /// Pass `Some(keypair)` to install a local device keypair so the
    /// outbound connector can sign + send `InboundIdentityAssertion`
    /// messages — required for any test that relies on the production
    /// responder path accepting frames.
    async fn build_handle_with_responder(
        rendezvous_url: String,
        local_peer_id: String,
        mesh_id: &str,
        inbound_acl: Option<PeerAcl>,
        local_device_keypair: Option<Arc<DeviceKeypair>>,
    ) -> MeshTransportHandle {
        let mesh_id = mesh_id.to_string();
        tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new_with_keypair(
                MeshTransportConfig {
                    mesh_id,
                    local_peer_id,
                    remote_peer_id: "qlink_unused-for-this-test".to_string(),
                    rendezvous_url,
                    relay_url: None,
                    bind_addr: "127.0.0.1:0".to_string(),
                    overall_deadline_ms: 2_000,
                    direct_probe_timeout_ms: 500,
                    probe_pacing_ms: 50,
                    enable_ice: false,
                    reconnect_initial_backoff_ms: 60_000,
                    reconnect_max_backoff_ms: 60_000,
                    packet_session_lifetime_seconds: DEFAULT_PACKET_SESSION_LIFETIME_SECONDS,
                    packet_session_rekey_after_bytes: DEFAULT_PACKET_SESSION_REKEY_AFTER_BYTES,
                    metrics_endpoint_bind_addr: None,
                    inbound_acl,
                    disable_inbound_responder: false,
                    peer_store_path: None,
                    peer_store_key_b64: None,
                    mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
                    dytallix_identity: None,
                },
                local_device_keypair,
            )
            .expect("transport construction with responder must succeed")
        })
        .await
        .unwrap()
    }

    /// Helper for the responder tests: build a dialer (client endpoint
    /// + connected QUIC session) targeting the handle's responder.
    async fn dial_responder(handle: &MeshTransportHandle) -> CarrierSession {
        let server_addr = handle
            .responder_local_addr()
            .expect("responder must be enabled");
        let cert_der = handle
            .server_certificate_der()
            .expect("responder must be enabled")
            .to_vec();
        let trusted = QuicCertificate::from_der(cert_der);
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let client = QuicEndpoint::client(bind, &[]).unwrap();
        let session = client
            .connect_with_trusted_cert(server_addr, &trusted)
            .await
            .expect("dial against responder must succeed");
        CarrierSession::from(session)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn responder_accepts_peer_in_allowlist() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();

        let dialer_key = DeviceKeypair::generate().unwrap();
        let dialer_peer_id = dialer_key.public_key().peer_id();
        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();

        let acl = PeerAcl::new().with_allow([dialer_peer_id.clone()]);
        let handle = build_handle_with_responder(
            rendezvous.local_addr().to_string(),
            local_peer_id.clone(),
            "devmesh",
            Some(acl),
            Some(local_key.clone()),
        )
        .await;

        let session = dial_responder(&handle).await;
        send_inbound_assertion(&session, &dialer_key, "devmesh")
            .await
            .unwrap();
        let session_keys = run_initiator_pqc_against_responder(
            &handle,
            &session,
            "devmesh",
            &dialer_key,
            local_peer_id,
        )
        .await;
        let mut frame_protector = PqcFrameProtector::new(session_keys);
        let protected = frame_protector.protect(b"hello mesh").unwrap();
        session.send_frame(protected).await.unwrap();

        // Poll the inbound queue until the frame surfaces. 2s ceiling
        // so the test fails loudly rather than hanging.
        let mut waited = 0_u64;
        let inbound = loop {
            if let Some(frame) = handle.try_receive_frame_from_any() {
                break frame;
            }
            if waited > 2_000 {
                panic!("inbound frame never reached the responder queue");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            waited += 20;
        };
        assert_eq!(inbound.peer_id, dialer_peer_id);
        assert_eq!(inbound.frame, b"hello mesh".to_vec());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn responder_does_not_surface_frame_without_pqc_session() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();

        let dialer_key = DeviceKeypair::generate().unwrap();
        let dialer_peer_id = dialer_key.public_key().peer_id();
        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();

        let acl = PeerAcl::new().with_allow([dialer_peer_id]);
        let handle = build_handle_with_responder(
            rendezvous.local_addr().to_string(),
            local_peer_id,
            "devmesh",
            Some(acl),
            Some(local_key.clone()),
        )
        .await;

        let session = dial_responder(&handle).await;
        send_inbound_assertion(&session, &dialer_key, "devmesh")
            .await
            .unwrap();
        session.send_frame(b"missing pqc".to_vec()).await.unwrap();

        let receive_result =
            tokio::time::timeout(Duration::from_millis(1_000), session.receive_frame()).await;
        assert!(
            matches!(receive_result, Ok(Err(_))),
            "responder must close identity-only sessions that never complete PQC"
        );
        assert!(
            handle.try_receive_frame_from_any().is_none(),
            "valid identity alone must not surface frames before PQC session completion"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn responder_closes_connection_when_pqc_session_stalls() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();

        let dialer_key = DeviceKeypair::generate().unwrap();
        let dialer_peer_id = dialer_key.public_key().peer_id();
        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();

        let acl = PeerAcl::new().with_allow([dialer_peer_id]);
        let handle = build_handle_with_responder(
            rendezvous.local_addr().to_string(),
            local_peer_id,
            "devmesh",
            Some(acl),
            Some(local_key.clone()),
        )
        .await;

        let session = dial_responder(&handle).await;
        send_inbound_assertion(&session, &dialer_key, "devmesh")
            .await
            .unwrap();

        let receive_result =
            tokio::time::timeout(Duration::from_millis(1_000), session.receive_frame()).await;
        match receive_result {
            Ok(Err(_)) => {}
            Ok(Ok(frame)) => panic!("stalled PQC session must not receive a frame: {frame:?}"),
            Err(_) => panic!("responder did not close stalled PQC session within timeout"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn responder_rejects_peer_not_in_allowlist() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();

        let allowed_key = DeviceKeypair::generate().unwrap();
        let allowed_peer_id = allowed_key.public_key().peer_id();
        let dialer_key = DeviceKeypair::generate().unwrap();
        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();

        let acl = PeerAcl::new().with_allow([allowed_peer_id]);
        let handle = build_handle_with_responder(
            rendezvous.local_addr().to_string(),
            local_peer_id,
            "devmesh",
            Some(acl),
            Some(local_key.clone()),
        )
        .await;

        let session = dial_responder(&handle).await;
        // Assertion send may complete before the responder closes the
        // connection (QUIC is async), so don't assert on its result —
        // assert on the receiver instead.
        let _ = send_inbound_assertion(&session, &dialer_key, "devmesh").await;
        let _ = session.send_frame(b"forbidden".to_vec()).await;

        // Drain for 500ms — well past any plausible queue latency on
        // loopback. The responder must NOT have surfaced anything.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            handle.try_receive_frame_from_any().is_none(),
            "denied peer should never reach the inbound queue"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn publish_self_then_two_peers_round_trip_via_rendezvous() {
        // Closes the loop on the responder + cert-publishing pipeline:
        // both peers publish their own peer record (with the responder's
        // server cert in `device_certificate_der`), then each dials the
        // other through the real rendezvous lookup. A frame from peer A
        // surfaces on peer B's inbound queue tagged with A's verified
        // peer_id — the exact end-to-end path that lab tests previously
        // could not exercise because no caller ever published the
        // responder's cert.
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_url = rendezvous.local_addr().to_string();

        let key_a = Arc::new(DeviceKeypair::generate().unwrap());
        let key_b = Arc::new(DeviceKeypair::generate().unwrap());
        let peer_a = key_a.public_key().peer_id();
        let peer_b = key_b.public_key().peer_id();

        // Each handle's inbound ACL is set to the *other* peer so we
        // also exercise the ACL path against rendezvous-discovered IDs.
        let acl_a = PeerAcl::new().with_allow([peer_b.clone()]);
        let acl_b = PeerAcl::new().with_allow([peer_a.clone()]);

        let handle_a = build_handle_with_responder(
            rendezvous_url.clone(),
            peer_a.clone(),
            "devmesh",
            Some(acl_a),
            Some(key_a.clone()),
        )
        .await;
        let handle_b = build_handle_with_responder(
            rendezvous_url.clone(),
            peer_b.clone(),
            "devmesh",
            Some(acl_b),
            Some(key_b.clone()),
        )
        .await;

        let _record_a = handle_a
            .publish_self(key_a.as_ref(), &rendezvous_url, 120, 1, vec![])
            .await
            .expect("peer A must publish its record");
        let _record_b = handle_b
            .publish_self(key_b.as_ref(), &rendezvous_url, 120, 1, vec![])
            .await
            .expect("peer B must publish its record");

        // Each side dials the other. add_peer spawns a session manager
        // that runs `connector.connect(peer_id)` with backoff; success
        // requires the rendezvous record + cert + responder + assertion
        // chain to all align.
        handle_a.add_peer(&peer_b).expect("add_peer B on handle A");
        handle_b.add_peer(&peer_a).expect("add_peer A on handle B");

        // Wait for both sessions to reach Ready. 5s is generous on
        // loopback (the existing direct-connect SLO is sub-millisecond)
        // but tolerant of CI scheduling jitter.
        let mut waited = 0_u64;
        loop {
            let a_ready = handle_a
                .peer_state_code(&peer_b)
                .map(|code| code == MeshTransportState::Ready.as_code())
                .unwrap_or(false);
            let b_ready = handle_b
                .peer_state_code(&peer_a)
                .map(|code| code == MeshTransportState::Ready.as_code())
                .unwrap_or(false);
            if a_ready && b_ready {
                break;
            }
            if waited > 5_000 {
                panic!(
                    "sessions never both reached Ready: a→b ready={a_ready} \
                     (last_error={:?}), b→a ready={b_ready} (last_error={:?})",
                    handle_a.peer_last_error(&peer_b),
                    handle_b.peer_last_error(&peer_a)
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited += 50;
        }

        // A → B
        handle_a
            .send_frame_to(&peer_b, b"hello from A".to_vec())
            .expect("A must enqueue frame to B");

        // The frame arrives at B's *inbound* queue via B's responder
        // (because A dialed B and sent on that session). Poll for it
        // with a 5s ceiling.
        let inbound = {
            let mut waited = 0_u64;
            loop {
                if let Some(frame) = handle_b.try_receive_frame_from_any() {
                    break frame;
                }
                if waited > 5_000 {
                    panic!("frame from A never reached B's inbound queue");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                waited += 50;
            }
        };
        assert_eq!(
            inbound.peer_id, peer_a,
            "B's responder must surface frames tagged with A's verified peer_id"
        );
        assert_eq!(inbound.frame, b"hello from A".to_vec());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn publish_self_rejects_keypair_that_doesnt_match_handle_local_peer_id() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();
        let handle = build_handle_with_responder(
            rendezvous.local_addr().to_string(),
            local_peer_id,
            "devmesh",
            None,
            Some(local_key.clone()),
        )
        .await;

        // Different keypair → different peer_id → publish_self should
        // refuse rather than mint a record peers can't authenticate.
        let other_key = DeviceKeypair::generate().unwrap();
        let err = handle
            .publish_self(
                &other_key,
                &rendezvous.local_addr().to_string(),
                120,
                1,
                vec![],
            )
            .await
            .expect_err("mismatched keypair must be rejected");
        assert!(
            err.to_string().contains("does not match"),
            "error should explain the mismatch, got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn responder_rejects_peer_with_forged_mesh_id() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();

        let dialer_key = DeviceKeypair::generate().unwrap();
        let dialer_peer_id = dialer_key.public_key().peer_id();
        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let local_peer_id = local_key.public_key().peer_id();

        // Dialer is on the allowlist — but signs the assertion for a
        // mesh they aren't a member of. Crypto verification rejects
        // before the ACL ever runs.
        let acl = PeerAcl::new().with_allow([dialer_peer_id]);
        let handle = build_handle_with_responder(
            rendezvous.local_addr().to_string(),
            local_peer_id,
            "devmesh",
            Some(acl),
            Some(local_key.clone()),
        )
        .await;

        let session = dial_responder(&handle).await;
        let _ = send_inbound_assertion(&session, &dialer_key, "wrong-mesh").await;
        let _ = session.send_frame(b"forbidden".to_vec()).await;

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            handle.try_receive_frame_from_any().is_none(),
            "peer asserting for the wrong mesh must be rejected by crypto verification"
        );
    }
}
