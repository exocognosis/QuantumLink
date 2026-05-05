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

use crate::{
    crypto::DeviceKeypair,
    discovery::{CandidateEndpoint, CandidateType, PeerRecord, UnsignedPeerRecord},
    error::{QlinkError, Result},
    ice::IceCredentials,
    inbound_identity::{
        receive_and_evaluate_inbound, InboundDecision, DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS,
    },
    mesh_connection::{
        MeshConnector, MeshConnectorConfig, NetworkEvent, NetworkEventResponse, PathKind,
    },
    metrics_endpoint::{spawn_metrics_endpoint, MetricsEndpoint, MetricsSnapshot},
    peer_acl::PeerAcl,
    peer_store::{
        open_file_peer_store, open_file_peer_store_with_key, InMemoryPeerStore, PeerStore,
    },
    quic_transport::QuicEndpoint,
    rendezvous::RendezvousClient,
    traversal::HOST_PRIORITY,
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::Duration,
};
use tokio::{
    runtime::Runtime,
    sync::{mpsc, Mutex as TokioMutex},
    task::JoinHandle,
};

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
    frames_sent: AtomicU64,
    frames_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    send_failures: AtomicU64,
    receive_failures: AtomicU64,
    reconnect_count: AtomicU64,
}

impl SharedState {
    fn new() -> Self {
        Self {
            state: StdMutex::new(MeshTransportState::Connecting),
            path_kind: StdMutex::new(None),
            last_error: StdMutex::new(None),
            frames_sent: AtomicU64::new(0),
            frames_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            send_failures: AtomicU64::new(0),
            receive_failures: AtomicU64::new(0),
            reconnect_count: AtomicU64::new(0),
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
    /// 32-byte ChaCha20-Poly1305 key. When set together with
    /// `peer_store_path`, the on-disk file is encrypted in the v2
    /// envelope; without it the file is plaintext JSON. The host
    /// (Swift app) is expected to mint + persist this key in the
    /// macOS Keychain. `qlinkctl` deployments without a Keychain
    /// can leave this `None` and rely on file mode 0o600.
    #[serde(default)]
    pub peer_store_key_b64: Option<String>,
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

/// A frame received from a specific remote peer. Multi-peer transports
/// preserve the source peer ID so callers can route inbound traffic.
#[derive(Debug, Clone)]
pub struct InboundFrame {
    pub peer_id: String,
    pub frame: Vec<u8>,
}

/// Per-peer session state held inside `MeshTransportHandle`. Each entry
/// drives one independent session manager loop with its own outbound
/// queue, network-event channel, and shared state.
struct PerPeerSession {
    outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    event_tx: mpsc::UnboundedSender<NetworkEvent>,
    shutdown_tx: mpsc::UnboundedSender<()>,
    shared: Arc<SharedState>,
    manager_task: Option<JoinHandle<()>>,
}

impl PerPeerSession {
    /// Tears down this peer's session. Called both when the operator
    /// removes the peer and when the whole transport is dropped.
    fn shutdown(&mut self) {
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
    /// Transport-level counters that aren't per-peer (today: just the
    /// network-event count).
    aggregate: Arc<AggregateState>,
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
    pub fn new_with_keypair(
        config: MeshTransportConfig,
        local_device_keypair: Option<Arc<DeviceKeypair>>,
    ) -> Result<Self> {
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
                .with_probe_pacing(Duration::from_millis(config.probe_pacing_ms));
        if let Some(relay) = config.relay_url.clone() {
            connector_config = connector_config.with_relay_server(relay);
        }
        if config.enable_ice {
            connector_config = connector_config.with_local_ice_credentials(local_credentials);
        }
        if let Some(keypair) = local_device_keypair {
            // Sanity check the keypair matches the configured peer_id
            // up front — otherwise we'd happily dial out under the
            // wrong identity, and the remote responder would just close
            // the connection with no actionable error.
            let keypair_peer_id = keypair.public_key().peer_id();
            if keypair_peer_id != config.local_peer_id {
                return Err(QlinkError::Protocol(format!(
                    "MeshTransportHandle local_device_keypair peer_id {keypair_peer_id} \
                     does not match config.local_peer_id {}",
                    config.local_peer_id
                )));
            }
            connector_config = connector_config.with_local_device_keypair(keypair);
        }

        // Resolve the configured persistence path, if any, into a
        // `FilePeerStore`. Construction errors (missing parent dir,
        // unreadable file) are surfaced up — we'd rather refuse to
        // start than silently degrade to ephemeral storage when the
        // operator asked for persistence. When `peer_store_key_b64`
        // is set, the file is wrapped in the v2 ChaCha20-Poly1305
        // envelope; the key MUST decode to exactly 32 bytes.
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
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<InboundFrame>();
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
                    Arc::new(move || {
                        mesh_transport_snapshot(&peers_provider, &aggregate_provider)
                    });
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
                let inbound_tx_responder = inbound_tx.clone();
                let task = runtime.spawn(run_responder_loop(
                    endpoint,
                    mesh_id,
                    inbound_acl,
                    inbound_tx_responder,
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
            aggregate,
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
        let runtime = self.runtime.as_ref().ok_or_else(|| {
            QlinkError::Protocol("mesh transport runtime is shut down".into())
        })?;
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
        let cert_der = self
            .server_certificate_der
            .as_ref()
            .ok_or_else(|| {
                QlinkError::Protocol(
                    "publish_self requires the inbound responder; \
                     `disable_inbound_responder` is set on this handle"
                        .into(),
                )
            })?
            .clone();
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
        let mut peers = self.peers.lock().map_err(|_| {
            QlinkError::Protocol("mesh transport peers mutex poisoned".into())
        })?;
        if peers.contains_key(remote_peer_id) {
            return Ok(());
        }

        let runtime = self.runtime.as_ref().ok_or_else(|| {
            QlinkError::Protocol("mesh transport runtime is shut down".into())
        })?;

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
        ));

        peers.insert(
            remote_peer_id.to_string(),
            PerPeerSession {
                outbound_tx,
                event_tx,
                shutdown_tx,
                shared,
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

    /// Sends a frame to a specific peer. Errors if the peer isn't active
    /// (call `add_peer` first) or if its outbound channel is closed.
    pub fn send_frame_to(&self, remote_peer_id: &str, frame: Vec<u8>) -> Result<()> {
        let len = frame.len() as u64;
        let peers = self.peers.lock().map_err(|_| {
            QlinkError::Protocol("mesh transport peers mutex poisoned".into())
        })?;
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
            network_event_count: self
                .aggregate
                .network_event_count
                .load(Ordering::Relaxed),
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
            network_event_count: self
                .aggregate
                .network_event_count
                .load(Ordering::Relaxed),
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
async fn run_responder_loop(
    server: QuicEndpoint,
    expected_mesh_id: String,
    inbound_acl: Option<Arc<PeerAcl>>,
    inbound_tx: mpsc::UnboundedSender<InboundFrame>,
) {
    loop {
        let session = match server.accept_one().await {
            Ok(session) => session,
            Err(_) => break,
        };
        let mesh_id = expected_mesh_id.clone();
        let acl = inbound_acl.clone();
        let inbound_tx = inbound_tx.clone();
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
                    let peer_id = assertion.peer_id;
                    while let Ok(frame) = session.receive_frame().await {
                        let inbound_frame = InboundFrame {
                            peer_id: peer_id.clone(),
                            frame,
                        };
                        if inbound_tx.send(inbound_frame).is_err() {
                            // Receiver dropped — the transport handle is
                            // gone or being torn down; nothing useful to
                            // do here.
                            break;
                        }
                    }
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
                consecutive_failures = 0;
                (link, outcome.path_kind)
            }
            Err(error) => {
                shared.set_last_error(Some(error.to_string()));
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

        shared.set_path_kind(Some(path_kind));
        shared.set_state(MeshTransportState::Ready);

        // Drive the link until it dies or we get an event that demands
        // reconnect.
        let need_reconnect = loop {
            tokio::select! {
                outbound = outbound_rx.recv() => {
                    let Some(frame) = outbound else { return; };
                    if let Err(error) = link.send_frame(frame).await {
                        shared.send_failures.fetch_add(1, Ordering::Relaxed);
                        shared.set_last_error(Some(error.to_string()));
                        break true; // link dead, retry connect
                    }
                }
                inbound = link.receive_frame() => {
                    match inbound {
                        Ok(frame) => {
                            let len = frame.len() as u64;
                            shared.frames_received.fetch_add(1, Ordering::Relaxed);
                            shared.bytes_received.fetch_add(len, Ordering::Relaxed);
                            let envelope = InboundFrame {
                                peer_id: remote_peer_id.clone(),
                                frame,
                            };
                            if inbound_tx.send(envelope).is_err() {
                                // Swift dropped the receiver — handle is
                                // dying; let the manager exit on next event.
                                return;
                            }
                        }
                        Err(error) => {
                            shared.receive_failures.fetch_add(1, Ordering::Relaxed);
                            shared.set_last_error(Some(error.to_string()));
                            break true; // link dead, retry connect
                        }
                    }
                }
                event = event_rx.recv() => {
                    match event {
                        Some(NetworkEvent::PathChanged) | Some(NetworkEvent::PostWake) => {
                            connector.handle_network_event(NetworkEvent::PathChanged);
                            break true;
                        }
                        Some(NetworkEvent::ReachabilityChanged { reachable: true }) => {
                            // Back online: re-probe to validate the path.
                            break true;
                        }
                        Some(_) => {
                            // PreSleep / Offline: keep the link, just record.
                        }
                        None => return, // event channel dropped
                    }
                }
                _ = shutdown_rx.recv() => {
                    link.close(b"transport shutdown");
                    shared.set_state(MeshTransportState::Stopped);
                    return;
                }
            }
        };

        link.close(b"reconnecting");
        if !need_reconnect {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::DeviceKeypair,
        discovery::{CandidateEndpoint, CandidateType, PeerRecord, UnsignedPeerRecord},
        inbound_identity::send_inbound_assertion,
        quic_transport::QuicCertificate,
        rendezvous::spawn_dev_rendezvous,
    };
    use std::net::{IpAddr, Ipv4Addr};

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

    #[tokio::test(flavor = "multi_thread")]
    async fn mesh_transport_connects_and_round_trips_a_frame() {
        // Stand up a dev rendezvous + a "remote peer" QUIC server.
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_cert_der = server_cert.as_der().to_vec();

        // Spawn an accept loop on the "remote" side that echoes any frame it
        // receives back to the sender.
        let _accept_loop = tokio::spawn(async move {
            loop {
                match server_endpoint.accept_one().await {
                    Ok(session) => {
                        tokio::spawn(async move {
                            while let Ok(frame) = session.receive_frame().await {
                                let _ = session.send_frame(frame).await;
                            }
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        let remote_key = DeviceKeypair::generate().unwrap();
        let remote_peer_id = remote_key.public_key().peer_id();
        let unsigned = UnsignedPeerRecord::new(
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
        .with_device_certificate(server_cert_der);
        let record = PeerRecord::signed(unsigned, &remote_key).unwrap();
        let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
        publisher.publish("devmesh", record).await.unwrap();

        // MeshTransportHandle::new() spins up its own runtime; we must call
        // it from a context that doesn't already own one. Spawn-blocking
        // gets us a thread free of tokio context.
        let local_key = DeviceKeypair::generate().unwrap();
        let local_peer_id = local_key.public_key().peer_id();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new(MeshTransportConfig {
                mesh_id: "devmesh".to_string(),
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
                metrics_endpoint_bind_addr: None,
                inbound_acl: None,
                disable_inbound_responder: true,
                peer_store_path: None,
                peer_store_key_b64: None,
            })
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

        let local_key = DeviceKeypair::generate().unwrap();
        let local_peer_id = local_key.public_key().peer_id();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new(MeshTransportConfig {
                mesh_id: "devmesh".to_string(),
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
                metrics_endpoint_bind_addr: None,
                inbound_acl: None,
                disable_inbound_responder: true,
                peer_store_path: None,
                peer_store_key_b64: None,
            })
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

        let local_key = DeviceKeypair::generate().unwrap();
        let local_peer_id = local_key.public_key().peer_id();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new(MeshTransportConfig {
                mesh_id: "devmesh".to_string(),
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
                metrics_endpoint_bind_addr: None,
                inbound_acl: None,
                disable_inbound_responder: true,
                peer_store_path: None,
                peer_store_key_b64: None,
            })
            .unwrap()
        })
        .await
        .unwrap();

        // Wait for the manager to cycle through several connect attempts.
        // 800ms is enough for at least 3 retries given 50→100→200 backoff
        // plus the bounded connect deadline.
        tokio::time::sleep(Duration::from_millis(800)).await;
        let metrics = handle.metrics();
        assert!(
            metrics.reconnect_count >= 2,
            "manager must retry instead of bailing — observed reconnect_count={}",
            metrics.reconnect_count
        );
        assert_eq!(handle.state_code(), MeshTransportState::Failed.as_code());
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

        let _accept_loop = tokio::spawn(async move {
            loop {
                match server_endpoint.accept_one().await {
                    Ok(session) => {
                        tokio::spawn(async move {
                            while let Ok(frame) = session.receive_frame().await {
                                let _ = session.send_frame(frame).await;
                            }
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        let remote_key = DeviceKeypair::generate().unwrap();
        let remote_peer_id = remote_key.public_key().peer_id();
        let unsigned = UnsignedPeerRecord::new(
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
        .with_device_certificate(server_cert_der);
        let record = PeerRecord::signed(unsigned, &remote_key).unwrap();
        let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
        publisher.publish("devmesh", record).await.unwrap();

        let local_key = DeviceKeypair::generate().unwrap();
        let local_peer_id = local_key.public_key().peer_id();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new(MeshTransportConfig {
                mesh_id: "devmesh".to_string(),
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
                metrics_endpoint_bind_addr: Some("127.0.0.1:0".to_string()),
                inbound_acl: None,
                disable_inbound_responder: true,
                peer_store_path: None,
                peer_store_key_b64: None,
            })
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

        let local_key = DeviceKeypair::generate().unwrap();
        let local_peer_id = local_key.public_key().peer_id();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new(MeshTransportConfig {
                mesh_id: "devmesh".to_string(),
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
                metrics_endpoint_bind_addr: None,
                inbound_acl: None,
                disable_inbound_responder: true,
                peer_store_path: None,
                peer_store_key_b64: None,
            })
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
        let _accept_a = tokio::spawn(async move {
            loop {
                match server_a.accept_one().await {
                    Ok(session) => {
                        tokio::spawn(async move {
                            while let Ok(frame) = session.receive_frame().await {
                                let mut out = b"A:".to_vec();
                                out.extend_from_slice(&frame);
                                let _ = session.send_frame(out).await;
                            }
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        // Peer B's "remote": echoes "B:<frame>"
        let (server_b, cert_b) = QuicEndpoint::server(bind).unwrap();
        let server_b_addr = server_b.local_addr().unwrap();
        let cert_b_der = cert_b.as_der().to_vec();
        let _accept_b = tokio::spawn(async move {
            loop {
                match server_b.accept_one().await {
                    Ok(session) => {
                        tokio::spawn(async move {
                            while let Ok(frame) = session.receive_frame().await {
                                let mut out = b"B:".to_vec();
                                out.extend_from_slice(&frame);
                                let _ = session.send_frame(out).await;
                            }
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        // Publish records for each remote peer.
        let key_a = DeviceKeypair::generate().unwrap();
        let peer_a_id = key_a.public_key().peer_id();
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
            .with_device_certificate(cert_a_der),
            &key_a,
        )
        .unwrap();

        let key_b = DeviceKeypair::generate().unwrap();
        let peer_b_id = key_b.public_key().peer_id();
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
            .with_device_certificate(cert_b_der),
            &key_b,
        )
        .unwrap();

        let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
        publisher.publish("devmesh", record_a).await.unwrap();
        publisher.publish("devmesh", record_b).await.unwrap();

        // Build the transport with peer A as the default; then add peer B.
        let local_key = DeviceKeypair::generate().unwrap();
        let local_peer_id = local_key.public_key().peer_id();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let peer_a_id_for_handle = peer_a_id.clone();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new(MeshTransportConfig {
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
                metrics_endpoint_bind_addr: None,
                inbound_acl: None,
                disable_inbound_responder: true,
                peer_store_path: None,
                peer_store_key_b64: None,
            })
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
        handle.send_frame_to(&peer_a_id, b"ping-A".to_vec()).unwrap();
        handle.send_frame_to(&peer_b_id, b"ping-B".to_vec()).unwrap();

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
        assert!(got_a, "peer A's echo did not arrive tagged with its peer_id");
        assert!(got_b, "peer B's echo did not arrive tagged with its peer_id");

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
        let _accept = tokio::spawn(async move {
            loop {
                match server.accept_one().await {
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
            .with_device_certificate(cert_der),
            &remote_key,
        )
        .unwrap();
        let publisher = RendezvousClient::new(rendezvous.local_addr().to_string());
        publisher.publish("devmesh", record).await.unwrap();

        let local_key = DeviceKeypair::generate().unwrap();
        let local_peer_id = local_key.public_key().peer_id();
        let rendezvous_url = rendezvous.local_addr().to_string();
        let remote_peer_id_for_handle = remote_peer_id.clone();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new(MeshTransportConfig {
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
                metrics_endpoint_bind_addr: None,
                inbound_acl: None,
                disable_inbound_responder: true,
                peer_store_path: None,
                peer_store_key_b64: None,
            })
            .expect("transport new")
        })
        .await
        .unwrap();

        // Wait for Ready then remove the peer.
        let mut waited = 0;
        while handle.peer_state_code(&remote_peer_id)
            != Some(MeshTransportState::Ready.as_code())
        {
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
        // Two peers with bogus rendezvous targets so they sit in
        // backoff. PathChanged should short-circuit the backoff for
        // BOTH peers — observed via per-peer reconnect_count both
        // bumping after the event.
        let local_key = DeviceKeypair::generate().unwrap();
        let local_peer_id = local_key.public_key().peer_id();
        let handle = tokio::task::spawn_blocking(move || {
            MeshTransportHandle::new(MeshTransportConfig {
                mesh_id: "devmesh".to_string(),
                local_peer_id,
                remote_peer_id: "qlink_does-not-exist-A".to_string(),
                rendezvous_url: "127.0.0.1:1".to_string(), // unreachable
                relay_url: None,
                bind_addr: "127.0.0.1:0".to_string(),
                overall_deadline_ms: 200,
                direct_probe_timeout_ms: 100,
                probe_pacing_ms: 50,
                enable_ice: false,
                reconnect_initial_backoff_ms: 5_000, // long enough that natural retry won't fire
                reconnect_max_backoff_ms: 5_000,
                metrics_endpoint_bind_addr: None,
                inbound_acl: None,
                disable_inbound_responder: true,
                peer_store_path: None,
                peer_store_key_b64: None,
            })
            .expect("transport new")
        })
        .await
        .unwrap();

        handle.add_peer("qlink_does-not-exist-B").unwrap();

        // Let initial connect attempts fail and the managers park in
        // backoff.
        tokio::time::sleep(Duration::from_millis(400)).await;

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
        tokio::time::sleep(Duration::from_millis(500)).await;
        let a_after = handle
            .peer_metrics("qlink_does-not-exist-A")
            .unwrap()
            .reconnect_count;
        let b_after = handle
            .peer_metrics("qlink_does-not-exist-B")
            .unwrap()
            .reconnect_count;
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
                let local_key = DeviceKeypair::generate().unwrap();
                MeshTransportHandle::new(MeshTransportConfig {
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
                    metrics_endpoint_bind_addr: None,
                    inbound_acl: None,
                    disable_inbound_responder: true,
                    peer_store_path: None,
                    peer_store_key_b64: None,
                })
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
                    metrics_endpoint_bind_addr: None,
                    inbound_acl,
                    disable_inbound_responder: false,
                    peer_store_path: None,
                    peer_store_key_b64: None,
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
    async fn dial_responder(handle: &MeshTransportHandle) -> crate::quic_transport::QuicDatagramSession {
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
        client
            .connect_with_trusted_cert(server_addr, &trusted)
            .await
            .expect("dial against responder must succeed")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn responder_accepts_peer_in_allowlist() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();

        let dialer_key = DeviceKeypair::generate().unwrap();
        let dialer_peer_id = dialer_key.public_key().peer_id();
        let local_key = DeviceKeypair::generate().unwrap();
        let local_peer_id = local_key.public_key().peer_id();

        let acl = PeerAcl::new().with_allow([dialer_peer_id.clone()]);
        let handle = build_handle_with_responder(
            rendezvous.local_addr().to_string(),
            local_peer_id,
            "devmesh",
            Some(acl),
            None,
        )
        .await;

        let session = dial_responder(&handle).await;
        send_inbound_assertion(&session, &dialer_key, "devmesh")
            .await
            .unwrap();
        session.send_frame(b"hello mesh".to_vec()).await.unwrap();

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
    async fn responder_rejects_peer_not_in_allowlist() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();

        let allowed_key = DeviceKeypair::generate().unwrap();
        let allowed_peer_id = allowed_key.public_key().peer_id();
        let dialer_key = DeviceKeypair::generate().unwrap();
        let local_key = DeviceKeypair::generate().unwrap();
        let local_peer_id = local_key.public_key().peer_id();

        let acl = PeerAcl::new().with_allow([allowed_peer_id]);
        let handle = build_handle_with_responder(
            rendezvous.local_addr().to_string(),
            local_peer_id,
            "devmesh",
            Some(acl),
            None,
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
        let local_key = DeviceKeypair::generate().unwrap();
        let local_peer_id = local_key.public_key().peer_id();
        let handle = build_handle_with_responder(
            rendezvous.local_addr().to_string(),
            local_peer_id,
            "devmesh",
            None,
            None,
        )
        .await;

        // Different keypair → different peer_id → publish_self should
        // refuse rather than mint a record peers can't authenticate.
        let other_key = DeviceKeypair::generate().unwrap();
        let err = handle
            .publish_self(&other_key, &rendezvous.local_addr().to_string(), 120, 1, vec![])
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
        let local_key = DeviceKeypair::generate().unwrap();
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
            None,
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
