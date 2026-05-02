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
    error::{QlinkError, Result},
    ice::IceCredentials,
    mesh_connection::{
        MeshConnector, MeshConnectorConfig, NetworkEvent, NetworkEventResponse, PathKind,
    },
    metrics_endpoint::{spawn_metrics_endpoint, MetricsEndpoint, MetricsSnapshot},
    quic_transport::QuicEndpoint,
    rendezvous::RendezvousClient,
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
}

impl MeshTransportHandle {
    pub fn from_json_config(bytes: &[u8]) -> Result<Self> {
        let config: MeshTransportConfig = serde_json::from_slice(bytes)?;
        Self::new(config)
    }

    pub fn new(config: MeshTransportConfig) -> Result<Self> {
        let runtime = Runtime::new().map_err(|err| {
            QlinkError::Protocol(format!("failed to create mesh transport runtime: {err}"))
        })?;

        let bind_addr: SocketAddr = config
            .bind_addr
            .parse()
            .map_err(|err| QlinkError::Protocol(format!("invalid bind_addr: {err}")))?;

        // The connector learns each peer's QUIC server cert from the
        // signed rendezvous record and uses `connect_with_trusted_cert`
        // for per-connection trust. The endpoint-level trust list is
        // empty — any direct `connect()` would fail by design.
        let _runtime_guard = runtime.enter();
        let quic_endpoint = QuicEndpoint::client(bind_addr, &[])?;

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

        let connector = Arc::new(MeshConnector::new(
            connector_config,
            rendezvous_client,
            quic_endpoint,
        ));

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
}
