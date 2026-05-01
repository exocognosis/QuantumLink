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
    network_event_count: AtomicU64,
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
            network_event_count: AtomicU64::new(0),
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

    fn snapshot_metrics(&self) -> MeshTransportRawMetrics {
        MeshTransportRawMetrics {
            frames_sent: self.frames_sent.load(Ordering::Relaxed),
            frames_received: self.frames_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            send_failures: self.send_failures.load(Ordering::Relaxed),
            receive_failures: self.receive_failures.load(Ordering::Relaxed),
            network_event_count: self.network_event_count.load(Ordering::Relaxed),
            reconnect_count: self.reconnect_count.load(Ordering::Relaxed),
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

pub struct MeshTransportHandle {
    /// Wrapped in `Option` so `Drop` can take it out and call
    /// `Runtime::shutdown_background()`. Letting a `Runtime` drop normally
    /// inside an async context panics with "Cannot drop a runtime in a
    /// context where blocking is not allowed".
    runtime: Option<Runtime>,
    shared: Arc<SharedState>,
    outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    inbound_rx: TokioMutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    event_tx: mpsc::UnboundedSender<NetworkEvent>,
    manager_task: StdMutex<Option<JoinHandle<()>>>,
    shutdown_tx: mpsc::UnboundedSender<()>,
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

        // The connector now learns the remote's QUIC server cert from the
        // signed rendezvous record and uses `connect_with_trusted_cert` for
        // per-connection trust. The endpoint-level trust list is empty —
        // any direct `connect()` would fail by design. (See module docs.)
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

        let shared = Arc::new(SharedState::new());

        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<NetworkEvent>();
        let (shutdown_tx, shutdown_rx) = mpsc::unbounded_channel::<()>();

        let remote_peer_id = config.remote_peer_id.clone();
        let connector_for_task = connector.clone();
        let shared_for_task = shared.clone();
        let backoff = BackoffConfig {
            initial: Duration::from_millis(config.reconnect_initial_backoff_ms.max(1)),
            max: Duration::from_millis(config.reconnect_max_backoff_ms.max(1)),
        };
        let manager_task = runtime.spawn(run_session_manager(
            connector_for_task,
            remote_peer_id,
            outbound_rx,
            inbound_tx,
            event_rx,
            shutdown_rx,
            shared_for_task,
            backoff,
        ));

        // Optional OpenMetrics endpoint. Off by default; only spawned when
        // the operator explicitly sets a bind address. The provider closure
        // pulls a fresh snapshot from `shared` on every scrape.
        let metrics_endpoint = match config.metrics_endpoint_bind_addr.as_ref() {
            Some(addr_str) => {
                let bind: SocketAddr = addr_str.parse().map_err(|err| {
                    QlinkError::Protocol(format!("invalid metrics_endpoint_bind_addr: {err}"))
                })?;
                let provider_state = shared.clone();
                let provider: crate::metrics_endpoint::MetricsSnapshotProvider =
                    Arc::new(move || mesh_transport_snapshot(&provider_state));
                Some(runtime.block_on(spawn_metrics_endpoint(bind, provider))?)
            }
            None => None,
        };

        Ok(Self {
            runtime: Some(runtime),
            shared,
            outbound_tx,
            inbound_rx: TokioMutex::new(inbound_rx),
            event_tx,
            manager_task: StdMutex::new(Some(manager_task)),
            shutdown_tx,
            metrics_endpoint: StdMutex::new(metrics_endpoint),
        })
    }

    /// Local address of the OpenMetrics endpoint, when one is bound. Useful
    /// for tests that need the assigned ephemeral port.
    pub fn metrics_endpoint_addr(&self) -> Option<SocketAddr> {
        self.metrics_endpoint
            .lock()
            .ok()?
            .as_ref()
            .map(|endpoint| endpoint.local_addr())
    }

    pub fn send_frame(&self, frame: Vec<u8>) -> Result<()> {
        let len = frame.len() as u64;
        match self.outbound_tx.send(frame) {
            Ok(()) => {
                self.shared.frames_sent.fetch_add(1, Ordering::Relaxed);
                self.shared.bytes_sent.fetch_add(len, Ordering::Relaxed);
                Ok(())
            }
            Err(_) => {
                self.shared.send_failures.fetch_add(1, Ordering::Relaxed);
                Err(QlinkError::Protocol(
                    "mesh transport outbound channel closed".into(),
                ))
            }
        }
    }

    pub fn try_receive_frame(&self) -> Option<Vec<u8>> {
        let mut rx = self.inbound_rx.try_lock().ok()?;
        match rx.try_recv() {
            Ok(frame) => Some(frame),
            Err(_) => None,
        }
    }

    pub fn handle_network_event(&self, event: NetworkEvent) -> NetworkEventResponse {
        self.shared
            .network_event_count
            .fetch_add(1, Ordering::Relaxed);
        // Send the event to the manager task; it'll invalidate its cache and
        // tear down the active session if the policy demands it. The
        // response we return reflects the static policy mapping rather than
        // the actual cache state inside the connector — sufficient for
        // operator telemetry.
        let _ = self.event_tx.send(event);
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

    pub fn metrics(&self) -> MeshTransportRawMetrics {
        self.shared.snapshot_metrics()
    }

    pub fn state_code(&self) -> u32 {
        self.shared.state_code()
    }

    pub fn path_kind_code(&self) -> u32 {
        self.shared.path_kind_code()
    }

    pub fn last_error(&self) -> Option<String> {
        self.shared.last_error.lock().ok()?.clone()
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
        if let Ok(mut guard) = self.manager_task.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        if let Ok(mut guard) = self.metrics_endpoint.lock() {
            if let Some(endpoint) = guard.take() {
                endpoint.shutdown();
            }
        }
        self.shared.set_state(MeshTransportState::Stopped);
    }
}

impl Drop for MeshTransportHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(());
        if let Ok(mut guard) = self.manager_task.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        if let Ok(mut guard) = self.metrics_endpoint.lock() {
            // Drop on MetricsEndpoint already aborts the listener task.
            guard.take();
        }
        // Take the runtime and shutdown asynchronously so this Drop is safe
        // to call from any context (including from within another tokio
        // runtime, which is what tests do).
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

fn mesh_transport_snapshot(shared: &Arc<SharedState>) -> MetricsSnapshot {
    let mut snapshot = MetricsSnapshot::default();

    // State + path kind expressed as gauges so dashboards can plot
    // transitions over time. Counters are the per-direction frame/byte
    // tallies the manager updates on every send/receive.
    snapshot.push_gauge(
        "qlink_mesh_transport_state",
        "Mesh transport state: 0=connecting, 1=ready, 2=failed, 3=stopped",
        shared.state_code() as f64,
    );
    snapshot.push_gauge(
        "qlink_mesh_transport_path_kind",
        "Selected path kind: 0=none, 1=direct, 2=relay",
        shared.path_kind_code() as f64,
    );

    snapshot.push_counter(
        "qlink_mesh_transport_frames_sent_total",
        "Total frames the manager has handed to the live MeshLink.send_frame",
        shared.frames_sent.load(Ordering::Relaxed) as f64,
    );
    snapshot.push_counter(
        "qlink_mesh_transport_frames_received_total",
        "Total frames the manager has pulled out of the live MeshLink.receive_frame",
        shared.frames_received.load(Ordering::Relaxed) as f64,
    );
    snapshot.push_counter(
        "qlink_mesh_transport_bytes_sent_total",
        "Total bytes accepted by the manager outbound queue",
        shared.bytes_sent.load(Ordering::Relaxed) as f64,
    );
    snapshot.push_counter(
        "qlink_mesh_transport_bytes_received_total",
        "Total bytes delivered out of the manager inbound queue",
        shared.bytes_received.load(Ordering::Relaxed) as f64,
    );
    snapshot.push_counter(
        "qlink_mesh_transport_send_failures_total",
        "Send-frame errors recorded by the manager (dead link, channel closed, etc.)",
        shared.send_failures.load(Ordering::Relaxed) as f64,
    );
    snapshot.push_counter(
        "qlink_mesh_transport_receive_failures_total",
        "Receive-frame errors recorded by the manager",
        shared.receive_failures.load(Ordering::Relaxed) as f64,
    );
    snapshot.push_counter(
        "qlink_mesh_transport_network_events_total",
        "System-level network events fed into the manager (path-changed, sleep, wake, reachability)",
        shared.network_event_count.load(Ordering::Relaxed) as f64,
    );
    snapshot.push_counter(
        "qlink_mesh_transport_reconnects_total",
        "Manager loop iterations after the first connect (i.e. reconnect attempts)",
        shared.reconnect_count.load(Ordering::Relaxed) as f64,
    );

    snapshot
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
    inbound_tx: mpsc::UnboundedSender<Vec<u8>>,
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
                            if inbound_tx.send(frame).is_err() {
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
}
