//! Tunnel engine — the Windows-service counterpart of the macOS
//! `PacketTunnelProvider.swift` + `MeshController.swift` orchestration.
//!
//! Owns the data plane end to end: adapter <-> pump <-> qlink-core <->
//! mesh transport, plus the strict-mode watchdog and the status snapshot
//! served over IPC. Platform-specific work (Wintun creation, routes,
//! DNS, WFP kill switch) is delegated to a [`PlatformNetwork`]
//! implementation so the engine itself runs and tests on any host.
//!
//! Connect sequencing (mirrors `startTunnel` on macOS):
//! 1. load/generate the device keypair + peer-store key (secret store)
//! 2. build the Rust packet core from the configuration
//! 3. engage the WFP kill switch (fail closed *before* any traffic can
//!    flow — strict mode refuses to continue if this fails)
//! 4. create the adapter, assign IP/MTU/routes/DNS
//! 5. start the mesh transport (or the local echo transport for
//!    development when no rendezvous server is configured)
//! 6. spawn the outbound and inbound pump threads + watchdog
//!
//! Teardown order is the reverse, except the kill-switch filters stay
//! installed until routes are removed so no plaintext window opens.

use crate::adapter::{protocol_family_for_packet, AdapterError, TunnelAdapter};
use crate::kill_switch::{KillSwitchWatchdog, WatchdogVerdict, DEFAULT_DEADLINE};
use crate::pump::{PumpError, TransportFrameSink, TunnelPacketPump};
use crate::secret_store::{
    load_or_generate_device_keypair, load_or_generate_peer_store_key, SecretStore,
};
use base64::Engine as _;
use qlink_core::crypto::DeviceKeypair;
use qlink_core::mesh_connection::NetworkEvent;
use qlink_core::mesh_transport::{MeshTransportConfig, MeshTransportHandle};
use qlink_core::packet_core::PacketTunnelCore;
use quantumlink_proto::models::{
    ConnectionPhase, DiscoveryIdentityMode, DytallixPeerTrustSummary, KillSwitchPolicy,
    MeshMetrics, MeshTrustPolicy, PathType, PeerIdentity, PeerStatus, TunnelConfiguration,
    TunnelStatus, TunnelTransportMetrics,
};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;

const PUMP_READ_TIMEOUT: Duration = Duration::from_millis(250);
const INBOUND_POLL_INTERVAL: Duration = Duration::from_millis(5);
const WATCHDOG_CADENCE: Duration = Duration::from_secs(1);

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("engine is already connected")]
    AlreadyConnected,
    #[error("secret store failed: {0}")]
    Secrets(#[from] crate::secret_store::SecretStoreError),
    #[error("core construction failed: {0}")]
    Core(#[from] qlink_core::QlinkError),
    #[error("platform network operation failed: {0}")]
    Platform(String),
    #[error("kill switch engagement failed and policy is strict: {0}")]
    KillSwitchStrict(String),
    #[error("adapter failed: {0}")]
    Adapter(#[from] AdapterError),
    #[error("pump failed: {0}")]
    Pump(#[from] PumpError),
    #[error("configuration invalid: {0}")]
    Config(String),
}

/// Privileged platform operations the engine delegates. The Windows
/// implementation lives in `win::platform::WindowsPlatform`; the
/// [`DevPlatform`] no-op variant runs everywhere else.
pub trait PlatformNetwork: Send + Sync {
    fn create_adapter(
        &self,
        config: &TunnelConfiguration,
    ) -> Result<Arc<dyn TunnelAdapter>, EngineError>;
    /// Assign overlay IP, MTU, protected routes, and DNS to the adapter.
    fn apply_network_config(
        &self,
        adapter: &Arc<dyn TunnelAdapter>,
        config: &TunnelConfiguration,
    ) -> Result<(), EngineError>;
    /// Install WFP filters pinning protected prefixes to the adapter.
    fn engage_kill_switch(&self, config: &TunnelConfiguration) -> Result<(), EngineError>;
    fn disengage_kill_switch(&self) -> Result<(), EngineError>;
    fn kill_switch_engaged(&self) -> bool;
    /// Remove routes/DNS and release the adapter.
    fn teardown(
        &self,
        adapter: &Arc<dyn TunnelAdapter>,
        config: &TunnelConfiguration,
    ) -> Result<(), EngineError>;
}

/// No-op platform for development hosts and unit tests: loopback
/// adapter, kill switch tracked as a boolean.
#[derive(Default)]
pub struct DevPlatform {
    engaged: AtomicBool,
    /// Test hook: make engage_kill_switch fail to exercise strict mode.
    pub fail_kill_switch: AtomicBool,
}

impl PlatformNetwork for DevPlatform {
    fn create_adapter(
        &self,
        _config: &TunnelConfiguration,
    ) -> Result<Arc<dyn TunnelAdapter>, EngineError> {
        Ok(Arc::new(crate::adapter::LoopbackAdapter::default()))
    }

    fn apply_network_config(
        &self,
        _adapter: &Arc<dyn TunnelAdapter>,
        _config: &TunnelConfiguration,
    ) -> Result<(), EngineError> {
        Ok(())
    }

    fn engage_kill_switch(&self, _config: &TunnelConfiguration) -> Result<(), EngineError> {
        if self.fail_kill_switch.load(Ordering::SeqCst) {
            return Err(EngineError::Platform(
                "dev kill switch forced failure".into(),
            ));
        }
        self.engaged.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn disengage_kill_switch(&self) -> Result<(), EngineError> {
        self.engaged.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn kill_switch_engaged(&self) -> bool {
        self.engaged.load(Ordering::SeqCst)
    }

    fn teardown(
        &self,
        adapter: &Arc<dyn TunnelAdapter>,
        _config: &TunnelConfiguration,
    ) -> Result<(), EngineError> {
        adapter.shutdown();
        Ok(())
    }
}

/// The active encrypted transport behind the pump.
enum ActiveTransport {
    /// Production: QUIC mesh with PQC handshake, relay fallback,
    /// rendezvous discovery (all inside qlink-core).
    Mesh(Arc<MeshTransportHandle>),
    /// Development/local-smoke: frames are queued back for inbound
    /// acceptance, exercising encode -> decode without a network.
    LocalEcho(Mutex<VecDeque<Vec<u8>>>),
}

impl ActiveTransport {
    fn is_ready(&self) -> bool {
        match self {
            // 1 == MeshTransportState::Ready
            ActiveTransport::Mesh(handle) => handle.state_code() == 1,
            ActiveTransport::LocalEcho(_) => true,
        }
    }
}

struct TransportSink {
    transport: Arc<ActiveTransport>,
}

impl TransportFrameSink for TransportSink {
    fn is_ready(&self) -> bool {
        self.transport.is_ready()
    }

    fn send_transport_frame(&self, frame: Vec<u8>) -> Result<(), PumpError> {
        match self.transport.as_ref() {
            ActiveTransport::Mesh(handle) => handle
                .send_frame(frame)
                .map_err(|error| PumpError::TransportSend(error.to_string())),
            ActiveTransport::LocalEcho(queue) => {
                queue.lock().unwrap().push_back(frame);
                Ok(())
            }
        }
    }
}

struct ActiveSession {
    config: TunnelConfiguration,
    adapter: Arc<dyn TunnelAdapter>,
    pump: Arc<Mutex<TunnelPacketPump<PacketTunnelCore>>>,
    transport: Arc<ActiveTransport>,
    local_peer_id: String,
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
    last_error: Arc<Mutex<Option<String>>>,
}

struct StartupRollback {
    platform: Arc<dyn PlatformNetwork>,
    config: TunnelConfiguration,
    adapter: Option<Arc<dyn TunnelAdapter>>,
    kill_switch_engaged: bool,
    committed: bool,
}

impl StartupRollback {
    fn new(platform: Arc<dyn PlatformNetwork>, config: &TunnelConfiguration) -> Self {
        Self {
            platform,
            config: config.clone(),
            adapter: None,
            kill_switch_engaged: false,
            committed: false,
        }
    }

    fn mark_kill_switch_engaged(&mut self) {
        self.kill_switch_engaged = true;
    }

    fn set_adapter(&mut self, adapter: &Arc<dyn TunnelAdapter>) {
        self.adapter = Some(Arc::clone(adapter));
    }

    fn commit(&mut self) {
        self.committed = true;
        self.adapter = None;
        self.kill_switch_engaged = false;
    }
}

impl Drop for StartupRollback {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Some(adapter) = self.adapter.take() {
            if let Err(error) = self.platform.teardown(&adapter, &self.config) {
                tracing::warn!(%error, "startup rollback teardown failed");
            }
        }
        if self.kill_switch_engaged {
            if let Err(error) = self.platform.disengage_kill_switch() {
                tracing::warn!(%error, "startup rollback kill switch disengage failed");
            }
        }
    }
}

pub struct TunnelEngine {
    secret_store: Arc<dyn SecretStore>,
    platform: Arc<dyn PlatformNetwork>,
    state_dir: PathBuf,
    session: Mutex<Option<ActiveSession>>,
    phase: Mutex<ConnectionPhase>,
    last_error: Mutex<Option<String>>,
}

impl TunnelEngine {
    pub fn new(
        secret_store: Arc<dyn SecretStore>,
        platform: Arc<dyn PlatformNetwork>,
        state_dir: PathBuf,
    ) -> Self {
        Self {
            secret_store,
            platform,
            state_dir,
            session: Mutex::new(None),
            phase: Mutex::new(ConnectionPhase::Idle),
            last_error: Mutex::new(None),
        }
    }

    pub fn connect(&self, config: TunnelConfiguration) -> Result<TunnelStatus, EngineError> {
        {
            let session = self.session.lock().unwrap();
            if session.is_some() {
                return Err(EngineError::AlreadyConnected);
            }
        }
        self.set_phase(ConnectionPhase::Preparing);

        let result = self.connect_inner(config);
        match &result {
            Ok(_) => self.set_phase(ConnectionPhase::Connected),
            Err(error) => {
                *self.last_error.lock().unwrap() = Some(error.to_string());
                self.set_phase(ConnectionPhase::Failed);
            }
        }
        result.map(|()| self.status())
    }

    fn connect_inner(&self, config: TunnelConfiguration) -> Result<(), EngineError> {
        crate::config::validate_configuration(&config).map_err(EngineError::Config)?;
        let mut rollback = StartupRollback::new(Arc::clone(&self.platform), &config);

        // 1. Stable identity + peer-store key.
        let keypair = load_or_generate_device_keypair(self.secret_store.as_ref())?;
        let peer_store_key = load_or_generate_peer_store_key(self.secret_store.as_ref())?;
        let local_peer_id = keypair.public_key().peer_id();

        // 2. Packet core.
        let core_config = serde_json::to_vec(&config.packet_core_config_json())
            .map_err(|error| EngineError::Config(error.to_string()))?;
        let core = PacketTunnelCore::from_json(&core_config)?;

        // 3. Kill switch BEFORE any adapter/routes exist. Fail-closed
        //    deployments log and continue (the pump still drops);
        //    strict deployments refuse to come up at all.
        if let Err(error) = self.platform.engage_kill_switch(&config) {
            match config.kill_switch {
                KillSwitchPolicy::Strict => {
                    return Err(EngineError::KillSwitchStrict(error.to_string()));
                }
                KillSwitchPolicy::FailClosed => {
                    tracing::warn!(%error, "kill switch engagement failed; pump-level fail-closed still applies");
                }
            }
        } else {
            rollback.mark_kill_switch_engaged();
        }

        // 4. Adapter + network configuration.
        self.set_phase(ConnectionPhase::Connecting);
        let adapter = self.platform.create_adapter(&config)?;
        rollback.set_adapter(&adapter);
        self.platform.apply_network_config(&adapter, &config)?;

        // 5. Transport.
        let transport = match config.rendezvous_servers.first() {
            Some(rendezvous_url) => {
                let mesh =
                    self.build_mesh_transport(&config, rendezvous_url, &keypair, &peer_store_key)?;
                Arc::new(ActiveTransport::Mesh(Arc::new(mesh)))
            }
            None => {
                tracing::info!(
                    "no rendezvous server configured; using local echo transport (development)"
                );
                Arc::new(ActiveTransport::LocalEcho(Mutex::new(VecDeque::new())))
            }
        };

        // Strict mode refuses a tunnel whose transport never establishes
        // during start (deadline = watchdog default).
        if config.kill_switch == KillSwitchPolicy::Strict {
            let deadline = std::time::Instant::now() + DEFAULT_DEADLINE;
            while !transport.is_ready() {
                if std::time::Instant::now() >= deadline {
                    return Err(EngineError::KillSwitchStrict(
                        "transport did not become ready during start".into(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }

        // 6. Pump threads.
        let pump = Arc::new(Mutex::new(TunnelPacketPump::new(Some(core))));
        let stop = Arc::new(AtomicBool::new(false));
        let last_error = Arc::new(Mutex::new(None));
        let mut threads = Vec::new();

        threads.push(spawn_outbound_loop(
            Arc::clone(&adapter),
            Arc::clone(&pump),
            Arc::clone(&transport),
            Arc::clone(&stop),
        ));
        threads.push(spawn_inbound_loop(
            Arc::clone(&adapter),
            Arc::clone(&pump),
            Arc::clone(&transport),
            Arc::clone(&stop),
        ));
        threads.push(spawn_watchdog_loop(
            config.kill_switch,
            Arc::clone(&transport),
            Arc::clone(&stop),
            Arc::clone(&last_error),
        ));

        *self.session.lock().unwrap() = Some(ActiveSession {
            config,
            adapter,
            pump,
            transport,
            local_peer_id,
            stop,
            threads,
            last_error,
        });
        rollback.commit();
        *self.last_error.lock().unwrap() = None;
        Ok(())
    }

    fn build_mesh_transport(
        &self,
        config: &TunnelConfiguration,
        rendezvous_url: &str,
        keypair: &DeviceKeypair,
        peer_store_key: &[u8; 32],
    ) -> Result<MeshTransportHandle, EngineError> {
        let peer_store_path = self.state_dir.join(crate::config::PEER_STORE_FILE);
        let mesh_config: MeshTransportConfig = serde_json::from_value(serde_json::json!({
            "meshId": config.mesh_id,
            "localPeerId": keypair.public_key().peer_id(),
            // Peers are added dynamically via add_peer; the primary slot
            // uses the same sentinel qlinkctl uses pre-configuration.
            "remotePeerId": "qlink_unconfigured",
            "rendezvousUrl": rendezvous_url,
            "relayUrl": config.relay_servers.first(),
            "bindAddr": "0.0.0.0:0",
            "peerStorePath": peer_store_path.to_string_lossy(),
            "peerStoreKeyB64": base64::engine::general_purpose::STANDARD.encode(peer_store_key),
        }))
        .map_err(|error| EngineError::Config(format!("mesh config: {error}")))?;

        let owned_keypair = keypair
            .seed()
            .ok_or_else(|| EngineError::Config("keypair has no persistable seed".into()))
            .and_then(|seed| {
                DeviceKeypair::from_seed(seed)
                    .map_err(|error| EngineError::Config(error.to_string()))
            })?;
        MeshTransportHandle::new_with_keypair(mesh_config, Some(Arc::new(owned_keypair)))
            .map_err(EngineError::Core)
    }

    pub fn disconnect(&self) -> TunnelStatus {
        let session = self.session.lock().unwrap().take();
        if let Some(mut session) = session {
            self.set_phase(ConnectionPhase::Disconnected);
            session.stop.store(true, Ordering::SeqCst);
            session.adapter.shutdown();
            if let ActiveTransport::Mesh(handle) = session.transport.as_ref() {
                handle.shutdown();
            }
            for thread in session.threads.drain(..) {
                let _ = thread.join();
            }
            // Routes go first, then the kill-switch filters, so no
            // plaintext window opens between the two.
            if let Err(error) = self.platform.teardown(&session.adapter, &session.config) {
                tracing::warn!(%error, "adapter teardown failed");
            }
            if let Err(error) = self.platform.disengage_kill_switch() {
                tracing::warn!(%error, "kill switch disengage failed");
            }
        }
        self.set_phase(ConnectionPhase::Idle);
        self.status()
    }

    /// Adds a mesh peer at runtime (multi-peer surface).
    pub fn add_peer(&self, peer_id: &str) -> Result<(), EngineError> {
        let session = self.session.lock().unwrap();
        let Some(session) = session.as_ref() else {
            return Err(EngineError::Platform("not connected".into()));
        };
        match session.transport.as_ref() {
            ActiveTransport::Mesh(handle) => handle.add_peer(peer_id).map_err(EngineError::Core),
            ActiveTransport::LocalEcho(_) => Err(EngineError::Platform(
                "local echo transport has no peers".into(),
            )),
        }
    }

    pub fn handle_network_event(&self, event: NetworkEvent) {
        let session = self.session.lock().unwrap();
        if let Some(session) = session.as_ref() {
            if let ActiveTransport::Mesh(handle) = session.transport.as_ref() {
                let response = handle.handle_network_event(event);
                if response.reprobe_recommended {
                    tracing::info!("network event recommends path re-probe");
                }
            }
        }
    }

    pub fn peer_state_code(&self, peer_id: &str) -> Option<u32> {
        let session = self.session.lock().unwrap();
        let session = session.as_ref()?;
        match session.transport.as_ref() {
            ActiveTransport::Mesh(handle) => handle.peer_state_code(peer_id),
            ActiveTransport::LocalEcho(_) => None,
        }
    }

    pub fn status(&self) -> TunnelStatus {
        let phase = *self.phase.lock().unwrap();
        let session = self.session.lock().unwrap();
        let mut status = TunnelStatus::idle();
        status.phase = phase;
        status.kill_switch_engaged = Some(self.platform.kill_switch_engaged());
        status.last_error = self.last_error.lock().unwrap().clone();

        if let Some(session) = session.as_ref() {
            status.route_mode = session.config.route_mode;
            status.dns_mode = session.config.dns_mode;
            status.overlay_ipv4_address = session.config.overlay_ipv4_address.clone();
            status.protected_routes = session.config.protected_routes.clone();
            status.peer_trust = DytallixPeerTrustSummary {
                required: session.config.mesh_trust_policy == MeshTrustPolicy::PublicRequired
                    || session.config.discovery_identity_mode != DiscoveryIdentityMode::Off,
                policy: session.config.mesh_trust_policy,
                identity_mode: session.config.discovery_identity_mode,
                registry_configured: session.config.dytallix_identity.is_some(),
                ..DytallixPeerTrustSummary::default()
            };
            status.pump = Some(session.pump.lock().unwrap().counters().as_proto());
            if let Some(error) = session.last_error.lock().unwrap().clone() {
                status.last_error = Some(error);
            }

            match session.transport.as_ref() {
                ActiveTransport::Mesh(handle) => {
                    let raw = handle.metrics();
                    status.path_type = match handle.path_kind_code() {
                        1 => PathType::Direct,
                        2 => PathType::Relay,
                        _ => PathType::Probing,
                    };
                    status.transport = Some(TunnelTransportMetrics {
                        state_code: handle.state_code(),
                        path_kind_code: handle.path_kind_code(),
                        frames_sent: raw.frames_sent,
                        frames_received: raw.frames_received,
                        bytes_sent: raw.bytes_sent,
                        bytes_received: raw.bytes_received,
                        send_failures: raw.send_failures,
                        receive_failures: raw.receive_failures,
                        network_event_count: raw.network_event_count,
                        reconnect_count: raw.reconnect_count,
                    });
                    let peers: Vec<PeerStatus> = handle
                        .peer_ids()
                        .into_iter()
                        .map(|peer_id| PeerStatus {
                            identity: PeerIdentity {
                                peer_id: peer_id.clone(),
                                alias: String::new(),
                                public_key_fingerprint: String::new(),
                            },
                            path_type: match handle.peer_path_kind_code(&peer_id) {
                                Some(1) => PathType::Direct,
                                Some(2) => PathType::Relay,
                                _ => PathType::Probing,
                            },
                            endpoints: Vec::new(),
                            overlay_address: String::new(),
                            rtt_milliseconds: None,
                            last_rekey_unix: None,
                            bytes_in: 0,
                            bytes_out: 0,
                        })
                        .collect();
                    status.metrics = MeshMetrics {
                        peer_count: peers.len() as u32,
                        direct_peer_count: peers
                            .iter()
                            .filter(|p| p.path_type == PathType::Direct)
                            .count() as u32,
                        relay_peer_count: peers
                            .iter()
                            .filter(|p| p.path_type == PathType::Relay)
                            .count() as u32,
                        bytes_in: raw.bytes_received,
                        bytes_out: raw.bytes_sent,
                        replay_drops: 0,
                        last_path_probe_unix: None,
                    };
                    status.peers = peers;
                }
                ActiveTransport::LocalEcho(_) => {
                    status.path_type = PathType::Direct;
                }
            }
            let _ = &session.local_peer_id;
        }
        status
    }

    /// Diagnostics export — Windows analog of `SupportBundleExporter`.
    /// Peer ids are redacted per the privacy spec before anything is
    /// written where a user might paste it into a ticket.
    pub fn diagnostics(&self) -> String {
        let status = self.status();
        let json = serde_json::json!({
            "service": env!("CARGO_PKG_VERSION"),
            "qlinkCoreSuite": "QLINK-FIPS203-MLKEM768-SHAKE256-v1",
            "status": diagnostics_status(&status),
        });
        quantumlink_proto::privacy::redact_diagnostics_text(
            &serde_json::to_string_pretty(&json).unwrap_or_else(|_| "{}".to_string()),
        )
    }

    fn set_phase(&self, phase: ConnectionPhase) {
        *self.phase.lock().unwrap() = phase;
    }
}

fn diagnostics_status(status: &TunnelStatus) -> serde_json::Value {
    let peers: Vec<_> = status
        .peers
        .iter()
        .map(|peer| {
            serde_json::json!({
                "identity": {
                    "peerID": quantumlink_proto::privacy::redact_peer_identifiers(
                        &peer.identity.peer_id,
                    ),
                    "aliasPresent": !peer.identity.alias.is_empty(),
                    "publicKeyFingerprintPresent": !peer.identity.public_key_fingerprint.is_empty(),
                },
                "pathType": peer.path_type,
                "endpointCount": peer.endpoints.len(),
                "overlayAddressPresent": !peer.overlay_address.is_empty(),
                "rttMilliseconds": peer.rtt_milliseconds,
                "lastRekeyUnix": peer.last_rekey_unix,
                "bytesIn": peer.bytes_in,
                "bytesOut": peer.bytes_out,
            })
        })
        .collect();

    serde_json::json!({
        "phase": status.phase,
        "pathType": status.path_type,
        "routeMode": status.route_mode,
        "dnsMode": status.dns_mode,
        "overlayAddressPresent": !status.overlay_ipv4_address.is_empty(),
        "protectedRouteCount": status.protected_routes.len(),
        "peers": peers,
        "metrics": status.metrics,
        "transport": status.transport,
        "pump": status.pump,
        "killSwitchEngaged": status.kill_switch_engaged,
        "peerTrust": {
            "required": status.peer_trust.required,
            "trustPolicy": status.peer_trust.policy,
            "identityMode": status.peer_trust.identity_mode,
            "registryConfigured": status.peer_trust.registry_configured,
            "verifiedPeerCount": status.peer_trust.verified_peer_count,
            "unverifiedPeerCount": status.peer_trust.unverified_peer_count,
            "pendingPeerCount": status.peer_trust.pending_peer_count,
            "failedPeerCount": status.peer_trust.failed_peer_count,
            "lastCheckedAtUnix": status.peer_trust.last_checked_at_unix,
        },
        "lastError": status
            .last_error
            .as_ref()
            .map(|error| quantumlink_proto::privacy::redact_diagnostics_text(error)),
    })
}

impl Drop for TunnelEngine {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// Outbound: adapter -> pump -> transport. One packet batch per adapter
/// read; the pump drains transport frames inline (pop-then-send).
fn spawn_outbound_loop(
    adapter: Arc<dyn TunnelAdapter>,
    pump: Arc<Mutex<TunnelPacketPump<PacketTunnelCore>>>,
    transport: Arc<ActiveTransport>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("qlink-pump-out".into())
        .spawn(move || {
            let sink = TransportSink {
                transport: Arc::clone(&transport),
            };
            while !stop.load(Ordering::SeqCst) {
                match adapter.receive(PUMP_READ_TIMEOUT) {
                    Ok(Some(packet)) => {
                        let family = protocol_family_for_packet(&packet);
                        pump.lock()
                            .unwrap()
                            .handle_packets(&[(family, packet.as_slice())], &sink);
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        })
        .expect("spawn outbound pump thread")
}

/// Inbound: transport -> pump -> adapter.
fn spawn_inbound_loop(
    adapter: Arc<dyn TunnelAdapter>,
    pump: Arc<Mutex<TunnelPacketPump<PacketTunnelCore>>>,
    transport: Arc<ActiveTransport>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("qlink-pump-in".into())
        .spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let inbound: Option<(Vec<u8>, Option<String>)> = match transport.as_ref() {
                    ActiveTransport::Mesh(handle) => handle
                        .try_receive_frame_from_any()
                        .map(|frame| (frame.frame, Some(frame.peer_id))),
                    ActiveTransport::LocalEcho(queue) => {
                        queue.lock().unwrap().pop_front().map(|frame| (frame, None))
                    }
                };
                let Some((frame, peer_id)) = inbound else {
                    std::thread::sleep(INBOUND_POLL_INTERVAL);
                    continue;
                };
                let mut pump = pump.lock().unwrap();
                if pump
                    .accept_transport_frame(&frame, peer_id.as_deref())
                    .is_ok()
                {
                    while let Some(packet) = pump.pop_tunnel_packet() {
                        if adapter.send(&packet.bytes).is_err() {
                            return;
                        }
                    }
                }
            }
        })
        .expect("spawn inbound pump thread")
}

/// Strict-mode watchdog: tears nothing down itself — it flips the stop
/// flag and records the reason; `disconnect` (driven by the IPC layer or
/// service control) completes the teardown. The WFP filters remain
/// installed throughout, so protected prefixes stay dark.
fn spawn_watchdog_loop(
    policy: KillSwitchPolicy,
    transport: Arc<ActiveTransport>,
    stop: Arc<AtomicBool>,
    last_error: Arc<Mutex<Option<String>>>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("qlink-watchdog".into())
        .spawn(move || {
            let mut watchdog = KillSwitchWatchdog::new(policy, DEFAULT_DEADLINE);
            while !stop.load(Ordering::SeqCst) {
                if watchdog.evaluate(transport.is_ready()) == WatchdogVerdict::Fire {
                    tracing::error!(
                        "strict kill switch deadline expired; halting data plane (protected prefixes remain blocked by WFP)"
                    );
                    *last_error.lock().unwrap() = Some(
                        "strict kill switch: transport unhealthy past deadline; tunnel halted"
                            .to_string(),
                    );
                    stop.store(true, Ordering::SeqCst);
                    break;
                }
                std::thread::sleep(WATCHDOG_CADENCE);
            }
        })
        .expect("spawn watchdog thread")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{AdapterError, LoopbackAdapter};
    use crate::secret_store::InMemorySecretStore;
    use quantumlink_proto::models::DytallixIdentityConfiguration;
    use quantumlink_proto::privacy;
    use std::sync::atomic::AtomicUsize;

    fn test_engine() -> (Arc<DevPlatform>, TunnelEngine) {
        let platform = Arc::new(DevPlatform::default());
        let engine = TunnelEngine::new(
            Arc::new(InMemorySecretStore::default()),
            Arc::clone(&platform) as Arc<dyn PlatformNetwork>,
            std::env::temp_dir(),
        );
        (platform, engine)
    }

    fn dev_config() -> TunnelConfiguration {
        let mut config = privacy::default_tunnel_configuration();
        config.protected_routes = vec!["100.127.0.0/16".to_string()];
        config
    }

    fn ipv4_packet(destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[100, 127, 0, 2]);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    #[derive(Default)]
    struct StartupFailurePlatform {
        adapter: Mutex<Option<Arc<LoopbackAdapter>>>,
        fail_create_adapter: AtomicBool,
        fail_apply_network_config: AtomicBool,
        engaged: AtomicBool,
        teardown_count: AtomicUsize,
        disengage_count: AtomicUsize,
    }

    impl PlatformNetwork for StartupFailurePlatform {
        fn create_adapter(
            &self,
            _config: &TunnelConfiguration,
        ) -> Result<Arc<dyn TunnelAdapter>, EngineError> {
            if self.fail_create_adapter.load(Ordering::SeqCst) {
                return Err(EngineError::Platform(
                    "forced adapter creation failure".into(),
                ));
            }
            let adapter = Arc::new(LoopbackAdapter::default());
            *self.adapter.lock().unwrap() = Some(Arc::clone(&adapter));
            Ok(adapter)
        }

        fn apply_network_config(
            &self,
            _adapter: &Arc<dyn TunnelAdapter>,
            _config: &TunnelConfiguration,
        ) -> Result<(), EngineError> {
            if self.fail_apply_network_config.load(Ordering::SeqCst) {
                return Err(EngineError::Platform(
                    "forced network configuration failure".into(),
                ));
            }
            Ok(())
        }

        fn engage_kill_switch(&self, _config: &TunnelConfiguration) -> Result<(), EngineError> {
            self.engaged.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn disengage_kill_switch(&self) -> Result<(), EngineError> {
            self.disengage_count.fetch_add(1, Ordering::SeqCst);
            self.engaged.store(false, Ordering::SeqCst);
            Ok(())
        }

        fn kill_switch_engaged(&self) -> bool {
            self.engaged.load(Ordering::SeqCst)
        }

        fn teardown(
            &self,
            adapter: &Arc<dyn TunnelAdapter>,
            _config: &TunnelConfiguration,
        ) -> Result<(), EngineError> {
            self.teardown_count.fetch_add(1, Ordering::SeqCst);
            adapter.shutdown();
            Ok(())
        }
    }

    #[test]
    fn connect_pump_roundtrip_disconnect() {
        let (_platform, engine) = test_engine();
        let status = engine.connect(dev_config()).unwrap();
        assert_eq!(status.phase, ConnectionPhase::Connected);
        assert_eq!(status.kill_switch_engaged, Some(true));

        let status = engine.disconnect();
        assert_eq!(status.phase, ConnectionPhase::Idle);
        assert_eq!(status.kill_switch_engaged, Some(false));
    }

    #[test]
    fn strict_mode_refuses_start_when_kill_switch_fails() {
        let (platform, engine) = test_engine();
        platform.fail_kill_switch.store(true, Ordering::SeqCst);
        let mut config = dev_config();
        config.kill_switch = KillSwitchPolicy::Strict;
        let error = engine.connect(config).unwrap_err();
        assert!(matches!(error, EngineError::KillSwitchStrict(_)));
        assert_eq!(engine.status().phase, ConnectionPhase::Failed);
    }

    #[test]
    fn fail_closed_mode_survives_kill_switch_failure() {
        let (platform, engine) = test_engine();
        platform.fail_kill_switch.store(true, Ordering::SeqCst);
        let status = engine.connect(dev_config()).unwrap();
        assert_eq!(status.phase, ConnectionPhase::Connected);
        assert_eq!(status.kill_switch_engaged, Some(false));
        engine.disconnect();
    }

    #[test]
    fn startup_failure_before_adapter_create_disengages_kill_switch() {
        let platform = Arc::new(StartupFailurePlatform::default());
        platform.fail_create_adapter.store(true, Ordering::SeqCst);
        let engine = TunnelEngine::new(
            Arc::new(InMemorySecretStore::default()),
            Arc::clone(&platform) as Arc<dyn PlatformNetwork>,
            std::env::temp_dir(),
        );

        assert!(matches!(
            engine.connect(dev_config()),
            Err(EngineError::Platform(_))
        ));
        assert!(!platform.kill_switch_engaged());
        assert_eq!(platform.disengage_count.load(Ordering::SeqCst), 1);
        assert_eq!(platform.teardown_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn startup_failure_after_adapter_create_rolls_back_adapter_and_kill_switch() {
        let platform = Arc::new(StartupFailurePlatform::default());
        platform
            .fail_apply_network_config
            .store(true, Ordering::SeqCst);
        let engine = TunnelEngine::new(
            Arc::new(InMemorySecretStore::default()),
            Arc::clone(&platform) as Arc<dyn PlatformNetwork>,
            std::env::temp_dir(),
        );

        assert!(matches!(
            engine.connect(dev_config()),
            Err(EngineError::Platform(_))
        ));
        assert!(!platform.kill_switch_engaged());
        assert_eq!(platform.disengage_count.load(Ordering::SeqCst), 1);
        assert_eq!(platform.teardown_count.load(Ordering::SeqCst), 1);

        let adapter = platform.adapter.lock().unwrap().clone().unwrap();
        assert!(matches!(
            adapter.receive(Duration::from_millis(1)),
            Err(AdapterError::ShutDown)
        ));
    }

    #[test]
    fn second_connect_is_rejected() {
        let (_platform, engine) = test_engine();
        engine.connect(dev_config()).unwrap();
        assert!(matches!(
            engine.connect(dev_config()),
            Err(EngineError::AlreadyConnected)
        ));
        engine.disconnect();
    }

    #[test]
    fn diagnostics_redact_peer_ids() {
        let (_platform, engine) = test_engine();
        engine.connect(dev_config()).unwrap();
        let diagnostics = engine.diagnostics();
        assert!(!diagnostics.contains("qlink_") || diagnostics.contains("qlink_[redacted]"));
        engine.disconnect();
    }

    #[test]
    fn diagnostics_export_summarizes_sensitive_network_and_registry_values() {
        let (_platform, engine) = test_engine();
        let mut config = dev_config();
        config.overlay_ipv4_address = "100.127.10.20".to_string();
        config.protected_routes = vec!["10.0.0.0/8".to_string(), "100.127.0.0/16".to_string()];
        config.mesh_trust_policy = MeshTrustPolicy::PublicRequired;
        config.discovery_identity_mode = DiscoveryIdentityMode::Verified;
        config.dytallix_identity = Some(DytallixIdentityConfiguration {
            endpoint: "https://registry.private.example".to_string(),
            contract_address: "0xabc1230000000000000000000000000000000000".to_string(),
            publish_wallet_address: false,
            network_id: Some("private-net".to_string()),
            chain_id: Some("private-chain".to_string()),
            allowed_rpc_endpoints: vec!["https://rpc.private.example".to_string()],
            keystore_path: Some(r"C:\QuantumLink\wallet.secret".to_string()),
            wallet_name: Some("operator-wallet".to_string()),
        });

        engine.connect(config).unwrap();
        let diagnostics = engine.diagnostics();

        assert!(!diagnostics.contains("10.0.0.0/8"));
        assert!(!diagnostics.contains("100.127.0.0/16"));
        assert!(!diagnostics.contains("100.127.10.20"));
        assert!(!diagnostics.contains("registry.private.example"));
        assert!(!diagnostics.contains("0xabc123"));
        assert!(!diagnostics.contains("wallet.secret"));
        assert!(!diagnostics.contains("operator-wallet"));
        assert!(diagnostics.contains(r#""protectedRouteCount": 2"#));
        assert!(diagnostics.contains(r#""registryConfigured": true"#));
        engine.disconnect();
    }

    #[test]
    fn diagnostics_export_redacts_failed_start_error_details() {
        let (_platform, engine) = test_engine();
        let mut config = dev_config();
        config.dns_servers = vec!["https://dns.private.example".to_string()];

        assert!(engine.connect(config).is_err());
        let diagnostics = engine.diagnostics();

        assert!(!diagnostics.contains("dns.private.example"));
        assert!(diagnostics.contains("[redacted-url]"));
    }

    #[test]
    fn empty_protected_routes_is_a_config_error() {
        let (_platform, engine) = test_engine();
        let mut config = dev_config();
        config.protected_routes.clear();
        assert!(matches!(
            engine.connect(config),
            Err(EngineError::Config(_))
        ));
    }

    #[test]
    fn packet_pump_full_path_via_loopback_platform() {
        // Use a platform that exposes the adapter it created so the test
        // can inject packets.
        struct CapturingPlatform {
            inner: DevPlatform,
            adapter: Mutex<Option<Arc<LoopbackAdapter>>>,
        }
        impl PlatformNetwork for CapturingPlatform {
            fn create_adapter(
                &self,
                _config: &TunnelConfiguration,
            ) -> Result<Arc<dyn TunnelAdapter>, EngineError> {
                let adapter = Arc::new(LoopbackAdapter::default());
                *self.adapter.lock().unwrap() = Some(Arc::clone(&adapter));
                Ok(adapter)
            }
            fn apply_network_config(
                &self,
                _adapter: &Arc<dyn TunnelAdapter>,
                _config: &TunnelConfiguration,
            ) -> Result<(), EngineError> {
                Ok(())
            }
            fn engage_kill_switch(&self, config: &TunnelConfiguration) -> Result<(), EngineError> {
                self.inner.engage_kill_switch(config)
            }
            fn disengage_kill_switch(&self) -> Result<(), EngineError> {
                self.inner.disengage_kill_switch()
            }
            fn kill_switch_engaged(&self) -> bool {
                self.inner.kill_switch_engaged()
            }
            fn teardown(
                &self,
                adapter: &Arc<dyn TunnelAdapter>,
                config: &TunnelConfiguration,
            ) -> Result<(), EngineError> {
                self.inner.teardown(adapter, config)
            }
        }

        let platform = Arc::new(CapturingPlatform {
            inner: DevPlatform::default(),
            adapter: Mutex::new(None),
        });
        let engine = TunnelEngine::new(
            Arc::new(InMemorySecretStore::default()),
            Arc::clone(&platform) as Arc<dyn PlatformNetwork>,
            std::env::temp_dir(),
        );
        engine.connect(dev_config()).unwrap();
        let adapter = platform.adapter.lock().unwrap().clone().unwrap();

        // Protected packet: encode -> echo transport -> decode -> back
        // out the adapter.
        adapter.inject_inbound(ipv4_packet([100, 127, 0, 9]));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let outbound = adapter.drain_outbound();
            if !outbound.is_empty() {
                assert_eq!(&outbound[0][16..20], &[100, 127, 0, 9]);
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "decrypted packet never came back out the adapter"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        // Unprotected packet is dropped by core policy, never echoed.
        adapter.inject_inbound(ipv4_packet([8, 8, 8, 8]));
        std::thread::sleep(Duration::from_millis(200));
        assert!(adapter.drain_outbound().is_empty());

        let status = engine.status();
        let pump = status.pump.unwrap();
        assert_eq!(pump.queued_for_transport, 1);
        assert_eq!(pump.dropped_unprotected, 1);
        assert_eq!(pump.tunnel_packets_emitted, 1);
        engine.disconnect();
    }
}
