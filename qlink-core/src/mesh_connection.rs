use crate::{
    crypto::{DeviceKeypair, SessionKeys},
    discovery::{CandidateEndpoint, CandidateType},
    dytallix_identity::{
        verify_registry_binding, DytallixIdentityRegistry, MeshTrustPolicy, RegistryDecision,
        RegistryNodeRecord,
    },
    error::{QlinkError, Result},
    ice::{perform_ice_check, IceCheckRequest, IceCredentials},
    inbound_identity::send_inbound_assertion,
    mdns_discovery::{compute_public_key_fingerprint, MdnsPeerObservation},
    peer_acl::PeerAcl,
    peer_store::{InMemoryPeerStore, PeerStore},
    pqc_frame::PqcFrameProtector,
    pqc_session_wire::run_pqc_session_initiator,
    quic_transport::{QuicCertificate, QuicDatagramSession, QuicEndpoint},
    relay::RelayClient,
    rendezvous::RendezvousClient,
    session_crypto::PqcSessionContext,
    traversal::{candidate_socket_addr, HOST_PRIORITY},
};
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, task::JoinSet};

const DEFAULT_DIRECT_PROBE_TIMEOUT: Duration = Duration::from_millis(750);
const DEFAULT_OVERALL_DEADLINE: Duration = Duration::from_secs(3);
/// RFC 8445 §6.1.4 default Ta interval between successive connectivity checks.
/// We deliberately stay close to the spec default so behavior is predictable
/// for operators familiar with ICE.
const DEFAULT_PROBE_PACING: Duration = Duration::from_millis(50);

pub trait IdentityRegistryLookup: Send + Sync {
    fn lookup<'a>(
        &'a self,
        peer_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RegistryNodeRecord>>> + Send + 'a>>;
}

impl IdentityRegistryLookup for DytallixIdentityRegistry {
    fn lookup<'a>(
        &'a self,
        peer_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RegistryNodeRecord>>> + Send + 'a>> {
        Box::pin(async move { DytallixIdentityRegistry::lookup(self, peer_id).await })
    }
}

#[derive(Clone)]
pub struct MeshConnectorConfig {
    pub mesh_id: String,
    pub local_peer_id: String,
    pub direct_probe_timeout: Duration,
    pub overall_deadline: Duration,
    /// Interval between successive paced connectivity checks (RFC 8445 Ta).
    pub probe_pacing: Duration,
    /// When `Some`, paced probes run an ICE binding-request check against the
    /// candidate before attempting the QUIC handshake. The check is signed
    /// with the remote peer's ICE password (from their signed rendezvous
    /// record) and authenticated by the responder. When `None`, probes go
    /// straight to a bare QUIC connect (legacy behavior).
    pub local_ice_credentials: Option<IceCredentials>,
    /// Per-check timeout for the ICE binding request itself; when omitted we
    /// reuse `direct_probe_timeout`.
    pub ice_check_timeout: Option<Duration>,
    pub relay_server: Option<String>,
    /// Peer authorization list. When set, the connector evaluates the
    /// remote peer ID against this ACL *before* any rendezvous lookup or
    /// candidate probe. Denied peers fail with a clear protocol error and
    /// never touch the network. Defaults to no ACL (all peers permitted).
    pub peer_acl: Option<PeerAcl>,
    /// Local device keypair. Required for direct links. The connector sends a signed
    /// `InboundIdentityAssertion` over a fresh uni-stream immediately
    /// after the QUIC handshake completes, then runs the app-layer PQC
    /// session before any direct link is returned.
    pub local_device_keypair: Option<Arc<DeviceKeypair>>,
    /// Registry policy applied after signed peer-record verification and
    /// before any direct or relay probing. Defaults to development-optional
    /// so existing private/dev meshes keep working until callers opt into
    /// public fail-closed policy.
    pub mesh_trust_policy: MeshTrustPolicy,
    /// Optional registry lookup client. Public meshes without a lookup still
    /// fail closed because `verify_registry_binding(None, PublicRequired)`
    /// rejects before dialing.
    pub identity_registry_lookup: Option<Arc<dyn IdentityRegistryLookup>>,
}

impl std::fmt::Debug for MeshConnectorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshConnectorConfig")
            .field("mesh_id", &self.mesh_id)
            .field("local_peer_id", &self.local_peer_id)
            .field("direct_probe_timeout", &self.direct_probe_timeout)
            .field("overall_deadline", &self.overall_deadline)
            .field("probe_pacing", &self.probe_pacing)
            .field("local_ice_credentials", &self.local_ice_credentials)
            .field("ice_check_timeout", &self.ice_check_timeout)
            .field("relay_server", &self.relay_server)
            .field("peer_acl", &self.peer_acl)
            .field("local_device_keypair", &self.local_device_keypair)
            .field("mesh_trust_policy", &self.mesh_trust_policy)
            .field(
                "identity_registry_lookup_configured",
                &self.identity_registry_lookup.is_some(),
            )
            .finish()
    }
}

impl MeshConnectorConfig {
    pub fn new(mesh_id: impl Into<String>, local_peer_id: impl Into<String>) -> Self {
        Self {
            mesh_id: mesh_id.into(),
            local_peer_id: local_peer_id.into(),
            direct_probe_timeout: DEFAULT_DIRECT_PROBE_TIMEOUT,
            overall_deadline: DEFAULT_OVERALL_DEADLINE,
            probe_pacing: DEFAULT_PROBE_PACING,
            local_ice_credentials: None,
            ice_check_timeout: None,
            relay_server: None,
            peer_acl: None,
            local_device_keypair: None,
            mesh_trust_policy: MeshTrustPolicy::DevelopmentOptional,
            identity_registry_lookup: None,
        }
    }

    pub fn with_peer_acl(mut self, acl: PeerAcl) -> Self {
        self.peer_acl = Some(acl);
        self
    }

    pub fn with_local_device_keypair(mut self, keypair: Arc<DeviceKeypair>) -> Self {
        self.local_device_keypair = Some(keypair);
        self
    }

    pub fn with_direct_probe_timeout(mut self, timeout: Duration) -> Self {
        self.direct_probe_timeout = timeout;
        self
    }

    pub fn with_overall_deadline(mut self, deadline: Duration) -> Self {
        self.overall_deadline = deadline;
        self
    }

    pub fn with_probe_pacing(mut self, pacing: Duration) -> Self {
        self.probe_pacing = pacing;
        self
    }

    pub fn with_relay_server(mut self, server: impl Into<String>) -> Self {
        self.relay_server = Some(server.into());
        self
    }

    pub fn with_local_ice_credentials(mut self, credentials: IceCredentials) -> Self {
        self.local_ice_credentials = Some(credentials);
        self
    }

    pub fn with_ice_check_timeout(mut self, timeout: Duration) -> Self {
        self.ice_check_timeout = Some(timeout);
        self
    }

    pub fn with_mesh_trust_policy(mut self, policy: MeshTrustPolicy) -> Self {
        self.mesh_trust_policy = policy;
        self
    }

    pub fn with_identity_registry_lookup(
        mut self,
        lookup: Arc<dyn IdentityRegistryLookup>,
    ) -> Self {
        self.identity_registry_lookup = Some(lookup);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Direct,
    Relay,
}

/// System-level network events that warrant re-validating active paths.
///
/// On macOS these are sourced by the Swift packet-tunnel provider:
/// `PathChanged` from `NWPathMonitor`, `PreSleep`/`PostWake` from
/// `NSWorkspace` notifications, and `ReachabilityChanged` from
/// `NWPathMonitor` reachability transitions. The Rust core stays platform-
/// neutral; the provider feeds events in via FFI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEvent {
    /// Active interface or addressing changed (Wi-Fi ↔ Ethernet ↔ tethering,
    /// or a DHCP renewal that shifted the local IP). Cached candidate
    /// addresses may now point at the wrong NAT mapping.
    PathChanged,
    /// System is about to suspend. Active probing is paused; in-flight
    /// connections are left as-is so they can be re-validated post-wake.
    PreSleep,
    /// System has resumed. Cached paths are suspect because external NAT
    /// mappings may have expired during sleep; re-probe is recommended.
    PostWake,
    /// Reachability transition. `false` indicates the device has gone
    /// offline; `true` indicates it has come back.
    ReachabilityChanged { reachable: bool },
}

/// Result of feeding a `NetworkEvent` into the connector. Lets callers report
/// "we just dropped N cached paths" telemetry and decide whether to schedule
/// an immediate re-probe loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkEventResponse {
    pub cache_entries_invalidated: usize,
    pub reprobe_recommended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    Established,
    TimedOut,
    Failed(String),
    /// ICE binding-request check failed before QUIC was even attempted. The
    /// string carries the underlying error (auth failure, response timeout,
    /// fingerprint mismatch, etc.).
    IceFailed(String),
}

#[derive(Debug, Clone)]
pub struct ProbeAttempt {
    pub candidate_type: CandidateType,
    pub address: SocketAddr,
    pub elapsed: Duration,
    pub outcome: ProbeOutcome,
    /// Time spent in the QUIC connect/TLS handshake phase for this
    /// candidate. `None` when the probe failed before QUIC was attempted.
    pub quic_connect_elapsed: Option<Duration>,
    /// Time spent sending the post-QUIC inbound identity assertion. `None`
    /// when QUIC never established.
    pub identity_assertion_elapsed: Option<Duration>,
    /// When the ICE pre-check succeeded, this is the round-trip time of the
    /// authenticated STUN binding request. `None` when ICE was disabled or
    /// the check did not complete.
    pub ice_round_trip: Option<Duration>,
    /// Peer-reflexive address learned from the ICE response's
    /// XOR-MAPPED-ADDRESS. May differ from the candidate's advertised address
    /// behind NAT (RFC 8445 §7.3.1.4 prflx candidate); the connector caches
    /// the candidate address it actually QUIC-connected to.
    pub peer_reflexive_address: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct ConnectionOutcome {
    pub remote_peer_id: String,
    pub path_kind: PathKind,
    pub remote_addr: Option<SocketAddr>,
    pub attempts: Vec<ProbeAttempt>,
    pub total_elapsed: Duration,
    pub used_cached_path: bool,
    pub registry_decision: RegistryDecision,
    pub peer_record_source: PeerRecordSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRecordSource {
    RendezvousLive,
    PeerStoreCache,
}

impl PeerRecordSource {
    pub fn trust_source_code(self) -> u32 {
        match self {
            Self::RendezvousLive => 1,
            Self::PeerStoreCache => 2,
        }
    }
}

pub struct DirectLink {
    pub remote_addr: SocketAddr,
    session: QuicDatagramSession,
    frame_protector: PqcFrameProtector,
}

pub struct RelayLink {
    pub remote_peer_id: String,
    pub client: RelayClient,
}

pub enum MeshLink {
    Direct(DirectLink),
    Relay(RelayLink),
}

impl std::fmt::Debug for MeshLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeshLink::Direct(link) => f
                .debug_struct("MeshLink::Direct")
                .field("remote_addr", &link.remote_addr)
                .finish(),
            MeshLink::Relay(link) => f
                .debug_struct("MeshLink::Relay")
                .field("remote_peer_id", &link.remote_peer_id)
                .finish(),
        }
    }
}

impl MeshLink {
    pub fn path_kind(&self) -> PathKind {
        match self {
            MeshLink::Direct(_) => PathKind::Direct,
            MeshLink::Relay(_) => PathKind::Relay,
        }
    }

    pub async fn send_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        match self {
            MeshLink::Direct(link) => {
                let protected = link.frame_protector.protect(&frame)?;
                link.session.send_frame(protected).await
            }
            MeshLink::Relay(link) => {
                link.client
                    .send_datagram(&link.remote_peer_id, &frame)
                    .await
            }
        }
    }

    pub async fn receive_frame(&mut self) -> Result<Vec<u8>> {
        match self {
            MeshLink::Direct(link) => {
                let protected = link.session.receive_frame().await?;
                link.frame_protector.open(&protected)
            }
            MeshLink::Relay(link) => match link.client.receive_datagram().await? {
                Some((_source, payload)) => Ok(payload),
                None => Err(QlinkError::Protocol(
                    "relay closed before delivering frame".into(),
                )),
            },
        }
    }

    pub fn close(&self, reason: &[u8]) {
        if let MeshLink::Direct(link) = self {
            link.session.close(reason);
        }
    }
}

#[derive(Debug, Default)]
pub struct LastGoodCache {
    inner: Mutex<HashMap<String, CachedPath>>,
}

#[derive(Debug, Clone, Copy)]
struct CachedPath {
    address: SocketAddr,
    last_used: Instant,
}

impl LastGoodCache {
    pub fn record(&self, peer_id: &str, address: SocketAddr) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(
                peer_id.to_string(),
                CachedPath {
                    address,
                    last_used: Instant::now(),
                },
            );
        }
    }

    pub fn lookup(&self, peer_id: &str) -> Option<SocketAddr> {
        self.inner
            .lock()
            .ok()?
            .get(peer_id)
            .map(|cached| cached.address)
    }

    pub fn invalidate(&self, peer_id: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.remove(peer_id);
        }
    }

    /// Drops every cached entry. Returns the number of entries that were
    /// removed so callers can surface "N paths invalidated" telemetry on
    /// network change / wake events.
    pub fn clear(&self) -> usize {
        match self.inner.lock() {
            Ok(mut guard) => {
                let count = guard.len();
                guard.clear();
                count
            }
            Err(_) => 0,
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|guard| guard.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn last_used(&self, peer_id: &str) -> Option<Instant> {
        self.inner
            .lock()
            .ok()?
            .get(peer_id)
            .map(|cached| cached.last_used)
    }
}

/// In-memory cache of [`MdnsPeerObservation`]s, keyed by remote peer ID.
///
/// Callers (typically a background task draining an `MdnsBrowser`) feed
/// observations via [`Self::record`]. The connector consults the cache
/// during `connect()` to fold in LAN-discovered host candidates that
/// rendezvous-published records may not reflect — e.g., the rendezvous
/// only knows the peer's public srflx address, but mDNS knows the
/// `192.168.x.x` an LAN peer can reach you on directly.
///
/// Entries past `ttl` are stale and silently excluded from lookups. There
/// is no background sweep — the cache is bounded by the natural turnover
/// of mDNS announcements, plus per-call filtering at lookup time.
#[derive(Debug)]
pub struct MdnsObservationCache {
    inner: Mutex<HashMap<String, Vec<TimestampedObservation>>>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct TimestampedObservation {
    observation: MdnsPeerObservation,
    recorded_at: Instant,
}

/// Default freshness window: observations older than 5 minutes are
/// considered stale. Matches typical mDNS announcement re-issue cadence
/// while bounding the window during which a peer that's gone offline
/// keeps "appearing" in connect attempts.
pub const DEFAULT_MDNS_OBSERVATION_TTL: Duration = Duration::from_secs(300);

impl Default for MdnsObservationCache {
    fn default() -> Self {
        Self::with_ttl(DEFAULT_MDNS_OBSERVATION_TTL)
    }
}

impl MdnsObservationCache {
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Records a fresh observation. Multiple observations for the same
    /// peer ID are kept (peers can announce on multiple interfaces); the
    /// connector deduplicates by address when folding into candidates.
    pub fn record(&self, observation: MdnsPeerObservation) {
        if let Ok(mut guard) = self.inner.lock() {
            let entries = guard
                .entry(observation.announcement.peer_id.clone())
                .or_default();
            // Drop any existing observation that announces the same set of
            // addresses; replace with the fresh one. This keeps the cache
            // from accumulating duplicates as the same peer re-announces.
            entries.retain(|existing| existing.observation.addresses != observation.addresses);
            entries.push(TimestampedObservation {
                observation,
                recorded_at: Instant::now(),
            });
        }
    }

    /// Returns observations for `peer_id` that are still within the TTL
    /// window. Stale entries are pruned in-place during the call so they
    /// don't accumulate.
    pub fn observations_for(&self, peer_id: &str) -> Vec<MdnsPeerObservation> {
        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };
        let Some(entries) = guard.get_mut(peer_id) else {
            return Vec::new();
        };
        // On freshly booted runners some platforms cannot represent
        // `now - ttl`; in that case every in-process observation is fresh.
        if let Some(cutoff) = Instant::now().checked_sub(self.ttl) {
            entries.retain(|entry| entry.recorded_at >= cutoff);
        }
        if entries.is_empty() {
            guard.remove(peer_id);
            return Vec::new();
        }
        entries
            .iter()
            .map(|entry| entry.observation.clone())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn clear(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.clear();
        }
    }
}

pub struct MeshConnector {
    config: MeshConnectorConfig,
    rendezvous: RendezvousClient,
    quic: QuicEndpoint,
    cache: LastGoodCache,
    mdns_cache: MdnsObservationCache,
    /// Persistent + in-memory cache of signed peer records. Defaults to
    /// in-memory; set via `with_peer_store` to use a file-backed store
    /// that survives process restarts. The connector consults the
    /// store as a fallback when rendezvous is unreachable, and writes
    /// through to it on every successful rendezvous lookup.
    peer_store: Arc<dyn PeerStore>,
}

impl MeshConnector {
    pub fn new(
        config: MeshConnectorConfig,
        rendezvous: RendezvousClient,
        quic: QuicEndpoint,
    ) -> Self {
        Self {
            config,
            rendezvous,
            quic,
            cache: LastGoodCache::default(),
            mdns_cache: MdnsObservationCache::default(),
            peer_store: Arc::new(InMemoryPeerStore::new()),
        }
    }

    /// Replaces the connector's peer record store. Use this to swap in
    /// a `FilePeerStore` (or any other `PeerStore` impl) for cross-
    /// restart persistence.
    pub fn with_peer_store(mut self, peer_store: Arc<dyn PeerStore>) -> Self {
        self.peer_store = peer_store;
        self
    }

    pub fn peer_store(&self) -> &Arc<dyn PeerStore> {
        &self.peer_store
    }

    pub fn config(&self) -> &MeshConnectorConfig {
        &self.config
    }

    pub fn cache(&self) -> &LastGoodCache {
        &self.cache
    }

    pub fn mdns_cache(&self) -> &MdnsObservationCache {
        &self.mdns_cache
    }

    /// Feeds an mDNS observation into the connector's local cache. The
    /// observation will be considered during the next call to `connect()`
    /// for the matching peer ID, provided it cross-checks the public-key
    /// fingerprint published in the rendezvous record.
    ///
    /// Caller is typically a background task draining an `MdnsBrowser`.
    /// Connector owns no mDNS state itself — it just consumes observations
    /// the caller hands in. This keeps the mDNS daemon lifecycle
    /// (entirely platform-dependent) outside the protocol library.
    pub fn record_mdns_observation(&self, observation: MdnsPeerObservation) {
        self.mdns_cache.record(observation);
    }

    /// Re-validates a single peer by dropping its cached path and re-running
    /// the full discovery → paced-probe → relay-fallback flow. Use this in
    /// response to per-peer health signals; for system-wide events (path
    /// change, wake) prefer `handle_network_event` which clears the entire
    /// cache up front.
    pub async fn reconnect(&self, remote_peer_id: &str) -> Result<(MeshLink, ConnectionOutcome)> {
        self.cache.invalidate(remote_peer_id);
        self.connect(remote_peer_id).await
    }

    /// Feeds a system-level network event into the connector. The connector
    /// adjusts its cache and tells the caller whether an immediate re-probe
    /// is recommended. The caller is expected to call `reconnect()` per peer
    /// (or `connect()` if peer state is fresh) when `reprobe_recommended` is
    /// true.
    ///
    /// The split between "the connector tracks cache lifetime" and "the
    /// caller drives the event loop" is deliberate: tunnel providers already
    /// own the active-peer set and the OS-level notifications, so the Rust
    /// core stays a pure protocol library.
    pub fn handle_network_event(&self, event: NetworkEvent) -> NetworkEventResponse {
        match event {
            NetworkEvent::PathChanged | NetworkEvent::PostWake => {
                let invalidated = self.cache.clear();
                NetworkEventResponse {
                    cache_entries_invalidated: invalidated,
                    reprobe_recommended: true,
                }
            }
            NetworkEvent::PreSleep => NetworkEventResponse {
                cache_entries_invalidated: 0,
                reprobe_recommended: false,
            },
            NetworkEvent::ReachabilityChanged { reachable } => {
                if reachable {
                    NetworkEventResponse {
                        cache_entries_invalidated: 0,
                        reprobe_recommended: true,
                    }
                } else {
                    // Going offline: keep cached entries; they may still be
                    // valid when reachability returns. Pause probing.
                    NetworkEventResponse {
                        cache_entries_invalidated: 0,
                        reprobe_recommended: false,
                    }
                }
            }
        }
    }

    pub async fn connect(&self, remote_peer_id: &str) -> Result<(MeshLink, ConnectionOutcome)> {
        let started = Instant::now();

        // ACL check happens before *anything* hits the network: a denied
        // peer doesn't reveal its presence to the rendezvous server and
        // never triggers STUN/QUIC traffic.
        if let Some(acl) = self.config.peer_acl.as_ref() {
            let decision = acl.evaluate(remote_peer_id);
            if !decision.is_allowed() {
                return Err(QlinkError::Protocol(format!(
                    "peer {remote_peer_id} rejected by ACL: {}",
                    decision.reason()
                )));
            }
        }

        // Rendezvous is the source of truth for freshness, so try it
        // first. If it succeeds, we write through to the local store
        // on the way out so a future rendezvous outage can fall back
        // to the cached record.
        //
        // If rendezvous fails (timeout, server down, transient
        // network) and we have a cached record for this peer, we use
        // it. The signature is re-verified below — a cache hit isn't
        // a trust shortcut, just a fallback source. Cached records are
        // still fully re-verified before use, including expiry, and an
        // expired cached record is rejected by `record.verify(...)`.
        let (record, peer_record_source) = match self
            .rendezvous
            .lookup(&self.config.mesh_id, remote_peer_id)
            .await
        {
            Ok(Some(fresh)) => {
                // Pre-verify before writing through so we never cache
                // a record we wouldn't trust. Verification runs again
                // below for the use-time check; the cost is negligible
                // and the duplication is intentional (cache invariant
                // vs. use invariant).
                if fresh.verify(&self.config.mesh_id).is_ok() {
                    self.peer_store.store(&self.config.mesh_id, &fresh);
                }
                (fresh, PeerRecordSource::RendezvousLive)
            }
            Ok(None) => {
                // Rendezvous is healthy but doesn't know this peer.
                // The cache might still have a record from a previous
                // session — accept it as a fallback.
                match self.peer_store.load(&self.config.mesh_id, remote_peer_id) {
                    Some(cached) => {
                        tracing::debug!(
                            peer_id = %remote_peer_id,
                            "peer not found in rendezvous; using cached record"
                        );
                        (cached, PeerRecordSource::PeerStoreCache)
                    }
                    None => {
                        return Err(QlinkError::Protocol(format!(
                            "peer {remote_peer_id} not found in rendezvous {}",
                            self.config.mesh_id
                        )));
                    }
                }
            }
            Err(rendezvous_error) => {
                // Network / server failure. The cache is exactly the
                // safety net the spec wants here.
                match self.peer_store.load(&self.config.mesh_id, remote_peer_id) {
                    Some(cached) => {
                        tracing::warn!(
                            peer_id = %remote_peer_id,
                            error = %rendezvous_error,
                            "rendezvous lookup failed; falling back to cached record"
                        );
                        (cached, PeerRecordSource::PeerStoreCache)
                    }
                    None => return Err(rendezvous_error),
                }
            }
        };
        record.verify(&self.config.mesh_id)?;
        let registry_record = match self.config.identity_registry_lookup.as_ref() {
            Some(registry) => match registry.lookup(remote_peer_id).await {
                Ok(record) => record,
                Err(error) => match self.config.mesh_trust_policy {
                    MeshTrustPolicy::PublicRequired => {
                        return Err(QlinkError::Protocol(format!(
                            "identity registry lookup failed: {error}"
                        )));
                    }
                    MeshTrustPolicy::PrivatePreferred | MeshTrustPolicy::DevelopmentOptional => {
                        tracing::warn!(
                            peer_id = %remote_peer_id,
                            error = %error,
                            policy = ?self.config.mesh_trust_policy,
                            "identity registry lookup failed; continuing without registry verification"
                        );
                        None
                    }
                },
            },
            None => None,
        };
        let registry_decision = verify_registry_binding(
            &record,
            registry_record.as_ref(),
            self.config.mesh_trust_policy,
        )?;

        let remote_ice_credentials = record.body.ice_credentials.clone();
        // The signed record carries the remote's QUIC server cert. We trust
        // it for the lifetime of this connect attempt; the ML-DSA signature
        // on the record ensures only the legitimate device key holder can
        // mint it. Empty bytes mean the peer hasn't published a cert yet —
        // direct QUIC connect is impossible and we'll fall back to relay.
        let remote_cert: Option<QuicCertificate> = if record.body.device_certificate_der.is_empty()
        {
            None
        } else {
            Some(QuicCertificate::from_der(
                record.body.device_certificate_der.clone(),
            ))
        };

        // Fold in any LAN-side candidates we've observed via mDNS, but only
        // when the announcement's truncated fingerprint matches the
        // public key from the (signed) rendezvous record. The cross-check
        // protects against an attacker on the LAN announcing themselves
        // under a legitimate peer ID — they can't forge the fingerprint
        // without also forging the rendezvous-published public key, which
        // requires the device private key.
        let mut all_endpoints: Vec<CandidateEndpoint> = record.body.endpoints.clone();
        let expected_fingerprint = compute_public_key_fingerprint(&record.body.device_public_key);
        for observation in self.mdns_cache.observations_for(remote_peer_id) {
            if observation.announcement.public_key_fingerprint != expected_fingerprint {
                tracing::debug!(
                    peer_id = %remote_peer_id,
                    "discarding mDNS observation: fingerprint mismatch"
                );
                continue;
            }
            for address in &observation.addresses {
                let already_listed = all_endpoints.iter().any(|existing| {
                    existing.port == address.port() && existing.address == address.ip().to_string()
                });
                if already_listed {
                    continue;
                }
                all_endpoints.push(CandidateEndpoint {
                    candidate_type: CandidateType::Host,
                    address: address.ip().to_string(),
                    port: address.port(),
                    priority: HOST_PRIORITY,
                });
            }
        }

        let cached_addr = self.cache.lookup(remote_peer_id);
        let direct_candidates = order_direct_candidates(&all_endpoints, cached_addr);
        let used_cached_path = cached_addr.is_some();
        let had_direct_candidates = !direct_candidates.is_empty();

        let probe_outcome = self
            .race_direct_probes(
                &direct_candidates,
                started,
                remote_ice_credentials,
                remote_cert,
                remote_peer_id,
            )
            .await;

        match probe_outcome {
            DirectProbeResult::Established {
                address,
                session,
                session_keys,
                attempts,
            } => {
                self.cache.record(remote_peer_id, address);
                let outcome = ConnectionOutcome {
                    remote_peer_id: remote_peer_id.to_string(),
                    path_kind: PathKind::Direct,
                    remote_addr: Some(address),
                    attempts,
                    total_elapsed: started.elapsed(),
                    used_cached_path,
                    registry_decision,
                    peer_record_source,
                };
                let link = MeshLink::Direct(DirectLink {
                    remote_addr: address,
                    session,
                    frame_protector: PqcFrameProtector::new(session_keys),
                });
                Ok((link, outcome))
            }
            DirectProbeResult::Exhausted { attempts } => {
                if had_direct_candidates {
                    self.cache.invalidate(remote_peer_id);
                }

                let detail = latest_probe_failure_summary(&attempts)
                    .map(|summary| format!("; last direct failure: {summary}"))
                    .unwrap_or_default();
                let Some(server) = self.config.relay_server.as_ref() else {
                    return Err(QlinkError::Protocol(format!(
                        "no direct candidate for peer {remote_peer_id} succeeded{detail} and no relay server is configured"
                    )));
                };

                Err(QlinkError::Protocol(format!(
                    "relay PQC session is required for peer {remote_peer_id}; \
                     raw relay fallback via {server} is disabled{detail}"
                )))
            }
        }
    }

    /// Runs paced parallel connectivity checks across the provided candidate
    /// list. Each check is offset from the prior by `config.probe_pacing`
    /// (RFC 8445 Ta default 50ms). The first check that produces an
    /// established QUIC session wins; the rest are aborted.
    ///
    /// This is *ICE-style* probing rather than RFC-conformant ICE: the
    /// connectivity check is a QUIC connect attempt, not a STUN binding
    /// request with USERNAME/MESSAGE-INTEGRITY. It still proves bidirectional
    /// UDP reachability — sufficient for v1 — and matches Quinn's data-plane
    /// flow so a successful probe directly yields the live session.
    async fn race_direct_probes(
        &self,
        candidates: &[CandidateEndpoint],
        started: Instant,
        remote_ice_credentials: IceCredentials,
        remote_cert: Option<QuicCertificate>,
        remote_peer_id: &str,
    ) -> DirectProbeResult {
        if candidates.is_empty() {
            return DirectProbeResult::Exhausted { attempts: vec![] };
        }
        // No cert published → direct QUIC is unauthenticated and disallowed.
        // Skip direct probing entirely so the caller falls back to relay.
        let Some(remote_cert) = remote_cert else {
            return DirectProbeResult::Exhausted { attempts: vec![] };
        };
        let Some(local_keypair) = self.config.local_device_keypair.clone() else {
            return DirectProbeResult::Exhausted {
                attempts: direct_keypair_required_attempts(candidates),
            };
        };

        let mut join_set: JoinSet<ProbeOutcomeRecord> = JoinSet::new();

        for (index, candidate) in candidates.iter().enumerate() {
            let address = match candidate_socket_addr(candidate) {
                Ok(addr) => addr,
                Err(error) => {
                    let candidate_type = candidate.candidate_type.clone();
                    join_set.spawn(async move {
                        ProbeOutcomeRecord::from_parts(
                            candidate_type,
                            None,
                            false,
                            Duration::ZERO,
                            ProbeOutcome::Failed(error.to_string()),
                        )
                    });
                    continue;
                }
            };

            let pacing_offset = self.config.probe_pacing.saturating_mul(index as u32);
            let probe_timeout = self.config.direct_probe_timeout;
            let overall_deadline = self.config.overall_deadline;
            let candidate_type = candidate.candidate_type.clone();
            let quic = self.quic.clone();
            let local_ice = self.config.local_ice_credentials.clone();
            let remote_ice = remote_ice_credentials.clone();
            let candidate_priority = candidate.priority;
            let ice_check_timeout = self
                .config
                .ice_check_timeout
                .unwrap_or(self.config.direct_probe_timeout);
            let cert = remote_cert.clone();
            let local_keypair = local_keypair.clone();
            let local_peer_id_for_task = self.config.local_peer_id.clone();
            let remote_peer_id_for_task = remote_peer_id.to_string();
            let carrier_binding = cert.as_der().to_vec();
            let mesh_id_for_task = self.config.mesh_id.clone();

            join_set.spawn(async move {
                tokio::time::sleep(pacing_offset).await;
                if started.elapsed() >= overall_deadline {
                    return ProbeOutcomeRecord::from_parts(
                        candidate_type,
                        Some(address),
                        false,
                        Duration::ZERO,
                        ProbeOutcome::TimedOut,
                    );
                }

                let probe_started = Instant::now();
                if remaining_probe_budget(
                    Instant::now(),
                    started,
                    probe_started,
                    probe_timeout,
                    overall_deadline,
                )
                .is_zero()
                {
                    return ProbeOutcomeRecord::from_parts(
                        candidate_type,
                        Some(address),
                        false,
                        Duration::ZERO,
                        ProbeOutcome::TimedOut,
                    );
                }

                // RFC 8445 connectivity check: if we have ICE credentials,
                // run an authenticated STUN binding request before opening
                // QUIC. Failure short-circuits the probe so a misbehaving or
                // unauthenticated peer never gets a QUIC handshake.
                let mut ice_round_trip: Option<Duration> = None;
                let mut peer_reflexive_address: Option<SocketAddr> = None;

                if let Some(local_ice) = local_ice.as_ref() {
                    let bind_addr = match address.ip() {
                        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                        IpAddr::V6(_) => {
                            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
                        }
                    };
                    let socket = match UdpSocket::bind(bind_addr).await {
                        Ok(socket) => socket,
                        Err(error) => {
                            return ProbeOutcomeRecord::from_parts(
                                candidate_type,
                                Some(address),
                                true,
                                probe_started.elapsed(),
                                ProbeOutcome::IceFailed(format!(
                                    "could not bind ICE socket: {error}"
                                )),
                            );
                        }
                    };

                    let request = IceCheckRequest {
                        remote_credentials: remote_ice.clone(),
                        local_ufrag: local_ice.ufrag.clone(),
                        local_priority: candidate_priority,
                        // Tiebreaker per RFC 8445 §6.1.1; a random u64 is fine
                        // because we always take the controlling role here.
                        controlling_tiebreaker: rand_u64(),
                        use_candidate: true,
                    };

                    let remaining = remaining_probe_budget(
                        Instant::now(),
                        started,
                        probe_started,
                        probe_timeout,
                        overall_deadline,
                    );
                    let bounded_ice_timeout = ice_check_timeout.min(remaining);
                    if bounded_ice_timeout.is_zero() {
                        return ProbeOutcomeRecord {
                            candidate_type,
                            address: Some(address),
                            launched: true,
                            elapsed: probe_started.elapsed(),
                            outcome: ProbeOutcome::TimedOut,
                            quic_connect_elapsed: None,
                            identity_assertion_elapsed: None,
                            ice_round_trip: None,
                            peer_reflexive_address: None,
                            session: None,
                            session_keys: None,
                        };
                    }

                    match perform_ice_check(&socket, address, request, bounded_ice_timeout).await {
                        Ok(result) => {
                            ice_round_trip = Some(result.round_trip);
                            peer_reflexive_address = result.mapped_address;
                        }
                        Err(error) => {
                            return ProbeOutcomeRecord {
                                candidate_type,
                                address: Some(address),
                                launched: true,
                                elapsed: probe_started.elapsed(),
                                outcome: ProbeOutcome::IceFailed(error.to_string()),
                                quic_connect_elapsed: None,
                                identity_assertion_elapsed: None,
                                ice_round_trip: None,
                                peer_reflexive_address: None,
                                session: None,
                                session_keys: None,
                            };
                        }
                    }
                }

                // Either ICE passed or it was disabled; now run the QUIC
                // handshake to establish the data path.
                let remaining_quic_timeout = remaining_probe_budget(
                    Instant::now(),
                    started,
                    probe_started,
                    probe_timeout,
                    overall_deadline,
                );
                if remaining_quic_timeout.is_zero() {
                    return ProbeOutcomeRecord {
                        candidate_type,
                        address: Some(address),
                        launched: true,
                        elapsed: probe_started.elapsed(),
                        outcome: ProbeOutcome::TimedOut,
                        quic_connect_elapsed: None,
                        identity_assertion_elapsed: None,
                        ice_round_trip,
                        peer_reflexive_address,
                        session: None,
                        session_keys: None,
                    };
                }

                let quic_started = Instant::now();
                let quic_result = tokio::time::timeout(
                    remaining_quic_timeout,
                    quic.connect_with_trusted_cert(address, &cert),
                )
                .await;
                let quic_connect_elapsed = quic_started.elapsed();

                match quic_result {
                    Ok(Ok(session)) => {
                        // QUIC handshake done. Send our inbound identity
                        // assertion, then complete the authenticated PQC
                        // session before the link can be considered direct.
                        let assertion_started = Instant::now();
                        let assertion_remaining = remaining_probe_budget(
                            Instant::now(),
                            started,
                            probe_started,
                            probe_timeout,
                            overall_deadline,
                        );
                        if assertion_remaining.is_zero() {
                            session.close(b"assertion send timed out");
                            return ProbeOutcomeRecord {
                                candidate_type,
                                address: Some(address),
                                launched: true,
                                elapsed: probe_started.elapsed(),
                                outcome: ProbeOutcome::TimedOut,
                                quic_connect_elapsed: Some(quic_connect_elapsed),
                                identity_assertion_elapsed: Some(assertion_started.elapsed()),
                                ice_round_trip,
                                peer_reflexive_address,
                                session: None,
                                session_keys: None,
                            };
                        }
                        let assertion_result = tokio::time::timeout(
                            assertion_remaining,
                            send_inbound_assertion(
                                &session,
                                local_keypair.as_ref(),
                                &mesh_id_for_task,
                            ),
                        )
                        .await;
                        match assertion_result {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                session.close(b"assertion send failed");
                                return ProbeOutcomeRecord {
                                    candidate_type,
                                    address: Some(address),
                                    launched: true,
                                    elapsed: probe_started.elapsed(),
                                    outcome: ProbeOutcome::Failed(format!(
                                        "inbound assertion send failed: {error}"
                                    )),
                                    quic_connect_elapsed: Some(quic_connect_elapsed),
                                    identity_assertion_elapsed: Some(assertion_started.elapsed()),
                                    ice_round_trip,
                                    peer_reflexive_address,
                                    session: None,
                                    session_keys: None,
                                };
                            }
                            Err(_) => {
                                session.close(b"assertion send timed out");
                                return ProbeOutcomeRecord {
                                    candidate_type,
                                    address: Some(address),
                                    launched: true,
                                    elapsed: probe_started.elapsed(),
                                    outcome: ProbeOutcome::TimedOut,
                                    quic_connect_elapsed: Some(quic_connect_elapsed),
                                    identity_assertion_elapsed: Some(assertion_started.elapsed()),
                                    ice_round_trip,
                                    peer_reflexive_address,
                                    session: None,
                                    session_keys: None,
                                };
                            }
                        }
                        let identity_assertion_elapsed = Some(assertion_started.elapsed());

                        let pqc_remaining = remaining_probe_budget(
                            Instant::now(),
                            started,
                            probe_started,
                            probe_timeout,
                            overall_deadline,
                        );
                        if pqc_remaining.is_zero() {
                            session.close(b"pqc session timed out");
                            return ProbeOutcomeRecord {
                                candidate_type,
                                address: Some(address),
                                launched: true,
                                elapsed: probe_started.elapsed(),
                                outcome: ProbeOutcome::TimedOut,
                                quic_connect_elapsed: Some(quic_connect_elapsed),
                                identity_assertion_elapsed,
                                ice_round_trip,
                                peer_reflexive_address,
                                session: None,
                                session_keys: None,
                            };
                        }

                        let pqc_context = PqcSessionContext::new(
                            mesh_id_for_task,
                            local_peer_id_for_task,
                            remote_peer_id_for_task,
                            carrier_binding,
                        );
                        let pqc_result = tokio::time::timeout(
                            pqc_remaining,
                            run_pqc_session_initiator(
                                &session,
                                pqc_context,
                                local_keypair.as_ref(),
                            ),
                        )
                        .await;
                        let session_keys = match pqc_result {
                            Ok(Ok(session_keys)) => session_keys,
                            Ok(Err(error)) => {
                                session.close(b"pqc session failed");
                                return ProbeOutcomeRecord {
                                    candidate_type,
                                    address: Some(address),
                                    launched: true,
                                    elapsed: probe_started.elapsed(),
                                    outcome: ProbeOutcome::Failed(format!(
                                        "PQC session failed: {error}"
                                    )),
                                    quic_connect_elapsed: Some(quic_connect_elapsed),
                                    identity_assertion_elapsed,
                                    ice_round_trip,
                                    peer_reflexive_address,
                                    session: None,
                                    session_keys: None,
                                };
                            }
                            Err(_) => {
                                session.close(b"pqc session timed out");
                                return ProbeOutcomeRecord {
                                    candidate_type,
                                    address: Some(address),
                                    launched: true,
                                    elapsed: probe_started.elapsed(),
                                    outcome: ProbeOutcome::TimedOut,
                                    quic_connect_elapsed: Some(quic_connect_elapsed),
                                    identity_assertion_elapsed,
                                    ice_round_trip,
                                    peer_reflexive_address,
                                    session: None,
                                    session_keys: None,
                                };
                            }
                        };

                        ProbeOutcomeRecord {
                            candidate_type,
                            address: Some(address),
                            launched: true,
                            elapsed: probe_started.elapsed(),
                            outcome: ProbeOutcome::Established,
                            quic_connect_elapsed: Some(quic_connect_elapsed),
                            identity_assertion_elapsed,
                            ice_round_trip,
                            peer_reflexive_address,
                            session: Some(session),
                            session_keys: Some(session_keys),
                        }
                    }
                    Ok(Err(error)) => ProbeOutcomeRecord {
                        candidate_type,
                        address: Some(address),
                        launched: true,
                        elapsed: probe_started.elapsed(),
                        outcome: ProbeOutcome::Failed(error.to_string()),
                        quic_connect_elapsed: Some(quic_connect_elapsed),
                        identity_assertion_elapsed: None,
                        ice_round_trip,
                        peer_reflexive_address,
                        session: None,
                        session_keys: None,
                    },
                    Err(_) => ProbeOutcomeRecord {
                        candidate_type,
                        address: Some(address),
                        launched: true,
                        elapsed: probe_started.elapsed(),
                        outcome: ProbeOutcome::TimedOut,
                        quic_connect_elapsed: Some(quic_connect_elapsed),
                        identity_assertion_elapsed: None,
                        ice_round_trip,
                        peer_reflexive_address,
                        session: None,
                        session_keys: None,
                    },
                }
            });
        }

        let mut attempts: Vec<ProbeAttempt> = Vec::new();
        let overall_remaining = self
            .config
            .overall_deadline
            .checked_sub(started.elapsed())
            .unwrap_or(Duration::ZERO);
        let race_deadline = tokio::time::Instant::now() + overall_remaining;

        loop {
            let next = tokio::select! {
                joined = join_set.join_next() => joined,
                _ = tokio::time::sleep_until(race_deadline) => {
                    join_set.shutdown().await;
                    break;
                }
            };

            let Some(joined) = next else {
                break;
            };

            let record = match joined {
                Ok(record) => record,
                Err(_) => continue,
            };

            if record.launched {
                if let Some(addr) = record.address {
                    attempts.push(ProbeAttempt {
                        candidate_type: record.candidate_type.clone(),
                        address: addr,
                        elapsed: record.elapsed,
                        outcome: record.outcome.clone(),
                        quic_connect_elapsed: record.quic_connect_elapsed,
                        identity_assertion_elapsed: record.identity_assertion_elapsed,
                        ice_round_trip: record.ice_round_trip,
                        peer_reflexive_address: record.peer_reflexive_address,
                    });
                }
            }

            if let (ProbeOutcome::Established, Some(session), Some(session_keys), Some(addr)) = (
                &record.outcome,
                record.session,
                record.session_keys,
                record.address,
            ) {
                join_set.shutdown().await;
                return DirectProbeResult::Established {
                    address: addr,
                    session,
                    session_keys,
                    attempts,
                };
            }
        }

        DirectProbeResult::Exhausted { attempts }
    }
}

enum DirectProbeResult {
    Established {
        address: SocketAddr,
        session: QuicDatagramSession,
        session_keys: SessionKeys,
        attempts: Vec<ProbeAttempt>,
    },
    Exhausted {
        attempts: Vec<ProbeAttempt>,
    },
}

struct ProbeOutcomeRecord {
    candidate_type: CandidateType,
    address: Option<SocketAddr>,
    launched: bool,
    elapsed: Duration,
    outcome: ProbeOutcome,
    quic_connect_elapsed: Option<Duration>,
    identity_assertion_elapsed: Option<Duration>,
    ice_round_trip: Option<Duration>,
    peer_reflexive_address: Option<SocketAddr>,
    session: Option<QuicDatagramSession>,
    session_keys: Option<SessionKeys>,
}

impl ProbeOutcomeRecord {
    fn from_parts(
        candidate_type: CandidateType,
        address: Option<SocketAddr>,
        launched: bool,
        elapsed: Duration,
        outcome: ProbeOutcome,
    ) -> Self {
        Self {
            candidate_type,
            address,
            launched,
            elapsed,
            outcome,
            quic_connect_elapsed: None,
            identity_assertion_elapsed: None,
            ice_round_trip: None,
            peer_reflexive_address: None,
            session: None,
            session_keys: None,
        }
    }
}

fn rand_u64() -> u64 {
    let mut bytes = [0_u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        // Fall back to a constant; the value is just an ICE tiebreaker, not
        // security-critical, but the entropy source failing is unusual.
        return 0xdead_beef_d00d_feed;
    }
    u64::from_be_bytes(bytes)
}

fn order_direct_candidates(
    endpoints: &[CandidateEndpoint],
    cached_addr: Option<SocketAddr>,
) -> Vec<CandidateEndpoint> {
    let mut direct: Vec<CandidateEndpoint> = endpoints
        .iter()
        .filter(|candidate| {
            matches!(
                candidate.candidate_type,
                CandidateType::Host | CandidateType::ServerReflexive
            )
        })
        .cloned()
        .collect();

    direct.sort_by(|a, b| b.priority.cmp(&a.priority));

    if let Some(target) = cached_addr {
        if let Some(position) = direct
            .iter()
            .position(|candidate| candidate_matches_addr(candidate, target))
        {
            let cached = direct.remove(position);
            direct.insert(0, cached);
        }
    }

    direct
}

fn direct_keypair_required_attempts(candidates: &[CandidateEndpoint]) -> Vec<ProbeAttempt> {
    candidates
        .iter()
        .filter_map(|candidate| {
            let address = candidate_socket_addr(candidate).ok()?;
            Some(ProbeAttempt {
                candidate_type: candidate.candidate_type.clone(),
                address,
                elapsed: Duration::ZERO,
                outcome: ProbeOutcome::Failed(
                    "direct PQC session requires local_device_keypair".to_string(),
                ),
                quic_connect_elapsed: None,
                identity_assertion_elapsed: None,
                ice_round_trip: None,
                peer_reflexive_address: None,
            })
        })
        .collect()
}

fn remaining_probe_budget(
    now: Instant,
    connect_started: Instant,
    probe_started: Instant,
    direct_probe_timeout: Duration,
    overall_deadline: Duration,
) -> Duration {
    let candidate_elapsed = now.duration_since(probe_started);
    let overall_elapsed = now.duration_since(connect_started);
    let candidate_remaining = direct_probe_timeout
        .checked_sub(candidate_elapsed)
        .unwrap_or(Duration::ZERO);
    let overall_remaining = overall_deadline
        .checked_sub(overall_elapsed)
        .unwrap_or(Duration::ZERO);
    candidate_remaining.min(overall_remaining)
}

fn latest_probe_failure_summary(attempts: &[ProbeAttempt]) -> Option<String> {
    attempts
        .iter()
        .rev()
        .map(|attempt| match &attempt.outcome {
            ProbeOutcome::Failed(reason) => reason.clone(),
            ProbeOutcome::IceFailed(reason) => reason.clone(),
            ProbeOutcome::TimedOut => "timed out".to_string(),
            ProbeOutcome::Established => "established".to_string(),
        })
        .next()
}

fn candidate_matches_addr(candidate: &CandidateEndpoint, addr: SocketAddr) -> bool {
    candidate
        .address
        .parse::<IpAddr>()
        .map(|ip| ip == addr.ip())
        .unwrap_or(false)
        && candidate.port == addr.port()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::DeviceKeypair,
        discovery::{PeerRecord, UnsignedPeerRecord},
        dytallix_identity::{MeshTrustPolicy, RegistryNodeRecord, RegistryNodeStatus},
        inbound_identity::{
            receive_and_evaluate_inbound, InboundDecision,
            DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS,
        },
        pqc_session_wire::run_pqc_session_responder,
        quic_transport::QuicEndpoint,
        relay::spawn_dev_relay,
        rendezvous::spawn_dev_rendezvous,
        session_crypto::PqcSessionContext,
    };
    use std::future::Future;
    use std::net::Ipv4Addr;
    use std::pin::Pin;

    const MESH_ID: &str = "devmesh";

    fn spawn_pqc_drain_accept_loop(
        server_endpoint: QuicEndpoint,
        responder_keypair: Arc<DeviceKeypair>,
        server_cert_der: Vec<u8>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                match server_endpoint.accept_one().await {
                    Ok(session) => {
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
                            if run_pqc_session_responder(
                                &session,
                                context,
                                responder_keypair.as_ref(),
                            )
                            .await
                            .is_err()
                            {
                                session.close(b"");
                                return;
                            }
                            let _ = session.receive_frame().await;
                        });
                    }
                    Err(_) => break,
                }
            }
        })
    }

    #[tokio::test]
    async fn direct_path_succeeds_and_caches_address() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_peer_id = remote_key.public_key().peer_id();
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_cert_der = server_cert.as_der().to_vec();
        let client_endpoint = QuicEndpoint::client(bind, &[server_cert]).unwrap();
        let _accept_loop = spawn_pqc_drain_accept_loop(
            server_endpoint,
            remote_key.clone(),
            server_cert_der.clone(),
        );

        let remote_record = signed_record_with_cert(
            remote_key.as_ref(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: server_addr.ip().to_string(),
                port: server_addr.port(),
                priority: 120,
            }],
            1,
            server_cert_der,
        );
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_direct_probe_timeout(Duration::from_millis(500))
                .with_overall_deadline(Duration::from_secs(2))
                .with_local_device_keypair(local_key.clone()),
            rendezvous_client,
            client_endpoint,
        );

        let (link, outcome) = connector.connect(&remote_peer_id).await.unwrap();
        assert_eq!(link.path_kind(), PathKind::Direct);
        assert_eq!(outcome.path_kind, PathKind::Direct);
        assert_eq!(outcome.remote_addr, Some(server_addr));
        assert_eq!(outcome.attempts.len(), 1);
        assert_eq!(outcome.attempts[0].outcome, ProbeOutcome::Established);
        assert!(outcome.attempts[0].quic_connect_elapsed.is_some());
        assert!(outcome.attempts[0].identity_assertion_elapsed.is_some());
        assert!(!outcome.used_cached_path);

        assert_eq!(connector.cache().lookup(&remote_peer_id), Some(server_addr));
    }

    #[tokio::test]
    async fn direct_probe_caps_identity_and_pqc_with_candidate_timeout() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_peer_id = remote_key.public_key().peer_id();
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_cert_der = server_cert.as_der().to_vec();
        let client_endpoint = QuicEndpoint::client(bind, &[server_cert]).unwrap();
        let _stalled_server = tokio::spawn(async move {
            let Ok(_session) = server_endpoint.accept_one().await else {
                return;
            };
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let remote_record = signed_record_with_cert(
            remote_key.as_ref(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: server_addr.ip().to_string(),
                port: server_addr.port(),
                priority: 120,
            }],
            1,
            server_cert_der,
        );
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let direct_timeout = Duration::from_millis(100);
        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_direct_probe_timeout(direct_timeout)
                .with_overall_deadline(Duration::from_millis(900))
                .with_local_device_keypair(local_key),
            rendezvous_client,
            client_endpoint,
        );

        let started = Instant::now();
        let err = connector.connect(&remote_peer_id).await.unwrap_err();
        let elapsed = started.elapsed();

        assert!(
            err.to_string().contains("no direct candidate"),
            "expected direct probing to fail, got {err}"
        );
        assert!(
            elapsed < Duration::from_millis(400),
            "identity/PQC must consume the same direct probe timeout; elapsed={elapsed:?}, direct_timeout={direct_timeout:?}"
        );
    }

    #[test]
    fn remaining_probe_budget_is_bounded_by_candidate_deadline() {
        let now = Instant::now();
        let connect_started = now
            .checked_sub(Duration::from_millis(100))
            .expect("test instant subtraction");
        let probe_started = now
            .checked_sub(Duration::from_millis(80))
            .expect("test instant subtraction");

        let remaining = remaining_probe_budget(
            now,
            connect_started,
            probe_started,
            Duration::from_millis(100),
            Duration::from_millis(900),
        );

        assert_eq!(remaining, Duration::from_millis(20));
    }

    #[tokio::test]
    async fn direct_failure_rejects_raw_relay_fallback() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let relay = spawn_dev_relay().await.unwrap();
        let relay_addr = relay.local_addr();

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        // Don't accept on the server: connect attempts will time out.
        drop(server_endpoint);
        let client_endpoint = QuicEndpoint::client(bind, &[server_cert]).unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = DeviceKeypair::generate().unwrap();
        let remote_peer_id = remote_key.public_key().peer_id();

        // Advertise an unreachable host candidate (port 1) so the direct probe will fail fast,
        // forcing the relay fallback path.
        let remote_record = signed_record(
            &remote_key,
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "127.0.0.1".to_string(),
                port: 1,
                priority: 120,
            }],
            1,
        );
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_direct_probe_timeout(Duration::from_millis(150))
                .with_overall_deadline(Duration::from_millis(500))
                .with_relay_server(relay_addr.to_string())
                .with_local_device_keypair(local_key),
            rendezvous_client,
            client_endpoint,
        );

        let error = connector.connect(&remote_peer_id).await.unwrap_err();
        assert!(
            error.to_string().contains("relay PQC session"),
            "raw relay fallback must fail closed: {error}"
        );
        assert!(connector.cache().lookup(&remote_peer_id).is_none());
    }

    #[tokio::test]
    async fn relay_fallback_is_rejected_without_pqc_session() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());
        let relay = spawn_dev_relay().await.unwrap();

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[server_cert]).unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = DeviceKeypair::generate().unwrap();
        let remote_peer_id = remote_key.public_key().peer_id();
        let remote_record = signed_record(
            &remote_key,
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "127.0.0.1".to_string(),
                port: 1,
                priority: 120,
            }],
            1,
        );
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_direct_probe_timeout(Duration::from_millis(150))
                .with_overall_deadline(Duration::from_millis(500))
                .with_relay_server(relay.local_addr().to_string())
                .with_local_device_keypair(local_key),
            rendezvous_client,
            client_endpoint,
        );

        let error = connector.connect(&remote_peer_id).await.unwrap_err();
        assert!(
            error.to_string().contains("relay PQC session"),
            "relay fallback must fail closed until it has an end-to-end PQC session: {error}"
        );
    }

    #[tokio::test]
    async fn missing_peer_returns_protocol_error() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[throwaway_cert]).unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id()),
            rendezvous_client,
            client_endpoint,
        );

        let error = connector.connect("not-published").await.unwrap_err();
        assert!(error.to_string().contains("not found in rendezvous"));
    }

    #[tokio::test]
    async fn cached_path_is_tried_first_on_subsequent_connect() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_cert_der = server_cert.as_der().to_vec();
        let client_endpoint = QuicEndpoint::client(bind, &[server_cert]).unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_peer_id = remote_key.public_key().peer_id();
        let _accept_loop = spawn_pqc_drain_accept_loop(
            server_endpoint,
            remote_key.clone(),
            server_cert_der.clone(),
        );

        // Two host candidates: one unreachable (priority 200), one reachable (priority 100).
        // First call will try priority 200 first (fail), then reach the working one.
        // After caching, the second call should probe the cached working address first.
        let remote_record = signed_record_with_cert(
            remote_key.as_ref(),
            vec![
                CandidateEndpoint {
                    candidate_type: CandidateType::Host,
                    address: "127.0.0.1".to_string(),
                    port: 1,
                    priority: 200,
                },
                CandidateEndpoint {
                    candidate_type: CandidateType::Host,
                    address: server_addr.ip().to_string(),
                    port: server_addr.port(),
                    priority: 100,
                },
            ],
            1,
            server_cert_der,
        );
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_direct_probe_timeout(Duration::from_millis(750))
                .with_overall_deadline(Duration::from_secs(3))
                .with_local_device_keypair(local_key.clone()),
            rendezvous_client,
            client_endpoint,
        );

        let (_, first) = connector.connect(&remote_peer_id).await.unwrap();
        assert_eq!(first.path_kind, PathKind::Direct);
        assert!(!first.used_cached_path);
        // The working candidate must be among the recorded attempts as
        // Established. With paced probes the unreachable peer may be aborted
        // before its outcome lands, so we don't assert on its presence.
        let working_attempt = first
            .attempts
            .iter()
            .find(|attempt| attempt.address == server_addr)
            .expect("working candidate should appear in first.attempts");
        assert_eq!(working_attempt.outcome, ProbeOutcome::Established);
        assert_eq!(connector.cache().lookup(&remote_peer_id), Some(server_addr));

        let (_, second) = connector.connect(&remote_peer_id).await.unwrap();
        assert_eq!(second.path_kind, PathKind::Direct);
        assert!(second.used_cached_path);
        // The cached path is paced ahead of the others (offset 0 vs 50ms+),
        // so it wins and the resulting attempt list starts with it.
        assert_eq!(second.attempts[0].address, server_addr);
        assert_eq!(second.attempts[0].outcome, ProbeOutcome::Established);
    }

    #[tokio::test]
    async fn ice_pre_check_fails_when_no_responder_is_listening() {
        use crate::ice::IceCredentials;

        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let throwaway_cert_der = throwaway_cert.as_der().to_vec();
        let client_endpoint = QuicEndpoint::client(bind, &[throwaway_cert]).unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = DeviceKeypair::generate().unwrap();
        let remote_peer_id = remote_key.public_key().peer_id();

        // No ICE responder bound at port 1; the connector will time out the
        // ICE check before ever attempting a QUIC handshake. The cert in the
        // record is a real (parseable) DER blob so the connector reaches the
        // ICE step rather than short-circuiting on cert-parse.
        let remote_record = signed_record_with_cert(
            &remote_key,
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "127.0.0.1".to_string(),
                port: 1,
                priority: 120,
            }],
            1,
            throwaway_cert_der,
        );
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_local_ice_credentials(IceCredentials::generate().unwrap())
                .with_ice_check_timeout(Duration::from_millis(150))
                .with_direct_probe_timeout(Duration::from_millis(150))
                .with_overall_deadline(Duration::from_millis(500))
                .with_local_device_keypair(local_key.clone()),
            rendezvous_client,
            client_endpoint,
        );

        let result = connector.connect(&remote_peer_id).await;
        // No relay configured, so the absence of a working direct path is a
        // hard failure. The probe attempt must record IceFailed so the
        // operator can distinguish auth/path failures from QUIC errors.
        let error = result.unwrap_err();
        assert!(error.to_string().contains("no direct candidate"));
    }

    #[tokio::test]
    async fn ice_pre_check_runs_before_quic_handshake() {
        use crate::ice::{spawn_dev_ice_responder, IceCredentials};

        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        // Generate the credentials that will be embedded in the (signed) peer
        // record AND used to sign the responder's binding-success replies.
        let remote_credentials = IceCredentials::generate().unwrap();

        // ICE responder lives on its own UDP port; no Quinn server here. We
        // expect ICE to succeed and QUIC to fail with a known error, which
        // proves ICE ran first.
        let responder = spawn_dev_ice_responder(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            remote_credentials.clone(),
        )
        .await
        .unwrap();
        let responder_addr = responder.local_addr();

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let throwaway_cert_der = throwaway_cert.as_der().to_vec();
        let client_endpoint = QuicEndpoint::client(bind, &[throwaway_cert]).unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = DeviceKeypair::generate().unwrap();
        let remote_peer_id = remote_key.public_key().peer_id();

        let unsigned = UnsignedPeerRecord::new_with_ice_credentials(
            MESH_ID,
            "remote-peer",
            remote_key.public_key(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: responder_addr.ip().to_string(),
                port: responder_addr.port(),
                priority: 120,
            }],
            vec!["100.127.0.10/32".to_string()],
            60,
            1,
            remote_credentials,
        )
        .with_device_certificate(throwaway_cert_der);
        let record = PeerRecord::signed(unsigned, &remote_key).unwrap();
        rendezvous_client.publish(MESH_ID, record).await.unwrap();

        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_local_ice_credentials(IceCredentials::generate().unwrap())
                .with_ice_check_timeout(Duration::from_millis(500))
                .with_direct_probe_timeout(Duration::from_millis(500))
                .with_overall_deadline(Duration::from_secs(2))
                .with_local_device_keypair(local_key.clone()),
            rendezvous_client,
            client_endpoint,
        );

        // No relay → the QUIC failure surfaces as the overall error. We
        // inspect the error message for context, then re-run with a relay so
        // we can verify that the ICE attempt was recorded.
        let _ = connector.connect(&remote_peer_id).await; // priming run is allowed to fail

        // Add a relay for fallback so the connector would previously return
        // a successful relay outcome. Relay is now fail-closed until it has
        // an end-to-end PQC session, but the error keeps the direct failure
        // summary so operators can still diagnose the post-ICE QUIC failure.
        let relay = spawn_dev_relay().await.unwrap();
        let connector_with_relay = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_local_ice_credentials(IceCredentials::generate().unwrap())
                .with_ice_check_timeout(Duration::from_millis(500))
                .with_direct_probe_timeout(Duration::from_millis(500))
                .with_overall_deadline(Duration::from_secs(2))
                .with_relay_server(relay.local_addr().to_string())
                .with_local_device_keypair(local_key.clone()),
            RendezvousClient::new(rendezvous.local_addr().to_string()),
            QuicEndpoint::client(bind, &[QuicEndpoint::server(bind).unwrap().1]).unwrap(),
        );

        let error = connector_with_relay
            .connect(&remote_peer_id)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("relay PQC session"),
            "relay path must fail closed without PQC: {error}"
        );
        assert!(
            error.to_string().contains("timed out")
                || error.to_string().contains("failed to establish"),
            "error should retain direct failure context: {error}"
        );
    }

    #[tokio::test]
    async fn paced_probes_let_fast_candidate_beat_unreachable_one() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_cert_der = server_cert.as_der().to_vec();
        let client_endpoint = QuicEndpoint::client(bind, &[server_cert]).unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_peer_id = remote_key.public_key().peer_id();
        let _accept_loop = spawn_pqc_drain_accept_loop(
            server_endpoint,
            remote_key.clone(),
            server_cert_der.clone(),
        );

        // Black-hole address (TEST-NET-1, RFC 5737) sitting first in the
        // candidate list. Sequential probes would have to wait for the full
        // probe timeout before trying anything else; paced probes start the
        // working candidate ~50ms later and let it win.
        let remote_record = signed_record_with_cert(
            remote_key.as_ref(),
            vec![
                CandidateEndpoint {
                    candidate_type: CandidateType::Host,
                    address: "192.0.2.1".to_string(),
                    port: 4433,
                    priority: 1_000_000,
                },
                CandidateEndpoint {
                    candidate_type: CandidateType::Host,
                    address: server_addr.ip().to_string(),
                    port: server_addr.port(),
                    priority: 1,
                },
            ],
            1,
            server_cert_der,
        );
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_direct_probe_timeout(Duration::from_millis(2_000))
                .with_overall_deadline(Duration::from_secs(3))
                .with_probe_pacing(Duration::from_millis(50))
                .with_local_device_keypair(local_key.clone()),
            rendezvous_client,
            client_endpoint,
        );

        let started = Instant::now();
        let (_, outcome) = connector.connect(&remote_peer_id).await.unwrap();
        let total = started.elapsed();

        assert_eq!(outcome.path_kind, PathKind::Direct);
        assert_eq!(outcome.remote_addr, Some(server_addr));
        // The probe-timeout is 2s, but parallel pacing should let us win in
        // well under a second. If we had probed sequentially, the unreachable
        // candidate would have eaten the full 2s before the second probe even
        // started.
        assert!(
            total < Duration::from_millis(1_500),
            "paced probes must beat sequential timeout, took {total:?}"
        );
    }

    #[test]
    fn last_good_cache_clear_drops_all_entries_and_returns_count() {
        let cache = LastGoodCache::default();
        cache.record("peer-a", "127.0.0.1:1".parse().unwrap());
        cache.record("peer-b", "127.0.0.1:2".parse().unwrap());
        cache.record("peer-c", "127.0.0.1:3".parse().unwrap());
        assert_eq!(cache.len(), 3);

        let dropped = cache.clear();
        assert_eq!(dropped, 3);
        assert!(cache.is_empty());
        assert!(cache.lookup("peer-a").is_none());
    }

    #[tokio::test]
    async fn handle_network_event_path_changed_clears_cache_and_recommends_reprobe() {
        let connector = build_test_connector_no_quic();
        connector
            .cache()
            .record("peer-x", "127.0.0.1:9".parse().unwrap());
        connector
            .cache()
            .record("peer-y", "127.0.0.1:10".parse().unwrap());

        let response = connector.handle_network_event(NetworkEvent::PathChanged);
        assert_eq!(response.cache_entries_invalidated, 2);
        assert!(response.reprobe_recommended);
        assert!(connector.cache().is_empty());
    }

    #[tokio::test]
    async fn handle_network_event_post_wake_clears_cache_and_recommends_reprobe() {
        let connector = build_test_connector_no_quic();
        connector
            .cache()
            .record("peer-z", "127.0.0.1:11".parse().unwrap());

        let response = connector.handle_network_event(NetworkEvent::PostWake);
        assert_eq!(response.cache_entries_invalidated, 1);
        assert!(response.reprobe_recommended);
        assert!(connector.cache().is_empty());
    }

    #[tokio::test]
    async fn handle_network_event_pre_sleep_preserves_cache_and_pauses_probing() {
        let connector = build_test_connector_no_quic();
        connector
            .cache()
            .record("peer-w", "127.0.0.1:12".parse().unwrap());

        let response = connector.handle_network_event(NetworkEvent::PreSleep);
        assert_eq!(response.cache_entries_invalidated, 0);
        assert!(!response.reprobe_recommended);
        assert_eq!(connector.cache().len(), 1, "PreSleep must not drop cache");
    }

    #[tokio::test]
    async fn handle_network_event_offline_preserves_cache_and_does_not_reprobe() {
        let connector = build_test_connector_no_quic();
        connector
            .cache()
            .record("peer-v", "127.0.0.1:13".parse().unwrap());

        let response =
            connector.handle_network_event(NetworkEvent::ReachabilityChanged { reachable: false });
        assert_eq!(response.cache_entries_invalidated, 0);
        assert!(!response.reprobe_recommended);
        assert_eq!(connector.cache().len(), 1);
    }

    #[tokio::test]
    async fn handle_network_event_back_online_recommends_reprobe_without_clearing() {
        let connector = build_test_connector_no_quic();
        connector
            .cache()
            .record("peer-u", "127.0.0.1:14".parse().unwrap());

        let response =
            connector.handle_network_event(NetworkEvent::ReachabilityChanged { reachable: true });
        assert_eq!(response.cache_entries_invalidated, 0);
        assert!(response.reprobe_recommended);
        assert_eq!(connector.cache().len(), 1);
    }

    #[tokio::test]
    async fn reconnect_invalidates_cache_then_runs_full_connect() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_cert_der = server_cert.as_der().to_vec();
        let client_endpoint = QuicEndpoint::client(bind, &[server_cert]).unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_peer_id = remote_key.public_key().peer_id();
        let _accept_loop = spawn_pqc_drain_accept_loop(
            server_endpoint,
            remote_key.clone(),
            server_cert_der.clone(),
        );

        let record = signed_record_with_cert(
            remote_key.as_ref(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: server_addr.ip().to_string(),
                port: server_addr.port(),
                priority: 120,
            }],
            1,
            server_cert_der,
        );
        rendezvous_client.publish(MESH_ID, record).await.unwrap();

        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_direct_probe_timeout(Duration::from_millis(500))
                .with_overall_deadline(Duration::from_secs(2))
                .with_local_device_keypair(local_key.clone()),
            rendezvous_client,
            client_endpoint,
        );

        // First connect populates the cache.
        let (_link1, first) = connector.connect(&remote_peer_id).await.unwrap();
        assert_eq!(first.path_kind, PathKind::Direct);
        assert!(connector.cache().lookup(&remote_peer_id).is_some());

        // Reconnect drops the cache entry, then re-establishes; the new
        // outcome should NOT report `used_cached_path` because reconnect
        // explicitly invalidates first.
        let (_link2, second) = connector.reconnect(&remote_peer_id).await.unwrap();
        assert_eq!(second.path_kind, PathKind::Direct);
        assert!(
            !second.used_cached_path,
            "reconnect must invalidate the cache before probing"
        );
        // Cache should be re-populated by the successful reconnect.
        assert_eq!(connector.cache().lookup(&remote_peer_id), Some(server_addr));
    }

    #[tokio::test]
    async fn public_registry_policy_rejects_missing_record_before_probing() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[throwaway_cert.clone()]).unwrap();

        let local_key = DeviceKeypair::generate().unwrap();
        let remote_key = DeviceKeypair::generate().unwrap();
        let remote_peer_id = remote_key.public_key().peer_id();
        let remote_record = signed_record_with_cert(
            &remote_key,
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "192.0.2.1".to_string(),
                port: 4433,
                priority: 120,
            }],
            1,
            throwaway_cert.as_der().to_vec(),
        );
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let registry = Arc::new(TestRegistryLookup::default());
        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_mesh_trust_policy(MeshTrustPolicy::PublicRequired)
                .with_identity_registry_lookup(registry.clone())
                .with_direct_probe_timeout(Duration::from_secs(30))
                .with_overall_deadline(Duration::from_secs(30)),
            rendezvous_client,
            client_endpoint,
        );

        let error = connector.connect(&remote_peer_id).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("registry record required by public mesh trust policy"),
            "public policy must fail on missing registry before probing: {error}"
        );
        assert_eq!(registry.lookup_count(), 1);
    }

    #[tokio::test]
    async fn public_registry_policy_accepts_active_matching_record_before_later_connect_failure() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[throwaway_cert.clone()]).unwrap();

        let local_key = DeviceKeypair::generate().unwrap();
        let remote_key = DeviceKeypair::generate().unwrap();
        let remote_peer_id = remote_key.public_key().peer_id();
        let remote_record =
            signed_record_with_cert(&remote_key, vec![], 1, throwaway_cert.as_der().to_vec());
        let registry_record = RegistryNodeRecord::from_peer_record(
            "daddr:owner:connector-test",
            &remote_record,
            RegistryNodeStatus::Active,
            1_725_000_000,
        )
        .unwrap();
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let registry = Arc::new(TestRegistryLookup::with_record(registry_record));
        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_mesh_trust_policy(MeshTrustPolicy::PublicRequired)
                .with_identity_registry_lookup(registry.clone()),
            rendezvous_client,
            client_endpoint,
        );

        let error = connector.connect(&remote_peer_id).await.unwrap_err();
        assert!(
            error.to_string().contains("no direct candidate"),
            "matching registry should pass; later no-candidate failure proves dial continued: {error}"
        );
        assert_eq!(registry.lookup_count(), 1);
    }

    #[tokio::test]
    async fn public_registry_policy_rejects_revoked_or_mismatched_record() {
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let cert_der = throwaway_cert.as_der().to_vec();
        let local_key = DeviceKeypair::generate().unwrap();

        for expected in [
            "registry record is revoked",
            "latest_peer_record_hash_hex mismatch",
        ] {
            let rendezvous = spawn_dev_rendezvous().await.unwrap();
            let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());
            let remote_key = DeviceKeypair::generate().unwrap();
            let remote_peer_id = remote_key.public_key().peer_id();
            let remote_record = signed_record_with_cert(&remote_key, vec![], 1, cert_der.clone());

            let mut registry_record = RegistryNodeRecord::from_peer_record(
                "daddr:owner:connector-test",
                &remote_record,
                RegistryNodeStatus::Active,
                1_725_000_000,
            )
            .unwrap();
            if expected == "registry record is revoked" {
                registry_record.status = RegistryNodeStatus::Revoked;
            } else {
                registry_record.latest_peer_record_hash_hex = "00".repeat(32);
            }

            rendezvous_client
                .publish(MESH_ID, remote_record)
                .await
                .unwrap();

            let connector = MeshConnector::new(
                MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                    .with_mesh_trust_policy(MeshTrustPolicy::PublicRequired)
                    .with_identity_registry_lookup(Arc::new(TestRegistryLookup::with_record(
                        registry_record,
                    ))),
                RendezvousClient::new(rendezvous.local_addr().to_string()),
                QuicEndpoint::client(bind, &[throwaway_cert.clone()]).unwrap(),
            );

            let error = connector.connect(&remote_peer_id).await.unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "expected `{expected}` for public registry rejection, got: {error}"
            );
        }
    }

    #[tokio::test]
    async fn private_registry_policy_accepts_missing_record() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[throwaway_cert.clone()]).unwrap();

        let local_key = DeviceKeypair::generate().unwrap();
        let remote_key = DeviceKeypair::generate().unwrap();
        let remote_peer_id = remote_key.public_key().peer_id();
        let remote_record =
            signed_record_with_cert(&remote_key, vec![], 1, throwaway_cert.as_der().to_vec());
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_mesh_trust_policy(MeshTrustPolicy::PrivatePreferred)
                .with_identity_registry_lookup(Arc::new(TestRegistryLookup::default())),
            rendezvous_client,
            client_endpoint,
        );

        let error = connector.connect(&remote_peer_id).await.unwrap_err();
        assert!(
            error.to_string().contains("no direct candidate"),
            "private policy should accept missing registry and fail later: {error}"
        );
    }

    #[tokio::test]
    async fn private_registry_policy_treats_lookup_error_as_missing_record() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[throwaway_cert.clone()]).unwrap();

        let local_key = DeviceKeypair::generate().unwrap();
        let remote_key = DeviceKeypair::generate().unwrap();
        let remote_peer_id = remote_key.public_key().peer_id();
        let remote_record =
            signed_record_with_cert(&remote_key, vec![], 1, throwaway_cert.as_der().to_vec());
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let registry = Arc::new(TestRegistryLookup::with_error("registry unavailable"));
        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_mesh_trust_policy(MeshTrustPolicy::PrivatePreferred)
                .with_identity_registry_lookup(registry.clone()),
            rendezvous_client,
            client_endpoint,
        );

        let error = connector.connect(&remote_peer_id).await.unwrap_err();
        assert!(
            error.to_string().contains("no direct candidate"),
            "private policy should continue past registry lookup errors and fail later: {error}"
        );
        assert_eq!(registry.lookup_count(), 1);
    }

    #[tokio::test]
    async fn development_registry_policy_treats_lookup_error_as_missing_record() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[throwaway_cert.clone()]).unwrap();

        let local_key = DeviceKeypair::generate().unwrap();
        let remote_key = DeviceKeypair::generate().unwrap();
        let remote_peer_id = remote_key.public_key().peer_id();
        let remote_record =
            signed_record_with_cert(&remote_key, vec![], 1, throwaway_cert.as_der().to_vec());
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let registry = Arc::new(TestRegistryLookup::with_error("registry unavailable"));
        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_mesh_trust_policy(MeshTrustPolicy::DevelopmentOptional)
                .with_identity_registry_lookup(registry.clone()),
            rendezvous_client,
            client_endpoint,
        );

        let error = connector.connect(&remote_peer_id).await.unwrap_err();
        assert!(
            error.to_string().contains("no direct candidate"),
            "development policy should continue past registry lookup errors and fail later: {error}"
        );
        assert_eq!(registry.lookup_count(), 1);
    }

    #[tokio::test]
    async fn public_registry_policy_rejects_lookup_error_before_probing() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[throwaway_cert.clone()]).unwrap();

        let local_key = DeviceKeypair::generate().unwrap();
        let remote_key = DeviceKeypair::generate().unwrap();
        let remote_peer_id = remote_key.public_key().peer_id();
        let remote_record = signed_record_with_cert(
            &remote_key,
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "192.0.2.1".to_string(),
                port: 4433,
                priority: 120,
            }],
            1,
            throwaway_cert.as_der().to_vec(),
        );
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let registry = Arc::new(TestRegistryLookup::with_error("registry unavailable"));
        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_mesh_trust_policy(MeshTrustPolicy::PublicRequired)
                .with_identity_registry_lookup(registry.clone())
                .with_direct_probe_timeout(Duration::from_secs(30))
                .with_overall_deadline(Duration::from_secs(30)),
            rendezvous_client,
            client_endpoint,
        );

        let started = Instant::now();
        let error = connector.connect(&remote_peer_id).await.unwrap_err();
        assert!(
            error.to_string().contains("registry unavailable"),
            "public policy should propagate lookup errors before probing: {error}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "public lookup error should reject before long direct probe timeout"
        );
        assert_eq!(registry.lookup_count(), 1);
    }

    fn build_test_connector_no_quic() -> MeshConnector {
        // For event-handling tests we never actually probe; a server-side
        // QUIC endpoint pair is the cheapest way to construct a valid client.
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[throwaway_cert]).unwrap();
        // The rendezvous client never gets called by these tests; a non-
        // routable address is fine.
        let rendezvous_client = RendezvousClient::new("127.0.0.1:1".to_string());
        MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, "local-peer"),
            rendezvous_client,
            client_endpoint,
        )
    }

    #[tokio::test]
    async fn peer_acl_denylist_short_circuits_before_rendezvous_lookup() {
        // Build a rendezvous client pointed at a non-routable address. If
        // the ACL is honored, the connector fails BEFORE attempting any
        // network IO, so the bogus rendezvous URL is never contacted.
        // (Without the ACL, the rendezvous lookup would fail with a
        // connect error instead of "rejected by ACL".)
        use crate::peer_acl::PeerAcl;

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[throwaway_cert]).unwrap();
        let rendezvous_client = RendezvousClient::new("127.0.0.1:1".to_string());

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let banned_peer_id = "qlink_banned-peer";
        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_peer_acl(PeerAcl::new().with_deny([banned_peer_id])),
            rendezvous_client,
            client_endpoint,
        );

        let error = connector.connect(banned_peer_id).await.unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("rejected by ACL") && message.contains("deny"),
            "ACL rejection must surface a clear reason: {message}"
        );
    }

    #[tokio::test]
    async fn peer_acl_allowlist_excludes_unlisted_peers() {
        use crate::peer_acl::PeerAcl;

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[throwaway_cert]).unwrap();
        let rendezvous_client = RendezvousClient::new("127.0.0.1:1".to_string());

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_peer_acl(PeerAcl::new().with_allow(["qlink_friend"])),
            rendezvous_client,
            client_endpoint,
        );

        let error = connector.connect("qlink_stranger").await.unwrap_err();
        assert!(
            error.to_string().contains("not on the allow list"),
            "unlisted peer must be rejected with the allowlist reason: {error}"
        );
    }

    #[tokio::test]
    async fn peer_acl_allowlist_permits_listed_peers_to_proceed() {
        // The ACL says "yes" → the connector proceeds to rendezvous
        // lookup. The peer doesn't exist, so the lookup fails with the
        // standard "not found in rendezvous" error — distinct from the
        // ACL-rejection error. This proves the ACL gate is open.
        use crate::peer_acl::PeerAcl;

        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[throwaway_cert]).unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let permitted_peer_id = "qlink_friend";
        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_peer_acl(PeerAcl::new().with_allow([permitted_peer_id])),
            rendezvous_client,
            client_endpoint,
        );

        let error = connector.connect(permitted_peer_id).await.unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("not found in rendezvous"),
            "ACL must let the request through to rendezvous; got: {message}"
        );
        assert!(
            !message.contains("rejected by ACL"),
            "request should NOT have been ACL-rejected: {message}"
        );
    }

    #[tokio::test]
    async fn wrong_cert_in_record_fails_quic_handshake_and_rejects_raw_relay() {
        // Two QUIC servers exist: peer A is the "real" server we want to
        // reach. Peer B's cert is the one we MIS-publish in A's record.
        // The connector trusts B's cert per the (signed) record; A presents
        // its own cert; rustls verification fails; the probe records a
        // failure; raw relay fallback is refused.
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());
        let relay = spawn_dev_relay().await.unwrap();

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (real_server_endpoint, _real_cert) = QuicEndpoint::server(bind).unwrap();
        let real_server_addr = real_server_endpoint.local_addr().unwrap();
        // Wrong cert: comes from a different self-signed QUIC endpoint.
        let (_decoy_endpoint, wrong_cert) = QuicEndpoint::server(bind).unwrap();
        let wrong_cert_der = wrong_cert.as_der().to_vec();

        let _accept_loop = tokio::spawn(async move {
            loop {
                match real_server_endpoint.accept_one().await {
                    Ok(_) => {} // Accept and discard — we expect TLS to fail before useful data flows.
                    Err(_) => break,
                }
            }
        });

        let client_endpoint = QuicEndpoint::client(bind, &[]).unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = DeviceKeypair::generate().unwrap();
        let remote_peer_id = remote_key.public_key().peer_id();

        // Record advertises the real server's address but the wrong cert.
        let remote_record = signed_record_with_cert(
            &remote_key,
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: real_server_addr.ip().to_string(),
                port: real_server_addr.port(),
                priority: 120,
            }],
            1,
            wrong_cert_der,
        );
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_direct_probe_timeout(Duration::from_millis(500))
                .with_overall_deadline(Duration::from_secs(2))
                .with_relay_server(relay.local_addr().to_string())
                .with_local_device_keypair(local_key.clone()),
            rendezvous_client,
            client_endpoint,
        );

        let error = connector.connect(&remote_peer_id).await.unwrap_err();
        let error = error.to_string();
        // The direct probe must have failed (TLS verification couldn't
        // match the server's real cert against the wrong one we trusted),
        // and raw relay fallback must be refused.
        assert!(
            error.contains("relay PQC session"),
            "raw relay fallback must fail closed: {error}"
        );
        assert!(
            error.contains("failed to establish")
                || error.contains("invalid peer certificate")
                || error.contains("timed out"),
            "wrong cert failure should remain visible in the relay-disabled error: {error}"
        );
    }

    #[tokio::test]
    async fn stale_certificate_after_rotation_fails_direct_and_rejects_raw_relay() {
        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());
        let relay = spawn_dev_relay().await.unwrap();

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (old_server_endpoint, old_cert) = QuicEndpoint::server(bind).unwrap();
        drop(old_server_endpoint);

        let (rotated_server_endpoint, _rotated_cert) = QuicEndpoint::server(bind).unwrap();
        let rotated_addr = rotated_server_endpoint.local_addr().unwrap();

        let _accept_loop = tokio::spawn(async move {
            loop {
                match rotated_server_endpoint.accept_one().await {
                    Ok(session) => {
                        tokio::spawn(async move {
                            let _ = session.receive_frame().await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        let client_endpoint = QuicEndpoint::client(bind, &[]).unwrap();
        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = DeviceKeypair::generate().unwrap();
        let remote_peer_id = remote_key.public_key().peer_id();

        let stale_record = signed_record_with_cert(
            &remote_key,
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: rotated_addr.ip().to_string(),
                port: rotated_addr.port(),
                priority: 120,
            }],
            1,
            old_cert.as_der().to_vec(),
        );
        rendezvous_client
            .publish(MESH_ID, stale_record)
            .await
            .unwrap();

        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_direct_probe_timeout(Duration::from_millis(500))
                .with_overall_deadline(Duration::from_secs(2))
                .with_relay_server(relay.local_addr().to_string())
                .with_local_device_keypair(local_key.clone()),
            rendezvous_client,
            client_endpoint,
        );

        let error = connector.connect(&remote_peer_id).await.unwrap_err();
        let error = error.to_string();
        assert!(
            error.contains("relay PQC session"),
            "raw relay fallback must fail closed after cert rotation: {error}"
        );
        assert!(matches!(
            error.as_str(),
            s if s.contains("failed to establish")
                || s.contains("invalid peer certificate")
                || s.contains("timed out")
        ));
    }

    #[tokio::test]
    async fn expired_peer_record_from_rendezvous_is_rejected_before_direct_probe() {
        let local_key = DeviceKeypair::generate().unwrap();
        let remote_key = DeviceKeypair::generate().unwrap();
        let remote_peer_id = remote_key.public_key().peer_id();
        let expired_record = signed_record_with_ttl(
            &remote_key,
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "127.0.0.1".to_string(),
                port: 1,
                priority: 120,
            }],
            0,
            1,
            b"test-cert".to_vec(),
        );

        let peer_store: Arc<dyn PeerStore> = Arc::new(InMemoryPeerStore::new());
        peer_store.store(MESH_ID, &expired_record);

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[throwaway_cert]).unwrap();
        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_direct_probe_timeout(Duration::from_millis(100))
                .with_overall_deadline(Duration::from_millis(300)),
            RendezvousClient::new("127.0.0.1:1".to_string()),
            client_endpoint,
        )
        .with_peer_store(peer_store);

        let error = connector.connect(&remote_peer_id).await.unwrap_err();
        assert!(matches!(error, QlinkError::RecordExpired));
    }

    // === mDNS observation integration tests ===

    #[tokio::test]
    async fn mdns_observation_with_matching_fingerprint_adds_extra_host_candidate() {
        use crate::mdns_discovery::{
            compute_public_key_fingerprint, MdnsPeerAnnouncement, MdnsPeerObservation,
        };

        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        // Bring up a real "remote" QUIC server so the LAN-side address we
        // synthesize via mDNS is reachable. The rendezvous-published
        // candidate is a deliberately unreachable port; the mDNS
        // observation provides the working one.
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let working_addr = server_endpoint.local_addr().unwrap();
        let server_cert_der = server_cert.as_der().to_vec();
        let client_endpoint = QuicEndpoint::client(bind, &[server_cert]).unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_peer_id = remote_key.public_key().peer_id();
        let _accept_loop = spawn_pqc_drain_accept_loop(
            server_endpoint,
            remote_key.clone(),
            server_cert_der.clone(),
        );
        let expected_fingerprint = compute_public_key_fingerprint(&remote_key.public_key());

        // Rendezvous record advertises only an unreachable candidate.
        let remote_record = signed_record_with_cert(
            remote_key.as_ref(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "127.0.0.1".to_string(),
                port: 1, // unreachable
                priority: 120,
            }],
            1,
            server_cert_der,
        );
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_direct_probe_timeout(Duration::from_millis(400))
                .with_overall_deadline(Duration::from_secs(2))
                .with_local_device_keypair(local_key.clone()),
            rendezvous_client,
            client_endpoint,
        );

        // Feed an mDNS observation that points at the working address.
        connector.record_mdns_observation(MdnsPeerObservation {
            announcement: MdnsPeerAnnouncement {
                peer_id: remote_peer_id.clone(),
                mesh_id: MESH_ID.to_string(),
                alias: "peer-mdns".to_string(),
                sequence: 1,
                public_key_fingerprint: expected_fingerprint,
            },
            addresses: vec![working_addr],
        });

        let (link, outcome) = connector.connect(&remote_peer_id).await.unwrap();
        assert_eq!(link.path_kind(), PathKind::Direct);
        assert_eq!(outcome.path_kind, PathKind::Direct);

        // The successful Established attempt must be the mDNS-supplied
        // address, not the unreachable rendezvous one.
        let established = outcome
            .attempts
            .iter()
            .find(|attempt| attempt.outcome == ProbeOutcome::Established)
            .expect("at least one probe must succeed");
        assert_eq!(established.address, working_addr);
    }

    #[tokio::test]
    async fn mdns_observation_with_wrong_fingerprint_is_silently_discarded() {
        use crate::mdns_discovery::MdnsPeerAnnouncement;

        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_unused_server, throwaway_cert) = QuicEndpoint::server(bind).unwrap();
        let throwaway_cert_der = throwaway_cert.as_der().to_vec();
        let client_endpoint = QuicEndpoint::client(bind, &[throwaway_cert]).unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_peer_id = remote_key.public_key().peer_id();

        // Rendezvous record advertises an unreachable candidate; without
        // mDNS, connect() should fail with no direct candidate working.
        let remote_record = signed_record_with_cert(
            &remote_key,
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "127.0.0.1".to_string(),
                port: 1,
                priority: 120,
            }],
            1,
            throwaway_cert_der,
        );
        rendezvous_client
            .publish(MESH_ID, remote_record)
            .await
            .unwrap();

        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_direct_probe_timeout(Duration::from_millis(150))
                .with_overall_deadline(Duration::from_millis(500)),
            rendezvous_client,
            client_endpoint,
        );

        // Attacker on the LAN announces under the right peer_id but with
        // a forged fingerprint and a bogus address.
        connector.record_mdns_observation(MdnsPeerObservation {
            announcement: MdnsPeerAnnouncement {
                peer_id: remote_peer_id.clone(),
                mesh_id: MESH_ID.to_string(),
                alias: "peer-attacker".to_string(),
                sequence: 1,
                public_key_fingerprint: "0000000000000000".to_string(),
            },
            addresses: vec!["127.0.0.1:2".parse().unwrap()],
        });

        let error = connector.connect(&remote_peer_id).await.unwrap_err();
        // The forged observation must NOT have surfaced any extra
        // candidate, so the connector exhausts and reports "no direct
        // candidate succeeded" rather than something that mentions the
        // attacker's address.
        assert!(
            error.to_string().contains("no direct candidate"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn mdns_cache_purges_stale_observations_past_ttl() {
        use crate::mdns_discovery::{MdnsPeerAnnouncement, MdnsPeerObservation};

        // 50 ms TTL so the test can advance past it quickly.
        let cache = MdnsObservationCache::with_ttl(Duration::from_millis(50));
        cache.record(MdnsPeerObservation {
            announcement: MdnsPeerAnnouncement {
                peer_id: "qlink_aged".to_string(),
                mesh_id: MESH_ID.to_string(),
                alias: "peer-aged".to_string(),
                sequence: 1,
                public_key_fingerprint: "deadbeefdeadbeef".to_string(),
            },
            addresses: vec!["127.0.0.1:9".parse().unwrap()],
        });

        assert_eq!(cache.observations_for("qlink_aged").len(), 1);

        // Sleep past the TTL.
        std::thread::sleep(Duration::from_millis(80));

        // Lookup must purge the stale entry and return empty.
        assert!(cache.observations_for("qlink_aged").is_empty());
        // The peer key is fully removed from the underlying map so the
        // cache size stays bounded over long runs.
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn mdns_cache_replaces_duplicate_observation_for_same_addresses() {
        use crate::mdns_discovery::{MdnsPeerAnnouncement, MdnsPeerObservation};

        let cache = MdnsObservationCache::default();
        let announcement = MdnsPeerAnnouncement {
            peer_id: "qlink_dup".to_string(),
            mesh_id: MESH_ID.to_string(),
            alias: "peer-dup".to_string(),
            sequence: 1,
            public_key_fingerprint: "abcdef0123456789".to_string(),
        };
        let addresses = vec!["127.0.0.1:1234".parse().unwrap()];

        // Record the same observation twice — the cache should NOT
        // accumulate duplicates (would cause the connector to probe the
        // same address multiple times in one connect cycle).
        cache.record(MdnsPeerObservation {
            announcement: announcement.clone(),
            addresses: addresses.clone(),
        });
        cache.record(MdnsPeerObservation {
            announcement,
            addresses,
        });

        assert_eq!(cache.observations_for("qlink_dup").len(), 1);
    }

    #[tokio::test]
    async fn connect_writes_through_to_peer_store_on_rendezvous_hit() {
        // After a successful rendezvous lookup, the record must end up
        // in the connector's peer_store — that's what populates the
        // cache for future rendezvous-outage fallback.
        use crate::peer_store::{InMemoryPeerStore, PeerStore};

        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_cert_der = server_cert.as_der().to_vec();
        let client_endpoint = QuicEndpoint::client(bind, &[server_cert]).unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_peer_id = remote_key.public_key().peer_id();
        let _accept_loop = spawn_pqc_drain_accept_loop(
            server_endpoint,
            remote_key.clone(),
            server_cert_der.clone(),
        );

        rendezvous_client
            .publish(
                MESH_ID,
                signed_record_with_cert(
                    remote_key.as_ref(),
                    vec![CandidateEndpoint {
                        candidate_type: CandidateType::Host,
                        address: server_addr.ip().to_string(),
                        port: server_addr.port(),
                        priority: 120,
                    }],
                    1,
                    server_cert_der.clone(),
                ),
            )
            .await
            .unwrap();

        let peer_store: Arc<dyn PeerStore> = Arc::new(InMemoryPeerStore::new());
        assert!(peer_store.is_empty(), "store starts empty");

        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_direct_probe_timeout(Duration::from_secs(2))
                .with_overall_deadline(Duration::from_secs(5))
                .with_local_device_keypair(local_key.clone()),
            rendezvous_client,
            client_endpoint,
        )
        .with_peer_store(peer_store.clone());

        let (_link, outcome) = connector.connect(&remote_peer_id).await.unwrap();
        assert_eq!(outcome.peer_record_source, PeerRecordSource::RendezvousLive);

        let cached = peer_store
            .load(MESH_ID, &remote_peer_id)
            .expect("write-through must populate the store");
        assert_eq!(cached.body.peer_id, remote_peer_id);
        assert_eq!(cached.body.sequence, 1);
        assert_eq!(peer_store.len(), 1);
    }

    #[tokio::test]
    async fn connect_falls_back_to_peer_store_when_rendezvous_unreachable() {
        // The reason we built persistence: a connector that can't
        // reach rendezvous must still be able to dial peers it has
        // previously authenticated. Pre-populate the store with a
        // valid signed record, point the connector at a dead
        // rendezvous address, and confirm the dial still completes.
        use crate::peer_store::{InMemoryPeerStore, PeerStore};

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_cert_der = server_cert.as_der().to_vec();
        let client_endpoint = QuicEndpoint::client(bind, &[server_cert]).unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_peer_id = remote_key.public_key().peer_id();
        let _accept_loop = spawn_pqc_drain_accept_loop(
            server_endpoint,
            remote_key.clone(),
            server_cert_der.clone(),
        );
        let cached_record = signed_record_with_cert(
            remote_key.as_ref(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: server_addr.ip().to_string(),
                port: server_addr.port(),
                priority: 120,
            }],
            1,
            server_cert_der,
        );

        let peer_store: Arc<dyn PeerStore> = Arc::new(InMemoryPeerStore::new());
        peer_store.store(MESH_ID, &cached_record);

        // Port 1 on loopback is reliably dead — no rendezvous server
        // listens there, so the connector's lookup will fail and it
        // must consult the peer_store fallback.
        let dead_rendezvous = RendezvousClient::new("127.0.0.1:1".to_string());
        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_direct_probe_timeout(Duration::from_secs(2))
                .with_overall_deadline(Duration::from_secs(5))
                .with_local_device_keypair(local_key.clone()),
            dead_rendezvous,
            client_endpoint,
        )
        .with_peer_store(peer_store);

        let (link, outcome) = connector
            .connect(&remote_peer_id)
            .await
            .expect("cached record must let the dial succeed");
        assert_eq!(link.path_kind(), PathKind::Direct);
        assert_eq!(outcome.path_kind, PathKind::Direct);
        assert_eq!(outcome.remote_addr, Some(server_addr));
        assert_eq!(outcome.peer_record_source, PeerRecordSource::PeerStoreCache);
    }

    #[tokio::test]
    async fn connect_falls_back_to_peer_store_when_rendezvous_returns_no_record() {
        // Distinct from the unreachable-rendezvous case: the server is
        // healthy but doesn't know this peer. The cached record is
        // still our best information and the connector should use it
        // rather than failing.
        use crate::peer_store::{InMemoryPeerStore, PeerStore};

        let rendezvous = spawn_dev_rendezvous().await.unwrap();
        let rendezvous_client = RendezvousClient::new(rendezvous.local_addr().to_string());

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let server_cert_der = server_cert.as_der().to_vec();
        let client_endpoint = QuicEndpoint::client(bind, &[server_cert]).unwrap();

        let local_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_key = Arc::new(DeviceKeypair::generate().unwrap());
        let remote_peer_id = remote_key.public_key().peer_id();
        let _accept_loop = spawn_pqc_drain_accept_loop(
            server_endpoint,
            remote_key.clone(),
            server_cert_der.clone(),
        );
        let cached_record = signed_record_with_cert(
            remote_key.as_ref(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: server_addr.ip().to_string(),
                port: server_addr.port(),
                priority: 120,
            }],
            1,
            server_cert_der,
        );

        let peer_store: Arc<dyn PeerStore> = Arc::new(InMemoryPeerStore::new());
        peer_store.store(MESH_ID, &cached_record);

        // Note: nothing was published to the rendezvous server for
        // this peer_id; the lookup will return Ok(None).
        let connector = MeshConnector::new(
            MeshConnectorConfig::new(MESH_ID, local_key.public_key().peer_id())
                .with_direct_probe_timeout(Duration::from_secs(2))
                .with_overall_deadline(Duration::from_secs(5))
                .with_local_device_keypair(local_key.clone()),
            rendezvous_client,
            client_endpoint,
        )
        .with_peer_store(peer_store);

        let (link, outcome) = connector
            .connect(&remote_peer_id)
            .await
            .expect("rendezvous-not-found must fall back to cache");
        assert_eq!(link.path_kind(), PathKind::Direct);
        assert_eq!(outcome.peer_record_source, PeerRecordSource::PeerStoreCache);
    }

    fn signed_record(
        keypair: &DeviceKeypair,
        endpoints: Vec<CandidateEndpoint>,
        sequence: u64,
    ) -> PeerRecord {
        // For tests, "any" cert bytes works because the QUIC handshake
        // doesn't actually run during candidate-pair probing in cases like
        // the unreachable-host test. Tests that need a real handshake pass
        // their server cert via `signed_record_with_cert`.
        signed_record_with_cert(keypair, endpoints, sequence, b"test-cert".to_vec())
    }

    fn signed_record_with_cert(
        keypair: &DeviceKeypair,
        endpoints: Vec<CandidateEndpoint>,
        sequence: u64,
        cert_der: Vec<u8>,
    ) -> PeerRecord {
        let body = UnsignedPeerRecord::new(
            MESH_ID,
            "test-peer",
            keypair.public_key(),
            endpoints,
            vec!["100.127.0.10/32".to_string()],
            60,
            sequence,
        )
        .with_device_certificate(cert_der);
        PeerRecord::signed(body, keypair).unwrap()
    }

    #[derive(Default)]
    struct TestRegistryLookup {
        record: Mutex<Option<RegistryNodeRecord>>,
        error: Mutex<Option<String>>,
        lookups: Mutex<usize>,
    }

    impl TestRegistryLookup {
        fn with_record(record: RegistryNodeRecord) -> Self {
            Self {
                record: Mutex::new(Some(record)),
                error: Mutex::new(None),
                lookups: Mutex::new(0),
            }
        }

        fn with_error(message: impl Into<String>) -> Self {
            Self {
                record: Mutex::new(None),
                error: Mutex::new(Some(message.into())),
                lookups: Mutex::new(0),
            }
        }

        fn lookup_count(&self) -> usize {
            *self.lookups.lock().unwrap()
        }
    }

    impl IdentityRegistryLookup for TestRegistryLookup {
        fn lookup<'a>(
            &'a self,
            _peer_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<RegistryNodeRecord>>> + Send + 'a>> {
            Box::pin(async move {
                *self.lookups.lock().unwrap() += 1;
                if let Some(message) = self.error.lock().unwrap().clone() {
                    return Err(QlinkError::Protocol(message));
                }
                Ok(self.record.lock().unwrap().clone())
            })
        }
    }
}
