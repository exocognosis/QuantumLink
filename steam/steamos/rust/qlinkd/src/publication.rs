//! Resident signed peer-record publication for SteamOS.
//!
//! `qlink-core` owns record construction, signatures, and rendezvous I/O.
//! SteamOS owns the resident lifecycle around those shared primitives:
//! crash-safe sequence reservation, TTL/2 refresh, bounded retry, redacted
//! status, and an owner-only current-record outbox for a separate Dytallix
//! synchronizer. Wallet material never enters `qlinkd`.

use qlink_core::crypto::DeviceKeypair;
use qlink_core::discovery::PeerRecord;
use qlink_core::dytallix_identity::DytallixRegistryBindingVersion;
use qlink_core::mesh_connection::{LocalRegistryBindingError, LocalRegistryBindingFailureKind};
use qlink_core::mesh_transport::MeshTransportHandle;
use qlink_proto::{
    DytallixBindingVersion, DytallixTrustDecision, DytallixTrustHealth, LocalRegistryBindingState,
};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const PUBLICATION_STATE_FILE: &str = "publication-state.json";
pub const PUBLICATION_RECORD_FILE: &str = "publication-record.json";
const PUBLICATION_STATE_SCHEMA_VERSION: u8 = 1;
const OWNER_FILE_MODE: u32 = 0o600;
const MAX_PUBLICATION_ERROR_BYTES: usize = 512;
const PUBLICATION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationPhase {
    NotStarted,
    Published,
    Degraded,
    Expired,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationSnapshot {
    pub phase: PublicationPhase,
    pub sequence: Option<u64>,
    pub expires_at_unix: Option<u64>,
    pub last_attempt_at_unix: Option<u64>,
    pub last_success_at_unix: Option<u64>,
    pub last_error: Option<String>,
    pub dytallix_required: bool,
    pub dytallix_decision: DytallixTrustDecision,
    pub dytallix_health: DytallixTrustHealth,
    pub local_binding_version: Option<DytallixBindingVersion>,
    pub local_binding_state: LocalRegistryBindingState,
    pub local_identity_revision: Option<u64>,
    pub local_binding_checked_at_unix: Option<u64>,
    pub local_binding_error: Option<String>,
}

impl PublicationSnapshot {
    pub fn not_started() -> Self {
        Self {
            phase: PublicationPhase::NotStarted,
            sequence: None,
            expires_at_unix: None,
            last_attempt_at_unix: None,
            last_success_at_unix: None,
            last_error: None,
            dytallix_required: false,
            dytallix_decision: DytallixTrustDecision::NotChecked,
            dytallix_health: DytallixTrustHealth::Unknown,
            local_binding_version: None,
            local_binding_state: LocalRegistryBindingState::NotConfigured,
            local_identity_revision: None,
            local_binding_checked_at_unix: None,
            local_binding_error: None,
        }
    }

    pub fn at(&self, now_unix: u64) -> Self {
        let mut snapshot = self.clone();
        if snapshot
            .expires_at_unix
            .is_some_and(|expires_at| expires_at <= now_unix)
        {
            snapshot.phase = PublicationPhase::Expired;
        }
        snapshot
    }

    pub fn is_current(&self, now_unix: u64) -> bool {
        self.expires_at_unix
            .is_some_and(|expires_at| expires_at > now_unix)
            && matches!(
                self.phase,
                PublicationPhase::Published | PublicationPhase::Degraded
            )
            && (!self.dytallix_required
                || (self.local_binding_version == Some(DytallixBindingVersion::StableIdentityV2)
                    && self.local_binding_state == LocalRegistryBindingState::Active))
    }
}

#[derive(Debug, Clone)]
pub struct PublicationWorkerConfig {
    pub rendezvous_url: String,
    pub rendezvous_auth_token: Option<String>,
    pub ttl_seconds: u64,
    pub overlay_routes: Vec<String>,
    pub state_dir: PathBuf,
    pub selected_peer_id: String,
    pub public_dytallix_required: bool,
}

pub struct PublicationController {
    snapshot: Arc<Mutex<PublicationSnapshot>>,
    command_tx: Option<mpsc::Sender<PublicationCommand>>,
    worker: Option<JoinHandle<()>>,
}

enum PublicationCommand {
    Refresh,
    Shutdown,
}

impl std::fmt::Debug for PublicationController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicationController")
            .field("snapshot", &self.snapshot(now_unix()))
            .finish_non_exhaustive()
    }
}

impl PublicationController {
    pub fn start(
        handle: Arc<MeshTransportHandle>,
        keypair: Arc<DeviceKeypair>,
        config: PublicationWorkerConfig,
    ) -> io::Result<Self> {
        let state_path = config.state_dir.join(PUBLICATION_STATE_FILE);
        let record_path = config.state_dir.join(PUBLICATION_RECORD_FILE);
        let machine = PublicationStateMachine::load(state_path, record_path, config.ttl_seconds)?;
        let mut machine = machine;
        machine.snapshot.dytallix_required = config.public_dytallix_required;
        machine.snapshot.local_binding_state = if config.public_dytallix_required {
            LocalRegistryBindingState::Pending
        } else {
            LocalRegistryBindingState::NotConfigured
        };
        let snapshot = Arc::new(Mutex::new(machine.snapshot.clone()));
        let worker_snapshot = snapshot.clone();
        let (command_tx, command_rx) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("qlinkd-publication".to_string())
            .spawn(move || {
                run_publication_worker(
                    handle,
                    keypair,
                    config,
                    machine,
                    worker_snapshot,
                    command_rx,
                )
            })?;
        Ok(Self {
            snapshot,
            command_tx: Some(command_tx),
            worker: Some(worker),
        })
    }

    pub fn snapshot(&self, at_unix: u64) -> PublicationSnapshot {
        self.snapshot
            .lock()
            .map(|snapshot| snapshot.at(at_unix))
            .unwrap_or_else(|_| PublicationSnapshot {
                phase: PublicationPhase::Expired,
                last_error: Some("publication status lock poisoned".to_string()),
                ..PublicationSnapshot::not_started()
            })
    }

    pub fn is_current(&self, at_unix: u64) -> bool {
        self.snapshot(at_unix).is_current(at_unix)
    }

    pub fn request_refresh(&self) {
        if let Some(command_tx) = self.command_tx.as_ref() {
            let _ = command_tx.send(PublicationCommand::Refresh);
        }
    }

    pub fn shutdown(&mut self) {
        if let Some(command_tx) = self.command_tx.take() {
            let _ = command_tx.send(PublicationCommand::Shutdown);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for PublicationController {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn run_publication_worker(
    handle: Arc<MeshTransportHandle>,
    keypair: Arc<DeviceKeypair>,
    config: PublicationWorkerConfig,
    mut machine: PublicationStateMachine,
    shared_snapshot: Arc<Mutex<PublicationSnapshot>>,
    command_rx: mpsc::Receiver<PublicationCommand>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            machine.record_failure(
                now_unix(),
                format!("publication runtime initialization failed: {error}"),
            );
            machine.snapshot.phase = PublicationPhase::Stopped;
            publish_snapshot(&shared_snapshot, &machine.snapshot);
            return;
        }
    };

    loop {
        let now = now_unix();
        let sequence = match machine.reserve_sequence(now) {
            Ok(sequence) => sequence,
            Err(error) => {
                machine.record_failure(now, format!("sequence reservation failed: {error}"));
                publish_snapshot(&shared_snapshot, &machine.snapshot);
                if wait_or_shutdown(&command_rx, machine.retry_delay()) {
                    break;
                }
                continue;
            }
        };
        publish_snapshot(&shared_snapshot, &machine.snapshot);

        let publish = handle.publish_self_with_extra_candidates_and_auth(
            keypair.as_ref(),
            &config.rendezvous_url,
            config.rendezvous_auth_token.as_deref(),
            config.ttl_seconds,
            sequence,
            Vec::new(),
            config.overlay_routes.clone(),
        );
        let published_record = match runtime
            .block_on(async { tokio::time::timeout(PUBLICATION_TIMEOUT, publish).await })
        {
            Ok(Ok(record)) => match machine.accept_record(sequence, now_unix(), record.clone()) {
                Ok(()) => Some(record),
                Err(error) => {
                    machine.record_failure(now_unix(), error);
                    None
                }
            },
            Ok(Err(error)) => {
                machine.record_failure(now_unix(), error.to_string());
                None
            }
            Err(_) => {
                machine.record_failure(
                    now_unix(),
                    format!(
                        "signed peer record publication timed out after {} seconds",
                        PUBLICATION_TIMEOUT.as_secs()
                    ),
                );
                None
            }
        };
        if let Some(record) = published_record.filter(|_| config.public_dytallix_required) {
            let local_validation = handle.validate_local_registry_binding(&record);
            match runtime.block_on(async {
                tokio::time::timeout(PUBLICATION_TIMEOUT, local_validation).await
            }) {
                Ok(Ok(proof)) => machine.record_local_binding_accepted(
                    now_unix(),
                    match proof.binding_version {
                        DytallixRegistryBindingVersion::ExactPeerRecordV1 => {
                            DytallixBindingVersion::ExactPeerRecordV1
                        }
                        DytallixRegistryBindingVersion::StableIdentityV2 => {
                            DytallixBindingVersion::StableIdentityV2
                        }
                    },
                    proof.identity_revision,
                ),
                Ok(Err(error)) => machine.record_local_binding_failure(now_unix(), error),
                Err(_) => machine.record_local_binding_failure(
                    now_unix(),
                    LocalRegistryBindingError {
                        binding_version: Some(DytallixRegistryBindingVersion::StableIdentityV2),
                        kind: LocalRegistryBindingFailureKind::Unavailable,
                        message: format!(
                            "local Dytallix binding validation timed out after {} seconds",
                            PUBLICATION_TIMEOUT.as_secs()
                        ),
                    },
                ),
            }

            let validation = handle.revalidate_peer_trust(&config.selected_peer_id);
            match runtime
                .block_on(async { tokio::time::timeout(PUBLICATION_TIMEOUT, validation).await })
            {
                Ok(Ok(_)) => machine.record_trust_accepted(),
                Ok(Err(error)) => machine.record_trust_failure(now_unix(), error.to_string()),
                Err(_) => machine.record_trust_failure(
                    now_unix(),
                    format!(
                        "Dytallix trust revalidation timed out after {} seconds",
                        PUBLICATION_TIMEOUT.as_secs()
                    ),
                ),
            }
        }
        publish_snapshot(&shared_snapshot, &machine.snapshot);

        let delay = machine.next_delay(now_unix());
        if wait_or_shutdown(&command_rx, delay) {
            break;
        }
    }

    machine.snapshot.phase = PublicationPhase::Stopped;
    publish_snapshot(&shared_snapshot, &machine.snapshot);
}

fn wait_or_shutdown(command_rx: &mpsc::Receiver<PublicationCommand>, delay: Duration) -> bool {
    match command_rx.recv_timeout(delay) {
        Ok(PublicationCommand::Refresh) | Err(mpsc::RecvTimeoutError::Timeout) => false,
        Ok(PublicationCommand::Shutdown) | Err(mpsc::RecvTimeoutError::Disconnected) => true,
    }
}

fn publish_snapshot(shared: &Mutex<PublicationSnapshot>, snapshot: &PublicationSnapshot) {
    if let Ok(mut guard) = shared.lock() {
        *guard = snapshot.clone();
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurablePublicationState {
    schema_version: u8,
    next_sequence: u64,
}

impl Default for DurablePublicationState {
    fn default() -> Self {
        Self {
            schema_version: PUBLICATION_STATE_SCHEMA_VERSION,
            next_sequence: 1,
        }
    }
}

#[derive(Debug)]
struct PublicationStateMachine {
    ttl_seconds: u64,
    state_path: PathBuf,
    record_path: PathBuf,
    next_sequence: u64,
    next_attempt_at_unix: u64,
    snapshot: PublicationSnapshot,
}

impl PublicationStateMachine {
    fn load(state_path: PathBuf, record_path: PathBuf, ttl_seconds: u64) -> io::Result<Self> {
        let durable = load_durable_state(&state_path)?;
        Ok(Self {
            ttl_seconds,
            state_path,
            record_path,
            next_sequence: durable.next_sequence.max(1),
            next_attempt_at_unix: 0,
            snapshot: PublicationSnapshot::not_started(),
        })
    }

    fn reserve_sequence(&mut self, now_unix: u64) -> io::Result<u64> {
        self.snapshot.last_attempt_at_unix = Some(now_unix);
        let sequence = self.next_sequence;
        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidData,
                "publication sequence exhausted; rotate device identity",
            )
        })?;
        write_json_atomically(
            &self.state_path,
            &DurablePublicationState {
                schema_version: PUBLICATION_STATE_SCHEMA_VERSION,
                next_sequence,
            },
        )?;
        self.next_sequence = next_sequence;
        Ok(sequence)
    }

    fn accept_record(
        &mut self,
        sequence: u64,
        now_unix: u64,
        record: PeerRecord,
    ) -> Result<(), String> {
        record
            .verify(&record.body.mesh_id)
            .map_err(|error| format!("published record verification failed: {error}"))?;
        if record.body.sequence != sequence {
            return Err("published record sequence did not match reservation".to_string());
        }
        if record.body.expires_at_unix <= now_unix {
            return Err("published record was already expired".to_string());
        }
        write_json_atomically(&self.record_path, &record)
            .map_err(|error| format!("current-record outbox write failed: {error}"))?;
        self.snapshot.phase = PublicationPhase::Published;
        self.snapshot.sequence = Some(sequence);
        self.snapshot.expires_at_unix = Some(record.body.expires_at_unix);
        self.snapshot.last_success_at_unix = Some(now_unix);
        self.snapshot.last_error = None;
        self.next_attempt_at_unix = now_unix.saturating_add((self.ttl_seconds / 2).max(1));
        Ok(())
    }

    fn record_failure(&mut self, now_unix: u64, error: String) {
        self.snapshot.last_error = Some(sanitize_error(error));
        self.snapshot.phase = if self
            .snapshot
            .expires_at_unix
            .is_some_and(|expires_at| expires_at <= now_unix)
        {
            PublicationPhase::Expired
        } else {
            PublicationPhase::Degraded
        };
        self.next_attempt_at_unix = now_unix.saturating_add(self.retry_delay().as_secs());
    }

    fn record_trust_accepted(&mut self) {
        self.snapshot.dytallix_decision = DytallixTrustDecision::Accepted;
        self.snapshot.dytallix_health = DytallixTrustHealth::Healthy;
    }

    fn record_trust_failure(&mut self, _now_unix: u64, error: String) {
        let lower = error.to_ascii_lowercase();
        self.snapshot.dytallix_decision = if lower.contains("revoked") {
            DytallixTrustDecision::Revoked
        } else if lower.contains("suspended") {
            DytallixTrustDecision::Suspended
        } else if lower.contains("mismatch") {
            DytallixTrustDecision::Mismatched
        } else if lower.contains("required") || lower.contains("not found") {
            DytallixTrustDecision::Denied
        } else {
            DytallixTrustDecision::NotChecked
        };
        self.snapshot.dytallix_health =
            if lower.contains("unavailable") || lower.contains("lookup failed") {
                DytallixTrustHealth::Unavailable
            } else {
                DytallixTrustHealth::Degraded
            };
    }

    fn record_local_binding_accepted(
        &mut self,
        checked_at_unix: u64,
        version: DytallixBindingVersion,
        identity_revision: Option<u64>,
    ) {
        self.snapshot.local_binding_version = Some(version);
        self.snapshot.local_binding_state = LocalRegistryBindingState::Active;
        self.snapshot.local_identity_revision = identity_revision;
        self.snapshot.local_binding_checked_at_unix = Some(checked_at_unix);
        self.snapshot.local_binding_error = None;
    }

    fn record_local_binding_failure(&mut self, now_unix: u64, error: LocalRegistryBindingError) {
        self.snapshot.local_binding_version = error.binding_version.map(|version| match version {
            DytallixRegistryBindingVersion::ExactPeerRecordV1 => {
                DytallixBindingVersion::ExactPeerRecordV1
            }
            DytallixRegistryBindingVersion::StableIdentityV2 => {
                DytallixBindingVersion::StableIdentityV2
            }
        });
        self.snapshot.local_binding_state = match error.kind {
            LocalRegistryBindingFailureKind::Missing => LocalRegistryBindingState::Missing,
            LocalRegistryBindingFailureKind::Revoked => LocalRegistryBindingState::Revoked,
            LocalRegistryBindingFailureKind::Suspended => LocalRegistryBindingState::Suspended,
            LocalRegistryBindingFailureKind::Expired => LocalRegistryBindingState::Expired,
            LocalRegistryBindingFailureKind::Mismatched => LocalRegistryBindingState::Mismatched,
            LocalRegistryBindingFailureKind::Unavailable => LocalRegistryBindingState::Unavailable,
        };
        self.snapshot.local_binding_checked_at_unix = Some(now_unix);
        self.snapshot.local_binding_error = Some(sanitize_error(error.message.clone()));
        self.record_failure(
            now_unix,
            format!("local Dytallix registry binding failed: {}", error.message),
        );
    }

    fn retry_delay(&self) -> Duration {
        Duration::from_secs((self.ttl_seconds / 4).clamp(1, 15))
    }

    fn next_delay(&self, now_unix: u64) -> Duration {
        Duration::from_secs(self.next_attempt_at_unix.saturating_sub(now_unix).max(1))
    }
}

fn load_durable_state(path: &Path) -> io::Result<DurablePublicationState> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("publication state {} is not a regular file", path.display()),
                ));
            }
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!(
                        "publication state {} must not be group- or world-accessible",
                        path.display()
                    ),
                ));
            }
            let state: DurablePublicationState = serde_json::from_slice(&std::fs::read(path)?)
                .map_err(|error| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        format!("invalid publication state {}: {error}", path.display()),
                    )
                })?;
            if state.schema_version != PUBLICATION_STATE_SCHEMA_VERSION || state.next_sequence == 0
            {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "unsupported or invalid publication state",
                ));
            }
            Ok(state)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(DurablePublicationState::default()),
        Err(error) => Err(error),
    }
}

fn write_json_atomically<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidInput,
            format!("path has no parent: {}", path.display()),
        )
    })?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("publication"),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(OWNER_FILE_MODE);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| {
        serde_json::to_writer(&mut file, value).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        #[cfg(unix)]
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(OWNER_FILE_MODE))?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn sanitize_error(mut error: String) -> String {
    error = error.replace(['\n', '\r'], " ");
    if error.len() > MAX_PUBLICATION_ERROR_BYTES {
        let mut end = MAX_PUBLICATION_ERROR_BYTES;
        while !error.is_char_boundary(end) {
            end -= 1;
        }
        error.truncate(end);
    }
    error
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlink_core::discovery::{CandidateEndpoint, CandidateType, UnsignedPeerRecord};
    use qlink_core::mesh_transport::MeshTransportConfig;
    use qlink_core::rendezvous::spawn_dev_rendezvous;

    fn machine(temp: &tempfile::TempDir, ttl_seconds: u64) -> PublicationStateMachine {
        PublicationStateMachine::load(
            temp.path().join(PUBLICATION_STATE_FILE),
            temp.path().join(PUBLICATION_RECORD_FILE),
            ttl_seconds,
        )
        .unwrap()
    }

    fn signed_record(
        keypair: &DeviceKeypair,
        ttl_seconds: u64,
        sequence: u64,
        now_unix: u64,
    ) -> PeerRecord {
        let mut body = UnsignedPeerRecord::new(
            "mesh",
            "local",
            keypair.public_key(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "127.0.0.1".to_string(),
                port: 9000,
                priority: 100,
            }],
            vec![],
            ttl_seconds,
            sequence,
        );
        body.expires_at_unix = now_unix + ttl_seconds;
        PeerRecord::signed(body, keypair).unwrap()
    }

    #[test]
    fn sequence_is_reserved_durably_before_publication() {
        let temp = tempfile::tempdir().unwrap();
        let mut state = machine(&temp, 120);
        assert_eq!(state.reserve_sequence(1_000).unwrap(), 1);
        let restarted = machine(&temp, 120);
        assert_eq!(restarted.next_sequence, 2);
    }

    #[test]
    fn refresh_failure_is_degraded_only_until_previous_expiry() {
        let temp = tempfile::tempdir().unwrap();
        let keypair = DeviceKeypair::generate().unwrap();
        let mut machine = machine(&temp, 20);
        let started_at = now_unix();
        let sequence = machine.reserve_sequence(started_at).unwrap();
        machine
            .accept_record(
                sequence,
                started_at,
                signed_record(&keypair, 20, sequence, started_at),
            )
            .unwrap();
        machine.record_failure(started_at + 10, "rendezvous unavailable".to_string());
        assert_eq!(
            machine.snapshot.at(started_at + 10).phase,
            PublicationPhase::Degraded
        );
        assert!(machine.snapshot.is_current(started_at + 19));
        assert!(!machine.snapshot.is_current(started_at + 20));
        assert_eq!(
            machine.snapshot.at(started_at + 20).phase,
            PublicationPhase::Expired
        );
    }

    #[test]
    fn public_current_state_requires_local_v2_binding_independent_of_remote_trust() {
        let mut snapshot = PublicationSnapshot {
            phase: PublicationPhase::Published,
            expires_at_unix: Some(2_000),
            dytallix_required: true,
            dytallix_decision: DytallixTrustDecision::Accepted,
            dytallix_health: DytallixTrustHealth::Healthy,
            ..PublicationSnapshot::not_started()
        };

        assert!(!snapshot.is_current(1_000));
        snapshot.local_binding_version = Some(DytallixBindingVersion::ExactPeerRecordV1);
        snapshot.local_binding_state = LocalRegistryBindingState::Active;
        assert!(!snapshot.is_current(1_000));
        snapshot.local_binding_version = Some(DytallixBindingVersion::StableIdentityV2);
        snapshot.local_identity_revision = Some(4);
        assert!(snapshot.is_current(1_000));

        snapshot.dytallix_health = DytallixTrustHealth::Unavailable;
        assert!(snapshot.is_current(1_000));
    }

    #[test]
    fn local_binding_failure_is_reported_independently_from_remote_trust() {
        let temp = tempfile::tempdir().unwrap();
        let mut machine = machine(&temp, 120);
        machine.snapshot.dytallix_decision = DytallixTrustDecision::Accepted;
        machine.snapshot.dytallix_health = DytallixTrustHealth::Healthy;

        machine.record_local_binding_failure(
            1_000,
            LocalRegistryBindingError {
                binding_version: Some(DytallixRegistryBindingVersion::StableIdentityV2),
                kind: LocalRegistryBindingFailureKind::Revoked,
                message: "stable identity is revoked".to_string(),
            },
        );

        assert_eq!(
            machine.snapshot.local_binding_state,
            LocalRegistryBindingState::Revoked
        );
        assert_eq!(
            machine.snapshot.dytallix_decision,
            DytallixTrustDecision::Accepted
        );
        assert_eq!(
            machine.snapshot.dytallix_health,
            DytallixTrustHealth::Healthy
        );
    }

    #[test]
    fn state_and_record_outbox_are_owner_only() {
        let temp = tempfile::tempdir().unwrap();
        let keypair = DeviceKeypair::generate().unwrap();
        let mut machine = machine(&temp, 120);
        let started_at = now_unix();
        let sequence = machine.reserve_sequence(started_at).unwrap();
        machine
            .accept_record(
                sequence,
                started_at,
                signed_record(&keypair, 120, sequence, started_at),
            )
            .unwrap();
        #[cfg(unix)]
        for path in [&machine.state_path, &machine.record_path] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                OWNER_FILE_MODE
            );
        }
    }

    #[test]
    fn remote_trust_failure_does_not_relabel_local_publication_or_enrollment() {
        let temp = tempfile::tempdir().unwrap();
        let keypair = DeviceKeypair::generate().unwrap();
        let mut machine = machine(&temp, 120);
        machine.snapshot.dytallix_required = true;
        let started_at = now_unix();
        let sequence = machine.reserve_sequence(started_at).unwrap();
        machine
            .accept_record(
                sequence,
                started_at,
                signed_record(&keypair, 120, sequence, started_at),
            )
            .unwrap();
        machine.record_local_binding_accepted(
            started_at,
            DytallixBindingVersion::StableIdentityV2,
            Some(1),
        );

        machine.record_trust_failure(
            started_at,
            "registry lookup failed: service unavailable".to_string(),
        );

        assert_eq!(machine.snapshot.phase, PublicationPhase::Published);
        assert_eq!(
            machine.snapshot.dytallix_decision,
            DytallixTrustDecision::NotChecked
        );
        assert_eq!(
            machine.snapshot.dytallix_health,
            DytallixTrustHealth::Unavailable
        );
        assert!(machine.snapshot.is_current(started_at + 1));
    }

    #[test]
    fn error_redaction_handles_multibyte_text_without_panicking() {
        let sanitized = sanitize_error(format!("{}\nsecret", "x".repeat(511) + "é"));

        assert!(sanitized.len() <= MAX_PUBLICATION_ERROR_BYTES);
        assert!(!sanitized.contains('\n'));
    }

    #[test]
    fn controller_publishes_and_refreshes_against_live_dev_rendezvous() {
        let (address_tx, address_rx) = mpsc::channel();
        let (stop_tx, stop_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let server = spawn_dev_rendezvous().await.unwrap();
                address_tx.send(server.local_addr()).unwrap();
                loop {
                    if stop_rx.try_recv().is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            });
        });
        let rendezvous = address_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let keypair = Arc::new(DeviceKeypair::generate().unwrap());
        let config: MeshTransportConfig = serde_json::from_value(serde_json::json!({
            "meshId": "mesh-live-publication",
            "localPeerId": keypair.public_key().peer_id(),
            "remotePeerId": "qlink_missing",
            "rendezvousUrl": rendezvous.to_string(),
            "bindAddr": "127.0.0.1:0"
        }))
        .unwrap();
        let handle =
            Arc::new(MeshTransportHandle::new_with_keypair(config, Some(keypair.clone())).unwrap());
        let mut controller = PublicationController::start(
            handle.clone(),
            keypair,
            PublicationWorkerConfig {
                rendezvous_url: rendezvous.to_string(),
                rendezvous_auth_token: None,
                ttl_seconds: 120,
                overlay_routes: vec!["100.64.0.0/10".to_string()],
                state_dir: temp.path().to_path_buf(),
                selected_peer_id: "qlink_missing".to_string(),
                public_dytallix_required: false,
            },
        )
        .unwrap();

        let initial_deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            let snapshot = controller.snapshot(now_unix());
            if snapshot.sequence == Some(1) {
                assert_eq!(snapshot.phase, PublicationPhase::Published);
                break;
            }
            assert!(
                std::time::Instant::now() < initial_deadline,
                "initial publication did not complete: {snapshot:?}"
            );
            std::thread::sleep(Duration::from_millis(25));
        }

        controller.request_refresh();
        let refresh_deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            let snapshot = controller.snapshot(now_unix());
            if snapshot.sequence.is_some_and(|sequence| sequence >= 2) {
                assert_eq!(snapshot.phase, PublicationPhase::Published);
                assert!(snapshot.is_current(now_unix()));
                break;
            }
            assert!(
                std::time::Instant::now() < refresh_deadline,
                "requested publication refresh did not complete: {snapshot:?}"
            );
            std::thread::sleep(Duration::from_millis(25));
        }

        controller.shutdown();
        handle.shutdown();
        stop_tx.send(()).unwrap();
        server.join().unwrap();
    }
}
