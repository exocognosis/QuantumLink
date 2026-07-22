//! Persistent + in-memory caches for signed `PeerRecord`s.
//!
//! Why this exists: `MeshConnector::connect` looks up the remote peer in
//! rendezvous on every call. Rendezvous outages therefore translate
//! directly into "no peers reachable," even ones we've successfully
//! talked to before. A `PeerStore` keeps the most-recently-seen signed
//! record around so the connector can fall back to it when rendezvous
//! is unavailable.
//!
//! Records carry an ML-DSA signature over the publishing peer's device
//! key, so a stored record cannot be forged or quietly altered between
//! cache writes — verification still happens at use time. The cache is
//! a fast-path / fallback, not a trust anchor.
//!
//! ## What's stored
//!
//! Signed `PeerRecord`s, keyed by `(mesh_id, peer_id)`. The record body
//! itself contains the TTL and sequence; callers (the connector) decide
//! how to weigh staleness.
//!
//! ## Why JSON, not SQLite or sled
//!
//! For v1 we expect O(hundreds) of records per device, write traffic
//! dominated by record refresh on TTL expiry, and a single writer
//! (the mesh transport handle's runtime). A pretty-printed JSON file
//! with atomic temp-file replace is small enough, easy to inspect, and
//! cheap to migrate when the schema evolves. SQLite is overkill at
//! this scale.
//!
//! ## What's NOT stored
//!
//! - `LastGoodCache` (last-good direct path per peer). Lost on restart;
//!   the connector quickly re-establishes.
//! - `MdnsObservationCache` (LAN observations). Lost on restart; mDNS
//!   re-announces.
//! - Local device keypair. Persistence of the long-term secret is a
//!   separate concern (Keychain on macOS, key file for `qlinkctl`).
//!
//! ## Protected At-Rest Cache
//!
//! Optional, opt-in. Open a `FilePeerStore` via
//! `open_file_peer_store_with_key` and the on-disk file is wrapped in a
//! SHAKE256 protected envelope with a 32-byte key. The host (Swift app)
//! mints the key on first launch and persists it in the macOS Keychain
//! (`com.quantumlink.macos.secrets` / `peer-store-key`); subsequent
//! launches reload the key and pass it across the FFI in base64 form via
//! `MeshTransportConfig.peer_store_key_b64`.
//!
//! Without a key, the file is written as plaintext JSON (v1 format,
//! preserved for back-compat). With a key, the file uses the v3
//! envelope: `{"version":3,"nonce_b64":"...","ciphertext_b64":"..."}`
//! where the ciphertext field stores a masked v1 inner JSON plus a
//! SHAKE256 authentication tag, with a fresh 24-byte nonce on every
//! write.
//!
//! Reads tolerate plaintext v1 and protected v3; an attempt to load v3
//! without a key (or with the wrong key) silently treats the cache as
//! empty, consistent with the existing "malformed file → empty" recovery
//! behavior. Legacy v2 protected files are also treated as empty rather
//! than decoded with the retired classical envelope. Records are still
//! signed, so an attacker who flipped the file format alone cannot inject
//! forged records.
//!
//! ## TTL eviction
//!
//! Records carry `expires_at_unix`. The store retains them past
//! expiry so callers can fall back to "stale beats nothing" under
//! rendezvous outage (per the connector's degraded-mode policy), but
//! a `prune_expired` sweep is exposed so callers can trim the cache
//! after a config change or before a long-lived process accumulates
//! months of dead records. The default behavior also opportunistically
//! prunes during writes — re-serializing the file is the expensive
//! part of `store`, so dropping expired entries during the rewrite is
//! free.

use crate::{
    discovery::{now_unix, PeerRecord},
    error::{QlinkError, Result},
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand_core_06::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

/// Storage interface for signed peer records.
///
/// Implementations MUST be `Send + Sync` (the connector shares its
/// store across the rendezvous-driven session manager tasks).
///
/// Errors from `store` are intentionally surfaced as logs rather than
/// `Result` to keep the connector's hot path clean — a degraded cache
/// must not block live connectivity.
pub trait PeerStore: Send + Sync + std::fmt::Debug {
    /// Returns the most recent record we have for `peer_id` in
    /// `mesh_id`. Callers MUST re-verify the record's signature before
    /// trusting it (`PeerRecord::verify`); the store does not.
    fn load(&self, mesh_id: &str, peer_id: &str) -> Option<PeerRecord>;

    /// Stores or replaces the record. Best-effort: implementations
    /// log on failure rather than returning errors.
    fn store(&self, mesh_id: &str, record: &PeerRecord);

    /// Removes the record for the given peer. Idempotent.
    fn forget(&self, mesh_id: &str, peer_id: &str);

    /// Total number of records across every mesh. For diagnostics +
    /// tests; not load-bearing.
    fn len(&self) -> usize;

    /// Convenience: `len() == 0`.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drops records whose `expires_at_unix` is at or before
    /// `now_unix`. Returns the number of records removed.
    /// Implementations are expected to also persist the trimmed
    /// state if they back to disk.
    fn prune_expired(&self, now_unix: u64) -> usize;
}

/// No-op + RAM-only store. Used when persistence isn't configured.
#[derive(Debug, Default)]
pub struct InMemoryPeerStore {
    inner: Mutex<HashMap<(String, String), PeerRecord>>,
}

impl InMemoryPeerStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PeerStore for InMemoryPeerStore {
    fn load(&self, mesh_id: &str, peer_id: &str) -> Option<PeerRecord> {
        let key = (mesh_id.to_string(), peer_id.to_string());
        self.inner.lock().ok()?.get(&key).cloned()
    }

    fn store(&self, mesh_id: &str, record: &PeerRecord) {
        let key = (mesh_id.to_string(), record.body.peer_id.clone());
        if let Ok(mut guard) = self.inner.lock() {
            // Opportunistic prune on every write — the in-memory
            // map is small enough that walking it for an O(n) sweep
            // is cheap, and keeps long-running processes from
            // accumulating dead records.
            let now = now_unix();
            guard.retain(|_, existing| existing.body.expires_at_unix > now);
            guard.insert(key, record.clone());
        }
    }

    fn forget(&self, mesh_id: &str, peer_id: &str) {
        let key = (mesh_id.to_string(), peer_id.to_string());
        if let Ok(mut guard) = self.inner.lock() {
            guard.remove(&key);
        }
    }

    fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    fn prune_expired(&self, now_unix: u64) -> usize {
        let Ok(mut guard) = self.inner.lock() else {
            return 0;
        };
        let before = guard.len();
        guard.retain(|_, record| record.body.expires_at_unix > now_unix);
        before - guard.len()
    }
}

/// On-disk JSON-backed store. Atomic writes via temp-file + rename so
/// a crashed process never leaves a half-written `peers.json` for the
/// next launch to choke on. Reads tolerate missing or malformed files
/// by silently treating the cache as empty — corruption shouldn't
/// brick the runtime.
///
/// Construct with `FilePeerStore::open(path)` for plaintext-on-disk
/// (back-compat / dev tooling), or `FilePeerStore::open_with_key(path, key)`
/// for SHAKE256-protected storage. The protection mode is a
/// privacy hardening for environments where disk read-access is in
/// scope of the threat model — records are signed but their
/// aggregate reveals "who this device talks to."
#[derive(Debug)]
pub struct FilePeerStore {
    path: PathBuf,
    /// Optional 32-byte SHAKE256 envelope key. When set, on-disk
    /// records are written in the v3 protected envelope; when None,
    /// the v1 plaintext format is used. Wrapped in a Mutex so
    /// `rotate_key` can swap it without `&mut self` (typical use is
    /// `Arc<dyn PeerStore>`, so interior mutability is required).
    encryption_key: Mutex<Option<[u8; 32]>>,
    inner: Mutex<FileStoreInner>,
}

#[derive(Debug)]
struct FileStoreInner {
    records: BTreeMap<String, BTreeMap<String, PeerRecord>>, // mesh_id → peer_id → record
}

/// Plaintext on-disk format (v1). Kept as the default for back-compat
/// and for `qlinkctl` deployments that don't have a Keychain.
#[derive(Serialize, Deserialize)]
struct PlaintextFormat {
    /// Bumped on incompatible schema changes. v1 format readers
    /// fall back to empty when they encounter an unknown version
    /// or the v3 protected envelope (which lives at version=3).
    version: u32,
    meshes: BTreeMap<String, BTreeMap<String, PeerRecord>>,
}

/// Protected on-disk envelope (v3). The inner JSON has the same
/// shape as the v1 plaintext format; only the meshes map is
/// masked and tagged. The 24-byte nonce is regenerated on every
/// write so repeated saves don't reuse it.
#[derive(Serialize, Deserialize)]
struct EncryptedFormat {
    version: u32,
    nonce_b64: String,
    ciphertext_b64: String,
}

const PLAINTEXT_FORMAT_VERSION: u32 = 1;
const LEGACY_PROTECTED_FORMAT_VERSION: u32 = 2;
const ENCRYPTED_FORMAT_VERSION: u32 = 3;
const PEER_STORE_NONCE_LEN: usize = 24;
const PEER_STORE_TAG_LEN: usize = 32;
/// Constant AAD for peer-store envelope domain separation. This binds
/// tags to the peer-store purpose, not to a specific file or machine;
/// copying an envelope with the same key preserves authenticity.
const ENCRYPTION_AAD: &[u8] = b"qlink-peer-store";
const PEER_STORE_STREAM_LABEL: &[u8] = b"QuantumLink peer-store SHAKE256 stream v3";
const PEER_STORE_TAG_LABEL: &[u8] = b"QuantumLink peer-store SHAKE256 tag v3";

fn shake256_xof(label: &[u8], chunks: &[&[u8]], out: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(label);
    hasher.update(&(out.len() as u64).to_be_bytes());
    for chunk in chunks {
        hasher.update(&(chunk.len() as u64).to_be_bytes());
        hasher.update(chunk);
    }
    let mut reader = hasher.finalize_xof();
    reader.read(out);
}

fn peer_store_mask(key: &[u8; 32], nonce: &[u8], input: &[u8]) -> Vec<u8> {
    let mut stream = vec![0_u8; input.len()];
    shake256_xof(
        PEER_STORE_STREAM_LABEL,
        &[key.as_slice(), nonce, ENCRYPTION_AAD],
        &mut stream,
    );
    input
        .iter()
        .zip(stream.iter())
        .map(|(byte, mask)| byte ^ mask)
        .collect()
}

fn peer_store_tag(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> [u8; PEER_STORE_TAG_LEN] {
    let mut tag = [0_u8; PEER_STORE_TAG_LEN];
    shake256_xof(
        PEER_STORE_TAG_LABEL,
        &[key.as_slice(), nonce, ENCRYPTION_AAD, ciphertext],
        &mut tag,
    );
    tag
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

impl FilePeerStore {
    /// Opens or creates a peer store at `path` in plaintext mode.
    /// The parent directory must exist. On-disk format is the v1
    /// JSON map; readers tolerate protected envelopes by silently
    /// returning an empty cache (rather than treating them as
    /// corrupt — the operator may simply have left the key behind).
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        Self::open_internal(path.into(), None)
    }

    /// Opens or creates a protected peer store at `path`. Subsequent
    /// writes use the v3 SHAKE256 envelope. Reads accept both v1
    /// plaintext (for migration after the key was added) and v3
    /// protected; v3 envelopes that don't authenticate under the
    /// supplied key are treated as empty rather than failing the whole
    /// runtime.
    pub fn open_with_key(path: impl Into<PathBuf>, key: [u8; 32]) -> Result<Self> {
        Self::open_internal(path.into(), Some(key))
    }

    fn open_internal(path: PathBuf, encryption_key: Option<[u8; 32]>) -> Result<Self> {
        let records = match fs::read(&path) {
            Ok(bytes) => Self::decode_or_empty(&bytes, encryption_key.as_ref()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => {
                return Err(QlinkError::Protocol(format!(
                    "failed to read peer store at {}: {error}",
                    path.display()
                )))
            }
        };
        Ok(Self {
            path,
            encryption_key: Mutex::new(encryption_key),
            inner: Mutex::new(FileStoreInner { records }),
        })
    }

    /// Decodes an on-disk file. Recognizes v1 plaintext, v3
    /// protected (when the key is supplied + matches), and gracefully
    /// degrades to "empty" on every other input — including
    /// malformed JSON, unknown versions, mismatched keys, and v3
    /// envelopes encountered without a key. The "empty on
    /// corruption" stance matches the existing back-compat policy:
    /// a stale file shouldn't brick the runtime.
    fn decode_or_empty(
        bytes: &[u8],
        encryption_key: Option<&[u8; 32]>,
    ) -> BTreeMap<String, BTreeMap<String, PeerRecord>> {
        // Sniff version first via a partial decode. This avoids
        // having to try the plaintext and protected schemas in sequence.
        #[derive(Deserialize)]
        struct VersionHeader {
            version: u32,
        }
        let header = match serde_json::from_slice::<VersionHeader>(bytes) {
            Ok(h) => h,
            Err(_) => {
                tracing::warn!("peer store on disk is malformed; treating as empty");
                return BTreeMap::new();
            }
        };
        match header.version {
            PLAINTEXT_FORMAT_VERSION => match serde_json::from_slice::<PlaintextFormat>(bytes) {
                Ok(parsed) => parsed.meshes,
                Err(_) => {
                    tracing::warn!("peer store v1 on disk failed to decode; treating as empty");
                    BTreeMap::new()
                }
            },
            LEGACY_PROTECTED_FORMAT_VERSION => {
                tracing::warn!(
                    "peer store legacy v2 envelope uses a retired classical primitive; \
                     treating as empty"
                );
                BTreeMap::new()
            }
            ENCRYPTED_FORMAT_VERSION => {
                let Some(key) = encryption_key else {
                    tracing::warn!(
                        "peer store on disk is protected (v3) but no key was supplied; \
                         treating as empty (set MeshTransportConfig.peer_store_key_b64)"
                    );
                    return BTreeMap::new();
                };
                match serde_json::from_slice::<EncryptedFormat>(bytes) {
                    Ok(envelope) => Self::open_envelope(&envelope, key).unwrap_or_else(|reason| {
                        tracing::warn!(
                            ?reason,
                            "peer store v3 envelope failed to open; treating as empty"
                        );
                        BTreeMap::new()
                    }),
                    Err(_) => {
                        tracing::warn!(
                            "peer store v3 envelope failed to decode; treating as empty"
                        );
                        BTreeMap::new()
                    }
                }
            }
            _ => {
                tracing::warn!("peer store on disk has unknown version; treating as empty");
                BTreeMap::new()
            }
        }
    }

    fn open_envelope(
        envelope: &EncryptedFormat,
        key: &[u8; 32],
    ) -> std::result::Result<BTreeMap<String, BTreeMap<String, PeerRecord>>, &'static str> {
        let nonce_bytes = B64
            .decode(&envelope.nonce_b64)
            .map_err(|_| "nonce base64 decode failed")?;
        if nonce_bytes.len() != PEER_STORE_NONCE_LEN {
            return Err("nonce must be exactly 24 bytes");
        }
        let encoded_payload = B64
            .decode(&envelope.ciphertext_b64)
            .map_err(|_| "ciphertext base64 decode failed")?;
        if encoded_payload.len() < PEER_STORE_TAG_LEN {
            return Err("ciphertext is too short to carry a tag");
        }
        let split_at = encoded_payload.len() - PEER_STORE_TAG_LEN;
        let (ciphertext, tag) = encoded_payload.split_at(split_at);
        let expected_tag = peer_store_tag(key, &nonce_bytes, ciphertext);
        if !constant_time_eq(tag, &expected_tag) {
            return Err("ciphertext authentication failed (wrong key or tampered file)");
        }
        let plaintext = peer_store_mask(key, &nonce_bytes, ciphertext);
        // Inner shape matches v1 plaintext.
        let parsed: PlaintextFormat =
            serde_json::from_slice(&plaintext).map_err(|_| "opened payload is not v1 JSON")?;
        Ok(parsed.meshes)
    }

    /// Writes the current in-memory state to disk via temp-file +
    /// rename. Failures are logged and dropped — the in-memory state
    /// is still authoritative for this process.
    fn persist(&self, snapshot: &BTreeMap<String, BTreeMap<String, PeerRecord>>) {
        if let Err(error) = self.try_persist(snapshot) {
            tracing::warn!(?error, path = %self.path.display(), "peer store persist failed");
        }
    }

    fn try_persist(&self, snapshot: &BTreeMap<String, BTreeMap<String, PeerRecord>>) -> Result<()> {
        // Snapshot the current key under the lock, then delegate.
        // The split-out `try_persist_with_key` is also used by
        // `rotate_key` to write under a new key before swapping.
        let key_copy = self.encryption_key.lock().ok().and_then(|g| *g);
        self.try_persist_with_key(snapshot, key_copy.as_ref())
    }
}

impl FilePeerStore {
    /// Rotates the on-disk protection key. The cache is opened under
    /// the current key (if any), protected under
    /// `new_key`, and atomically replaced on disk. After return,
    /// the in-memory state is preserved and subsequent writes use
    /// the new key.
    ///
    /// Pass `Some(...)` for `new_key` to migrate from plaintext to
    /// protected (or to roll an existing protected store under a
    /// fresh key); pass `None` to drop at-rest protection entirely (writes
    /// out the v1 plaintext format). The latter is useful when an
    /// operator decommissions the Keychain item and wants to keep
    /// the cache without re-priming it.
    ///
    /// Returns the number of records persisted under the new key.
    /// Errors only surface real I/O failures (write to disk failed,
    /// permission denied) — the records themselves are already in
    /// memory and the persisted state is updated atomically via
    /// the same temp-file + rename path used by `store`.
    pub fn rotate_key(&self, new_key: Option<[u8; 32]>) -> Result<usize> {
        let snapshot = {
            let Ok(mut guard) = self.inner.lock() else {
                return Err(QlinkError::Protocol(
                    "peer store mutex poisoned during rotate_key".into(),
                ));
            };
            // Opportunistic prune so the rotated file is also trim.
            let now = now_unix();
            guard.records.retain(|_, by_peer| {
                by_peer.retain(|_, record| record.body.expires_at_unix > now);
                !by_peer.is_empty()
            });
            guard.records.clone()
        };
        // Replace the protection key BEFORE persisting so the
        // write goes out under the new key. We use unsafe interior
        // mutation via a separate Mutex around the key — but
        // simpler: just rebuild the persist payload manually here
        // with the new key and then mutate the field.
        //
        // Implementation: persist under the new key first via a
        // direct call, then if that succeeds, swap the field on
        // self. Doing it in this order means an I/O failure during
        // rotation leaves both the on-disk file and the in-memory
        // key in their pre-rotation state.
        self.try_persist_with_key(&snapshot, new_key.as_ref())?;
        // Swap the key after the persist succeeds so an I/O failure
        // mid-rotation leaves both the on-disk file and the
        // in-memory key in their pre-rotation state.
        if let Ok(mut guard) = self.encryption_key.lock() {
            *guard = new_key;
        }
        Ok(snapshot.values().map(|m| m.len()).sum())
    }

    /// Like `try_persist` but with a caller-supplied key (used by
    /// `rotate_key` to write out under the new key before swapping
    /// the field). Bypasses `self.encryption_key` entirely.
    fn try_persist_with_key(
        &self,
        snapshot: &BTreeMap<String, BTreeMap<String, PeerRecord>>,
        key: Option<&[u8; 32]>,
    ) -> Result<()> {
        let encoded = match key {
            None => {
                let payload = PlaintextFormat {
                    version: PLAINTEXT_FORMAT_VERSION,
                    meshes: snapshot.clone(),
                };
                serde_json::to_vec_pretty(&payload)?
            }
            Some(key) => {
                let inner = PlaintextFormat {
                    version: PLAINTEXT_FORMAT_VERSION,
                    meshes: snapshot.clone(),
                };
                let inner_bytes = serde_json::to_vec(&inner)?;
                let mut nonce = [0_u8; PEER_STORE_NONCE_LEN];
                OsRng.fill_bytes(&mut nonce);
                let ciphertext = peer_store_mask(key, &nonce, &inner_bytes);
                let tag = peer_store_tag(key, &nonce, &ciphertext);
                let mut encoded_payload = Vec::with_capacity(ciphertext.len() + tag.len());
                encoded_payload.extend_from_slice(&ciphertext);
                encoded_payload.extend_from_slice(&tag);
                let envelope = EncryptedFormat {
                    version: ENCRYPTED_FORMAT_VERSION,
                    nonce_b64: B64.encode(nonce),
                    ciphertext_b64: B64.encode(&encoded_payload),
                };
                serde_json::to_vec_pretty(&envelope)?
            }
        };
        self.atomic_write(&encoded)
    }

    /// Splits out the temp-file + rename + chmod dance so both
    /// `try_persist` and `try_persist_with_key` share it.
    fn atomic_write(&self, encoded: &[u8]) -> Result<()> {
        let mut temp_path = self.path.clone();
        let mut filename = self
            .path
            .file_name()
            .ok_or_else(|| {
                QlinkError::Protocol(format!(
                    "peer store path {} has no file name",
                    self.path.display()
                ))
            })?
            .to_os_string();
        filename.push(".tmp");
        temp_path.set_file_name(filename);

        {
            let mut file = fs::File::create(&temp_path).map_err(|err| {
                QlinkError::Protocol(format!(
                    "failed to create peer store temp at {}: {err}",
                    temp_path.display()
                ))
            })?;
            file.write_all(encoded).map_err(|err| {
                QlinkError::Protocol(format!(
                    "failed to write peer store temp at {}: {err}",
                    temp_path.display()
                ))
            })?;
            let _ = file.sync_all();
        }
        fs::rename(&temp_path, &self.path).map_err(|err| {
            QlinkError::Protocol(format!(
                "failed to rename peer store temp into place: {err}"
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(&self.path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = fs::set_permissions(&self.path, perms);
            }
        }
        Ok(())
    }
}

impl PeerStore for FilePeerStore {
    fn load(&self, mesh_id: &str, peer_id: &str) -> Option<PeerRecord> {
        self.inner
            .lock()
            .ok()?
            .records
            .get(mesh_id)?
            .get(peer_id)
            .cloned()
    }

    fn store(&self, mesh_id: &str, record: &PeerRecord) {
        let snapshot = {
            let Ok(mut guard) = self.inner.lock() else {
                return;
            };
            // Opportunistic prune: re-serializing the file is the
            // expensive part of every write, so dropping expired
            // entries here is free. Long-running deployments stay
            // trim without needing an explicit timer.
            let now = now_unix();
            guard.records.retain(|_, by_peer| {
                by_peer.retain(|_, existing| existing.body.expires_at_unix > now);
                !by_peer.is_empty()
            });
            guard
                .records
                .entry(mesh_id.to_string())
                .or_default()
                .insert(record.body.peer_id.clone(), record.clone());
            guard.records.clone()
        };
        self.persist(&snapshot);
    }

    fn forget(&self, mesh_id: &str, peer_id: &str) {
        let snapshot = {
            let Ok(mut guard) = self.inner.lock() else {
                return;
            };
            let removed = guard
                .records
                .get_mut(mesh_id)
                .and_then(|by_peer| by_peer.remove(peer_id))
                .is_some();
            if !removed {
                return;
            }
            // Clean up empty mesh maps so we don't accumulate stale
            // mesh IDs over time.
            if let Some(by_peer) = guard.records.get(mesh_id) {
                if by_peer.is_empty() {
                    guard.records.remove(mesh_id);
                }
            }
            guard.records.clone()
        };
        self.persist(&snapshot);
    }

    fn len(&self) -> usize {
        self.inner
            .lock()
            .map(|g| g.records.values().map(|m| m.len()).sum())
            .unwrap_or(0)
    }

    fn prune_expired(&self, now_unix: u64) -> usize {
        let (removed, snapshot) = {
            let Ok(mut guard) = self.inner.lock() else {
                return 0;
            };
            let before: usize = guard.records.values().map(|m| m.len()).sum();
            guard.records.retain(|_, by_peer| {
                by_peer.retain(|_, record| record.body.expires_at_unix > now_unix);
                !by_peer.is_empty()
            });
            let after: usize = guard.records.values().map(|m| m.len()).sum();
            (before - after, guard.records.clone())
        };
        if removed > 0 {
            self.persist(&snapshot);
        }
        removed
    }
}

/// Convenience for paths the connector / handle constructors hand
/// around: returns the parent directory, asserting it exists.
fn assert_parent_exists(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        QlinkError::Protocol(format!(
            "peer store path {} has no parent directory",
            path.display()
        ))
    })?;
    if !parent.exists() {
        return Err(QlinkError::Protocol(format!(
            "peer store parent directory {} does not exist; create it before opening the store",
            parent.display()
        )));
    }
    Ok(())
}

/// Re-export for callers that want a one-shot "open or fail" entry
/// point — wraps the parent-exists invariant the trait doesn't
/// otherwise enforce.
pub fn open_file_peer_store(path: impl AsRef<Path>) -> Result<FilePeerStore> {
    let path = path.as_ref();
    assert_parent_exists(path)?;
    FilePeerStore::open(path.to_path_buf())
}

/// Protected variant of `open_file_peer_store`. Subsequent writes go
/// to disk in the v3 SHAKE256 envelope. The host (Swift app) is
/// responsible for minting + persisting the key — typically in macOS
/// Keychain.
pub fn open_file_peer_store_with_key(
    path: impl AsRef<Path>,
    key: [u8; 32],
) -> Result<FilePeerStore> {
    let path = path.as_ref();
    assert_parent_exists(path)?;
    FilePeerStore::open_with_key(path.to_path_buf(), key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::DeviceKeypair,
        discovery::{CandidateEndpoint, CandidateType, UnsignedPeerRecord},
    };
    use tempfile::tempdir;

    fn fresh_signed_record(mesh_id: &str) -> (DeviceKeypair, PeerRecord) {
        let keypair = DeviceKeypair::generate().unwrap();
        let body = UnsignedPeerRecord::new(
            mesh_id,
            "alias",
            keypair.public_key(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "127.0.0.1".to_string(),
                port: 4433,
                priority: 100,
            }],
            vec!["100.127.0.10/32".to_string()],
            300,
            1,
        );
        let record = PeerRecord::signed(body, &keypair).unwrap();
        (keypair, record)
    }

    #[test]
    fn in_memory_store_round_trips_a_record() {
        let store = InMemoryPeerStore::new();
        let (_, record) = fresh_signed_record("devmesh");
        let peer_id = record.body.peer_id.clone();

        store.store("devmesh", &record);
        assert_eq!(store.len(), 1);

        let loaded = store.load("devmesh", &peer_id).unwrap();
        assert_eq!(loaded.body.peer_id, peer_id);
        assert_eq!(loaded.signature, record.signature);

        store.forget("devmesh", &peer_id);
        assert!(store.load("devmesh", &peer_id).is_none());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn in_memory_store_keys_records_by_mesh_id() {
        let store = InMemoryPeerStore::new();
        let (_, record) = fresh_signed_record("devmesh");
        let peer_id = record.body.peer_id.clone();

        store.store("devmesh", &record);
        // Same peer_id, different mesh: nothing leaked across meshes.
        assert!(store.load("other-mesh", &peer_id).is_none());
    }

    #[test]
    fn file_store_round_trip_survives_reload_from_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");

        let (_, record) = fresh_signed_record("devmesh");
        let peer_id = record.body.peer_id.clone();

        // First handle: store a record + drop the handle.
        {
            let store = open_file_peer_store(&path).unwrap();
            store.store("devmesh", &record);
            assert_eq!(store.len(), 1);
        }

        // Reopen: the record must still be there.
        let store = open_file_peer_store(&path).unwrap();
        assert_eq!(store.len(), 1);
        let loaded = store.load("devmesh", &peer_id).unwrap();
        assert_eq!(loaded.signature, record.signature);
    }

    #[test]
    fn file_store_treats_malformed_disk_contents_as_empty_cache() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        // Write garbage that doesn't parse as the on-disk format.
        fs::write(&path, b"this is not json").unwrap();

        let store = open_file_peer_store(&path).unwrap();
        assert_eq!(store.len(), 0, "malformed cache must not crash open");

        // Subsequent writes succeed and rewrite the file with the
        // current schema.
        let (_, record) = fresh_signed_record("devmesh");
        let peer_id = record.body.peer_id.clone();
        store.store("devmesh", &record);
        assert!(store.load("devmesh", &peer_id).is_some());
    }

    #[test]
    fn file_store_treats_unknown_schema_version_as_empty_cache() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        // Plausibly-shaped JSON but a future schema version.
        fs::write(&path, br#"{"version":99,"meshes":{}}"#).unwrap();

        let store = open_file_peer_store(&path).unwrap();
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn file_store_forget_removes_record_and_persists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");

        let (_, record) = fresh_signed_record("devmesh");
        let peer_id = record.body.peer_id.clone();

        let store = open_file_peer_store(&path).unwrap();
        store.store("devmesh", &record);
        store.forget("devmesh", &peer_id);
        assert!(store.load("devmesh", &peer_id).is_none());

        // Reopen confirms forget was persisted.
        drop(store);
        let store = open_file_peer_store(&path).unwrap();
        assert!(store.load("devmesh", &peer_id).is_none());
    }

    #[test]
    fn open_file_peer_store_rejects_nonexistent_parent_directory() {
        let dir = tempdir().unwrap();
        let bad_path = dir.path().join("does-not-exist").join("peers.json");
        let err = open_file_peer_store(&bad_path).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn file_store_replaces_record_when_storing_a_newer_one_for_same_peer() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = open_file_peer_store(&path).unwrap();

        let keypair = DeviceKeypair::generate().unwrap();
        let body_v1 = UnsignedPeerRecord::new(
            "devmesh",
            "alias",
            keypair.public_key(),
            vec![],
            vec![],
            300,
            1,
        );
        let body_v2 = UnsignedPeerRecord::new(
            "devmesh",
            "alias",
            keypair.public_key(),
            vec![],
            vec![],
            300,
            2,
        );
        let record_v1 = PeerRecord::signed(body_v1, &keypair).unwrap();
        let record_v2 = PeerRecord::signed(body_v2, &keypair).unwrap();
        let peer_id = record_v1.body.peer_id.clone();

        store.store("devmesh", &record_v1);
        store.store("devmesh", &record_v2);

        let loaded = store.load("devmesh", &peer_id).unwrap();
        assert_eq!(loaded.body.sequence, 2);
        assert_eq!(store.len(), 1, "same peer must not duplicate");
    }

    // MARK: - TTL eviction

    /// Builds a signed record whose body's `expires_at_unix` is
    /// fixed at `expires_at` rather than computed off `now_unix() +
    /// ttl`. Lets prune tests assert against deterministic timestamps.
    fn fresh_signed_record_expiring_at(mesh_id: &str, expires_at: u64) -> PeerRecord {
        let keypair = DeviceKeypair::generate().unwrap();
        let mut body = UnsignedPeerRecord::new(
            mesh_id,
            "alias",
            keypair.public_key(),
            vec![],
            vec![],
            300,
            1,
        );
        body.expires_at_unix = expires_at;
        PeerRecord::signed(body, &keypair).unwrap()
    }

    #[test]
    fn in_memory_prune_drops_expired_records_and_returns_count() {
        // Use real now_unix() as the reference so the opportunistic
        // prune-on-store inside `store()` (which uses live time)
        // doesn't trip before the test's explicit `prune_expired`
        // call.
        let now = now_unix();
        let store = InMemoryPeerStore::new();
        let live = fresh_signed_record_expiring_at("devmesh", now + 600);
        let dead = fresh_signed_record_expiring_at("devmesh", now + 100);
        store.store("devmesh", &live);
        store.store("devmesh", &dead);
        assert_eq!(store.len(), 2);

        // Now sweep at `now + 300`: `dead` is past expiry, `live`
        // survives.
        let removed = store.prune_expired(now + 300);
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 1);
        assert!(store.load("devmesh", &live.body.peer_id).is_some());
        assert!(store.load("devmesh", &dead.body.peer_id).is_none());
    }

    #[test]
    fn file_store_prune_persists_pruned_state_to_disk() {
        let now = now_unix();
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = open_file_peer_store(&path).unwrap();
        let dead = fresh_signed_record_expiring_at("devmesh", now + 100);
        store.store("devmesh", &dead);

        // Reading the file before prune confirms `dead` is on disk.
        let before = fs::read_to_string(&path).unwrap();
        assert!(before.contains(&dead.body.peer_id));

        let removed = store.prune_expired(now + 200);
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 0);

        // After prune, the on-disk file no longer mentions the peer.
        let after = fs::read_to_string(&path).unwrap();
        assert!(!after.contains(&dead.body.peer_id));

        // Reload from disk — also empty.
        drop(store);
        let store = open_file_peer_store(&path).unwrap();
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn store_opportunistically_prunes_expired_records_during_writes() {
        // Pin the prune-on-store contract: writing a fresh record
        // also drops any expired neighbors that were lying around
        // from earlier sessions, so long-running deployments stay
        // trim without an explicit timer.
        let now = now_unix();
        let store = InMemoryPeerStore::new();
        let dead = fresh_signed_record_expiring_at("devmesh", now.saturating_sub(60));
        let fresh = fresh_signed_record_expiring_at("devmesh", now + 600);

        store.store("devmesh", &dead);
        // The first store doesn't trigger eviction of itself —
        // prune happens BEFORE the new insert. Verified by the
        // record being temporarily present:
        assert_eq!(store.len(), 1);

        store.store("devmesh", &fresh);
        // After the second store, `dead` was evicted by the
        // opportunistic prune; only `fresh` remains.
        assert_eq!(store.len(), 1);
        assert!(store.load("devmesh", &fresh.body.peer_id).is_some());
        assert!(store.load("devmesh", &dead.body.peer_id).is_none());
    }

    // MARK: - Protected envelope (v3)

    #[test]
    fn protected_store_uses_v3_shake_envelope_shape() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let key = [42_u8; 32];

        let (_, record) = fresh_signed_record("devmesh");
        let peer_id = record.body.peer_id.clone();
        {
            let store = open_file_peer_store_with_key(&path, key).unwrap();
            store.store("devmesh", &record);
        }

        let raw = fs::read(&path).unwrap();
        let envelope: EncryptedFormat = serde_json::from_slice(&raw).unwrap();
        let nonce = B64.decode(&envelope.nonce_b64).unwrap();
        let ciphertext = B64.decode(&envelope.ciphertext_b64).unwrap();

        assert_eq!(envelope.version, ENCRYPTED_FORMAT_VERSION);
        assert_eq!(envelope.version, 3);
        assert_eq!(nonce.len(), 24);
        assert!(
            ciphertext.len() >= 32,
            "protected payload must carry an authentication tag"
        );
        assert!(
            !String::from_utf8_lossy(&raw).contains(&peer_id),
            "peer_id leaked into the protected file"
        );
    }

    #[test]
    fn encrypted_store_round_trips_through_disk_with_correct_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let key = [42_u8; 32];

        let (_, record) = fresh_signed_record("devmesh");
        let peer_id = record.body.peer_id.clone();

        {
            let store = open_file_peer_store_with_key(&path, key).unwrap();
            store.store("devmesh", &record);
        }

        // The on-disk file should be a v3 envelope, not the v1
        // plaintext `meshes` map. A weak but real test: peer_id
        // must NOT appear in cleartext on disk.
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"version\""));
        assert!(raw.contains("ciphertext_b64"));
        assert!(
            !raw.contains(&peer_id),
            "peer_id leaked into the protected file: {raw}"
        );

        // Reopening with the same key returns the record.
        let store = open_file_peer_store_with_key(&path, key).unwrap();
        let loaded = store.load("devmesh", &peer_id).unwrap();
        assert_eq!(loaded.signature, record.signature);
    }

    #[test]
    fn encrypted_store_treats_wrong_key_as_empty_cache_rather_than_failing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let key = [1_u8; 32];

        let (_, record) = fresh_signed_record("devmesh");
        let peer_id = record.body.peer_id.clone();
        {
            let store = open_file_peer_store_with_key(&path, key).unwrap();
            store.store("devmesh", &record);
        }

        // Open with a different key — must not panic, must not
        // open, must report empty rather than poisoning the
        // runtime with a hard error (consistent with other
        // "malformed file → empty" recovery paths in this module).
        let wrong_key = [2_u8; 32];
        let store = open_file_peer_store_with_key(&path, wrong_key).unwrap();
        assert_eq!(store.len(), 0);
        assert!(store.load("devmesh", &peer_id).is_none());
    }

    #[test]
    fn encrypted_store_treats_v3_file_with_no_key_as_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let key = [7_u8; 32];

        let (_, record) = fresh_signed_record("devmesh");
        {
            let store = open_file_peer_store_with_key(&path, key).unwrap();
            store.store("devmesh", &record);
        }

        // Reopen in plaintext mode — the v3 envelope is unreadable
        // and we recover by treating the cache as empty rather than
        // refusing to start.
        let store = open_file_peer_store(&path).unwrap();
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn encrypted_store_can_read_v1_plaintext_file_for_migration() {
        // Operators who previously ran in plaintext mode and add a
        // key later should still see their cached records on the
        // first launch — we read both formats, only writes are
        // gated by the configured mode.
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");

        let (_, record) = fresh_signed_record("devmesh");
        let peer_id = record.body.peer_id.clone();
        {
            // Plaintext write.
            let store = open_file_peer_store(&path).unwrap();
            store.store("devmesh", &record);
        }

        // Encrypted reopen — must read the v1 plaintext.
        let key = [11_u8; 32];
        let store = open_file_peer_store_with_key(&path, key).unwrap();
        assert!(store.load("devmesh", &peer_id).is_some());

        // First write through the protected store re-encodes to v3.
        let (_, replacement) = fresh_signed_record("devmesh");
        store.store("devmesh", &replacement);
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("ciphertext_b64"));
    }

    #[test]
    fn rotate_key_round_trips_records_under_new_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let original_key = [3_u8; 32];
        let new_key = [9_u8; 32];

        let (_, record) = fresh_signed_record("devmesh");
        let peer_id = record.body.peer_id.clone();
        {
            let store = open_file_peer_store_with_key(&path, original_key).unwrap();
            store.store("devmesh", &record);
            let persisted = store.rotate_key(Some(new_key)).unwrap();
            assert_eq!(persisted, 1);
        }

        // Original key no longer reads anything (file was rewritten
        // under new_key). Empty rather than error, per the
        // soft-failure policy.
        let original_view = open_file_peer_store_with_key(&path, original_key).unwrap();
        assert_eq!(original_view.len(), 0);

        // New key reads the record.
        let new_view = open_file_peer_store_with_key(&path, new_key).unwrap();
        assert!(new_view.load("devmesh", &peer_id).is_some());
    }

    #[test]
    fn rotate_key_can_drop_encryption_to_plaintext() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let key = [5_u8; 32];

        let (_, record) = fresh_signed_record("devmesh");
        let peer_id = record.body.peer_id.clone();
        {
            let store = open_file_peer_store_with_key(&path, key).unwrap();
            store.store("devmesh", &record);
            store.rotate_key(None).unwrap();
        }

        // After dropping at-rest protection, a plaintext-mode opener reads
        // the records.
        let plain_view = open_file_peer_store(&path).unwrap();
        assert!(plain_view.load("devmesh", &peer_id).is_some());

        // Subsequent writes from the (still-loaded) original store
        // should also be plaintext now — verified by re-opening
        // with the protected opener and getting empty (the file is
        // a v1 plaintext envelope; plaintext readers handle it,
        // protected readers also try v1 and succeed). Adjust to
        // assert the on-disk shape.
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"version\""));
        assert!(!raw.contains("ciphertext_b64"));
    }

    #[test]
    fn rotate_key_can_promote_plaintext_store_to_encrypted() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");

        let (_, record) = fresh_signed_record("devmesh");
        let peer_id = record.body.peer_id.clone();
        let new_key = [42_u8; 32];

        // Start in plaintext mode.
        let store = open_file_peer_store(&path).unwrap();
        store.store("devmesh", &record);

        // Promote to protected via rotate_key.
        store.rotate_key(Some(new_key)).unwrap();

        // The on-disk file is now a v3 envelope.
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("ciphertext_b64"));
        assert!(
            !raw.contains(&peer_id),
            "peer_id leaked into the file after rotation: {raw}"
        );

        // Subsequent writes from the same handle stay protected.
        let (_, second_record) = fresh_signed_record("devmesh");
        store.store("devmesh", &second_record);
        let raw_after = fs::read_to_string(&path).unwrap();
        assert!(raw_after.contains("ciphertext_b64"));

        // A fresh opener with the rotated key reads everything.
        drop(store);
        let view = open_file_peer_store_with_key(&path, new_key).unwrap();
        assert!(view.load("devmesh", &peer_id).is_some());
        assert!(view.load("devmesh", &second_record.body.peer_id).is_some());
    }

    #[test]
    fn rotate_key_on_empty_cache_is_a_clean_no_op() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = open_file_peer_store(&path).unwrap();
        let new_key = [7_u8; 32];

        let count = store.rotate_key(Some(new_key)).unwrap();
        assert_eq!(count, 0);

        // The file exists and is a valid v3 envelope (empty meshes).
        let view = open_file_peer_store_with_key(&path, new_key).unwrap();
        assert_eq!(view.len(), 0);
    }

    #[test]
    fn encrypted_store_uses_a_fresh_nonce_per_write() {
        // Reusing a (key, nonce) pair would reuse the SHAKE256 mask.
        // This test guards against accidental nonce reuse by checking
        // that two writes of the same content land at different
        // protected payloads on disk.
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let key = [13_u8; 32];
        let store = open_file_peer_store_with_key(&path, key).unwrap();

        let (_, record) = fresh_signed_record("devmesh");
        store.store("devmesh", &record);
        let first = fs::read_to_string(&path).unwrap();

        // Second store of the same record forces a rewrite.
        store.store("devmesh", &record);
        let second = fs::read_to_string(&path).unwrap();

        assert_ne!(
            first, second,
            "two writes must produce different ciphertext (fresh nonce per write)"
        );
    }
}
