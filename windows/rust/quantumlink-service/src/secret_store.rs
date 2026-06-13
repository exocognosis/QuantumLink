//! Platform secret-store abstraction.
//!
//! Replaces `KeychainSecretStore.swift` on Windows. The production
//! implementation ([`win::dpapi::DpapiSecretStore`](crate::win::dpapi))
//! wraps each secret with DPAPI (`CryptProtectData`, machine scope with
//! service-supplied entropy) and persists the opaque blob under
//! `%ProgramData%\QuantumLink\secrets\`, readable only by the service
//! account (directory ACL applied at install time).
//!
//! Account names are shared with macOS so support docs and diagnostics
//! line up across platforms (see `DeviceKeypairStore.swift` and
//! `PeerStoreKey.swift`).

use qlink_core::crypto::DeviceKeypair;
use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;

/// Account names, mirrored from the macOS Keychain layer.
pub mod accounts {
    /// 32-byte ML-DSA seed for the local device keypair
    /// (`DeviceKeypairStore.defaultAccount`).
    pub const DEVICE_KEYPAIR_SEED: &str = "device-keypair-seed";
    /// 32-byte ChaCha20-Poly1305 key encrypting the on-disk peer store
    /// (`PeerStoreKey.defaultAccount`).
    pub const PEER_STORE_KEY: &str = "peer-store-key";
}

#[derive(Debug, Error)]
pub enum SecretStoreError {
    #[error("secret store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("platform crypto operation failed: {0}")]
    Crypto(String),
    #[error("stored item is malformed: {0}")]
    InvalidItem(String),
}

pub trait SecretStore: Send + Sync {
    fn store(&self, account: &str, data: &[u8]) -> Result<(), SecretStoreError>;
    fn load(&self, account: &str) -> Result<Option<Vec<u8>>, SecretStoreError>;
    fn delete(&self, account: &str) -> Result<(), SecretStoreError>;
}

/// In-memory store for tests and non-Windows development hosts.
#[derive(Default)]
pub struct InMemorySecretStore {
    items: Mutex<HashMap<String, Vec<u8>>>,
}

impl SecretStore for InMemorySecretStore {
    fn store(&self, account: &str, data: &[u8]) -> Result<(), SecretStoreError> {
        self.items
            .lock()
            .unwrap()
            .insert(account.to_string(), data.to_vec());
        Ok(())
    }

    fn load(&self, account: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        Ok(self.items.lock().unwrap().get(account).cloned())
    }

    fn delete(&self, account: &str) -> Result<(), SecretStoreError> {
        self.items.lock().unwrap().remove(account);
        Ok(())
    }
}

/// Load-or-generate-and-persist flow for the local device keypair —
/// port of `DeviceKeypairStore.swift`. Without persistence the published
/// `peer_id` changes per service restart and the mesh identity breaks.
pub fn load_or_generate_device_keypair(
    store: &dyn SecretStore,
) -> Result<DeviceKeypair, SecretStoreError> {
    if let Some(existing) = store.load(accounts::DEVICE_KEYPAIR_SEED)? {
        // Defensive: a wrong-length item means an older build wrote
        // something different here. Regenerate + replace rather than
        // failing every start with a cryptic seed-decode error.
        if existing.len() == 32 {
            let mut seed = [0_u8; 32];
            seed.copy_from_slice(&existing);
            if let Ok(keypair) = DeviceKeypair::from_seed(seed) {
                return Ok(keypair);
            }
        }
    }
    let keypair = DeviceKeypair::generate()
        .map_err(|error| SecretStoreError::Crypto(format!("keypair generation failed: {error}")))?;
    let seed = keypair.seed().ok_or_else(|| {
        SecretStoreError::Crypto("generated keypair has no persistable seed".into())
    })?;
    store.store(accounts::DEVICE_KEYPAIR_SEED, &seed)?;
    Ok(keypair)
}

/// Load-or-generate flow for the peer-store encryption key — port of
/// `PeerStoreKey.swift`. Returned as raw 32 bytes; the engine encodes it
/// as base64 for `MeshTransportConfig.peer_store_key_b64`.
pub fn load_or_generate_peer_store_key(
    store: &dyn SecretStore,
) -> Result<[u8; 32], SecretStoreError> {
    if let Some(existing) = store.load(accounts::PEER_STORE_KEY)? {
        if existing.len() == 32 {
            let mut key = [0_u8; 32];
            key.copy_from_slice(&existing);
            return Ok(key);
        }
    }
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key)
        .map_err(|error| SecretStoreError::Crypto(format!("random key failed: {error}")))?;
    store.store(accounts::PEER_STORE_KEY, &key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_keypair_is_stable_across_loads() {
        let store = InMemorySecretStore::default();
        let first = load_or_generate_device_keypair(&store).unwrap();
        let second = load_or_generate_device_keypair(&store).unwrap();
        assert_eq!(
            first.public_key().peer_id(),
            second.public_key().peer_id(),
            "peer_id must be stable across restarts"
        );
    }

    #[test]
    fn corrupt_seed_is_replaced_not_fatal() {
        let store = InMemorySecretStore::default();
        store
            .store(accounts::DEVICE_KEYPAIR_SEED, b"not-32-bytes")
            .unwrap();
        let keypair = load_or_generate_device_keypair(&store).unwrap();
        assert!(!keypair.public_key().peer_id().is_empty());
        // The replacement seed was persisted.
        let stored = store.load(accounts::DEVICE_KEYPAIR_SEED).unwrap().unwrap();
        assert_eq!(stored.len(), 32);
    }

    #[test]
    fn peer_store_key_is_stable() {
        let store = InMemorySecretStore::default();
        let first = load_or_generate_peer_store_key(&store).unwrap();
        let second = load_or_generate_peer_store_key(&store).unwrap();
        assert_eq!(first, second);
    }
}
