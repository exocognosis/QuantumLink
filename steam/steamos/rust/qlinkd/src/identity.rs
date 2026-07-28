//! Persistent SteamOS device identity for the daemon.
//!
//! The Windows service loads a stable device keypair from the DPAPI-backed
//! secret store (`secret_store::load_or_generate_device_keypair`) and macOS
//! loads one from the Keychain. SteamOS has neither DPAPI nor Keychain, so the
//! daemon persists its ML-DSA device seed and peer-store envelope key as
//! `0600` files under the state directory, using the same `O_NOFOLLOW` +
//! atomic-rename discipline the network-ownership record uses.
//!
//! This identity is what a live mesh transport requires: the `peer_id` derived
//! from the device public key must match `MeshTransportConfig.local_peer_id`,
//! and the connector signs an `InboundIdentityAssertion` with the keypair so a
//! remote responder can verify it. The peer-store key protects the on-disk
//! `FilePeerStore` used for graceful degradation under rendezvous outage.
//!
//! Secrets never enter the tunnel runtime beyond the validated transport
//! configuration, matching the product boundary "the tunnel/runtime receives
//! only validated policy and registry configuration; it must not own wallet
//! secrets."

use qlink_core::crypto::DeviceKeypair;
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const DEVICE_SEED_FILE: &str = "device-identity.seed";
const PEER_STORE_KEY_FILE: &str = "peer-store.key";
/// Owner read/write only. Device secrets must never be group- or
/// world-readable, even transiently.
pub const SECRET_FILE_MODE: u32 = 0o600;
const SECRET_LEN: usize = 32;

/// A persistent device identity: the ML-DSA keypair that anchors this node's
/// `peer_id`, plus the 32-byte SHAKE256 envelope key for the encrypted peer
/// store.
#[derive(Debug)]
pub struct DeviceIdentity {
    keypair: DeviceKeypair,
    peer_store_key: [u8; SECRET_LEN],
}

impl DeviceIdentity {
    /// The stable `qlink_...` peer id derived from the device public key. This
    /// is the value that must be published to rendezvous and must match
    /// `MeshTransportConfig.local_peer_id`.
    pub fn peer_id(&self) -> String {
        self.keypair.public_key().peer_id()
    }

    pub fn keypair(&self) -> &DeviceKeypair {
        &self.keypair
    }

    /// The 32-byte peer-store envelope key. Callers base64-encode this for
    /// `MeshTransportConfig.peer_store_key_b64`.
    pub fn peer_store_key(&self) -> [u8; SECRET_LEN] {
        self.peer_store_key
    }
}

pub fn device_seed_path(state_dir: &Path) -> PathBuf {
    state_dir.join(DEVICE_SEED_FILE)
}

pub fn peer_store_key_path(state_dir: &Path) -> PathBuf {
    state_dir.join(PEER_STORE_KEY_FILE)
}

/// Loads the persistent device identity, generating and persisting a fresh
/// keypair + peer-store key on first run. The seed and key files are created
/// with `0600` permissions; existing files with looser permissions are
/// tightened on load.
pub fn load_or_generate_device_identity(state_dir: &Path) -> io::Result<DeviceIdentity> {
    std::fs::create_dir_all(state_dir)?;

    let seed = load_or_generate_secret(&device_seed_path(state_dir))?;
    let keypair = DeviceKeypair::from_seed(seed).map_err(|error| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("failed to load device keypair from persisted seed: {error}"),
        )
    })?;
    let peer_store_key = load_or_generate_secret(&peer_store_key_path(state_dir))?;

    Ok(DeviceIdentity {
        keypair,
        peer_store_key,
    })
}

fn load_or_generate_secret(path: &Path) -> io::Result<[u8; SECRET_LEN]> {
    match read_secret(path)? {
        Some(secret) => Ok(secret),
        None => {
            let mut secret = [0_u8; SECRET_LEN];
            getrandom::fill(&mut secret).map_err(|error| {
                io::Error::other(format!(
                    "OS randomness unavailable for device secret: {error}"
                ))
            })?;
            write_secret_atomically(path, &secret)?;
            Ok(secret)
        }
    }
}

fn read_secret(path: &Path) -> io::Result<Option<[u8; SECRET_LEN]>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err(io::Error::new(
                    ErrorKind::AlreadyExists,
                    format!(
                        "device secret path {} is not a regular file",
                        path.display()
                    ),
                ));
            }
            let mut file = open_secret_for_read(path)?;
            tighten_permissions(&file)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            let secret: [u8; SECRET_LEN] = bytes.as_slice().try_into().map_err(|_| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "device secret {} must be exactly {SECRET_LEN} bytes; got {}",
                        path.display(),
                        bytes.len()
                    ),
                )
            })?;
            Ok(Some(secret))
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn write_secret_atomically(path: &Path, secret: &[u8; SECRET_LEN]) -> io::Result<()> {
    let temp_path = secret_temp_path(path);
    let write_result = (|| {
        let mut file = open_secret_for_create(&temp_path)?;
        file.write_all(secret)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp_path, path)
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_result
}

fn secret_temp_path(path: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "secret".to_string());
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce))
}

#[cfg(unix)]
fn open_secret_for_read(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_secret_for_read(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new().read(true).open(path)
}

#[cfg(unix)]
fn open_secret_for_create(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(SECRET_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_secret_for_create(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(unix)]
fn tighten_permissions(file: &std::fs::File) -> io::Result<()> {
    let metadata = file.metadata()?;
    let mut permissions = metadata.permissions();
    if permissions.mode() & 0o777 != SECRET_FILE_MODE {
        permissions.set_mode(SECRET_FILE_MODE);
        file.set_permissions(permissions)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn tighten_permissions(_file: &std::fs::File) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_identity_is_generated_then_stable_across_reloads() {
        let temp = tempfile::tempdir().unwrap();
        let first = load_or_generate_device_identity(temp.path()).unwrap();
        let second = load_or_generate_device_identity(temp.path()).unwrap();

        assert_eq!(first.peer_id(), second.peer_id());
        assert!(first.peer_id().starts_with("qlink_"));
        assert_eq!(first.peer_store_key(), second.peer_store_key());
        assert!(first.keypair().seed().is_some());
    }

    #[test]
    fn device_identity_files_are_created_owner_only() {
        let temp = tempfile::tempdir().unwrap();
        let _identity = load_or_generate_device_identity(temp.path()).unwrap();

        for path in [
            device_seed_path(temp.path()),
            peer_store_key_path(temp.path()),
        ] {
            let metadata = std::fs::metadata(&path).unwrap();
            assert!(metadata.is_file(), "{} should be a file", path.display());
            #[cfg(unix)]
            assert_eq!(
                metadata.permissions().mode() & 0o777,
                SECRET_FILE_MODE,
                "{} should be 0600",
                path.display()
            );
        }
    }

    #[test]
    fn corrupt_length_secret_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path()).unwrap();
        std::fs::write(device_seed_path(temp.path()), b"too short").unwrap();

        let error = load_or_generate_device_identity(temp.path()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(error.to_string().contains("exactly 32 bytes"));
    }

    #[cfg(unix)]
    #[test]
    fn tightens_loose_permissions_on_load() {
        let temp = tempfile::tempdir().unwrap();
        let _first = load_or_generate_device_identity(temp.path()).unwrap();
        let seed_path = device_seed_path(temp.path());
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let _second = load_or_generate_device_identity(temp.path()).unwrap();

        let mode = std::fs::metadata(&seed_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, SECRET_FILE_MODE);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_secret_path_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path()).unwrap();
        let outside = temp.path().join("outside.seed");
        std::fs::write(&outside, [0_u8; SECRET_LEN]).unwrap();
        std::os::unix::fs::symlink(&outside, device_seed_path(temp.path())).unwrap();

        let error = load_or_generate_device_identity(temp.path()).unwrap_err();
        assert!(
            error.to_string().contains("O_NOFOLLOW")
                || error.raw_os_error() == Some(libc::ELOOP)
                || error.kind() == ErrorKind::AlreadyExists
        );
    }
}
