//! DPAPI-backed secret store — the Windows replacement for
//! `KeychainSecretStore.swift`.
//!
//! Each secret is wrapped with `CryptProtectData` using machine scope
//! (the service runs as LocalSystem and must read secrets before any
//! user logs on) plus a fixed application-entropy salt, then persisted
//! as one blob file per account under `%ProgramData%\QuantumLink\secrets\`.
//!
//! Defense layers:
//! 1. DPAPI machine-key encryption — nothing on disk is plaintext, and
//!    blobs cannot be decrypted on another machine.
//! 2. Directory ACL (applied by the installer): SYSTEM + Administrators
//!    only. Ordinary processes of the logged-on user cannot read the
//!    blobs at all.
//! 3. App entropy — a different LocalSystem service on the same host
//!    cannot decrypt without also knowing this constant (defense in
//!    depth, not a hard boundary).

use crate::secret_store::{SecretStore, SecretStoreError};
use std::path::PathBuf;
use windows::core::PWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE,
    CRYPTPROTECT_UI_FORBIDDEN,
};

/// App-specific DPAPI entropy. Changing this orphans every stored
/// secret — bump only with a migration.
const APP_ENTROPY: &[u8] = b"com.quantumlink.windows.secrets.v1";

pub struct DpapiSecretStore {
    directory: PathBuf,
}

impl DpapiSecretStore {
    pub fn new(directory: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&directory)?;
        Ok(Self { directory })
    }

    fn path_for(&self, account: &str) -> Result<PathBuf, SecretStoreError> {
        if account.is_empty()
            || !account
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(SecretStoreError::InvalidItem(format!(
                "account name {account:?} is not filesystem-safe"
            )));
        }
        Ok(self.directory.join(format!("{account}.dpapi")))
    }
}

impl SecretStore for DpapiSecretStore {
    fn store(&self, account: &str, data: &[u8]) -> Result<(), SecretStoreError> {
        let path = self.path_for(account)?;
        let protected = protect(data)?;
        // Atomic replace so a crash never leaves a half-written blob.
        let temp = path.with_extension("dpapi.tmp");
        std::fs::write(&temp, &protected)?;
        std::fs::rename(&temp, &path)?;
        Ok(())
    }

    fn load(&self, account: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        let path = self.path_for(account)?;
        let blob = match std::fs::read(&path) {
            Ok(blob) => blob,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        unprotect(&blob).map(Some)
    }

    fn delete(&self, account: &str) -> Result<(), SecretStoreError> {
        let path = self.path_for(account)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn protect(data: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut entropy = CRYPT_INTEGER_BLOB {
        cbData: APP_ENTROPY.len() as u32,
        pbData: APP_ENTROPY.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(
            &mut input,
            PWSTR::null(),
            Some(&mut entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
            &mut output,
        )
        .map_err(|error| SecretStoreError::Crypto(format!("CryptProtectData: {error}")))?;
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(Some(HLOCAL(output.pbData as *mut core::ffi::c_void)));
    }
    Ok(bytes)
}

fn unprotect(blob: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: blob.len() as u32,
        pbData: blob.as_ptr() as *mut u8,
    };
    let mut entropy = CRYPT_INTEGER_BLOB {
        cbData: APP_ENTROPY.len() as u32,
        pbData: APP_ENTROPY.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(
            &mut input,
            None,
            Some(&mut entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|error| SecretStoreError::Crypto(format!("CryptUnprotectData: {error}")))?;
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(Some(HLOCAL(output.pbData as *mut core::ffi::c_void)));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These run only on Windows CI — they exercise real DPAPI.
    #[test]
    fn round_trips_secret_on_same_machine() {
        let dir = tempfile::tempdir().unwrap();
        let store = DpapiSecretStore::new(dir.path().to_path_buf()).unwrap();
        store.store("device-keypair-seed", &[7_u8; 32]).unwrap();

        // On-disk blob must not contain the plaintext.
        let raw = std::fs::read(dir.path().join("device-keypair-seed.dpapi")).unwrap();
        assert!(!raw.windows(32).any(|window| window == [7_u8; 32]));

        let loaded = store.load("device-keypair-seed").unwrap().unwrap();
        assert_eq!(loaded, vec![7_u8; 32]);

        store.delete("device-keypair-seed").unwrap();
        assert!(store.load("device-keypair-seed").unwrap().is_none());
    }

    #[test]
    fn rejects_path_traversal_account_names() {
        let dir = tempfile::tempdir().unwrap();
        let store = DpapiSecretStore::new(dir.path().to_path_buf()).unwrap();
        assert!(store.store("../escape", b"x").is_err());
        assert!(store.store("a\\b", b"x").is_err());
        assert!(store.store("", b"x").is_err());
    }
}
