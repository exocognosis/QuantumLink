use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const REGISTRY_SCHEMA_VERSION: u8 = 2;
pub const INITIAL_IDENTITY_REVISION: u64 = 1;
pub const MIN_PEER_RECORD_TTL_SECONDS: u64 = 30;
pub const MAX_PEER_RECORD_TTL_SECONDS: u64 = 86_400;

const CONTRACT_DOMAIN: &str = "quantumlink-node-registry-v2";
const DEVICE_AUTHORIZATION_PURPOSE: &str = "authorize-stable-identity-binding";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableIdentityRecord {
    pub schema_version: u8,
    pub peer_id: String,
    pub owner_daddr: String,
    pub device_public_key_hash_hex: String,
    pub node_signing_public_key_hash_hex: String,
    pub status: IdentityStatus,
    pub identity_revision: u64,
    pub authorization_expires_at: Option<u64>,
    pub max_peer_record_ttl_seconds: u64,
    pub mesh_scope_hash_hex: Option<String>,
    pub metadata_commitment_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletAuthorization {
    pub actor_public_key_hex: String,
    pub actor_signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorization {
    pub device_public_key_algorithm: String,
    pub device_public_key_hex: String,
    pub device_signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEvent {
    pub peer_id: String,
    pub event_type: String,
    pub actor_daddr: String,
    pub identity_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryError {
    #[error("unsupported schema version")]
    UnsupportedSchemaVersion,
    #[error("unauthorized")]
    Unauthorized,
    #[error("identity not found")]
    NotFound,
    #[error("invalid hex field")]
    InvalidHex,
    #[error("invalid peer id")]
    InvalidPeerId,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("identity already registered")]
    AlreadyRegistered,
    #[error("invalid identity revision")]
    InvalidRevision,
    #[error("identity revoked")]
    Revoked,
    #[error("invalid status transition")]
    InvalidStatusTransition,
    #[error("policy value out of bounds")]
    PolicyOutOfBounds,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuantumLinkNodeRegistryV2 {
    identities: BTreeMap<String, StableIdentityRecord>,
    events: Vec<RegistryEvent>,
}

impl QuantumLinkNodeRegistryV2 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_identity(
        &mut self,
        record: StableIdentityRecord,
        wallet_authorization: WalletAuthorization,
        device_authorization: DeviceAuthorization,
    ) -> Result<(), RegistryError> {
        validate_record(&record)?;
        if record.identity_revision != INITIAL_IDENTITY_REVISION {
            return Err(RegistryError::InvalidRevision);
        }
        if record.status != IdentityStatus::Active {
            return Err(RegistryError::InvalidStatusTransition);
        }
        if self.identities.contains_key(&record.peer_id) {
            return Err(RegistryError::AlreadyRegistered);
        }

        let actor_daddr =
            verified_actor_daddr(&wallet_authorization, &canonical_register_payload(&record)?)?;
        require_matching_owner(&record.owner_daddr, &actor_daddr)?;
        validate_device_authorization(&record, &device_authorization)?;

        self.events.push(RegistryEvent {
            peer_id: record.peer_id.clone(),
            event_type: "registered".to_string(),
            actor_daddr,
            identity_revision: record.identity_revision,
        });
        self.identities.insert(record.peer_id.clone(), record);
        Ok(())
    }

    pub fn update_identity(
        &mut self,
        record: StableIdentityRecord,
        wallet_authorization: WalletAuthorization,
        device_authorization: DeviceAuthorization,
    ) -> Result<(), RegistryError> {
        validate_record(&record)?;
        if record.status == IdentityStatus::Revoked {
            return Err(RegistryError::InvalidStatusTransition);
        }

        let existing = self
            .identities
            .get(&record.peer_id)
            .ok_or(RegistryError::NotFound)?;
        if existing.status == IdentityStatus::Revoked {
            return Err(RegistryError::Revoked);
        }
        if record.owner_daddr != existing.owner_daddr {
            return Err(RegistryError::Unauthorized);
        }
        require_next_revision(existing.identity_revision, record.identity_revision)?;

        let actor_daddr =
            verified_actor_daddr(&wallet_authorization, &canonical_update_payload(&record)?)?;
        require_matching_owner(&existing.owner_daddr, &actor_daddr)?;
        validate_device_authorization(&record, &device_authorization)?;

        self.events.push(RegistryEvent {
            peer_id: record.peer_id.clone(),
            event_type: "updated".to_string(),
            actor_daddr,
            identity_revision: record.identity_revision,
        });
        self.identities.insert(record.peer_id.clone(), record);
        Ok(())
    }

    pub fn revoke_identity(
        &mut self,
        peer_id: &str,
        identity_revision: u64,
        wallet_authorization: WalletAuthorization,
    ) -> Result<(), RegistryError> {
        validate_peer_id(peer_id)?;
        let existing = self
            .identities
            .get(peer_id)
            .ok_or(RegistryError::NotFound)?;
        if existing.status == IdentityStatus::Revoked {
            return Err(RegistryError::Revoked);
        }
        require_next_revision(existing.identity_revision, identity_revision)?;

        let actor_daddr = verified_actor_daddr(
            &wallet_authorization,
            &canonical_revoke_payload(peer_id, identity_revision)?,
        )?;
        require_matching_owner(&existing.owner_daddr, &actor_daddr)?;

        let record = self
            .identities
            .get_mut(peer_id)
            .ok_or(RegistryError::NotFound)?;
        record.status = IdentityStatus::Revoked;
        record.identity_revision = identity_revision;
        self.events.push(RegistryEvent {
            peer_id: peer_id.to_string(),
            event_type: "revoked".to_string(),
            actor_daddr,
            identity_revision,
        });
        Ok(())
    }

    pub fn suspend_identity(
        &mut self,
        peer_id: &str,
        identity_revision: u64,
        wallet_authorization: WalletAuthorization,
    ) -> Result<(), RegistryError> {
        validate_peer_id(peer_id)?;
        let existing = self
            .identities
            .get(peer_id)
            .ok_or(RegistryError::NotFound)?;
        if existing.status == IdentityStatus::Revoked {
            return Err(RegistryError::Revoked);
        }
        require_next_revision(existing.identity_revision, identity_revision)?;
        let actor_daddr = verified_actor_daddr(
            &wallet_authorization,
            &canonical_suspend_payload(peer_id, identity_revision)?,
        )?;
        require_matching_owner(&existing.owner_daddr, &actor_daddr)?;

        let record = self
            .identities
            .get_mut(peer_id)
            .ok_or(RegistryError::NotFound)?;
        record.status = IdentityStatus::Suspended;
        record.identity_revision = identity_revision;
        self.events.push(RegistryEvent {
            peer_id: peer_id.to_string(),
            event_type: "suspended".to_string(),
            actor_daddr,
            identity_revision,
        });
        Ok(())
    }

    pub fn get_identity(&self, peer_id: &str) -> Option<StableIdentityRecord> {
        self.identities.get(peer_id).cloned()
    }

    pub fn events(&self, peer_id: &str) -> Vec<RegistryEvent> {
        self.events
            .iter()
            .filter(|event| event.peer_id == peer_id)
            .cloned()
            .collect()
    }
}

pub fn validate_record(record: &StableIdentityRecord) -> Result<(), RegistryError> {
    if record.schema_version != REGISTRY_SCHEMA_VERSION {
        return Err(RegistryError::UnsupportedSchemaVersion);
    }
    validate_peer_id(&record.peer_id)?;
    validate_hex32(&record.device_public_key_hash_hex)?;
    validate_hex32(&record.node_signing_public_key_hash_hex)?;
    if let Some(value) = record.mesh_scope_hash_hex.as_deref() {
        validate_hex32(value)?;
    }
    if let Some(value) = record.metadata_commitment_hex.as_deref() {
        validate_hex32(value)?;
    }
    if record.owner_daddr.is_empty()
        || record.identity_revision == 0
        || record.authorization_expires_at == Some(0)
        || !(MIN_PEER_RECORD_TTL_SECONDS..=MAX_PEER_RECORD_TTL_SECONDS)
            .contains(&record.max_peer_record_ttl_seconds)
    {
        return Err(RegistryError::PolicyOutOfBounds);
    }
    Ok(())
}

pub fn canonical_register_payload(record: &StableIdentityRecord) -> Result<Vec<u8>, RegistryError> {
    canonical_record_payload("register_identity", record)
}

pub fn canonical_update_payload(record: &StableIdentityRecord) -> Result<Vec<u8>, RegistryError> {
    canonical_record_payload("update_identity", record)
}

pub fn canonical_device_authorization_payload(
    record: &StableIdentityRecord,
) -> Result<Vec<u8>, RegistryError> {
    #[derive(Serialize)]
    struct Payload<'a> {
        contract: &'static str,
        schema_version: u8,
        purpose: &'static str,
        binding: &'a StableIdentityRecord,
    }

    serde_json::to_vec(&Payload {
        contract: CONTRACT_DOMAIN,
        schema_version: REGISTRY_SCHEMA_VERSION,
        purpose: DEVICE_AUTHORIZATION_PURPOSE,
        binding: record,
    })
    .map_err(|_| RegistryError::InvalidSignature)
}

pub fn canonical_revoke_payload(
    peer_id: &str,
    identity_revision: u64,
) -> Result<Vec<u8>, RegistryError> {
    #[derive(Serialize)]
    struct Payload<'a> {
        contract: &'static str,
        schema_version: u8,
        operation: &'static str,
        peer_id: &'a str,
        identity_revision: u64,
    }

    validate_peer_id(peer_id)?;
    serde_json::to_vec(&Payload {
        contract: CONTRACT_DOMAIN,
        schema_version: REGISTRY_SCHEMA_VERSION,
        operation: "revoke_identity",
        peer_id,
        identity_revision,
    })
    .map_err(|_| RegistryError::InvalidSignature)
}

pub fn canonical_suspend_payload(
    peer_id: &str,
    identity_revision: u64,
) -> Result<Vec<u8>, RegistryError> {
    canonical_status_payload("suspend_identity", peer_id, identity_revision)
}

fn canonical_status_payload(
    operation: &'static str,
    peer_id: &str,
    identity_revision: u64,
) -> Result<Vec<u8>, RegistryError> {
    #[derive(Serialize)]
    struct Payload<'a> {
        contract: &'static str,
        schema_version: u8,
        operation: &'static str,
        peer_id: &'a str,
        identity_revision: u64,
    }

    validate_peer_id(peer_id)?;
    serde_json::to_vec(&Payload {
        contract: CONTRACT_DOMAIN,
        schema_version: REGISTRY_SCHEMA_VERSION,
        operation,
        peer_id,
        identity_revision,
    })
    .map_err(|_| RegistryError::InvalidSignature)
}

fn canonical_record_payload(
    operation: &'static str,
    record: &StableIdentityRecord,
) -> Result<Vec<u8>, RegistryError> {
    #[derive(Serialize)]
    struct Payload<'a> {
        contract: &'static str,
        schema_version: u8,
        operation: &'static str,
        record: &'a StableIdentityRecord,
    }

    serde_json::to_vec(&Payload {
        contract: CONTRACT_DOMAIN,
        schema_version: REGISTRY_SCHEMA_VERSION,
        operation,
        record,
    })
    .map_err(|_| RegistryError::InvalidSignature)
}

fn validate_device_authorization(
    record: &StableIdentityRecord,
    authorization: &DeviceAuthorization,
) -> Result<(), RegistryError> {
    if authorization.device_public_key_algorithm != "ML-DSA-65" {
        return Err(RegistryError::InvalidSignature);
    }

    let public_key = decode_hex(&authorization.device_public_key_hex)?;
    let signature = decode_hex(&authorization.device_signature_hex)?;
    if quantumlink_peer_id(&public_key) != record.peer_id {
        return Err(RegistryError::InvalidPeerId);
    }
    if device_public_key_hash_hex(&authorization.device_public_key_algorithm, &public_key)?
        != record.device_public_key_hash_hex
    {
        return Err(RegistryError::InvalidSignature);
    }

    let payload = canonical_device_authorization_payload(record)?;
    if !verify_quantumlink_mldsa65_signature(&public_key, &payload, &signature)? {
        return Err(RegistryError::InvalidSignature);
    }
    Ok(())
}

fn require_matching_owner(expected: &str, actual: &str) -> Result<(), RegistryError> {
    if expected == actual {
        Ok(())
    } else {
        Err(RegistryError::Unauthorized)
    }
}

fn require_next_revision(current: u64, proposed: u64) -> Result<(), RegistryError> {
    if current.checked_add(1) == Some(proposed) {
        Ok(())
    } else {
        Err(RegistryError::InvalidRevision)
    }
}

fn validate_peer_id(peer_id: &str) -> Result<(), RegistryError> {
    if peer_id.starts_with("qlink_")
        && peer_id.len() > "qlink_".len()
        && peer_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Ok(())
    } else {
        Err(RegistryError::InvalidPeerId)
    }
}

fn validate_hex32(value: &str) -> Result<(), RegistryError> {
    if value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(RegistryError::InvalidHex)
    }
}

fn quantumlink_peer_id(public_key: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let digest = Sha256::digest(public_key);
    format!("qlink_{}", URL_SAFE_NO_PAD.encode(&digest[..16]))
}

fn device_public_key_hash_hex(algorithm: &str, public_key: &[u8]) -> Result<String, RegistryError> {
    #[derive(Serialize)]
    struct DevicePublicKey<'a> {
        algorithm: &'a str,
        bytes: &'a [u8],
    }

    let encoded = serde_json::to_vec(&DevicePublicKey {
        algorithm,
        bytes: public_key,
    })
    .map_err(|_| RegistryError::InvalidSignature)?;
    Ok(hex_encode(&Sha256::digest(encoded)))
}

fn verify_quantumlink_mldsa65_signature(
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<bool, RegistryError> {
    use ml_dsa::{
        signature::Verifier, EncodedSignature, EncodedVerifyingKey, MlDsa65,
        Signature as MlDsaSignature, VerifyingKey as MlDsaVerifyingKey,
    };

    let verifying_key_bytes = EncodedVerifyingKey::<MlDsa65>::try_from(public_key)
        .map_err(|_| RegistryError::InvalidSignature)?;
    let verifying_key = MlDsaVerifyingKey::<MlDsa65>::decode(&verifying_key_bytes);
    let signature_bytes = EncodedSignature::<MlDsa65>::try_from(signature)
        .map_err(|_| RegistryError::InvalidSignature)?;
    let signature = MlDsaSignature::<MlDsa65>::decode(&signature_bytes)
        .ok_or(RegistryError::InvalidSignature)?;
    Ok(verifying_key.verify(payload, &signature).is_ok())
}

fn verified_actor_daddr(
    authorization: &WalletAuthorization,
    payload: &[u8],
) -> Result<String, RegistryError> {
    let public_key = decode_hex(&authorization.actor_public_key_hex)?;
    let signature = decode_hex(&authorization.actor_signature_hex)?;
    if !verify_wallet_mldsa65_signature(&public_key, payload, &signature)? {
        return Err(RegistryError::InvalidSignature);
    }
    daddr_from_public_key(&public_key)
}

#[cfg(not(target_arch = "wasm32"))]
fn verify_wallet_mldsa65_signature(
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<bool, RegistryError> {
    dytallix_core::signature::verify_mldsa65(public_key, payload, signature)
        .map_err(|_| RegistryError::InvalidSignature)
}

#[cfg(not(target_arch = "wasm32"))]
fn daddr_from_public_key(public_key: &[u8]) -> Result<String, RegistryError> {
    dytallix_core::address::DAddr::from_public_key(public_key)
        .map(|address| address.to_string())
        .map_err(|_| RegistryError::InvalidSignature)
}

#[cfg(target_arch = "wasm32")]
fn verify_wallet_mldsa65_signature(
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<bool, RegistryError> {
    use fips204::traits::{SerDes, Verifier};

    if public_key.len() != 1_952 || signature.len() != fips204::ml_dsa_65::SIG_LEN {
        return Err(RegistryError::InvalidSignature);
    }
    let public_key_bytes = public_key
        .try_into()
        .map_err(|_| RegistryError::InvalidSignature)?;
    let public_key = fips204::ml_dsa_65::PublicKey::try_from_bytes(public_key_bytes)
        .map_err(|_| RegistryError::InvalidSignature)?;
    let signature_bytes = signature
        .try_into()
        .map_err(|_| RegistryError::InvalidSignature)?;
    Ok(public_key.verify(payload, &signature_bytes, &[]))
}

#[cfg(target_arch = "wasm32")]
fn daddr_from_public_key(public_key: &[u8]) -> Result<String, RegistryError> {
    use bech32::{Bech32m, Hrp};

    if public_key.len() != 1_952 {
        return Err(RegistryError::InvalidSignature);
    }
    let hrp = Hrp::parse("dytallix").map_err(|_| RegistryError::InvalidSignature)?;
    bech32::encode::<Bech32m>(hrp, blake3::hash(public_key).as_bytes())
        .map_err(|_| RegistryError::InvalidSignature)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, RegistryError> {
    let bytes = value.as_bytes();
    if bytes.len() % 2 != 0 || !bytes.iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RegistryError::InvalidHex);
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Ok((hex_value(pair[0])? << 4) | hex_value(pair[1])?))
        .collect()
}

fn hex_value(byte: u8) -> Result<u8, RegistryError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(RegistryError::InvalidHex),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
const MAX_STORAGE_VALUE_SIZE: usize = 16 * 1024;

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
fn identity_storage_key(peer_id: &str) -> Result<Vec<u8>, RegistryError> {
    validate_peer_id(peer_id)?;
    Ok(format!("v2:identity:{peer_id}").into_bytes())
}

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
fn events_storage_key(peer_id: &str) -> Result<Vec<u8>, RegistryError> {
    validate_peer_id(peer_id)?;
    Ok(format!("v2:events:{peer_id}").into_bytes())
}

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
fn encode_identity(record: &StableIdentityRecord) -> Result<Vec<u8>, String> {
    serde_json::to_vec(record).map_err(|error| format!("identity encode failed: {error}"))
}

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
fn decode_identity(value: &[u8]) -> Result<StableIdentityRecord, String> {
    serde_json::from_slice(value).map_err(|error| format!("identity decode failed: {error}"))
}

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
fn encode_events(events: &[RegistryEvent]) -> Result<Vec<u8>, String> {
    serde_json::to_vec(events).map_err(|error| format!("events encode failed: {error}"))
}

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
fn decode_events(value: &[u8]) -> Result<Vec<RegistryEvent>, String> {
    serde_json::from_slice(value).map_err(|error| format!("events decode failed: {error}"))
}

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
fn validate_storage_value_size(value: &[u8]) -> Result<(), String> {
    if value.len() > MAX_STORAGE_VALUE_SIZE {
        Err(format!(
            "storage value exceeds storage limit: {} bytes",
            value.len()
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm_contract {
    use super::*;
    use serde::de::DeserializeOwned;

    const MAX_INPUT_BYTES: usize = 64 * 1024;
    const MAX_RETURN_BYTES: usize = 1024;
    const MAX_RETURN_PAYLOAD_BYTES: usize = MAX_RETURN_BYTES - 4;

    #[link(wasm_import_module = "env")]
    extern "C" {
        fn storage_get(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32) -> i32;
        fn storage_set(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32) -> i32;
        fn read_input(out_ptr: i32, max_len: i32) -> i32;
        fn write_output(ptr: i32, len: i32);
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RegisterRequest {
        record: StableIdentityRecord,
        #[serde(flatten)]
        wallet_authorization: WalletAuthorization,
        #[serde(flatten)]
        device_authorization: DeviceAuthorization,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct UpdateRequest {
        record: StableIdentityRecord,
        #[serde(flatten)]
        wallet_authorization: WalletAuthorization,
        #[serde(flatten)]
        device_authorization: DeviceAuthorization,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RevokeRequest {
        peer_id: String,
        identity_revision: u64,
        #[serde(flatten)]
        wallet_authorization: WalletAuthorization,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SuspendRequest {
        peer_id: String,
        identity_revision: u64,
        #[serde(flatten)]
        wallet_authorization: WalletAuthorization,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PeerRequest {
        peer_id: String,
    }

    #[derive(Serialize)]
    struct ContractResponse {
        ok: bool,
        identity: Option<StableIdentityRecord>,
        events: Vec<RegistryEvent>,
        error: Option<String>,
    }

    #[no_mangle]
    pub extern "C" fn register_identity() {
        let response = read_host_request::<RegisterRequest>().and_then(|request| {
            let peer_id = request.record.peer_id.clone();
            with_peer_state(&peer_id, |registry| {
                registry.register_identity(
                    request.record,
                    request.wallet_authorization,
                    request.device_authorization,
                )
            })
        });
        write_host_result(response);
    }

    #[no_mangle]
    pub extern "C" fn update_identity() {
        let response = read_host_request::<UpdateRequest>().and_then(|request| {
            let peer_id = request.record.peer_id.clone();
            with_peer_state(&peer_id, |registry| {
                registry.update_identity(
                    request.record,
                    request.wallet_authorization,
                    request.device_authorization,
                )
            })
        });
        write_host_result(response);
    }

    #[no_mangle]
    pub extern "C" fn revoke_identity() {
        let response = read_host_request::<RevokeRequest>().and_then(|request| {
            with_peer_state(&request.peer_id, |registry| {
                registry.revoke_identity(
                    &request.peer_id,
                    request.identity_revision,
                    request.wallet_authorization,
                )
            })
        });
        write_host_result(response);
    }

    #[no_mangle]
    pub extern "C" fn suspend_identity() {
        let response = read_host_request::<SuspendRequest>().and_then(|request| {
            with_peer_state(&request.peer_id, |registry| {
                registry.suspend_identity(
                    &request.peer_id,
                    request.identity_revision,
                    request.wallet_authorization,
                )
            })
        });
        write_host_result(response);
    }

    #[no_mangle]
    pub extern "C" fn get_identity() {
        let response = read_host_request::<PeerRequest>().and_then(|request| {
            load_identity(&request.peer_id).map(|identity| ContractResponse {
                ok: true,
                identity,
                events: Vec::new(),
                error: None,
            })
        });
        write_host_result(response);
    }

    #[no_mangle]
    pub extern "C" fn events() {
        let response = read_host_request::<PeerRequest>().and_then(|request| {
            load_events(&request.peer_id).map(|events| ContractResponse {
                ok: true,
                identity: None,
                events,
                error: None,
            })
        });
        write_host_result(response);
    }

    fn with_peer_state(
        peer_id: &str,
        action: impl FnOnce(&mut QuantumLinkNodeRegistryV2) -> Result<(), RegistryError>,
    ) -> Result<ContractResponse, String> {
        let mut registry = QuantumLinkNodeRegistryV2::new();
        if let Some(identity) = load_identity(peer_id)? {
            registry.identities.insert(peer_id.to_string(), identity);
        }
        registry.events = load_events(peer_id)?;
        action(&mut registry).map_err(|error| error.to_string())?;

        let identity = registry
            .get_identity(peer_id)
            .ok_or_else(|| "operation did not produce identity state".to_string())?;
        let events = registry.events(peer_id);
        save_peer_state(peer_id, &identity, &events)?;
        Ok(ContractResponse {
            ok: true,
            identity: None,
            events: Vec::new(),
            error: None,
        })
    }

    fn load_identity(peer_id: &str) -> Result<Option<StableIdentityRecord>, String> {
        let key = identity_storage_key(peer_id).map_err(|error| error.to_string())?;
        storage_get_raw(&key)?
            .map(|value| decode_identity(&value))
            .transpose()
    }

    fn load_events(peer_id: &str) -> Result<Vec<RegistryEvent>, String> {
        let key = events_storage_key(peer_id).map_err(|error| error.to_string())?;
        storage_get_raw(&key)?
            .map(|value| decode_events(&value))
            .transpose()
            .map(|events| events.unwrap_or_default())
    }

    fn save_peer_state(
        peer_id: &str,
        identity: &StableIdentityRecord,
        events: &[RegistryEvent],
    ) -> Result<(), String> {
        let identity_key = identity_storage_key(peer_id).map_err(|error| error.to_string())?;
        let events_key = events_storage_key(peer_id).map_err(|error| error.to_string())?;
        let identity_value = encode_identity(identity)?;
        let events_value = encode_events(events)?;
        validate_storage_value_size(&identity_value)?;
        validate_storage_value_size(&events_value)?;
        storage_set_raw(&identity_key, &identity_value)?;
        storage_set_raw(&events_key, &events_value)
    }

    fn read_host_request<T: DeserializeOwned>() -> Result<T, String> {
        let mut input = vec![0u8; MAX_INPUT_BYTES];
        let len = unsafe { read_input(input.as_mut_ptr() as i32, input.len() as i32) };
        if len < 0 {
            return Err(format!("read_input failed with code {len}"));
        }
        let len = len as usize;
        if len > MAX_INPUT_BYTES {
            return Err(format!(
                "read_input returned oversized payload: {len} bytes"
            ));
        }
        input.truncate(len);
        serde_json::from_slice(&input).map_err(|error| error.to_string())
    }

    fn storage_get_raw(key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let mut value = vec![0u8; MAX_STORAGE_VALUE_SIZE];
        let len = unsafe {
            storage_get(
                key.as_ptr() as i32,
                key.len() as i32,
                value.as_mut_ptr() as i32,
                value.len() as i32,
            )
        };
        if len <= 0 {
            return Ok(None);
        }
        let len = len as usize;
        if len > MAX_STORAGE_VALUE_SIZE {
            return Err(format!("storage_get returned oversized value: {len} bytes"));
        }
        value.truncate(len);
        Ok(Some(value))
    }

    fn storage_set_raw(key: &[u8], value: &[u8]) -> Result<(), String> {
        validate_storage_value_size(value)?;
        let status = unsafe {
            storage_set(
                key.as_ptr() as i32,
                key.len() as i32,
                value.as_ptr() as i32,
                value.len() as i32,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(format!("storage_set failed with code {status}"))
        }
    }

    fn write_host_result(result: Result<ContractResponse, String>) {
        let response = result.unwrap_or_else(|error| ContractResponse {
            ok: false,
            identity: None,
            events: Vec::new(),
            error: Some(error),
        });
        let mut payload = serde_json::to_vec(&response).unwrap_or_else(|_| {
            b"{\"ok\":false,\"identity\":null,\"events\":[],\"error\":\"serialization failed\"}"
                .to_vec()
        });
        if payload.len() > MAX_RETURN_PAYLOAD_BYTES {
            payload =
                b"{\"ok\":false,\"identity\":null,\"events\":[],\"error\":\"response too large\"}"
                    .to_vec();
        }
        unsafe { write_output(payload.as_ptr() as i32, payload.len() as i32) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dytallix_core::{address::DAddr, keypair::DytallixKeypair};
    use ml_dsa::{
        signature::{Keypair, Signer},
        KeyGen, MlDsa65, Signature as MlDsaSignature,
    };

    struct Device {
        signing_key: ml_dsa::SigningKey<MlDsa65>,
        public_key: Vec<u8>,
    }

    fn make_device(seed_byte: u8) -> Device {
        let seed = ml_dsa::B32::try_from([seed_byte; 32].as_slice()).unwrap();
        let signing_key = MlDsa65::from_seed(&seed);
        let public_key = signing_key.verifying_key().encode().as_slice().to_vec();
        Device {
            signing_key,
            public_key,
        }
    }

    fn owner_daddr(owner: &DytallixKeypair) -> String {
        DAddr::from_public_key(owner.public_key())
            .unwrap()
            .to_string()
    }

    fn record(owner: &DytallixKeypair, device: &Device) -> StableIdentityRecord {
        StableIdentityRecord {
            schema_version: REGISTRY_SCHEMA_VERSION,
            peer_id: quantumlink_peer_id(&device.public_key),
            owner_daddr: owner_daddr(owner),
            device_public_key_hash_hex: device_public_key_hash_hex("ML-DSA-65", &device.public_key)
                .unwrap(),
            node_signing_public_key_hash_hex: "22".repeat(32),
            status: IdentityStatus::Active,
            identity_revision: INITIAL_IDENTITY_REVISION,
            authorization_expires_at: Some(4_102_444_800),
            max_peer_record_ttl_seconds: 300,
            mesh_scope_hash_hex: Some("33".repeat(32)),
            metadata_commitment_hex: Some("44".repeat(32)),
        }
    }

    fn device_authorization(device: &Device, record: &StableIdentityRecord) -> DeviceAuthorization {
        let payload = canonical_device_authorization_payload(record).unwrap();
        let signature: MlDsaSignature<MlDsa65> = device.signing_key.sign(&payload);
        DeviceAuthorization {
            device_public_key_algorithm: "ML-DSA-65".to_string(),
            device_public_key_hex: hex_encode(&device.public_key),
            device_signature_hex: hex_encode(signature.encode().as_slice()),
        }
    }

    fn wallet_authorization(owner: &DytallixKeypair, payload: &[u8]) -> WalletAuthorization {
        WalletAuthorization {
            actor_public_key_hex: hex_encode(owner.public_key()),
            actor_signature_hex: hex_encode(&owner.sign(payload).unwrap()),
        }
    }

    fn register(
        registry: &mut QuantumLinkNodeRegistryV2,
        owner: &DytallixKeypair,
        device: &Device,
        record: &StableIdentityRecord,
    ) -> Result<(), RegistryError> {
        registry.register_identity(
            record.clone(),
            wallet_authorization(owner, &canonical_register_payload(record).unwrap()),
            device_authorization(device, record),
        )
    }

    fn update(
        registry: &mut QuantumLinkNodeRegistryV2,
        owner: &DytallixKeypair,
        device: &Device,
        record: &StableIdentityRecord,
    ) -> Result<(), RegistryError> {
        registry.update_identity(
            record.clone(),
            wallet_authorization(owner, &canonical_update_payload(record).unwrap()),
            device_authorization(device, record),
        )
    }

    #[test]
    fn owner_can_register_update_and_revoke_stable_identity() {
        let owner = DytallixKeypair::generate();
        let device = make_device(1);
        let initial = record(&owner, &device);
        let mut registry = QuantumLinkNodeRegistryV2::new();
        register(&mut registry, &owner, &device, &initial).unwrap();

        let mut updated = initial.clone();
        updated.identity_revision = 2;
        updated.status = IdentityStatus::Suspended;
        updated.max_peer_record_ttl_seconds = 600;
        update(&mut registry, &owner, &device, &updated).unwrap();

        registry
            .revoke_identity(
                &updated.peer_id,
                3,
                wallet_authorization(
                    &owner,
                    &canonical_revoke_payload(&updated.peer_id, 3).unwrap(),
                ),
            )
            .unwrap();

        let stored = registry.get_identity(&updated.peer_id).unwrap();
        assert_eq!(stored.status, IdentityStatus::Revoked);
        assert_eq!(stored.identity_revision, 3);
        assert_eq!(
            registry
                .events(&updated.peer_id)
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            ["registered", "updated", "revoked"]
        );
    }

    #[test]
    fn owner_can_suspend_without_compromised_device_cooperation() {
        let owner = DytallixKeypair::generate();
        let attacker = DytallixKeypair::generate();
        let device = make_device(13);
        let initial = record(&owner, &device);
        let mut registry = QuantumLinkNodeRegistryV2::new();
        register(&mut registry, &owner, &device, &initial).unwrap();

        assert_eq!(
            registry.suspend_identity(
                &initial.peer_id,
                2,
                wallet_authorization(
                    &attacker,
                    &canonical_suspend_payload(&initial.peer_id, 2).unwrap(),
                ),
            ),
            Err(RegistryError::Unauthorized)
        );
        registry
            .suspend_identity(
                &initial.peer_id,
                2,
                wallet_authorization(
                    &owner,
                    &canonical_suspend_payload(&initial.peer_id, 2).unwrap(),
                ),
            )
            .unwrap();

        let suspended = registry.get_identity(&initial.peer_id).unwrap();
        assert_eq!(suspended.status, IdentityStatus::Suspended);
        assert_eq!(suspended.identity_revision, 2);

        let mut reactivated = suspended;
        reactivated.status = IdentityStatus::Active;
        reactivated.identity_revision = 3;
        update(&mut registry, &owner, &device, &reactivated).unwrap();
        assert_eq!(
            registry.get_identity(&initial.peer_id).unwrap().status,
            IdentityStatus::Active
        );
    }

    #[test]
    fn wrong_wallet_cannot_register_update_or_revoke() {
        let owner = DytallixKeypair::generate();
        let attacker = DytallixKeypair::generate();
        let device = make_device(2);
        let initial = record(&owner, &device);
        let mut registry = QuantumLinkNodeRegistryV2::new();

        assert_eq!(
            register(&mut registry, &attacker, &device, &initial),
            Err(RegistryError::Unauthorized)
        );
        register(&mut registry, &owner, &device, &initial).unwrap();

        let mut updated = initial.clone();
        updated.identity_revision = 2;
        assert_eq!(
            update(&mut registry, &attacker, &device, &updated),
            Err(RegistryError::Unauthorized)
        );
        assert_eq!(
            registry.revoke_identity(
                &initial.peer_id,
                2,
                wallet_authorization(
                    &attacker,
                    &canonical_revoke_payload(&initial.peer_id, 2).unwrap(),
                ),
            ),
            Err(RegistryError::Unauthorized)
        );
    }

    #[test]
    fn wrong_device_key_and_device_tampering_are_rejected() {
        let owner = DytallixKeypair::generate();
        let device = make_device(3);
        let wrong_device = make_device(4);
        let initial = record(&owner, &device);
        let mut registry = QuantumLinkNodeRegistryV2::new();

        assert_eq!(
            register(&mut registry, &owner, &wrong_device, &initial),
            Err(RegistryError::InvalidPeerId)
        );

        let wallet = wallet_authorization(&owner, &canonical_register_payload(&initial).unwrap());
        let mut tampered = initial.clone();
        tampered.max_peer_record_ttl_seconds += 1;
        assert_eq!(
            registry.register_identity(tampered, wallet, device_authorization(&device, &initial),),
            Err(RegistryError::InvalidSignature)
        );
    }

    #[test]
    fn wallet_payload_tampering_is_rejected() {
        let owner = DytallixKeypair::generate();
        let device = make_device(5);
        let initial = record(&owner, &device);
        let wallet = wallet_authorization(&owner, &canonical_register_payload(&initial).unwrap());
        let mut tampered = initial.clone();
        tampered.metadata_commitment_hex = Some("55".repeat(32));

        assert_eq!(
            QuantumLinkNodeRegistryV2::new().register_identity(
                tampered.clone(),
                wallet,
                device_authorization(&device, &tampered),
            ),
            Err(RegistryError::InvalidSignature)
        );
    }

    #[test]
    fn revisions_must_be_exactly_monotonic() {
        let owner = DytallixKeypair::generate();
        let device = make_device(6);
        let initial = record(&owner, &device);
        let mut registry = QuantumLinkNodeRegistryV2::new();
        register(&mut registry, &owner, &device, &initial).unwrap();

        for invalid_revision in [1, 3] {
            let mut updated = initial.clone();
            updated.identity_revision = invalid_revision;
            assert_eq!(
                update(&mut registry, &owner, &device, &updated),
                Err(RegistryError::InvalidRevision)
            );
        }

        let mut updated = initial;
        updated.identity_revision = 2;
        update(&mut registry, &owner, &device, &updated).unwrap();
    }

    #[test]
    fn revocation_is_terminal() {
        let owner = DytallixKeypair::generate();
        let device = make_device(7);
        let initial = record(&owner, &device);
        let peer_id = initial.peer_id.clone();
        let mut registry = QuantumLinkNodeRegistryV2::new();
        register(&mut registry, &owner, &device, &initial).unwrap();
        registry
            .revoke_identity(
                &peer_id,
                2,
                wallet_authorization(&owner, &canonical_revoke_payload(&peer_id, 2).unwrap()),
            )
            .unwrap();

        let mut attempted_reactivation = registry.get_identity(&peer_id).unwrap();
        attempted_reactivation.status = IdentityStatus::Active;
        attempted_reactivation.identity_revision = 3;
        assert_eq!(
            update(&mut registry, &owner, &device, &attempted_reactivation),
            Err(RegistryError::Revoked)
        );
        assert_eq!(
            registry.revoke_identity(
                &peer_id,
                3,
                wallet_authorization(&owner, &canonical_revoke_payload(&peer_id, 3).unwrap(),),
            ),
            Err(RegistryError::Revoked)
        );
    }

    #[test]
    fn policy_bounds_and_schema_are_enforced() {
        let owner = DytallixKeypair::generate();
        let device = make_device(8);
        let baseline = record(&owner, &device);

        for ttl in [
            MIN_PEER_RECORD_TTL_SECONDS - 1,
            MAX_PEER_RECORD_TTL_SECONDS + 1,
        ] {
            let mut invalid = baseline.clone();
            invalid.max_peer_record_ttl_seconds = ttl;
            assert_eq!(
                validate_record(&invalid),
                Err(RegistryError::PolicyOutOfBounds)
            );
        }

        let mut invalid_expiry = baseline.clone();
        invalid_expiry.authorization_expires_at = Some(0);
        assert_eq!(
            validate_record(&invalid_expiry),
            Err(RegistryError::PolicyOutOfBounds)
        );

        let mut wrong_schema = baseline;
        wrong_schema.schema_version = 1;
        assert_eq!(
            validate_record(&wrong_schema),
            Err(RegistryError::UnsupportedSchemaVersion)
        );
    }

    #[test]
    fn schema_excludes_ephemeral_peer_record_fields() {
        let owner = DytallixKeypair::generate();
        let device = make_device(9);
        let value = serde_json::to_value(record(&owner, &device)).unwrap();
        let object = value.as_object().unwrap();
        for excluded in [
            "latest_peer_record_hash_hex",
            "endpoints",
            "ice_credentials",
            "transport_public_key_hash_hex",
            "sequence",
            "expires_at",
        ] {
            assert!(
                !object.contains_key(excluded),
                "{excluded} must stay off-chain"
            );
        }
    }

    #[test]
    fn stable_binding_payload_is_domain_separated() {
        let owner = DytallixKeypair::generate();
        let device = make_device(10);
        let record = record(&owner, &device);
        let payload = canonical_device_authorization_payload(&record).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();

        assert_eq!(value["contract"], CONTRACT_DOMAIN);
        assert_eq!(value["schema_version"], REGISTRY_SCHEMA_VERSION);
        assert_eq!(value["purpose"], DEVICE_AUTHORIZATION_PURPOSE);
        assert_eq!(value["binding"]["identity_revision"], 1);
    }

    #[test]
    fn unknown_schema_fields_are_rejected() {
        let owner = DytallixKeypair::generate();
        let device = make_device(11);
        let mut value = serde_json::to_value(record(&owner, &device)).unwrap();
        value["endpoint"] = serde_json::Value::String("198.51.100.7:443".to_string());
        assert!(serde_json::from_value::<StableIdentityRecord>(value).is_err());
    }

    #[test]
    fn storage_round_trips_v2_state_and_uses_versioned_keys() {
        let owner = DytallixKeypair::generate();
        let device = make_device(12);
        let record = record(&owner, &device);
        assert_eq!(
            decode_identity(&encode_identity(&record).unwrap()).unwrap(),
            record
        );
        assert!(
            String::from_utf8(identity_storage_key(&record.peer_id).unwrap())
                .unwrap()
                .starts_with("v2:identity:")
        );

        let events = vec![RegistryEvent {
            peer_id: record.peer_id.clone(),
            event_type: "registered".to_string(),
            actor_daddr: record.owner_daddr.clone(),
            identity_revision: 1,
        }];
        assert_eq!(
            decode_events(&encode_events(&events).unwrap()).unwrap(),
            events
        );
        assert!(validate_storage_value_size(&vec![0; MAX_STORAGE_VALUE_SIZE]).is_ok());
        assert!(validate_storage_value_size(&vec![0; MAX_STORAGE_VALUE_SIZE + 1]).is_err());
        assert!(
            String::from_utf8(events_storage_key(&record.peer_id).unwrap())
                .unwrap()
                .starts_with("v2:events:")
        );
    }
}
