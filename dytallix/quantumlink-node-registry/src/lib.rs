use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Active,
    Revoked,
    Suspended,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub peer_id: String,
    pub owner_daddr: String,
    pub device_public_key_hash_hex: String,
    pub pqc_binding_hash_hex: String,
    pub node_signing_public_key_hash_hex: String,
    pub transport_public_key_hash_hex: String,
    pub latest_peer_record_hash_hex: String,
    pub status: NodeStatus,
    pub reputation_score: u64,
    pub stake_status: Option<String>,
    pub updated_at: u64,
    pub expires_at: Option<u64>,
    pub metadata_commitment_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletAuthorization {
    pub actor_public_key_hex: String,
    pub actor_signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBindingAuthorization {
    pub device_public_key_algorithm: String,
    pub device_public_key_hex: String,
    pub device_binding_signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEvent {
    pub peer_id: String,
    pub event_type: String,
    pub actor_daddr: String,
    pub block_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum RegistryError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("node not found")]
    NotFound,
    #[error("invalid hex field")]
    InvalidHex,
    #[error("invalid peer id")]
    InvalidPeerId,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("node already registered")]
    AlreadyRegistered,
    #[error("stale record")]
    StaleRecord,
    #[error("node revoked")]
    Revoked,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuantumLinkNodeRegistry {
    nodes: BTreeMap<String, NodeRecord>,
    events: Vec<RegistryEvent>,
}

impl QuantumLinkNodeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_node(
        &mut self,
        record: NodeRecord,
        authorization: WalletAuthorization,
        device_authorization: DeviceBindingAuthorization,
    ) -> Result<(), RegistryError> {
        validate_record(&record)?;
        if self.nodes.contains_key(&record.peer_id) {
            return Err(RegistryError::AlreadyRegistered);
        }

        let actor_daddr =
            verified_actor_daddr(&authorization, &canonical_register_payload(&record)?)?;

        let mut stored = record;
        stored.owner_daddr = actor_daddr.clone();
        validate_device_binding(&stored, &device_authorization)?;
        self.events.push(RegistryEvent {
            peer_id: stored.peer_id.clone(),
            event_type: "registered".to_string(),
            actor_daddr,
            block_time: stored.updated_at,
        });
        self.nodes.insert(stored.peer_id.clone(), stored);
        Ok(())
    }

    pub fn update_node(
        &mut self,
        record: NodeRecord,
        authorization: WalletAuthorization,
        device_authorization: DeviceBindingAuthorization,
    ) -> Result<(), RegistryError> {
        validate_record(&record)?;
        let actor_daddr =
            verified_actor_daddr(&authorization, &canonical_update_payload(&record)?)?;
        let existing = self
            .nodes
            .get(&record.peer_id)
            .ok_or(RegistryError::NotFound)?;
        if existing.owner_daddr != actor_daddr {
            return Err(RegistryError::Unauthorized);
        }
        if existing.status == NodeStatus::Revoked {
            return Err(RegistryError::Revoked);
        }
        if record.updated_at <= existing.updated_at {
            return Err(RegistryError::StaleRecord);
        }
        let owner = existing.owner_daddr.clone();

        let mut stored = record;
        stored.owner_daddr = owner;
        validate_device_binding(&stored, &device_authorization)?;
        self.events.push(RegistryEvent {
            peer_id: stored.peer_id.clone(),
            event_type: "updated".to_string(),
            actor_daddr,
            block_time: stored.updated_at,
        });
        self.nodes.insert(stored.peer_id.clone(), stored);
        Ok(())
    }

    pub fn revoke_node(
        &mut self,
        peer_id: &str,
        block_time: u64,
        authorization: WalletAuthorization,
    ) -> Result<(), RegistryError> {
        validate_peer_id(peer_id)?;
        let actor_daddr = verified_actor_daddr(
            &authorization,
            &canonical_revoke_payload(peer_id, block_time)?,
        )?;
        self.require_owner(&actor_daddr, peer_id)?;

        let record = self.nodes.get_mut(peer_id).ok_or(RegistryError::NotFound)?;
        if record.status == NodeStatus::Revoked {
            return Err(RegistryError::Revoked);
        }
        if block_time <= record.updated_at {
            return Err(RegistryError::StaleRecord);
        }
        record.status = NodeStatus::Revoked;
        record.updated_at = block_time;
        self.events.push(RegistryEvent {
            peer_id: peer_id.to_string(),
            event_type: "revoked".to_string(),
            actor_daddr,
            block_time,
        });
        Ok(())
    }

    pub fn get_node(&self, peer_id: &str) -> Option<NodeRecord> {
        self.nodes.get(peer_id).cloned()
    }

    pub fn events(&self, peer_id: &str) -> Vec<RegistryEvent> {
        self.events
            .iter()
            .filter(|event| event.peer_id == peer_id)
            .cloned()
            .collect()
    }

    fn require_owner(&self, actor_daddr: &str, peer_id: &str) -> Result<&str, RegistryError> {
        let owner = self
            .nodes
            .get(peer_id)
            .ok_or(RegistryError::NotFound)?
            .owner_daddr
            .as_str();
        if owner == actor_daddr {
            Ok(owner)
        } else {
            Err(RegistryError::Unauthorized)
        }
    }
}

fn validate_record(record: &NodeRecord) -> Result<(), RegistryError> {
    validate_peer_id(&record.peer_id)?;
    validate_hex32(&record.device_public_key_hash_hex)?;
    validate_hex32(&record.pqc_binding_hash_hex)?;
    validate_hex32(&record.node_signing_public_key_hash_hex)?;
    validate_hex32(&record.transport_public_key_hash_hex)?;
    validate_hex32(&record.latest_peer_record_hash_hex)?;
    if let Some(commitment) = record.metadata_commitment_hex.as_deref() {
        validate_hex32(commitment)?;
    }
    Ok(())
}

fn validate_device_binding(
    record: &NodeRecord,
    authorization: &DeviceBindingAuthorization,
) -> Result<(), RegistryError> {
    if authorization.device_public_key_algorithm != "ML-DSA-65" {
        return Err(RegistryError::InvalidSignature);
    }

    let public_key = decode_hex(&authorization.device_public_key_hex)?;
    let signature = decode_hex(&authorization.device_binding_signature_hex)?;

    if quantumlink_peer_id(&public_key) != record.peer_id {
        return Err(RegistryError::InvalidPeerId);
    }

    let device_public_key_hash =
        device_public_key_hash_hex(&authorization.device_public_key_algorithm, &public_key)?;
    if device_public_key_hash != record.device_public_key_hash_hex {
        return Err(RegistryError::InvalidSignature);
    }
    if record.node_signing_public_key_hash_hex != device_public_key_hash {
        return Err(RegistryError::InvalidSignature);
    }
    if pqc_binding_hash_hex(record)? != record.pqc_binding_hash_hex {
        return Err(RegistryError::InvalidSignature);
    }

    let payload = canonical_device_binding_payload(record)?;
    if !verify_quantumlink_mldsa65_signature(&public_key, &payload, &signature)? {
        return Err(RegistryError::InvalidSignature);
    }

    Ok(())
}

fn quantumlink_peer_id(public_key: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let digest = Sha256::digest(public_key);
    format!("qlink_{}", URL_SAFE_NO_PAD.encode(&digest[..16]))
}

fn device_public_key_hash_hex(algorithm: &str, public_key: &[u8]) -> Result<String, RegistryError> {
    #[derive(Serialize)]
    struct DevicePublicKeyJson<'a> {
        algorithm: &'a str,
        bytes: &'a [u8],
    }

    let bytes = serde_json::to_vec(&DevicePublicKeyJson {
        algorithm,
        bytes: public_key,
    })
    .map_err(|_| RegistryError::InvalidSignature)?;
    Ok(sha256_hex(&bytes))
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

    let vk_bytes = EncodedVerifyingKey::<MlDsa65>::try_from(public_key)
        .map_err(|_| RegistryError::InvalidSignature)?;
    let verifying_key = MlDsaVerifyingKey::<MlDsa65>::decode(&vk_bytes);
    let sig_bytes = EncodedSignature::<MlDsa65>::try_from(signature)
        .map_err(|_| RegistryError::InvalidSignature)?;
    let signature =
        MlDsaSignature::<MlDsa65>::decode(&sig_bytes).ok_or(RegistryError::InvalidSignature)?;

    Ok(verifying_key.verify(payload, &signature).is_ok())
}

fn validate_peer_id(peer_id: &str) -> Result<(), RegistryError> {
    if peer_id.starts_with("qlink_") {
        Ok(())
    } else {
        Err(RegistryError::InvalidPeerId)
    }
}

fn validate_hex32(value: &str) -> Result<(), RegistryError> {
    if value.len() == 64 && value.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(RegistryError::InvalidHex)
    }
}

#[derive(Serialize)]
struct CanonicalDeviceBindingPayload<'a> {
    contract: &'static str,
    version: u8,
    owner_daddr: &'a str,
    peer_id: &'a str,
    device_public_key_hash_hex: &'a str,
    node_signing_public_key_hash_hex: &'a str,
    transport_public_key_hash_hex: &'a str,
    latest_peer_record_hash_hex: &'a str,
}

#[derive(Serialize)]
struct CanonicalRecordPayload<'a> {
    contract: &'static str,
    version: u8,
    operation: &'static str,
    record: &'a NodeRecord,
}

#[derive(Serialize)]
struct CanonicalRevokePayload<'a> {
    contract: &'static str,
    version: u8,
    operation: &'static str,
    peer_id: &'a str,
    block_time: u64,
}

fn canonical_register_payload(record: &NodeRecord) -> Result<Vec<u8>, RegistryError> {
    canonical_record_payload("register_node", record)
}

fn canonical_update_payload(record: &NodeRecord) -> Result<Vec<u8>, RegistryError> {
    canonical_record_payload("update_node", record)
}

fn canonical_device_binding_payload(record: &NodeRecord) -> Result<Vec<u8>, RegistryError> {
    serde_json::to_vec(&CanonicalDeviceBindingPayload {
        contract: "quantumlink-node-registry",
        version: 1,
        owner_daddr: &record.owner_daddr,
        peer_id: &record.peer_id,
        device_public_key_hash_hex: &record.device_public_key_hash_hex,
        node_signing_public_key_hash_hex: &record.node_signing_public_key_hash_hex,
        transport_public_key_hash_hex: &record.transport_public_key_hash_hex,
        latest_peer_record_hash_hex: &record.latest_peer_record_hash_hex,
    })
    .map_err(|_| RegistryError::InvalidSignature)
}

fn pqc_binding_hash_hex(record: &NodeRecord) -> Result<String, RegistryError> {
    Ok(sha256_hex(&canonical_device_binding_payload(record)?))
}

fn canonical_record_payload(
    operation: &'static str,
    record: &NodeRecord,
) -> Result<Vec<u8>, RegistryError> {
    serde_json::to_vec(&CanonicalRecordPayload {
        contract: "quantumlink-node-registry",
        version: 1,
        operation,
        record,
    })
    .map_err(|_| RegistryError::InvalidSignature)
}

fn canonical_revoke_payload(peer_id: &str, block_time: u64) -> Result<Vec<u8>, RegistryError> {
    serde_json::to_vec(&CanonicalRevokePayload {
        contract: "quantumlink-node-registry",
        version: 1,
        operation: "revoke_node",
        peer_id,
        block_time,
    })
    .map_err(|_| RegistryError::InvalidSignature)
}

fn verified_actor_daddr(
    authorization: &WalletAuthorization,
    payload: &[u8],
) -> Result<String, RegistryError> {
    let public_key = decode_hex(&authorization.actor_public_key_hex)?;
    let signature = decode_hex(&authorization.actor_signature_hex)?;
    let verified = verify_mldsa65_signature(&public_key, payload, &signature)?;
    if !verified {
        return Err(RegistryError::InvalidSignature);
    }
    daddr_from_public_key(&public_key)
}

#[cfg(not(target_arch = "wasm32"))]
fn verify_mldsa65_signature(
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
fn verify_mldsa65_signature(
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<bool, RegistryError> {
    use fips204::traits::{SerDes, Verifier};

    const MLDSA65_PUBLIC_KEY_BYTES: usize = 1_952;
    const MLDSA65_SIGNATURE_BYTES: usize = 3_309;

    if public_key.len() != MLDSA65_PUBLIC_KEY_BYTES || signature.len() != MLDSA65_SIGNATURE_BYTES {
        return Err(RegistryError::InvalidSignature);
    }

    let public_key_bytes = public_key
        .try_into()
        .map_err(|_| RegistryError::InvalidSignature)?;
    let public_key = fips204::ml_dsa_65::PublicKey::try_from_bytes(public_key_bytes)
        .map_err(|_| RegistryError::InvalidSignature)?;
    let signature_bytes: [u8; fips204::ml_dsa_65::SIG_LEN] = signature
        .try_into()
        .map_err(|_| RegistryError::InvalidSignature)?;

    Ok(public_key.verify(payload, &signature_bytes, &[]))
}

#[cfg(target_arch = "wasm32")]
fn daddr_from_public_key(public_key: &[u8]) -> Result<String, RegistryError> {
    use bech32::{Bech32m, Hrp};

    const MLDSA65_PUBLIC_KEY_BYTES: usize = 1_952;
    if public_key.len() != MLDSA65_PUBLIC_KEY_BYTES {
        return Err(RegistryError::InvalidSignature);
    }

    let hash = blake3::hash(public_key);
    let hrp = Hrp::parse("dytallix").map_err(|_| RegistryError::InvalidSignature)?;
    bech32::encode::<Bech32m>(hrp, hash.as_bytes()).map_err(|_| RegistryError::InvalidSignature)
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

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
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

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
const MAX_STORAGE_VALUE_SIZE: usize = 16 * 1024;

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn node_storage_key(peer_id: &str) -> Result<Vec<u8>, RegistryError> {
    validate_peer_id(peer_id)?;
    Ok(format!("node:{peer_id}").into_bytes())
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn events_storage_key(peer_id: &str) -> Result<Vec<u8>, RegistryError> {
    validate_peer_id(peer_id)?;
    Ok(format!("events:{peer_id}").into_bytes())
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn encode_node_record(record: &NodeRecord) -> Result<Vec<u8>, String> {
    serde_json::to_vec(record).map_err(|error| format!("node record encode failed: {error}"))
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn decode_node_record(value: &[u8]) -> Result<NodeRecord, String> {
    serde_json::from_slice(value).map_err(|error| format!("node record decode failed: {error}"))
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn encode_registry_events(events: &[RegistryEvent]) -> Result<Vec<u8>, String> {
    serde_json::to_vec(events).map_err(|error| format!("registry events encode failed: {error}"))
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn decode_registry_events(value: &[u8]) -> Result<Vec<RegistryEvent>, String> {
    serde_json::from_slice(value).map_err(|error| format!("registry events decode failed: {error}"))
}

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
#[derive(Debug)]
struct PreparedPeerStateWrites {
    node_key: Vec<u8>,
    node_value: Vec<u8>,
    events_key: Vec<u8>,
    events_value: Vec<u8>,
}

#[cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
fn prepare_peer_state_writes(
    peer_id: &str,
    record: &NodeRecord,
    events: &[RegistryEvent],
) -> Result<PreparedPeerStateWrites, String> {
    let node_key = node_storage_key(peer_id).map_err(|error| error.to_string())?;
    let events_key = events_storage_key(peer_id).map_err(|error| error.to_string())?;
    let node_value = encode_node_record(record)?;
    let events_value = encode_registry_events(events)?;
    validate_storage_value_size(&node_value)?;
    validate_storage_value_size(&events_value)?;

    Ok(PreparedPeerStateWrites {
        node_key,
        node_value,
        events_key,
        events_value,
    })
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

    const MAX_RETURN_BYTES: usize = 1024;
    const MAX_RETURN_PAYLOAD_BYTES: usize = MAX_RETURN_BYTES - 4;
    const MAX_INPUT_BYTES: usize = 64 * 1024;

    #[link(wasm_import_module = "env")]
    extern "C" {
        fn storage_get(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32) -> i32;
        fn storage_set(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32) -> i32;
        fn read_input(out_ptr: i32, max_len: i32) -> i32;
        fn write_output(ptr: i32, len: i32);
    }

    #[derive(Debug, Deserialize)]
    struct RegisterNodeRequest {
        record: NodeRecord,
        #[serde(flatten)]
        authorization: WalletAuthorization,
        #[serde(flatten)]
        device_authorization: DeviceBindingAuthorization,
    }

    #[derive(Debug, Deserialize)]
    struct UpdateNodeRequest {
        record: NodeRecord,
        #[serde(flatten)]
        authorization: WalletAuthorization,
        #[serde(flatten)]
        device_authorization: DeviceBindingAuthorization,
    }

    #[derive(Debug, Deserialize)]
    struct RevokeNodeRequest {
        peer_id: String,
        block_time: u64,
        #[serde(flatten)]
        authorization: WalletAuthorization,
    }

    #[derive(Debug, Deserialize)]
    struct GetNodeRequest {
        peer_id: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct ContractResponse {
        ok: bool,
        node: Option<NodeRecord>,
        events: Vec<RegistryEvent>,
        error: Option<String>,
    }

    #[no_mangle]
    pub extern "C" fn contract_register_node(ptr: i32, len: i32) -> i32 {
        let request = match read_request::<RegisterNodeRequest>(ptr, len) {
            Ok(request) => request,
            Err(error) => return error_response(error),
        };
        let peer_id = request.record.peer_id.clone();
        with_peer_state(&peer_id, |registry| {
            registry.register_node(
                request.record,
                request.authorization,
                request.device_authorization,
            )
        })
    }

    #[no_mangle]
    pub extern "C" fn register_node() {
        handle_host_register_node();
    }

    #[no_mangle]
    pub extern "C" fn contract_update_node(ptr: i32, len: i32) -> i32 {
        let request = match read_request::<UpdateNodeRequest>(ptr, len) {
            Ok(request) => request,
            Err(error) => return error_response(error),
        };
        let peer_id = request.record.peer_id.clone();
        with_peer_state(&peer_id, |registry| {
            registry.update_node(
                request.record,
                request.authorization,
                request.device_authorization,
            )
        })
    }

    #[no_mangle]
    pub extern "C" fn update_node() {
        handle_host_update_node();
    }

    #[no_mangle]
    pub extern "C" fn contract_revoke_node(ptr: i32, len: i32) -> i32 {
        let request = match read_request::<RevokeNodeRequest>(ptr, len) {
            Ok(request) => request,
            Err(error) => return error_response(error),
        };
        with_peer_state(&request.peer_id, |registry| {
            registry.revoke_node(&request.peer_id, request.block_time, request.authorization)
        })
    }

    #[no_mangle]
    pub extern "C" fn revoke_node() {
        handle_host_revoke_node();
    }

    #[no_mangle]
    pub extern "C" fn contract_get_node(ptr: i32, len: i32) -> i32 {
        let request = match read_request::<GetNodeRequest>(ptr, len) {
            Ok(request) => request,
            Err(error) => return error_response(error),
        };
        let node = match load_node(&request.peer_id) {
            Ok(node) => node,
            Err(error) => return error_response(error),
        };
        ok_response(node, Vec::new())
    }

    #[no_mangle]
    pub extern "C" fn get_node() {
        handle_host_get_node();
    }

    #[no_mangle]
    pub extern "C" fn contract_events(ptr: i32, len: i32) -> i32 {
        let request = match read_request::<GetNodeRequest>(ptr, len) {
            Ok(request) => request,
            Err(error) => return error_response(error),
        };
        let events = match load_events(&request.peer_id) {
            Ok(events) => events,
            Err(error) => return error_response(error),
        };
        ok_response(None, events)
    }

    #[no_mangle]
    pub extern "C" fn events() {
        handle_host_events();
    }

    #[no_mangle]
    pub extern "C" fn contract_free(ptr: i32, len: i32) {
        if ptr > 0 && len > 0 {
            unsafe {
                drop(Vec::from_raw_parts(
                    ptr as *mut u8,
                    len as usize,
                    len as usize,
                ));
            }
        }
    }

    fn with_peer_state(
        peer_id: &str,
        action: impl FnOnce(&mut QuantumLinkNodeRegistry) -> Result<(), RegistryError>,
    ) -> i32 {
        let existing = match load_node(peer_id) {
            Ok(existing) => existing,
            Err(error) => return error_response(error),
        };
        let events = match load_events(peer_id) {
            Ok(events) => events,
            Err(error) => return error_response(error),
        };
        let mut registry = QuantumLinkNodeRegistry::new();
        if let Some(record) = existing {
            registry.nodes.insert(peer_id.to_string(), record);
        }
        registry.events = events;

        match action(&mut registry) {
            Ok(()) => {
                let save_result = registry
                    .get_node(peer_id)
                    .ok_or_else(|| "peer operation did not produce a node record".to_string())
                    .and_then(|record| {
                        prepare_peer_state_writes(peer_id, &record, &registry.events(peer_id))
                    })
                    .and_then(save_peer_state_writes);
                match save_result {
                    Ok(()) => ok_response(None, Vec::new()),
                    Err(error) => error_response(error),
                }
            }
            Err(error) => error_response(error),
        }
    }

    fn read_request<T: DeserializeOwned>(ptr: i32, len: i32) -> Result<T, String> {
        if ptr <= 0 {
            return Err("request pointer was null or invalid".to_string());
        }
        if len < 0 {
            return Err("request length was negative".to_string());
        }
        let payload = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
        serde_json::from_slice(payload).map_err(|error| error.to_string())
    }

    fn load_node(peer_id: &str) -> Result<Option<NodeRecord>, String> {
        let key = node_storage_key(peer_id).map_err(|error| error.to_string())?;
        match storage_get_raw(&key)? {
            Some(value) => decode_node_record(&value).map(Some),
            None => Ok(None),
        }
    }

    fn load_events(peer_id: &str) -> Result<Vec<RegistryEvent>, String> {
        let key = events_storage_key(peer_id).map_err(|error| error.to_string())?;
        match storage_get_raw(&key)? {
            Some(value) => decode_registry_events(&value),
            None => Ok(Vec::new()),
        }
    }

    fn save_peer_state_writes(writes: PreparedPeerStateWrites) -> Result<(), String> {
        storage_set_raw(&writes.node_key, &writes.node_value)?;
        storage_set_raw(&writes.events_key, &writes.events_value)
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
        if status != 0 {
            return Err(format!("storage_set failed with code {status}"));
        }
        Ok(())
    }

    fn ok_response(node: Option<NodeRecord>, events: Vec<RegistryEvent>) -> i32 {
        write_response(&ContractResponse {
            ok: true,
            node,
            events,
            error: None,
        })
    }

    fn error_response(error: impl ToString) -> i32 {
        write_response(&ContractResponse {
            ok: false,
            node: None,
            events: Vec::new(),
            error: Some(error.to_string()),
        })
    }

    fn write_response(response: &ContractResponse) -> i32 {
        let mut payload = serde_json::to_vec(response).unwrap_or_else(|_| {
            b"{\"ok\":false,\"node\":null,\"events\":[],\"error\":\"serialization failed\"}"
                .to_vec()
        });
        if payload.len() > MAX_RETURN_PAYLOAD_BYTES {
            payload =
                b"{\"ok\":false,\"node\":null,\"events\":[],\"error\":\"response too large\"}"
                    .to_vec();
        }
        let len = payload.len() as u32;
        let mut buffer = Vec::with_capacity(payload.len() + 4);
        buffer.extend_from_slice(&len.to_le_bytes());
        buffer.extend_from_slice(&payload);
        let mut boxed = buffer.into_boxed_slice();
        let ptr = boxed.as_mut_ptr();
        std::mem::forget(boxed);
        ptr as i32
    }

    fn handle_host_register_node() {
        let response = match read_host_request::<RegisterNodeRequest>() {
            Ok(request) => {
                let peer_id = request.record.peer_id.clone();
                let ptr = with_peer_state(&peer_id, |registry| {
                    registry.register_node(
                        request.record,
                        request.authorization,
                        request.device_authorization,
                    )
                });
                read_response_pointer(ptr)
            }
            Err(error) => response_error(error),
        };
        write_host_response(&response);
    }

    fn handle_host_update_node() {
        let response = match read_host_request::<UpdateNodeRequest>() {
            Ok(request) => {
                let peer_id = request.record.peer_id.clone();
                let ptr = with_peer_state(&peer_id, |registry| {
                    registry.update_node(
                        request.record,
                        request.authorization,
                        request.device_authorization,
                    )
                });
                read_response_pointer(ptr)
            }
            Err(error) => response_error(error),
        };
        write_host_response(&response);
    }

    fn handle_host_revoke_node() {
        let response = match read_host_request::<RevokeNodeRequest>() {
            Ok(request) => {
                let ptr = with_peer_state(&request.peer_id.clone(), |registry| {
                    registry.revoke_node(
                        &request.peer_id,
                        request.block_time,
                        request.authorization,
                    )
                });
                read_response_pointer(ptr)
            }
            Err(error) => response_error(error),
        };
        write_host_response(&response);
    }

    fn handle_host_get_node() {
        let response = match read_host_request::<GetNodeRequest>() {
            Ok(request) => match load_node(&request.peer_id) {
                Ok(node) => response_ok(node, Vec::new()),
                Err(error) => response_error(error),
            },
            Err(error) => response_error(error),
        };
        write_host_response(&response);
    }

    fn handle_host_events() {
        let response = match read_host_request::<GetNodeRequest>() {
            Ok(request) => match load_events(&request.peer_id) {
                Ok(events) => response_ok(None, events),
                Err(error) => response_error(error),
            },
            Err(error) => response_error(error),
        };
        write_host_response(&response);
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

    fn write_host_response(response: &ContractResponse) {
        let mut payload = serde_json::to_vec(response).unwrap_or_else(|_| {
            b"{\"ok\":false,\"node\":null,\"events\":[],\"error\":\"serialization failed\"}"
                .to_vec()
        });
        if payload.len() > MAX_RETURN_PAYLOAD_BYTES {
            payload =
                b"{\"ok\":false,\"node\":null,\"events\":[],\"error\":\"response too large\"}"
                    .to_vec();
        }
        unsafe {
            write_output(payload.as_ptr() as i32, payload.len() as i32);
        }
    }

    fn read_response_pointer(ptr: i32) -> ContractResponse {
        if ptr <= 0 {
            return response_error("invalid response pointer");
        }
        let len_bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, 4) };
        let len =
            u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        if len > MAX_RETURN_PAYLOAD_BYTES {
            return response_error("response too large");
        }
        let payload = unsafe { std::slice::from_raw_parts((ptr as *const u8).add(4), len) };
        serde_json::from_slice(payload)
            .unwrap_or_else(|error| response_error(format!("response decode failed: {error}")))
    }

    fn response_ok(node: Option<NodeRecord>, events: Vec<RegistryEvent>) -> ContractResponse {
        ContractResponse {
            ok: true,
            node,
            events,
            error: None,
        }
    }

    fn response_error(error: impl ToString) -> ContractResponse {
        ContractResponse {
            ok: false,
            node: None,
            events: Vec::new(),
            error: Some(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dytallix_core::address::DAddr;
    use dytallix_core::keypair::DytallixKeypair;
    use ml_dsa::{
        signature::{Keypair, Signer},
        KeyGen, MlDsa65, Signature as MlDsaSignature,
    };
    use qlink_core::dytallix_identity::{
        RegistryContractMethod as QlinkRegistryContractMethod,
        RegistryNodeRecord as QlinkRegistryNodeRecord,
        RegistryNodeStatus as QlinkRegistryNodeStatus,
        WalletAuthorization as QlinkWalletAuthorization,
    };
    use sha2::{Digest, Sha256};

    fn active_record() -> NodeRecord {
        NodeRecord {
            peer_id: "qlink_peer".to_string(),
            owner_daddr:
                "dytallix1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
                    .to_string(),
            device_public_key_hash_hex: "11".repeat(32),
            pqc_binding_hash_hex: "12".repeat(32),
            node_signing_public_key_hash_hex: "13".repeat(32),
            transport_public_key_hash_hex: "14".repeat(32),
            latest_peer_record_hash_hex: "22".repeat(32),
            status: NodeStatus::Active,
            reputation_score: 0,
            stake_status: None,
            updated_at: 100,
            expires_at: Some(1_000),
            metadata_commitment_hex: None,
        }
    }

    struct QuantumLinkDevice {
        signing_key: ml_dsa::SigningKey<MlDsa65>,
        public_key_bytes: Vec<u8>,
        peer_id: String,
        device_public_key_hash_hex: String,
    }

    fn quantumlink_device(seed_byte: u8) -> QuantumLinkDevice {
        let seed = [seed_byte; 32];
        let parsed_seed = ml_dsa::B32::try_from(seed.as_slice()).unwrap();
        let signing_key = MlDsa65::from_seed(&parsed_seed);
        let public_key_bytes = signing_key.verifying_key().encode().as_slice().to_vec();
        let peer_id = quantumlink_peer_id(&public_key_bytes);
        let device_public_key_hash_hex = device_public_key_hash_hex(&public_key_bytes);
        QuantumLinkDevice {
            signing_key,
            public_key_bytes,
            peer_id,
            device_public_key_hash_hex,
        }
    }

    fn quantumlink_peer_id(public_key_bytes: &[u8]) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let digest = Sha256::digest(public_key_bytes);
        format!("qlink_{}", URL_SAFE_NO_PAD.encode(&digest[..16]))
    }

    fn device_public_key_hash_hex(public_key_bytes: &[u8]) -> String {
        #[derive(Serialize)]
        struct DevicePublicKeyJson<'a> {
            algorithm: &'static str,
            bytes: &'a [u8],
        }

        let bytes = serde_json::to_vec(&DevicePublicKeyJson {
            algorithm: "ML-DSA-65",
            bytes: public_key_bytes,
        })
        .unwrap();
        hex_encode(&Sha256::digest(bytes))
    }

    fn device_bound_record(owner_daddr: &str, device: &QuantumLinkDevice) -> NodeRecord {
        let mut record = NodeRecord {
            peer_id: device.peer_id.clone(),
            owner_daddr: owner_daddr.to_string(),
            device_public_key_hash_hex: device.device_public_key_hash_hex.clone(),
            pqc_binding_hash_hex: "00".repeat(32),
            node_signing_public_key_hash_hex: device.device_public_key_hash_hex.clone(),
            transport_public_key_hash_hex: "14".repeat(32),
            latest_peer_record_hash_hex: "22".repeat(32),
            status: NodeStatus::Active,
            reputation_score: 0,
            stake_status: None,
            updated_at: 100,
            expires_at: Some(1_000),
            metadata_commitment_hex: None,
        };
        record.pqc_binding_hash_hex = pqc_binding_hash_hex(&record).unwrap();
        record
    }

    fn device_auth_for_record(
        device: &QuantumLinkDevice,
        record: &NodeRecord,
    ) -> DeviceBindingAuthorization {
        let payload = canonical_device_binding_payload(record).unwrap();
        let signature: MlDsaSignature<MlDsa65> = device.signing_key.sign(&payload);
        DeviceBindingAuthorization {
            device_public_key_algorithm: "ML-DSA-65".to_string(),
            device_public_key_hex: hex_encode(&device.public_key_bytes),
            device_binding_signature_hex: hex_encode(signature.encode().as_slice()),
        }
    }

    fn record_for_owner(
        owner: &DytallixKeypair,
        seed_byte: u8,
    ) -> (String, QuantumLinkDevice, NodeRecord) {
        let owner_daddr = DAddr::from_public_key(owner.public_key())
            .unwrap()
            .to_string();
        let device = quantumlink_device(seed_byte);
        let record = device_bound_record(&owner_daddr, &device);
        (owner_daddr, device, record)
    }

    fn refresh_pqc_binding(record: &mut NodeRecord) {
        record.pqc_binding_hash_hex = pqc_binding_hash_hex(record).unwrap();
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

    fn wallet_auth_for_register(
        keypair: &DytallixKeypair,
        record: &NodeRecord,
    ) -> WalletAuthorization {
        let payload = canonical_register_payload(record).unwrap();
        WalletAuthorization {
            actor_public_key_hex: hex_encode(keypair.public_key()),
            actor_signature_hex: hex_encode(&keypair.sign(&payload).unwrap()),
        }
    }

    fn wallet_auth_for_update(
        keypair: &DytallixKeypair,
        record: &NodeRecord,
    ) -> WalletAuthorization {
        let payload = canonical_update_payload(record).unwrap();
        WalletAuthorization {
            actor_public_key_hex: hex_encode(keypair.public_key()),
            actor_signature_hex: hex_encode(&keypair.sign(&payload).unwrap()),
        }
    }

    fn wallet_auth_for_revoke(
        keypair: &DytallixKeypair,
        peer_id: &str,
        block_time: u64,
    ) -> WalletAuthorization {
        let payload = canonical_revoke_payload(peer_id, block_time).unwrap();
        WalletAuthorization {
            actor_public_key_hex: hex_encode(keypair.public_key()),
            actor_signature_hex: hex_encode(&keypair.sign(&payload).unwrap()),
        }
    }

    fn qlink_record_from_contract(record: &NodeRecord) -> QlinkRegistryNodeRecord {
        QlinkRegistryNodeRecord {
            peer_id: record.peer_id.clone(),
            owner_daddr: record.owner_daddr.clone(),
            device_public_key_hash_hex: record.device_public_key_hash_hex.clone(),
            pqc_binding_hash_hex: record.pqc_binding_hash_hex.clone(),
            node_signing_public_key_hash_hex: record.node_signing_public_key_hash_hex.clone(),
            transport_public_key_hash_hex: record.transport_public_key_hash_hex.clone(),
            latest_peer_record_hash_hex: record.latest_peer_record_hash_hex.clone(),
            status: match record.status {
                NodeStatus::Active => QlinkRegistryNodeStatus::Active,
                NodeStatus::Revoked => QlinkRegistryNodeStatus::Revoked,
                NodeStatus::Suspended => QlinkRegistryNodeStatus::Suspended,
            },
            reputation_score: record.reputation_score,
            stake_status: record.stake_status.clone(),
            updated_at: record.updated_at,
            expires_at: record.expires_at,
            metadata_commitment_hex: record.metadata_commitment_hex.clone(),
        }
    }

    fn contract_wallet_auth_from_qlink(auth: QlinkWalletAuthorization) -> WalletAuthorization {
        WalletAuthorization {
            actor_public_key_hex: auth.actor_public_key_hex,
            actor_signature_hex: auth.actor_signature_hex,
        }
    }

    #[test]
    fn register_update_revoke_and_lookup_are_real_contract_state_transitions() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let (owner_daddr, device, record) = record_for_owner(&owner, 1);
        let register_auth = wallet_auth_for_register(&owner, &record);

        registry
            .register_node(
                record.clone(),
                register_auth,
                device_auth_for_record(&device, &record),
            )
            .expect("registration should succeed");
        let mut expected = record;
        expected.owner_daddr = owner_daddr.clone();
        assert_eq!(registry.get_node(&expected.peer_id).unwrap(), expected);

        let mut updated = expected.clone();
        updated.latest_peer_record_hash_hex = "33".repeat(32);
        updated.updated_at = 200;
        refresh_pqc_binding(&mut updated);
        let update_auth = wallet_auth_for_update(&owner, &updated);
        registry
            .update_node(
                updated.clone(),
                update_auth,
                device_auth_for_record(&device, &updated),
            )
            .expect("owner should update");
        assert_eq!(registry.get_node(&updated.peer_id).unwrap(), updated);

        registry
            .revoke_node(
                &updated.peer_id,
                300,
                wallet_auth_for_revoke(&owner, &updated.peer_id, 300),
            )
            .expect("owner should revoke");
        assert_eq!(
            registry.get_node(&updated.peer_id).unwrap().status,
            NodeStatus::Revoked
        );
    }

    #[test]
    fn qlink_core_wallet_authorization_is_accepted_for_register_update_and_revoke() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let (_, device, record) = record_for_owner(&owner, 42);

        let register_auth = QlinkWalletAuthorization::sign_record(
            QlinkRegistryContractMethod::RegisterNode,
            &qlink_record_from_contract(&record),
            &owner,
        )
        .unwrap();
        registry
            .register_node(
                record.clone(),
                contract_wallet_auth_from_qlink(register_auth),
                device_auth_for_record(&device, &record),
            )
            .expect("qlink-core signed registration should verify");

        let mut updated = registry.get_node(&record.peer_id).unwrap();
        updated.latest_peer_record_hash_hex = "44".repeat(32);
        updated.updated_at = 200;
        refresh_pqc_binding(&mut updated);
        let update_auth = QlinkWalletAuthorization::sign_record(
            QlinkRegistryContractMethod::UpdateNode,
            &qlink_record_from_contract(&updated),
            &owner,
        )
        .unwrap();
        registry
            .update_node(
                updated.clone(),
                contract_wallet_auth_from_qlink(update_auth),
                device_auth_for_record(&device, &updated),
            )
            .expect("qlink-core signed update should verify");

        let revoke_auth =
            QlinkWalletAuthorization::sign_revoke(&updated.peer_id, 300, &owner).unwrap();
        registry
            .revoke_node(
                &updated.peer_id,
                300,
                contract_wallet_auth_from_qlink(revoke_auth),
            )
            .expect("qlink-core signed revocation should verify");

        assert_eq!(
            registry.get_node(&updated.peer_id).unwrap().status,
            NodeStatus::Revoked
        );
    }

    #[test]
    fn non_owner_cannot_update_or_revoke() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let other = DytallixKeypair::generate();
        let (_, device, record) = record_for_owner(&owner, 2);
        registry
            .register_node(
                record.clone(),
                wallet_auth_for_register(&owner, &record),
                device_auth_for_record(&device, &record),
            )
            .unwrap();

        assert_eq!(
            registry.update_node(
                record.clone(),
                wallet_auth_for_update(&other, &record),
                device_auth_for_record(&device, &record),
            ),
            Err(RegistryError::Unauthorized)
        );
        assert_eq!(
            registry.revoke_node(
                &record.peer_id,
                250,
                wallet_auth_for_revoke(&other, &record.peer_id, 250)
            ),
            Err(RegistryError::Unauthorized)
        );
    }

    #[test]
    fn registration_and_updates_canonicalize_owner_to_actor() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let (owner_daddr, device, record) = record_for_owner(&owner, 3);
        let register_auth = wallet_auth_for_register(&owner, &record);
        registry
            .register_node(
                record.clone(),
                register_auth,
                device_auth_for_record(&device, &record),
            )
            .unwrap();
        assert_eq!(
            registry.get_node(&record.peer_id).unwrap().owner_daddr,
            owner_daddr
        );

        let mut updated = record.clone();
        updated.latest_peer_record_hash_hex = "55".repeat(32);
        updated.updated_at = 125;
        refresh_pqc_binding(&mut updated);
        let update_auth = wallet_auth_for_update(&owner, &updated);
        registry
            .update_node(
                updated.clone(),
                update_auth,
                device_auth_for_record(&device, &updated),
            )
            .unwrap();
        let stored = registry.get_node(&record.peer_id).unwrap();
        assert_eq!(stored.owner_daddr, owner_daddr);
        assert_eq!(stored.latest_peer_record_hash_hex, "55".repeat(32));
    }

    #[test]
    fn duplicate_register_and_stale_updates_are_rejected() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let (_, device, record) = record_for_owner(&owner, 4);
        registry
            .register_node(
                record.clone(),
                wallet_auth_for_register(&owner, &record),
                device_auth_for_record(&device, &record),
            )
            .unwrap();

        assert_eq!(
            registry.register_node(
                record.clone(),
                wallet_auth_for_register(&owner, &record),
                device_auth_for_record(&device, &record),
            ),
            Err(RegistryError::AlreadyRegistered)
        );

        let mut stale_update = record.clone();
        stale_update.latest_peer_record_hash_hex = "88".repeat(32);
        stale_update.updated_at = 100;
        refresh_pqc_binding(&mut stale_update);
        assert_eq!(
            registry.update_node(
                stale_update.clone(),
                wallet_auth_for_update(&owner, &stale_update),
                device_auth_for_record(&device, &stale_update),
            ),
            Err(RegistryError::StaleRecord)
        );
    }

    #[test]
    fn revoked_records_reject_register_and_update_replays() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let (_, device, record) = record_for_owner(&owner, 5);
        let register_auth = wallet_auth_for_register(&owner, &record);
        registry
            .register_node(
                record.clone(),
                register_auth.clone(),
                device_auth_for_record(&device, &record),
            )
            .unwrap();

        let mut old_update = record.clone();
        old_update.latest_peer_record_hash_hex = "99".repeat(32);
        old_update.updated_at = 200;
        refresh_pqc_binding(&mut old_update);
        let old_update_auth = wallet_auth_for_update(&owner, &old_update);
        registry
            .update_node(
                old_update.clone(),
                old_update_auth.clone(),
                device_auth_for_record(&device, &old_update),
            )
            .unwrap();
        registry
            .revoke_node(
                &record.peer_id,
                300,
                wallet_auth_for_revoke(&owner, &record.peer_id, 300),
            )
            .unwrap();

        assert_eq!(
            registry.register_node(
                record.clone(),
                register_auth,
                device_auth_for_record(&device, &record),
            ),
            Err(RegistryError::AlreadyRegistered)
        );
        assert_eq!(
            registry.update_node(
                old_update.clone(),
                old_update_auth,
                device_auth_for_record(&device, &old_update),
            ),
            Err(RegistryError::Revoked)
        );
        assert_eq!(
            registry.get_node(&record.peer_id).unwrap().status,
            NodeStatus::Revoked
        );
    }

    #[test]
    fn mismatched_wallet_signature_payload_is_rejected() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let (_, device, mut record) = record_for_owner(&owner, 6);
        registry
            .register_node(
                record.clone(),
                wallet_auth_for_register(&owner, &record),
                device_auth_for_record(&device, &record),
            )
            .unwrap();

        record.latest_peer_record_hash_hex = "66".repeat(32);
        refresh_pqc_binding(&mut record);
        let signature_for_different_payload =
            wallet_auth_for_update(&owner, &registry.get_node(&record.peer_id).unwrap())
                .actor_signature_hex;
        let auth = WalletAuthorization {
            actor_public_key_hex: hex_encode(owner.public_key()),
            actor_signature_hex: signature_for_different_payload,
        };
        assert_eq!(
            registry.update_node(
                record.clone(),
                auth,
                device_auth_for_record(&device, &record)
            ),
            Err(RegistryError::InvalidSignature)
        );
    }

    #[test]
    fn signed_payload_from_different_wallet_cannot_spoof_owner() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let other = DytallixKeypair::generate();
        let (owner_daddr, device, mut record) = record_for_owner(&owner, 7);
        registry
            .register_node(
                record.clone(),
                wallet_auth_for_register(&owner, &record),
                device_auth_for_record(&device, &record),
            )
            .unwrap();

        record.owner_daddr = owner_daddr;
        record.latest_peer_record_hash_hex = "77".repeat(32);
        refresh_pqc_binding(&mut record);
        assert_eq!(
            registry.update_node(
                record.clone(),
                wallet_auth_for_update(&other, &record),
                device_auth_for_record(&device, &record),
            ),
            Err(RegistryError::Unauthorized)
        );
        assert_eq!(
            registry.revoke_node(
                &record.peer_id,
                500,
                wallet_auth_for_revoke(&other, &record.peer_id, 500)
            ),
            Err(RegistryError::Unauthorized)
        );
    }

    #[test]
    fn validation_rejects_non_quantumlink_peer_ids_and_non_32_byte_hex_fields() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let (_, device, valid_record) = record_for_owner(&owner, 8);
        let valid_device_auth = device_auth_for_record(&device, &valid_record);

        let mut invalid_peer_id = valid_record.clone();
        invalid_peer_id.peer_id = "other_peer".to_string();
        let invalid_peer_auth = wallet_auth_for_register(&owner, &invalid_peer_id);
        assert_eq!(
            registry.register_node(
                invalid_peer_id,
                invalid_peer_auth,
                valid_device_auth.clone()
            ),
            Err(RegistryError::InvalidPeerId)
        );

        let mut invalid_hex = valid_record.clone();
        invalid_hex.device_public_key_hash_hex = "abc123".to_string();
        let invalid_hex_auth = wallet_auth_for_register(&owner, &invalid_hex);
        assert_eq!(
            registry.register_node(invalid_hex, invalid_hex_auth, valid_device_auth.clone()),
            Err(RegistryError::InvalidHex)
        );

        let mut invalid_pqc_binding_hash = valid_record.clone();
        invalid_pqc_binding_hash.pqc_binding_hash_hex = "12".repeat(31);
        let invalid_pqc_auth = wallet_auth_for_register(&owner, &invalid_pqc_binding_hash);
        assert_eq!(
            registry.register_node(
                invalid_pqc_binding_hash,
                invalid_pqc_auth,
                valid_device_auth.clone(),
            ),
            Err(RegistryError::InvalidHex)
        );

        let mut invalid_node_signing_hash = valid_record.clone();
        invalid_node_signing_hash.node_signing_public_key_hash_hex = "gg".repeat(32);
        let invalid_node_auth = wallet_auth_for_register(&owner, &invalid_node_signing_hash);
        assert_eq!(
            registry.register_node(
                invalid_node_signing_hash,
                invalid_node_auth,
                valid_device_auth.clone(),
            ),
            Err(RegistryError::InvalidHex)
        );

        let mut invalid_transport_hash = valid_record.clone();
        invalid_transport_hash.transport_public_key_hash_hex = "14".repeat(33);
        let invalid_transport_auth = wallet_auth_for_register(&owner, &invalid_transport_hash);
        assert_eq!(
            registry.register_node(
                invalid_transport_hash,
                invalid_transport_auth,
                valid_device_auth.clone(),
            ),
            Err(RegistryError::InvalidHex)
        );

        let mut invalid_metadata = valid_record;
        invalid_metadata.metadata_commitment_hex = Some("zz".repeat(32));
        let invalid_metadata_auth = wallet_auth_for_register(&owner, &invalid_metadata);
        assert_eq!(
            registry.register_node(invalid_metadata, invalid_metadata_auth, valid_device_auth),
            Err(RegistryError::InvalidHex)
        );
    }

    #[test]
    fn events_are_recorded_for_state_transitions() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let (_, device, record) = record_for_owner(&owner, 9);
        registry
            .register_node(
                record.clone(),
                wallet_auth_for_register(&owner, &record),
                device_auth_for_record(&device, &record),
            )
            .unwrap();

        let mut updated = record.clone();
        updated.latest_peer_record_hash_hex = "44".repeat(32);
        updated.updated_at = 125;
        refresh_pqc_binding(&mut updated);
        let update_auth = wallet_auth_for_update(&owner, &updated);
        registry
            .update_node(
                updated.clone(),
                update_auth,
                device_auth_for_record(&device, &updated),
            )
            .unwrap();
        registry
            .revoke_node(
                &record.peer_id,
                150,
                wallet_auth_for_revoke(&owner, &record.peer_id, 150),
            )
            .unwrap();

        let events = registry.events(&record.peer_id);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_type, "registered");
        assert_eq!(events[1].event_type, "updated");
        assert_eq!(events[2].event_type, "revoked");
    }

    #[test]
    fn stale_revoke_after_newer_update_is_rejected_without_mutating_record() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let (_, device, record) = record_for_owner(&owner, 15);
        registry
            .register_node(
                record.clone(),
                wallet_auth_for_register(&owner, &record),
                device_auth_for_record(&device, &record),
            )
            .unwrap();

        let mut updated = record.clone();
        updated.latest_peer_record_hash_hex = "aa".repeat(32);
        updated.updated_at = 300;
        refresh_pqc_binding(&mut updated);
        registry
            .update_node(
                updated.clone(),
                wallet_auth_for_update(&owner, &updated),
                device_auth_for_record(&device, &updated),
            )
            .unwrap();

        assert_eq!(
            registry.revoke_node(
                &record.peer_id,
                200,
                wallet_auth_for_revoke(&owner, &record.peer_id, 200),
            ),
            Err(RegistryError::StaleRecord)
        );
        assert_eq!(registry.get_node(&record.peer_id).unwrap(), updated);
        assert_eq!(registry.events(&record.peer_id).len(), 2);
    }

    #[test]
    fn duplicate_revoke_replay_is_rejected_without_appending_event() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let (_, device, record) = record_for_owner(&owner, 16);
        registry
            .register_node(
                record.clone(),
                wallet_auth_for_register(&owner, &record),
                device_auth_for_record(&device, &record),
            )
            .unwrap();

        registry
            .revoke_node(
                &record.peer_id,
                200,
                wallet_auth_for_revoke(&owner, &record.peer_id, 200),
            )
            .unwrap();
        let revoked_record = registry.get_node(&record.peer_id).unwrap();
        let events_after_first_revoke = registry.events(&record.peer_id);
        assert_eq!(events_after_first_revoke.len(), 2);

        assert_eq!(
            registry.revoke_node(
                &record.peer_id,
                200,
                wallet_auth_for_revoke(&owner, &record.peer_id, 200),
            ),
            Err(RegistryError::Revoked)
        );
        assert_eq!(registry.get_node(&record.peer_id).unwrap(), revoked_record);
        assert_eq!(registry.events(&record.peer_id), events_after_first_revoke);
    }

    #[test]
    fn oversized_events_prevent_preparing_any_peer_state_storage_write() {
        let record = active_record();
        let normal_event = RegistryEvent {
            peer_id: record.peer_id.clone(),
            event_type: "registered".to_string(),
            actor_daddr: "dytallix1operator".to_string(),
            block_time: record.updated_at,
        };
        let prepared =
            prepare_peer_state_writes(&record.peer_id, &record, &[normal_event]).unwrap();
        assert_eq!(
            prepared.node_key,
            node_storage_key(&record.peer_id).unwrap()
        );
        assert_eq!(
            prepared.events_key,
            events_storage_key(&record.peer_id).unwrap()
        );
        assert!(prepared.node_value.len() < MAX_STORAGE_VALUE_SIZE);
        assert!(prepared.events_value.len() < MAX_STORAGE_VALUE_SIZE);

        let oversized_event = RegistryEvent {
            peer_id: record.peer_id.clone(),
            event_type: "registered".to_string(),
            actor_daddr: "dytallix1".repeat(MAX_STORAGE_VALUE_SIZE),
            block_time: record.updated_at,
        };

        let error = prepare_peer_state_writes(&record.peer_id, &record, &[oversized_event])
            .expect_err("oversized events must fail before returning writes");

        assert!(error.contains("storage value exceeds storage limit"));
    }

    #[test]
    fn corrupt_registry_state_returns_error_instead_of_panicking() {
        let error = decode_node_record(b"{not json").unwrap_err();
        assert!(error.contains("node record decode failed"));
    }

    #[test]
    fn node_status_serializes_as_snake_case() {
        for (status, json) in [
            (NodeStatus::Active, "\"active\""),
            (NodeStatus::Revoked, "\"revoked\""),
            (NodeStatus::Suspended, "\"suspended\""),
        ] {
            assert_eq!(serde_json::to_string(&status).unwrap(), json);
            assert_eq!(serde_json::from_str::<NodeStatus>(json).unwrap(), status);
        }
    }

    #[test]
    fn contract_rejects_device_binding_signed_for_different_owner_payload() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let owner_daddr = DAddr::from_public_key(owner.public_key())
            .unwrap()
            .to_string();
        let device = quantumlink_device(7);
        let record = device_bound_record(&owner_daddr, &device);
        let other_owner_record = device_bound_record("dytallix1differentowner", &device);

        assert_eq!(
            registry.register_node(
                record.clone(),
                wallet_auth_for_register(&owner, &record),
                device_auth_for_record(&device, &other_owner_record),
            ),
            Err(RegistryError::InvalidSignature)
        );
    }

    #[test]
    fn contract_rejects_first_claim_by_other_wallet_without_device_signature_for_owner() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let legitimate_owner = DytallixKeypair::generate();
        let attacker = DytallixKeypair::generate();
        let legitimate_owner_daddr = DAddr::from_public_key(legitimate_owner.public_key())
            .unwrap()
            .to_string();
        let attacker_daddr = DAddr::from_public_key(attacker.public_key())
            .unwrap()
            .to_string();
        let device = quantumlink_device(9);
        let legitimate_record = device_bound_record(&legitimate_owner_daddr, &device);
        let attacker_record = device_bound_record(&attacker_daddr, &device);

        assert_eq!(
            registry.register_node(
                attacker_record.clone(),
                wallet_auth_for_register(&attacker, &attacker_record),
                device_auth_for_record(&device, &legitimate_record),
            ),
            Err(RegistryError::InvalidSignature)
        );
    }

    #[test]
    fn contract_rejects_device_public_key_peer_id_mismatch() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let (_, device, mut record) = record_for_owner(&owner, 10);
        record.peer_id = "qlink_wrong_peer_id".to_string();
        refresh_pqc_binding(&mut record);

        assert_eq!(
            registry.register_node(
                record.clone(),
                wallet_auth_for_register(&owner, &record),
                device_auth_for_record(&device, &record),
            ),
            Err(RegistryError::InvalidPeerId)
        );
    }

    #[test]
    fn contract_rejects_device_public_key_hash_mismatch() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let (_, device, mut record) = record_for_owner(&owner, 11);
        record.device_public_key_hash_hex = "00".repeat(32);
        refresh_pqc_binding(&mut record);

        assert_eq!(
            registry.register_node(
                record.clone(),
                wallet_auth_for_register(&owner, &record),
                device_auth_for_record(&device, &record),
            ),
            Err(RegistryError::InvalidSignature)
        );
    }

    #[test]
    fn contract_rejects_node_signing_hash_mismatch() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let (_, device, mut record) = record_for_owner(&owner, 12);
        record.node_signing_public_key_hash_hex = "33".repeat(32);
        refresh_pqc_binding(&mut record);

        assert_eq!(
            registry.register_node(
                record.clone(),
                wallet_auth_for_register(&owner, &record),
                device_auth_for_record(&device, &record),
            ),
            Err(RegistryError::InvalidSignature)
        );
    }

    #[test]
    fn contract_rejects_pqc_binding_hash_mismatch() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let (_, device, mut record) = record_for_owner(&owner, 13);
        record.pqc_binding_hash_hex = "44".repeat(32);

        assert_eq!(
            registry.register_node(
                record.clone(),
                wallet_auth_for_register(&owner, &record),
                device_auth_for_record(&device, &record),
            ),
            Err(RegistryError::InvalidSignature)
        );
    }

    #[test]
    fn contract_rejects_invalid_device_binding_signature() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let owner = DytallixKeypair::generate();
        let (_, device, record) = record_for_owner(&owner, 14);
        let mut device_auth = device_auth_for_record(&device, &record);
        device_auth
            .device_binding_signature_hex
            .replace_range(0..2, "00");

        assert_eq!(
            registry.register_node(
                record.clone(),
                wallet_auth_for_register(&owner, &record),
                device_auth,
            ),
            Err(RegistryError::InvalidSignature)
        );
    }

    #[test]
    fn per_peer_storage_serialization_does_not_depend_on_global_registry_blob() {
        let mut total_bytes = 0usize;

        for index in 0..256 {
            let peer_id = format!("qlink_peer_{index}");
            let mut record = active_record();
            record.peer_id = peer_id.clone();
            record.latest_peer_record_hash_hex = format!("{:02x}", index % 256).repeat(32);
            record.updated_at = index;
            let event = RegistryEvent {
                peer_id: peer_id.clone(),
                event_type: "registered".to_string(),
                actor_daddr: "dytallix1operator".to_string(),
                block_time: index,
            };

            let node_key = node_storage_key(&peer_id).unwrap();
            let events_key = events_storage_key(&peer_id).unwrap();
            let node_value = encode_node_record(&record).unwrap();
            let events_value = encode_registry_events(&[event]).unwrap();

            assert_eq!(node_key, format!("node:{peer_id}").as_bytes());
            assert_eq!(events_key, format!("events:{peer_id}").as_bytes());
            assert_eq!(decode_node_record(&node_value).unwrap(), record);
            assert_eq!(decode_registry_events(&events_value).unwrap().len(), 1);
            assert!(node_value.len() < MAX_STORAGE_VALUE_SIZE);
            assert!(events_value.len() < MAX_STORAGE_VALUE_SIZE);
            total_bytes += node_value.len() + events_value.len();
        }

        assert!(total_bytes > MAX_STORAGE_VALUE_SIZE);
    }
}
