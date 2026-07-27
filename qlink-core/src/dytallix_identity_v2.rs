use crate::{
    crypto::{DeviceKeypair, DevicePublicKey},
    discovery::{now_unix, PeerRecord},
    inbound_identity::InboundIdentityAssertion,
};
use dytallix_core::{address::DAddr, keypair::DytallixKeypair, signature::verify_mldsa65};
use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const STABLE_IDENTITY_SCHEMA_VERSION: u8 = 2;

const CONTRACT_DOMAIN: &str = "quantumlink-node-registry-v2";
const DEVICE_AUTHORIZATION_PURPOSE: &str = "authorize-stable-identity-binding";
const MESH_SCOPE_HASH_DOMAIN: &[u8] = b"QuantumLink Dytallix stable identity mesh scope v2";
const MIN_PEER_RECORD_TTL_SECONDS: u64 = 30;
const MAX_PEER_RECORD_TTL_SECONDS: u64 = 86_400;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegistryIdentityStatusV2 {
    Active,
    Revoked,
    Suspended,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RegistryIdentityRecordV2 {
    pub schema_version: u8,
    pub peer_id: String,
    pub owner_daddr: String,
    pub device_public_key_hash_hex: String,
    pub node_signing_public_key_hash_hex: String,
    pub status: RegistryIdentityStatusV2,
    pub identity_revision: u64,
    pub authorization_expires_at: Option<u64>,
    pub max_peer_record_ttl_seconds: u64,
    pub mesh_scope_hash_hex: Option<String>,
    pub metadata_commitment_hex: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryIdentityRecordV2Wire {
    schema_version: u8,
    peer_id: String,
    owner_daddr: String,
    device_public_key_hash_hex: String,
    node_signing_public_key_hash_hex: String,
    status: RegistryIdentityStatusV2,
    identity_revision: u64,
    authorization_expires_at: Option<u64>,
    max_peer_record_ttl_seconds: u64,
    mesh_scope_hash_hex: Option<String>,
    metadata_commitment_hex: Option<String>,
}

impl<'de> Deserialize<'de> for RegistryIdentityRecordV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RegistryIdentityRecordV2Wire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            peer_id: wire.peer_id,
            owner_daddr: wire.owner_daddr,
            device_public_key_hash_hex: wire.device_public_key_hash_hex,
            node_signing_public_key_hash_hex: wire.node_signing_public_key_hash_hex,
            status: wire.status,
            identity_revision: wire.identity_revision,
            authorization_expires_at: wire.authorization_expires_at,
            max_peer_record_ttl_seconds: wire.max_peer_record_ttl_seconds,
            mesh_scope_hash_hex: wire.mesh_scope_hash_hex,
            metadata_commitment_hex: wire.metadata_commitment_hex,
        };
        record.validate().map_err(D::Error::custom)?;
        Ok(record)
    }
}

impl RegistryIdentityRecordV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_device_public_key(
        owner_daddr: impl Into<String>,
        device_public_key: &DevicePublicKey,
        status: RegistryIdentityStatusV2,
        identity_revision: u64,
        authorization_expires_at: Option<u64>,
        max_peer_record_ttl_seconds: u64,
        mesh_scope: Option<&str>,
        metadata_commitment_hex: Option<String>,
    ) -> StableIdentityV2Result<Self> {
        let owner_daddr = owner_daddr.into();
        let peer_id = device_public_key.peer_id();
        let device_public_key_hash_hex = device_public_key_hash_hex(device_public_key)?;
        let record = Self {
            schema_version: STABLE_IDENTITY_SCHEMA_VERSION,
            peer_id,
            owner_daddr,
            device_public_key_hash_hex: device_public_key_hash_hex.clone(),
            node_signing_public_key_hash_hex: device_public_key_hash_hex,
            status,
            identity_revision,
            authorization_expires_at,
            max_peer_record_ttl_seconds,
            mesh_scope_hash_hex: mesh_scope.map(mesh_scope_hash_hex),
            metadata_commitment_hex,
        };
        record.validate()?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_peer_record(
        owner_daddr: impl Into<String>,
        peer_record: &PeerRecord,
        status: RegistryIdentityStatusV2,
        identity_revision: u64,
        authorization_expires_at: Option<u64>,
        max_peer_record_ttl_seconds: u64,
        bind_mesh_scope: bool,
        metadata_commitment_hex: Option<String>,
    ) -> StableIdentityV2Result<Self> {
        if peer_record.body.peer_id != peer_record.body.device_public_key.peer_id() {
            return Err(StableIdentityV2Error::WrongDevice);
        }
        let mut record = Self::from_device_public_key(
            owner_daddr,
            &peer_record.body.device_public_key,
            status,
            identity_revision,
            authorization_expires_at,
            max_peer_record_ttl_seconds,
            bind_mesh_scope.then_some(peer_record.body.mesh_id.as_str()),
            metadata_commitment_hex,
        )?;
        record.peer_id = peer_record.body.peer_id.clone();
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> StableIdentityV2Result<()> {
        if self.schema_version != STABLE_IDENTITY_SCHEMA_VERSION {
            return Err(StableIdentityV2Error::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        if self.peer_id.trim().is_empty() {
            return Err(StableIdentityV2Error::InvalidRecord(
                "peer_id must not be empty".into(),
            ));
        }
        DAddr::from_str(&self.owner_daddr).map_err(|err| {
            StableIdentityV2Error::InvalidRecord(format!("owner_daddr is invalid: {err}"))
        })?;
        require_sha256_hex(
            "device_public_key_hash_hex",
            &self.device_public_key_hash_hex,
        )?;
        require_sha256_hex(
            "node_signing_public_key_hash_hex",
            &self.node_signing_public_key_hash_hex,
        )?;
        if self.identity_revision == 0 {
            return Err(StableIdentityV2Error::InvalidRecord(
                "identity_revision must be greater than zero".into(),
            ));
        }
        if self.authorization_expires_at == Some(0) {
            return Err(StableIdentityV2Error::InvalidRecord(
                "authorization_expires_at must be greater than zero when present".into(),
            ));
        }
        if !(MIN_PEER_RECORD_TTL_SECONDS..=MAX_PEER_RECORD_TTL_SECONDS)
            .contains(&self.max_peer_record_ttl_seconds)
        {
            return Err(StableIdentityV2Error::InvalidRecord(
                "max_peer_record_ttl_seconds must be between 30 and 86400".into(),
            ));
        }
        if let Some(mesh_scope_hash_hex) = &self.mesh_scope_hash_hex {
            require_sha256_hex("mesh_scope_hash_hex", mesh_scope_hash_hex)?;
        }
        if let Some(metadata_commitment_hex) = &self.metadata_commitment_hex {
            require_sha256_hex("metadata_commitment_hex", metadata_commitment_hex)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegistryIdentityOperationV2 {
    Register,
    Update,
}

impl RegistryIdentityOperationV2 {
    fn contract_method(self) -> &'static str {
        match self {
            Self::Register => "register_identity",
            Self::Update => "update_identity",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletAuthorizationV2 {
    pub actor_public_key_hex: String,
    pub actor_signature_hex: String,
}

impl WalletAuthorizationV2 {
    pub fn sign(
        operation: RegistryIdentityOperationV2,
        record: &RegistryIdentityRecordV2,
        keypair: &DytallixKeypair,
    ) -> StableIdentityV2Result<Self> {
        record.validate()?;
        require_wallet_owner(record, keypair.public_key())?;
        let payload = canonical_wallet_payload_bytes(operation, record)?;
        let signature = keypair.sign(&payload).map_err(|err| {
            StableIdentityV2Error::WalletAuthorization(format!(
                "Dytallix wallet signing failed: {err}"
            ))
        })?;
        Ok(Self {
            actor_public_key_hex: hex::encode(keypair.public_key()),
            actor_signature_hex: hex::encode(signature),
        })
    }

    pub fn verify(
        &self,
        operation: RegistryIdentityOperationV2,
        record: &RegistryIdentityRecordV2,
    ) -> StableIdentityV2Result<()> {
        record.validate()?;
        let public_key = decode_hex("actor_public_key_hex", &self.actor_public_key_hex)?;
        require_wallet_owner(record, &public_key)?;
        let signature = decode_hex("actor_signature_hex", &self.actor_signature_hex)?;
        let payload = canonical_wallet_payload_bytes(operation, record)?;
        let verified = verify_mldsa65(&public_key, &payload, &signature).map_err(|err| {
            StableIdentityV2Error::WalletAuthorization(format!(
                "wallet signature could not be verified: {err}"
            ))
        })?;
        if !verified {
            return Err(StableIdentityV2Error::WalletAuthorization(
                "wallet signature verification failed".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceAuthorizationV2 {
    pub device_public_key_algorithm: String,
    pub device_public_key_hex: String,
    pub device_signature_hex: String,
}

impl DeviceAuthorizationV2 {
    pub fn sign(
        operation: RegistryIdentityOperationV2,
        record: &RegistryIdentityRecordV2,
        keypair: &DeviceKeypair,
    ) -> StableIdentityV2Result<Self> {
        record.validate()?;
        let public_key = keypair.public_key();
        require_record_device(record, &public_key)?;
        let payload = canonical_device_payload_bytes(operation, record)?;
        Ok(Self {
            device_public_key_algorithm: public_key.algorithm,
            device_public_key_hex: hex::encode(public_key.bytes),
            device_signature_hex: hex::encode(keypair.sign(&payload)),
        })
    }

    pub fn verify(
        &self,
        operation: RegistryIdentityOperationV2,
        record: &RegistryIdentityRecordV2,
    ) -> StableIdentityV2Result<()> {
        record.validate()?;
        let public_key = DevicePublicKey {
            algorithm: self.device_public_key_algorithm.clone(),
            bytes: decode_hex("device_public_key_hex", &self.device_public_key_hex)?,
        };
        require_record_device(record, &public_key)?;
        let signature = decode_hex("device_signature_hex", &self.device_signature_hex)?;
        let payload = canonical_device_payload_bytes(operation, record)?;
        public_key.verify(&payload, &signature).map_err(|_| {
            StableIdentityV2Error::DeviceAuthorization(
                "device signature verification failed".into(),
            )
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StableRegistryBindingDecisionV2 {
    Accepted,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StableIdentityV2Error {
    #[error("unsupported Dytallix stable identity schema version {0}")]
    UnsupportedSchemaVersion(u8),
    #[error("invalid Dytallix stable identity record: {0}")]
    InvalidRecord(String),
    #[error("Dytallix stable identity record is missing")]
    Missing,
    #[error("Dytallix stable identity is revoked")]
    Revoked,
    #[error("Dytallix stable identity is suspended")]
    Suspended,
    #[error("Dytallix stable identity device binding does not match the peer record")]
    WrongDevice,
    #[error("Dytallix stable identity node signing key does not match the peer record")]
    WrongNodeSigningKey,
    #[error("Dytallix stable identity authorization expired at {expires_at}")]
    AuthorizationExpired { expires_at: u64 },
    #[error("peer record does not contain a signed issued_at_unix timestamp")]
    MissingSignedIssuedAt,
    #[error("peer record TTL is invalid: {0}")]
    InvalidPeerRecordTtl(String),
    #[error("peer record TTL {actual_seconds}s exceeds registry maximum {maximum_seconds}s")]
    PeerRecordTtlExceeded {
        actual_seconds: u64,
        maximum_seconds: u64,
    },
    #[error("peer record is invalid: {0}")]
    InvalidPeerRecord(String),
    #[error("peer record mesh scope does not match the stable registry identity")]
    WrongMeshScope,
    #[error("wallet authorization is invalid: {0}")]
    WalletAuthorization(String),
    #[error("device authorization is invalid: {0}")]
    DeviceAuthorization(String),
}

pub type StableIdentityV2Result<T> = std::result::Result<T, StableIdentityV2Error>;

#[derive(Serialize)]
struct CanonicalWalletPayload<'a> {
    contract: &'static str,
    schema_version: u8,
    operation: &'static str,
    record: &'a RegistryIdentityRecordV2,
}

#[derive(Serialize)]
struct CanonicalDevicePayload<'a> {
    contract: &'static str,
    schema_version: u8,
    purpose: &'static str,
    binding: &'a RegistryIdentityRecordV2,
}

pub fn canonical_wallet_payload_bytes(
    operation: RegistryIdentityOperationV2,
    record: &RegistryIdentityRecordV2,
) -> StableIdentityV2Result<Vec<u8>> {
    record.validate()?;
    serde_json::to_vec(&CanonicalWalletPayload {
        contract: CONTRACT_DOMAIN,
        schema_version: STABLE_IDENTITY_SCHEMA_VERSION,
        operation: operation.contract_method(),
        record,
    })
    .map_err(|err| {
        StableIdentityV2Error::InvalidRecord(format!(
            "wallet authorization payload serialization failed: {err}"
        ))
    })
}

pub fn canonical_device_payload_bytes(
    _operation: RegistryIdentityOperationV2,
    record: &RegistryIdentityRecordV2,
) -> StableIdentityV2Result<Vec<u8>> {
    record.validate()?;
    serde_json::to_vec(&CanonicalDevicePayload {
        contract: CONTRACT_DOMAIN,
        schema_version: STABLE_IDENTITY_SCHEMA_VERSION,
        purpose: DEVICE_AUTHORIZATION_PURPOSE,
        binding: record,
    })
    .map_err(|err| {
        StableIdentityV2Error::InvalidRecord(format!(
            "device authorization payload serialization failed: {err}"
        ))
    })
}

pub fn device_public_key_hash_hex(
    device_public_key: &DevicePublicKey,
) -> StableIdentityV2Result<String> {
    let bytes = serde_json::to_vec(device_public_key).map_err(|err| {
        StableIdentityV2Error::InvalidRecord(format!(
            "device public key serialization failed: {err}"
        ))
    })?;
    Ok(sha256_hex(&bytes))
}

pub fn mesh_scope_hash_hex(mesh_scope: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MESH_SCOPE_HASH_DOMAIN);
    hasher.update([0]);
    hasher.update(mesh_scope.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn verify_stable_registry_binding(
    peer_record: &PeerRecord,
    registry_record: Option<&RegistryIdentityRecordV2>,
) -> StableIdentityV2Result<StableRegistryBindingDecisionV2> {
    verify_stable_registry_binding_at(peer_record, registry_record, now_unix())
}

pub fn verify_stable_registry_binding_at(
    peer_record: &PeerRecord,
    registry_record: Option<&RegistryIdentityRecordV2>,
    verification_time_unix: u64,
) -> StableIdentityV2Result<StableRegistryBindingDecisionV2> {
    verify_peer_record_signature(peer_record, verification_time_unix)?;
    let registry_record = registry_record.ok_or(StableIdentityV2Error::Missing)?;
    registry_record.validate()?;
    require_active_and_unexpired(registry_record, verification_time_unix)?;

    let issued_at_unix = signed_peer_record_issued_at_unix(peer_record)?;
    verify_stable_registry_binding_with_issued_at(peer_record, registry_record, issued_at_unix)
}

pub fn verify_stable_inbound_registry_binding(
    assertion: &InboundIdentityAssertion,
    registry_record: Option<&RegistryIdentityRecordV2>,
    expected_mesh_id: &str,
    max_age_seconds: u64,
) -> StableIdentityV2Result<StableRegistryBindingDecisionV2> {
    assertion
        .verify(expected_mesh_id, max_age_seconds)
        .map_err(|error| StableIdentityV2Error::InvalidPeerRecord(error.to_string()))?;
    let registry_record = registry_record.ok_or(StableIdentityV2Error::Missing)?;
    registry_record.validate()?;
    require_active_and_unexpired(registry_record, now_unix())?;

    if registry_record.peer_id != assertion.peer_id {
        return Err(StableIdentityV2Error::WrongDevice);
    }
    let key_hash = device_public_key_hash_hex(&assertion.device_public_key)?;
    if registry_record.device_public_key_hash_hex != key_hash {
        return Err(StableIdentityV2Error::WrongDevice);
    }
    if registry_record.node_signing_public_key_hash_hex != key_hash {
        return Err(StableIdentityV2Error::WrongNodeSigningKey);
    }
    if registry_record
        .mesh_scope_hash_hex
        .as_ref()
        .is_some_and(|expected| expected != &mesh_scope_hash_hex(&assertion.mesh_id))
    {
        return Err(StableIdentityV2Error::WrongMeshScope);
    }

    Ok(StableRegistryBindingDecisionV2::Accepted)
}

fn verify_stable_registry_binding_with_issued_at(
    peer_record: &PeerRecord,
    registry_record: &RegistryIdentityRecordV2,
    issued_at_unix: u64,
) -> StableIdentityV2Result<StableRegistryBindingDecisionV2> {
    if registry_record.peer_id != peer_record.body.peer_id {
        return Err(StableIdentityV2Error::WrongDevice);
    }

    let peer_key_hash = device_public_key_hash_hex(&peer_record.body.device_public_key)?;
    if registry_record.device_public_key_hash_hex != peer_key_hash {
        return Err(StableIdentityV2Error::WrongDevice);
    }
    if registry_record.node_signing_public_key_hash_hex != peer_key_hash {
        return Err(StableIdentityV2Error::WrongNodeSigningKey);
    }

    if registry_record
        .mesh_scope_hash_hex
        .as_ref()
        .is_some_and(|expected| expected != &mesh_scope_hash_hex(&peer_record.body.mesh_id))
    {
        return Err(StableIdentityV2Error::WrongMeshScope);
    }

    let ttl_seconds = peer_record
        .body
        .expires_at_unix
        .checked_sub(issued_at_unix)
        .filter(|ttl| *ttl > 0)
        .ok_or_else(|| {
            StableIdentityV2Error::InvalidPeerRecordTtl(
                "expires_at_unix must be greater than signed issued_at_unix".into(),
            )
        })?;
    if ttl_seconds > registry_record.max_peer_record_ttl_seconds {
        return Err(StableIdentityV2Error::PeerRecordTtlExceeded {
            actual_seconds: ttl_seconds,
            maximum_seconds: registry_record.max_peer_record_ttl_seconds,
        });
    }

    Ok(StableRegistryBindingDecisionV2::Accepted)
}

fn verify_peer_record_signature(
    peer_record: &PeerRecord,
    verification_time_unix: u64,
) -> StableIdentityV2Result<()> {
    if peer_record.body.expires_at_unix <= verification_time_unix {
        return Err(StableIdentityV2Error::InvalidPeerRecord(
            "record has expired".into(),
        ));
    }
    if peer_record.body.device_public_key.peer_id() != peer_record.body.peer_id {
        return Err(StableIdentityV2Error::InvalidPeerRecord(
            "peer_id does not match the signed device public key".into(),
        ));
    }
    let canonical_bytes = peer_record.body.canonical_bytes().map_err(|err| {
        StableIdentityV2Error::InvalidPeerRecord(format!("signed body serialization failed: {err}"))
    })?;
    peer_record
        .body
        .device_public_key
        .verify(&canonical_bytes, &peer_record.signature)
        .map_err(|_| {
            StableIdentityV2Error::InvalidPeerRecord(
                "peer record signature verification failed".into(),
            )
        })
}

fn signed_peer_record_issued_at_unix(peer_record: &PeerRecord) -> StableIdentityV2Result<u64> {
    if peer_record.body.issued_at_unix == 0 {
        Err(StableIdentityV2Error::MissingSignedIssuedAt)
    } else {
        Ok(peer_record.body.issued_at_unix)
    }
}

fn require_active_and_unexpired(
    record: &RegistryIdentityRecordV2,
    verification_time_unix: u64,
) -> StableIdentityV2Result<()> {
    match record.status {
        RegistryIdentityStatusV2::Active => {}
        RegistryIdentityStatusV2::Revoked => return Err(StableIdentityV2Error::Revoked),
        RegistryIdentityStatusV2::Suspended => return Err(StableIdentityV2Error::Suspended),
    }
    if let Some(expires_at) = record.authorization_expires_at {
        if expires_at <= verification_time_unix {
            return Err(StableIdentityV2Error::AuthorizationExpired { expires_at });
        }
    }
    Ok(())
}

fn require_record_device(
    record: &RegistryIdentityRecordV2,
    device_public_key: &DevicePublicKey,
) -> StableIdentityV2Result<()> {
    if record.peer_id != device_public_key.peer_id()
        || record.device_public_key_hash_hex != device_public_key_hash_hex(device_public_key)?
    {
        return Err(StableIdentityV2Error::WrongDevice);
    }
    Ok(())
}

fn require_wallet_owner(
    record: &RegistryIdentityRecordV2,
    public_key: &[u8],
) -> StableIdentityV2Result<()> {
    let owner = DAddr::from_public_key(public_key).map_err(|err| {
        StableIdentityV2Error::WalletAuthorization(format!(
            "wallet public key cannot derive a Dytallix owner address: {err}"
        ))
    })?;
    if owner.as_str() != record.owner_daddr {
        return Err(StableIdentityV2Error::WalletAuthorization(
            "wallet public key does not match owner_daddr".into(),
        ));
    }
    Ok(())
}

fn require_sha256_hex(field: &str, value: &str) -> StableIdentityV2Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StableIdentityV2Error::InvalidRecord(format!(
            "{field} must be 32-byte lowercase hexadecimal"
        )));
    }
    Ok(())
}

fn decode_hex(field: &str, value: &str) -> StableIdentityV2Result<Vec<u8>> {
    hex::decode(value).map_err(|err| {
        StableIdentityV2Error::InvalidRecord(format!("{field} is not valid hexadecimal: {err}"))
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        discovery::{CandidateEndpoint, CandidateType, UnsignedPeerRecord},
        ice::IceCredentials,
    };

    const NOW: u64 = 1_900_000_000;

    fn wallet_and_owner() -> (DytallixKeypair, String) {
        let keypair = DytallixKeypair::generate();
        let owner = DAddr::from_public_key(keypair.public_key())
            .unwrap()
            .as_str()
            .to_string();
        (keypair, owner)
    }

    fn signed_peer_record(
        keypair: &DeviceKeypair,
        mesh_id: &str,
        expires_at_unix: u64,
        sequence: u64,
    ) -> PeerRecord {
        let body = UnsignedPeerRecord {
            mesh_id: mesh_id.to_string(),
            peer_id: keypair.public_key().peer_id(),
            alias: format!("peer-{sequence}"),
            device_public_key: keypair.public_key(),
            endpoints: vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "192.0.2.10".into(),
                port: 4433,
                priority: 100,
            }],
            routes: vec!["100.64.0.1/32".into()],
            issued_at_unix: NOW,
            expires_at_unix,
            sequence,
            ice_credentials: IceCredentials {
                ufrag: format!("user{sequence}"),
                password: format!("password{sequence}"),
            },
            device_certificate_der: format!("certificate-{sequence}").into_bytes(),
        };
        PeerRecord::signed(body, keypair).unwrap()
    }

    fn active_record(
        owner: &str,
        peer_record: &PeerRecord,
        max_ttl: u64,
    ) -> RegistryIdentityRecordV2 {
        RegistryIdentityRecordV2::from_peer_record(
            owner,
            peer_record,
            RegistryIdentityStatusV2::Active,
            1,
            Some(NOW + 3_600),
            max_ttl,
            true,
            Some("ab".repeat(32)),
        )
        .unwrap()
    }

    fn verify_with_issued_at(
        peer_record: &PeerRecord,
        record: Option<&RegistryIdentityRecordV2>,
        issued_at_unix: u64,
    ) -> StableIdentityV2Result<StableRegistryBindingDecisionV2> {
        verify_peer_record_signature(peer_record, NOW)?;
        let record = record.ok_or(StableIdentityV2Error::Missing)?;
        record.validate()?;
        require_active_and_unexpired(record, NOW)?;
        verify_stable_registry_binding_with_issued_at(peer_record, record, issued_at_unix)
    }

    #[test]
    fn schema_serializes_exact_stable_fields_and_excludes_transient_fields() {
        let keypair = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&keypair, "mesh-a", NOW + 120, 7);
        let (_, owner) = wallet_and_owner();
        let record = active_record(&owner, &peer_record, 300);
        let value = serde_json::to_value(record).unwrap();
        let object = value.as_object().unwrap();

        let expected = [
            "schema_version",
            "peer_id",
            "owner_daddr",
            "device_public_key_hash_hex",
            "node_signing_public_key_hash_hex",
            "status",
            "identity_revision",
            "authorization_expires_at",
            "max_peer_record_ttl_seconds",
            "mesh_scope_hash_hex",
            "metadata_commitment_hex",
        ];
        assert_eq!(object.len(), expected.len());
        for field in expected {
            assert!(object.contains_key(field), "missing field {field}");
        }
        for transient in [
            "latest_peer_record_hash_hex",
            "transport_public_key_hash_hex",
            "expires_at_unix",
            "sequence",
            "endpoints",
            "ice_credentials",
        ] {
            assert!(!object.contains_key(transient));
        }
        assert_eq!(object["schema_version"], STABLE_IDENTITY_SCHEMA_VERSION);
    }

    #[test]
    fn construction_is_stable_across_transient_peer_record_refreshes() {
        let keypair = DeviceKeypair::generate().unwrap();
        let first = signed_peer_record(&keypair, "mesh-a", NOW + 120, 1);
        let second = signed_peer_record(&keypair, "mesh-a", NOW + 240, 2);
        let (_, owner) = wallet_and_owner();

        let first_record = active_record(&owner, &first, 300);
        let second_record = active_record(&owner, &second, 300);

        assert_eq!(first_record, second_record);
    }

    #[test]
    fn construction_rejects_peer_id_that_does_not_match_device_key() {
        let keypair = DeviceKeypair::generate().unwrap();
        let mut peer_record = signed_peer_record(&keypair, "mesh-a", NOW + 120, 1);
        peer_record.body.peer_id.push_str("-tampered");
        let (_, owner) = wallet_and_owner();

        let error = RegistryIdentityRecordV2::from_peer_record(
            owner,
            &peer_record,
            RegistryIdentityStatusV2::Active,
            1,
            None,
            120,
            true,
            None,
        )
        .unwrap_err();

        assert_eq!(error, StableIdentityV2Error::WrongDevice);
    }

    #[test]
    fn canonical_payloads_match_contract_domains_and_operations() {
        let keypair = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&keypair, "mesh-a", NOW + 120, 1);
        let (_, owner) = wallet_and_owner();
        let record = active_record(&owner, &peer_record, 300);

        let wallet =
            canonical_wallet_payload_bytes(RegistryIdentityOperationV2::Register, &record).unwrap();
        let wallet_again =
            canonical_wallet_payload_bytes(RegistryIdentityOperationV2::Register, &record).unwrap();
        let device =
            canonical_device_payload_bytes(RegistryIdentityOperationV2::Register, &record).unwrap();
        let update =
            canonical_wallet_payload_bytes(RegistryIdentityOperationV2::Update, &record).unwrap();

        assert_eq!(wallet, wallet_again);
        assert_ne!(wallet, device);
        assert_ne!(wallet, update);
        let wallet: serde_json::Value = serde_json::from_slice(&wallet).unwrap();
        let device: serde_json::Value = serde_json::from_slice(&device).unwrap();
        let update: serde_json::Value = serde_json::from_slice(&update).unwrap();
        assert_eq!(wallet["contract"], CONTRACT_DOMAIN);
        assert_eq!(wallet["operation"], "register_identity");
        assert_eq!(wallet["record"]["peer_id"], record.peer_id);
        assert_eq!(update["operation"], "update_identity");
        assert_eq!(device["contract"], CONTRACT_DOMAIN);
        assert_eq!(device["purpose"], DEVICE_AUTHORIZATION_PURPOSE);
        assert_eq!(device["binding"]["peer_id"], record.peer_id);
    }

    #[test]
    fn canonical_authorization_bytes_match_the_v2_contract() {
        let keypair = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&keypair, "mesh-a", NOW + 120, 1);
        let (_, owner) = wallet_and_owner();
        let record = active_record(&owner, &peer_record, 300);
        let contract_record: quantumlink_node_registry_v2::StableIdentityRecord =
            serde_json::from_value(serde_json::to_value(&record).unwrap()).unwrap();

        assert_eq!(
            canonical_wallet_payload_bytes(RegistryIdentityOperationV2::Register, &record).unwrap(),
            quantumlink_node_registry_v2::canonical_register_payload(&contract_record).unwrap()
        );
        assert_eq!(
            canonical_wallet_payload_bytes(RegistryIdentityOperationV2::Update, &record).unwrap(),
            quantumlink_node_registry_v2::canonical_update_payload(&contract_record).unwrap()
        );
        assert_eq!(
            canonical_device_payload_bytes(RegistryIdentityOperationV2::Register, &record).unwrap(),
            quantumlink_node_registry_v2::canonical_device_authorization_payload(&contract_record)
                .unwrap()
        );
    }

    #[test]
    fn wallet_authorization_verifies_owner_bound_canonical_record() {
        let device = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&device, "mesh-a", NOW + 120, 1);
        let (wallet, owner) = wallet_and_owner();
        let record = active_record(&owner, &peer_record, 300);

        let authorization =
            WalletAuthorizationV2::sign(RegistryIdentityOperationV2::Register, &record, &wallet)
                .unwrap();

        authorization
            .verify(RegistryIdentityOperationV2::Register, &record)
            .unwrap();
        assert!(authorization
            .verify(RegistryIdentityOperationV2::Update, &record)
            .is_err());

        let mut changed = record.clone();
        changed.identity_revision += 1;
        assert!(authorization
            .verify(RegistryIdentityOperationV2::Register, &changed)
            .is_err());
    }

    #[test]
    fn wallet_authorization_rejects_wrong_owner() {
        let device = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&device, "mesh-a", NOW + 120, 1);
        let (wallet, _) = wallet_and_owner();
        let (_, other_owner) = wallet_and_owner();
        let record = active_record(&other_owner, &peer_record, 300);

        let error =
            WalletAuthorizationV2::sign(RegistryIdentityOperationV2::Register, &record, &wallet)
                .unwrap_err();

        assert!(matches!(
            error,
            StableIdentityV2Error::WalletAuthorization(_)
        ));
    }

    #[test]
    fn device_authorization_verifies_and_rejects_tampering() {
        let device = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&device, "mesh-a", NOW + 120, 1);
        let (_, owner) = wallet_and_owner();
        let record = active_record(&owner, &peer_record, 300);

        let authorization =
            DeviceAuthorizationV2::sign(RegistryIdentityOperationV2::Register, &record, &device)
                .unwrap();

        authorization
            .verify(RegistryIdentityOperationV2::Register, &record)
            .unwrap();
        let mut changed = record.clone();
        changed.identity_revision += 1;
        assert!(authorization
            .verify(RegistryIdentityOperationV2::Register, &changed)
            .is_err());
    }

    #[test]
    fn device_authorization_rejects_wrong_device() {
        let device = DeviceKeypair::generate().unwrap();
        let wrong_device = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&device, "mesh-a", NOW + 120, 1);
        let (_, owner) = wallet_and_owner();
        let record = active_record(&owner, &peer_record, 300);

        let error = DeviceAuthorizationV2::sign(
            RegistryIdentityOperationV2::Register,
            &record,
            &wrong_device,
        )
        .unwrap_err();

        assert_eq!(error, StableIdentityV2Error::WrongDevice);
    }

    #[test]
    fn active_matching_binding_is_accepted_with_signed_timing_evidence() {
        let device = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&device, "mesh-a", NOW + 120, 1);
        let (_, owner) = wallet_and_owner();
        let record = active_record(&owner, &peer_record, 120);

        assert_eq!(
            verify_with_issued_at(&peer_record, Some(&record), NOW).unwrap(),
            StableRegistryBindingDecisionV2::Accepted
        );
    }

    #[test]
    fn public_verifier_requires_nonzero_signed_issued_at() {
        let device = DeviceKeypair::generate().unwrap();
        let mut peer_record = signed_peer_record(&device, "mesh-a", NOW + 120, 1);
        peer_record.body.issued_at_unix = 0;
        peer_record.signature = device.sign(&peer_record.body.canonical_bytes().unwrap());
        let (_, owner) = wallet_and_owner();
        let record = active_record(&owner, &peer_record, 120);

        let error =
            verify_stable_registry_binding_at(&peer_record, Some(&record), NOW).unwrap_err();

        assert_eq!(error, StableIdentityV2Error::MissingSignedIssuedAt);
    }

    #[test]
    fn missing_registry_identity_is_rejected() {
        let device = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&device, "mesh-a", NOW + 120, 1);

        let error = verify_stable_registry_binding_at(&peer_record, None, NOW).unwrap_err();

        assert_eq!(error, StableIdentityV2Error::Missing);
    }

    #[test]
    fn revoked_and_suspended_identities_are_rejected() {
        let device = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&device, "mesh-a", NOW + 120, 1);
        let (_, owner) = wallet_and_owner();
        let mut record = active_record(&owner, &peer_record, 120);

        record.status = RegistryIdentityStatusV2::Revoked;
        assert_eq!(
            verify_with_issued_at(&peer_record, Some(&record), NOW).unwrap_err(),
            StableIdentityV2Error::Revoked
        );

        record.status = RegistryIdentityStatusV2::Suspended;
        assert_eq!(
            verify_with_issued_at(&peer_record, Some(&record), NOW).unwrap_err(),
            StableIdentityV2Error::Suspended
        );
    }

    #[test]
    fn wrong_device_identity_is_rejected() {
        let device = DeviceKeypair::generate().unwrap();
        let other_device = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&device, "mesh-a", NOW + 120, 1);
        let other_peer_record = signed_peer_record(&other_device, "mesh-a", NOW + 120, 1);
        let (_, owner) = wallet_and_owner();
        let record = active_record(&owner, &other_peer_record, 120);

        assert_eq!(
            verify_with_issued_at(&peer_record, Some(&record), NOW).unwrap_err(),
            StableIdentityV2Error::WrongDevice
        );
    }

    #[test]
    fn expired_authorization_is_rejected() {
        let device = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&device, "mesh-a", NOW + 120, 1);
        let (_, owner) = wallet_and_owner();
        let mut record = active_record(&owner, &peer_record, 120);
        record.authorization_expires_at = Some(NOW);

        assert_eq!(
            verify_with_issued_at(&peer_record, Some(&record), NOW).unwrap_err(),
            StableIdentityV2Error::AuthorizationExpired { expires_at: NOW }
        );
    }

    #[test]
    fn peer_record_ttl_policy_is_enforced_from_signed_issued_at() {
        let device = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&device, "mesh-a", NOW + 301, 1);
        let (_, owner) = wallet_and_owner();
        let record = active_record(&owner, &peer_record, 300);

        assert_eq!(
            verify_with_issued_at(&peer_record, Some(&record), NOW).unwrap_err(),
            StableIdentityV2Error::PeerRecordTtlExceeded {
                actual_seconds: 301,
                maximum_seconds: 300,
            }
        );
    }

    #[test]
    fn non_positive_peer_record_ttl_is_rejected() {
        let device = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&device, "mesh-a", NOW + 120, 1);
        let (_, owner) = wallet_and_owner();
        let record = active_record(&owner, &peer_record, 300);

        let error = verify_stable_registry_binding_with_issued_at(
            &peer_record,
            &record,
            peer_record.body.expires_at_unix,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            StableIdentityV2Error::InvalidPeerRecordTtl(_)
        ));
    }

    #[test]
    fn wrong_mesh_scope_is_rejected() {
        let device = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&device, "mesh-a", NOW + 120, 1);
        let (_, owner) = wallet_and_owner();
        let mut record = active_record(&owner, &peer_record, 120);
        record.mesh_scope_hash_hex = Some(mesh_scope_hash_hex("mesh-b"));

        assert_eq!(
            verify_with_issued_at(&peer_record, Some(&record), NOW).unwrap_err(),
            StableIdentityV2Error::WrongMeshScope
        );
    }

    #[test]
    fn malformed_or_wrong_version_records_are_rejected() {
        let device = DeviceKeypair::generate().unwrap();
        let peer_record = signed_peer_record(&device, "mesh-a", NOW + 120, 1);
        let (_, owner) = wallet_and_owner();
        let mut record = active_record(&owner, &peer_record, 120);

        let mut wrong_version_json = serde_json::to_value(&record).unwrap();
        wrong_version_json["schema_version"] = serde_json::json!(1);
        let error =
            serde_json::from_value::<RegistryIdentityRecordV2>(wrong_version_json).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported Dytallix stable identity schema version 1"));

        let mut extra_field_json = serde_json::to_value(&record).unwrap();
        extra_field_json["latest_peer_record_hash_hex"] = serde_json::json!("ab".repeat(32));
        let error =
            serde_json::from_value::<RegistryIdentityRecordV2>(extra_field_json).unwrap_err();
        assert!(error.to_string().contains("unknown field"));

        record.schema_version = 1;
        assert_eq!(
            record.validate().unwrap_err(),
            StableIdentityV2Error::UnsupportedSchemaVersion(1)
        );

        record.schema_version = STABLE_IDENTITY_SCHEMA_VERSION;
        record.device_public_key_hash_hex = "ABCDEF".repeat(10) + "ABCD";
        assert!(matches!(
            record.validate().unwrap_err(),
            StableIdentityV2Error::InvalidRecord(_)
        ));
    }

    #[test]
    fn tampered_peer_record_signature_is_rejected_before_binding() {
        let device = DeviceKeypair::generate().unwrap();
        let mut peer_record = signed_peer_record(&device, "mesh-a", NOW + 120, 1);
        let (_, owner) = wallet_and_owner();
        let record = active_record(&owner, &peer_record, 120);
        peer_record.body.routes.push("100.64.0.2/32".into());

        let error = verify_with_issued_at(&peer_record, Some(&record), NOW).unwrap_err();

        assert!(matches!(error, StableIdentityV2Error::InvalidPeerRecord(_)));
    }
}
