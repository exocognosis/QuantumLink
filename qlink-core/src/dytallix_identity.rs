use crate::{
    crypto::DevicePublicKey,
    discovery::{now_unix, PeerRecord},
    dytallix_identity_v2::RegistryIdentityRecordV2,
    error::{QlinkError, Result},
    inbound_identity::InboundIdentityAssertion,
};
use dytallix_core::{address::DAddr, keypair::DytallixKeypair};
use dytallix_sdk::{
    client::DytallixClient,
    keystore::Keystore,
    transaction::{estimate_default_gas_limits, Message, Transaction},
};
use reqwest::Url;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, path::PathBuf};

const REGISTRY_CONTRACT_NAME: &str = "quantumlink-node-registry";
const REGISTRY_CONTRACT_VERSION: u8 = 1;
const CONTRACT_CALL_GAS_LIMIT: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MeshTrustPolicy {
    PublicRequired,
    PrivatePreferred,
    DevelopmentOptional,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegistryNodeStatus {
    Active,
    Revoked,
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryNodeRecord {
    pub peer_id: String,
    pub owner_daddr: String,
    pub device_public_key_hash_hex: String,
    pub pqc_binding_hash_hex: String,
    pub node_signing_public_key_hash_hex: String,
    pub transport_public_key_hash_hex: String,
    pub latest_peer_record_hash_hex: String,
    pub status: RegistryNodeStatus,
    pub reputation_score: u64,
    pub stake_status: Option<String>,
    pub updated_at: u64,
    pub expires_at: Option<u64>,
    pub metadata_commitment_hex: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryDecision {
    Accepted,
    AcceptedWithoutRegistryPrivate,
    AcceptedWithoutRegistryDevelopment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DytallixPolicyStatus {
    Active,
    Missing,
    Revoked,
    Suspended,
    Mismatched,
    Stale,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DytallixRegistryBindingVersion {
    #[default]
    ExactPeerRecordV1,
    StableIdentityV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryIdentityLookupRecord {
    ExactPeerRecordV1(RegistryNodeRecord),
    StableIdentityV2(RegistryIdentityRecordV2),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DytallixPolicyDecision {
    pub accepted: bool,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DytallixRegistryLookupConfig {
    pub endpoint: String,
    pub contract_address: String,
    pub binding_version: DytallixRegistryBindingVersion,
    pub network_id: Option<String>,
    pub chain_id: Option<String>,
    pub allowed_rpc_endpoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DytallixRegistryConfig {
    pub endpoint: String,
    pub contract_address: String,
    pub keystore_path: PathBuf,
    pub wallet_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryContractMethod {
    RegisterNode,
    UpdateNode,
    RevokeNode,
    GetNode,
}

impl RegistryContractMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RegisterNode => "register_node",
            Self::UpdateNode => "update_node",
            Self::RevokeNode => "revoke_node",
            Self::GetNode => "get_node",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletAuthorization {
    pub actor_public_key_hex: String,
    pub actor_signature_hex: String,
}

impl WalletAuthorization {
    pub fn sign_record(
        method: RegistryContractMethod,
        record: &RegistryNodeRecord,
        keypair: &DytallixKeypair,
    ) -> Result<Self> {
        let payload = canonical_wallet_record_payload_bytes(method, record)?;
        Self::sign_payload(&payload, keypair)
    }

    pub fn sign_revoke(peer_id: &str, block_time: u64, keypair: &DytallixKeypair) -> Result<Self> {
        let payload = canonical_wallet_revoke_payload_bytes(peer_id, block_time)?;
        Self::sign_payload(&payload, keypair)
    }

    fn sign_payload(payload: &[u8], keypair: &DytallixKeypair) -> Result<Self> {
        let signature = keypair
            .sign(payload)
            .map_err(|err| QlinkError::Crypto(format!("dytallix wallet signing failed: {err}")))?;
        Ok(Self {
            actor_public_key_hex: hex::encode(keypair.public_key()),
            actor_signature_hex: hex::encode(signature),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceBindingAuthorization {
    pub device_public_key_algorithm: String,
    pub device_public_key_hex: String,
    pub device_binding_signature_hex: String,
}

impl DeviceBindingAuthorization {
    pub fn sign(
        owner_daddr: &str,
        peer_record: &PeerRecord,
        keypair: &crate::crypto::DeviceKeypair,
    ) -> Result<Self> {
        let public_key = keypair.public_key();
        if public_key != peer_record.body.device_public_key {
            return Err(QlinkError::Protocol(
                "device keypair does not match peer record device public key".into(),
            ));
        }

        let payload = canonical_binding_payload_bytes(owner_daddr, peer_record)?;
        let signature = keypair.sign(&payload);
        Ok(Self {
            device_public_key_algorithm: public_key.algorithm,
            device_public_key_hex: hex::encode(public_key.bytes),
            device_binding_signature_hex: hex::encode(signature),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterNodeRequest {
    pub record: RegistryNodeRecord,
    #[serde(flatten)]
    pub wallet_authorization: WalletAuthorization,
    #[serde(flatten)]
    pub device_binding_authorization: DeviceBindingAuthorization,
}

impl RegisterNodeRequest {
    pub fn new(
        record: RegistryNodeRecord,
        wallet_authorization: WalletAuthorization,
        device_binding_authorization: DeviceBindingAuthorization,
    ) -> Self {
        Self {
            record,
            wallet_authorization,
            device_binding_authorization,
        }
    }
}

pub type UpdateNodeRequest = RegisterNodeRequest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokeNodeRequest {
    pub peer_id: String,
    pub block_time: u64,
    #[serde(flatten)]
    pub wallet_authorization: WalletAuthorization,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetNodeRequest {
    pub peer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistryQueryResponse {
    pub ok: bool,
    #[serde(default)]
    pub node: Option<RegistryNodeRecord>,
    #[serde(default)]
    pub events: Vec<serde_json::Value>,
    #[serde(default)]
    pub error: Option<String>,
}

pub type RegistryContractResponse = RegistryQueryResponse;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedContractCall {
    pub method: &'static str,
    pub args_hex: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RegistrySubmission {
    pub tx_hash: Option<String>,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DytallixEnrollmentWallet {
    pub keystore_path: PathBuf,
    pub wallet_name: String,
    pub wallet_address: String,
    pub created_wallet: bool,
}

impl RegistryNodeRecord {
    pub fn from_peer_record(
        owner_daddr: impl Into<String>,
        peer_record: &PeerRecord,
        status: RegistryNodeStatus,
        updated_at: u64,
    ) -> Result<Self> {
        let owner_daddr = owner_daddr.into();
        Ok(Self {
            peer_id: peer_record.body.peer_id.clone(),
            owner_daddr: owner_daddr.clone(),
            device_public_key_hash_hex: device_public_key_hash_hex(peer_record)?,
            pqc_binding_hash_hex: pqc_binding_hash_hex(&owner_daddr, peer_record)?,
            node_signing_public_key_hash_hex: node_signing_public_key_hash_hex(peer_record)?,
            transport_public_key_hash_hex: transport_public_key_hash_hex(peer_record),
            latest_peer_record_hash_hex: latest_peer_record_hash_hex(peer_record)?,
            status,
            reputation_score: 0,
            stake_status: None,
            updated_at,
            expires_at: Some(peer_record.body.expires_at_unix),
            metadata_commitment_hex: None,
        })
    }
}

pub fn verify_registry_binding(
    peer_record: &PeerRecord,
    registry_record: Option<&RegistryNodeRecord>,
    policy: MeshTrustPolicy,
) -> Result<RegistryDecision> {
    verify_peer_record_identity(peer_record)?;

    let Some(registry_record) = registry_record else {
        return match policy {
            MeshTrustPolicy::PublicRequired => Err(QlinkError::Protocol(
                "registry record required by public mesh trust policy".into(),
            )),
            MeshTrustPolicy::PrivatePreferred => {
                Ok(RegistryDecision::AcceptedWithoutRegistryPrivate)
            }
            MeshTrustPolicy::DevelopmentOptional => {
                Ok(RegistryDecision::AcceptedWithoutRegistryDevelopment)
            }
        };
    };

    if registry_record.status != RegistryNodeStatus::Active {
        let status = match registry_record.status {
            RegistryNodeStatus::Active => "active",
            RegistryNodeStatus::Revoked => "revoked",
            RegistryNodeStatus::Suspended => "suspended",
        };
        return Err(QlinkError::Protocol(format!("registry record is {status}")));
    }
    if registry_record
        .expires_at
        .is_some_and(|expires_at| expires_at <= now_unix())
    {
        return Err(QlinkError::Protocol(
            "registry record has expired".to_string(),
        ));
    }

    require_match(
        "peer_id",
        &registry_record.peer_id,
        &peer_record.body.peer_id,
    )?;
    require_match(
        "device_public_key_hash_hex",
        &registry_record.device_public_key_hash_hex,
        &device_public_key_hash_hex(peer_record)?,
    )?;
    require_match(
        "latest_peer_record_hash_hex",
        &registry_record.latest_peer_record_hash_hex,
        &latest_peer_record_hash_hex(peer_record)?,
    )?;
    require_match(
        "pqc_binding_hash_hex",
        &registry_record.pqc_binding_hash_hex,
        &pqc_binding_hash_hex(&registry_record.owner_daddr, peer_record)?,
    )?;
    require_match(
        "node_signing_public_key_hash_hex",
        &registry_record.node_signing_public_key_hash_hex,
        &node_signing_public_key_hash_hex(peer_record)?,
    )?;
    require_match(
        "transport_public_key_hash_hex",
        &registry_record.transport_public_key_hash_hex,
        &transport_public_key_hash_hex(peer_record),
    )?;

    Ok(RegistryDecision::Accepted)
}

pub fn evaluate_dytallix_policy_status(
    policy: MeshTrustPolicy,
    status: DytallixPolicyStatus,
    explicitly_requires_verification: bool,
) -> Result<DytallixPolicyDecision> {
    if status == DytallixPolicyStatus::Active {
        return Ok(DytallixPolicyDecision {
            accepted: true,
            warning: None,
        });
    }

    if status == DytallixPolicyStatus::Unavailable
        && !explicitly_requires_verification
        && policy != MeshTrustPolicy::PublicRequired
    {
        return Ok(DytallixPolicyDecision {
            accepted: true,
            warning: Some(
                "Dytallix registry unavailable; continuing under private/development trust policy"
                    .to_string(),
            ),
        });
    }

    Err(QlinkError::Protocol(format!(
        "active Dytallix registry record required by {}: {}",
        mesh_trust_policy_label(policy),
        dytallix_policy_status_label(status)
    )))
}

pub fn verify_inbound_registry_assertion(
    assertion: &InboundIdentityAssertion,
    registry_record: Option<&RegistryNodeRecord>,
    policy: MeshTrustPolicy,
) -> Result<RegistryDecision> {
    let Some(registry_record) = registry_record else {
        return match policy {
            MeshTrustPolicy::PublicRequired => Err(QlinkError::Protocol(
                "registry record required by public mesh trust policy".into(),
            )),
            MeshTrustPolicy::PrivatePreferred => {
                Ok(RegistryDecision::AcceptedWithoutRegistryPrivate)
            }
            MeshTrustPolicy::DevelopmentOptional => {
                Ok(RegistryDecision::AcceptedWithoutRegistryDevelopment)
            }
        };
    };

    if registry_record.status != RegistryNodeStatus::Active {
        let status = match registry_record.status {
            RegistryNodeStatus::Active => "active",
            RegistryNodeStatus::Revoked => "revoked",
            RegistryNodeStatus::Suspended => "suspended",
        };
        return Err(QlinkError::Protocol(format!("registry record is {status}")));
    }
    if registry_record
        .expires_at
        .is_some_and(|expires_at| expires_at <= now_unix())
    {
        return Err(QlinkError::Protocol(
            "registry record has expired".to_string(),
        ));
    }

    require_match("peer_id", &registry_record.peer_id, &assertion.peer_id)?;
    let assertion_key_hash =
        device_public_key_hash_hex_from_public_key(&assertion.device_public_key)?;
    require_match(
        "device_public_key_hash_hex",
        &registry_record.device_public_key_hash_hex,
        &assertion_key_hash,
    )?;
    require_match(
        "node_signing_public_key_hash_hex",
        &registry_record.node_signing_public_key_hash_hex,
        &assertion_key_hash,
    )?;

    Ok(RegistryDecision::Accepted)
}

fn mesh_trust_policy_label(policy: MeshTrustPolicy) -> &'static str {
    match policy {
        MeshTrustPolicy::PublicRequired => "public mesh policy",
        MeshTrustPolicy::PrivatePreferred => "private mesh policy",
        MeshTrustPolicy::DevelopmentOptional => "development mesh policy",
    }
}

fn dytallix_policy_status_label(status: DytallixPolicyStatus) -> &'static str {
    match status {
        DytallixPolicyStatus::Active => "active",
        DytallixPolicyStatus::Missing => "missing",
        DytallixPolicyStatus::Revoked => "revoked",
        DytallixPolicyStatus::Suspended => "suspended",
        DytallixPolicyStatus::Mismatched => "mismatched",
        DytallixPolicyStatus::Stale => "stale",
        DytallixPolicyStatus::Unavailable => "registry unavailable",
    }
}

pub fn device_public_key_hash_hex(peer_record: &PeerRecord) -> Result<String> {
    device_public_key_hash_hex_from_public_key(&peer_record.body.device_public_key)
}

pub fn device_public_key_hash_hex_from_public_key(
    device_public_key: &DevicePublicKey,
) -> Result<String> {
    let bytes = serde_json::to_vec(device_public_key)?;
    Ok(sha256_hex(&bytes))
}

pub fn latest_peer_record_hash_hex(peer_record: &PeerRecord) -> Result<String> {
    Ok(hex_encode(&peer_record.record_hash()?))
}

pub fn node_signing_public_key_hash_hex(peer_record: &PeerRecord) -> Result<String> {
    device_public_key_hash_hex(peer_record)
}

pub fn transport_public_key_hash_hex(peer_record: &PeerRecord) -> String {
    sha256_hex(&peer_record.body.device_certificate_der)
}

pub fn pqc_binding_hash_hex(owner_daddr: &str, peer_record: &PeerRecord) -> Result<String> {
    Ok(sha256_hex(&canonical_binding_payload_bytes(
        owner_daddr,
        peer_record,
    )?))
}

pub fn canonical_binding_payload_bytes(
    owner_daddr: &str,
    peer_record: &PeerRecord,
) -> Result<Vec<u8>> {
    let payload = CanonicalBindingPayload {
        contract: "quantumlink-node-registry",
        version: 1,
        owner_daddr: owner_daddr.to_string(),
        peer_id: peer_record.body.peer_id.clone(),
        device_public_key_hash_hex: device_public_key_hash_hex(peer_record)?,
        node_signing_public_key_hash_hex: node_signing_public_key_hash_hex(peer_record)?,
        transport_public_key_hash_hex: transport_public_key_hash_hex(peer_record),
        latest_peer_record_hash_hex: latest_peer_record_hash_hex(peer_record)?,
    };
    serde_json::to_vec(&payload).map_err(Into::into)
}

pub fn canonical_wallet_record_payload_bytes(
    operation: RegistryContractMethod,
    record: &RegistryNodeRecord,
) -> Result<Vec<u8>> {
    let payload = CanonicalWalletRecordPayload {
        contract: REGISTRY_CONTRACT_NAME,
        version: REGISTRY_CONTRACT_VERSION,
        operation: operation.as_str(),
        record,
    };
    serde_json::to_vec(&payload).map_err(Into::into)
}

pub fn canonical_wallet_revoke_payload_bytes(peer_id: &str, block_time: u64) -> Result<Vec<u8>> {
    let payload = CanonicalWalletRevokePayload {
        contract: REGISTRY_CONTRACT_NAME,
        version: REGISTRY_CONTRACT_VERSION,
        operation: RegistryContractMethod::RevokeNode.as_str(),
        peer_id,
        block_time,
    };
    serde_json::to_vec(&payload).map_err(Into::into)
}

pub fn encode_contract_args<T: Serialize>(request: &T) -> Result<String> {
    let bytes = serde_json::to_vec(request)?;
    Ok(hex::encode(bytes))
}

pub fn encode_contract_call_args<T: Serialize>(
    method: RegistryContractMethod,
    request: &T,
) -> Result<EncodedContractCall> {
    Ok(EncodedContractCall {
        method: method.as_str(),
        args_hex: encode_contract_args(request)?,
    })
}

impl DytallixRegistryConfig {
    pub fn new(
        endpoint: impl Into<String>,
        contract_address: impl Into<String>,
        keystore_path: impl Into<PathBuf>,
        wallet_name: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            endpoint: endpoint.into(),
            contract_address: normalize_contract_address(&contract_address.into())?,
            keystore_path: keystore_path.into(),
            wallet_name,
        })
    }
}

impl DytallixRegistryLookupConfig {
    pub fn new(endpoint: impl Into<String>, contract_address: impl Into<String>) -> Result<Self> {
        Ok(Self {
            endpoint: endpoint.into(),
            contract_address: normalize_lookup_contract_identifier(&contract_address.into())?,
            binding_version: DytallixRegistryBindingVersion::ExactPeerRecordV1,
            network_id: None,
            chain_id: None,
            allowed_rpc_endpoints: Vec::new(),
        })
    }

    pub fn with_network_pins(
        mut self,
        network_id: Option<String>,
        chain_id: Option<String>,
        allowed_rpc_endpoints: Vec<String>,
    ) -> Result<Self> {
        self.network_id = normalize_optional_pin(network_id);
        self.chain_id = normalize_optional_pin(chain_id);
        self.allowed_rpc_endpoints = normalize_endpoint_allowlist(allowed_rpc_endpoints);
        self.validate_endpoint_allowlist()?;
        Ok(self)
    }

    fn validate_endpoint_allowlist(&self) -> Result<()> {
        if self.allowed_rpc_endpoints.is_empty() {
            return Ok(());
        }
        let endpoint = normalize_endpoint_pin(&self.endpoint);
        if self
            .allowed_rpc_endpoints
            .iter()
            .any(|allowed| normalize_endpoint_pin(allowed) == endpoint)
        {
            return Ok(());
        }
        Err(QlinkError::Protocol(format!(
            "dytallix registry endpoint is not in the pinned allowlist: {}",
            self.endpoint
        )))
    }
}

fn normalize_optional_pin(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn normalize_endpoint_allowlist(endpoints: Vec<String>) -> Vec<String> {
    endpoints
        .into_iter()
        .filter_map(|endpoint| normalize_optional_pin(Some(endpoint)))
        .collect()
}

fn normalize_endpoint_pin(endpoint: &str) -> String {
    endpoint.trim().trim_end_matches('/').to_ascii_lowercase()
}

pub fn ensure_dytallix_enrollment_wallet(
    config: &DytallixRegistryConfig,
) -> Result<DytallixEnrollmentWallet> {
    let mut keystore =
        Keystore::open_or_create(config.keystore_path.clone()).map_err(dytallix_sdk_error)?;
    let mut created_wallet = false;
    let wallet_name = match config.wallet_name.as_deref() {
        Some(name) => {
            if !keystore.list().iter().any(|entry| entry.name == name) {
                let keypair = DytallixKeypair::generate();
                keystore
                    .add_keypair(&keypair, name)
                    .map_err(dytallix_sdk_error)?;
                created_wallet = true;
            }
            keystore.set_active(name).map_err(dytallix_sdk_error)?;
            name.to_owned()
        }
        None => {
            if let Some(active) = keystore.active() {
                active.name.clone()
            } else {
                let name = "quantumlink";
                if !keystore.list().iter().any(|entry| entry.name == name) {
                    let keypair = DytallixKeypair::generate();
                    keystore
                        .add_keypair(&keypair, name)
                        .map_err(dytallix_sdk_error)?;
                    created_wallet = true;
                }
                keystore.set_active(name).map_err(dytallix_sdk_error)?;
                name.to_owned()
            }
        }
    };
    keystore.save().map_err(dytallix_sdk_error)?;
    harden_keystore_permissions(&config.keystore_path)?;
    let wallet = keystore
        .get_keypair(&wallet_name)
        .map_err(dytallix_sdk_error)?;
    let wallet_address = DAddr::from_public_key(wallet.public_key())
        .map_err(|err| {
            QlinkError::InvalidKey(format!("dytallix address derivation failed: {err}"))
        })?
        .to_string();

    Ok(DytallixEnrollmentWallet {
        keystore_path: config.keystore_path.clone(),
        wallet_name,
        wallet_address,
        created_wallet,
    })
}

#[cfg(unix)]
fn harden_keystore_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .map_err(|err| QlinkError::Protocol(format!("failed to inspect Dytallix keystore: {err}")))?
        .permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions).map_err(|err| {
        QlinkError::Protocol(format!(
            "failed to harden Dytallix keystore permissions: {err}"
        ))
    })
}

#[cfg(not(unix))]
fn harden_keystore_permissions(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

impl<'de> Deserialize<'de> for DytallixRegistryLookupConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct RawLookupConfig {
            endpoint: String,
            contract_address: String,
            #[serde(default)]
            publish_wallet_address: bool,
            #[serde(default)]
            binding_version: DytallixRegistryBindingVersion,
            #[serde(default)]
            network_id: Option<String>,
            #[serde(default)]
            chain_id: Option<String>,
            #[serde(default)]
            allowed_rpc_endpoints: Vec<String>,
        }

        let raw = RawLookupConfig::deserialize(deserializer)?;
        let _ = raw.publish_wallet_address;
        Self::new(raw.endpoint, raw.contract_address)
            .map(|mut config| {
                config.binding_version = raw.binding_version;
                config
            })
            .and_then(|config| {
                config.with_network_pins(raw.network_id, raw.chain_id, raw.allowed_rpc_endpoints)
            })
            .map_err(serde::de::Error::custom)
    }
}

pub struct DytallixIdentityRegistry {
    lookup_config: DytallixRegistryLookupConfig,
    write_config: Option<DytallixRegistryConfig>,
    http: reqwest::Client,
}

impl DytallixIdentityRegistry {
    pub fn binding_version(&self) -> DytallixRegistryBindingVersion {
        self.lookup_config.binding_version
    }

    pub fn new(mut config: DytallixRegistryConfig) -> Result<Self> {
        config.contract_address = normalize_contract_address(&config.contract_address)?;
        let lookup_config = DytallixRegistryLookupConfig {
            endpoint: config.endpoint.clone(),
            contract_address: config.contract_address.clone(),
            binding_version: DytallixRegistryBindingVersion::ExactPeerRecordV1,
            network_id: None,
            chain_id: None,
            allowed_rpc_endpoints: Vec::new(),
        };
        Self::build(lookup_config, Some(config))
    }

    pub fn from_lookup_config(mut config: DytallixRegistryLookupConfig) -> Result<Self> {
        config.contract_address = normalize_lookup_contract_identifier(&config.contract_address)?;
        Self::build(config, None)
    }

    fn build(
        lookup_config: DytallixRegistryLookupConfig,
        write_config: Option<DytallixRegistryConfig>,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|err| QlinkError::Protocol(format!("dytallix HTTP client failed: {err}")))?;
        Ok(Self {
            lookup_config,
            write_config,
            http,
        })
    }

    pub async fn lookup(&self, peer_id: &str) -> Result<Option<RegistryNodeRecord>> {
        let request = GetNodeRequest {
            peer_id: peer_id.to_owned(),
        };
        let call = encode_contract_call_args(RegistryContractMethod::GetNode, &request)?;
        let path = format!(
            "/api/contracts/{}/query/{}?args={}",
            self.lookup_config.contract_address, call.method, call.args_hex
        );
        let response = decode_registry_query_response(self.get_json(&path).await?)?;
        if response.ok {
            Ok(response.node)
        } else {
            Err(QlinkError::Protocol(format!(
                "dytallix registry lookup failed: {}",
                response
                    .error
                    .unwrap_or_else(|| "unknown contract error".into())
            )))
        }
    }

    pub async fn lookup_identity(
        &self,
        peer_id: &str,
    ) -> Result<Option<RegistryIdentityLookupRecord>> {
        match self.lookup_config.binding_version {
            DytallixRegistryBindingVersion::ExactPeerRecordV1 => self
                .lookup(peer_id)
                .await
                .map(|record| record.map(RegistryIdentityLookupRecord::ExactPeerRecordV1)),
            DytallixRegistryBindingVersion::StableIdentityV2 => self
                .lookup_stable_identity_v2(peer_id)
                .await
                .map(|record| record.map(RegistryIdentityLookupRecord::StableIdentityV2)),
        }
    }

    async fn lookup_stable_identity_v2(
        &self,
        peer_id: &str,
    ) -> Result<Option<RegistryIdentityRecordV2>> {
        #[derive(Serialize)]
        struct GetIdentityRequest<'a> {
            peer_id: &'a str,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StableIdentityQueryResponse {
            ok: bool,
            identity: Option<RegistryIdentityRecordV2>,
            #[serde(default)]
            events: Vec<serde_json::Value>,
            error: Option<String>,
        }

        let args_hex = hex::encode(serde_json::to_vec(&GetIdentityRequest { peer_id })?);
        let path = format!(
            "/api/contracts/{}/query/get_identity?args={args_hex}",
            self.lookup_config.contract_address
        );
        let value: serde_json::Value = self.get_json(&path).await?;
        let response: StableIdentityQueryResponse =
            decode_contract_response(value, "stable identity")?;
        let _ = response.events;
        if response.ok {
            Ok(response.identity)
        } else {
            Err(QlinkError::Protocol(format!(
                "dytallix stable identity lookup failed: {}",
                response
                    .error
                    .unwrap_or_else(|| "unknown contract error".into())
            )))
        }
    }

    pub async fn register(
        &self,
        peer_record: &PeerRecord,
        device_keypair: &crate::crypto::DeviceKeypair,
        updated_at: u64,
    ) -> Result<RegistrySubmission> {
        self.write_record(
            RegistryContractMethod::RegisterNode,
            peer_record,
            device_keypair,
            updated_at,
        )
        .await
    }

    pub async fn update(
        &self,
        peer_record: &PeerRecord,
        device_keypair: &crate::crypto::DeviceKeypair,
        updated_at: u64,
    ) -> Result<RegistrySubmission> {
        self.write_record(
            RegistryContractMethod::UpdateNode,
            peer_record,
            device_keypair,
            updated_at,
        )
        .await
    }

    pub async fn revoke(&self, peer_id: &str, block_time: u64) -> Result<RegistrySubmission> {
        let wallet = self.load_wallet_keypair()?;
        let wallet_auth = WalletAuthorization::sign_revoke(peer_id, block_time, &wallet)?;
        let request = RevokeNodeRequest {
            peer_id: peer_id.to_owned(),
            block_time,
            wallet_authorization: wallet_auth,
        };
        self.submit_contract_request(RegistryContractMethod::RevokeNode, &request, &wallet)
            .await
    }

    async fn write_record(
        &self,
        method: RegistryContractMethod,
        peer_record: &PeerRecord,
        device_keypair: &crate::crypto::DeviceKeypair,
        updated_at: u64,
    ) -> Result<RegistrySubmission> {
        let wallet = self.load_wallet_keypair()?;
        let owner = DAddr::from_public_key(wallet.public_key())
            .map_err(|err| {
                QlinkError::InvalidKey(format!("dytallix address derivation failed: {err}"))
            })?
            .to_string();
        let record = RegistryNodeRecord::from_peer_record(
            owner.clone(),
            peer_record,
            RegistryNodeStatus::Active,
            updated_at,
        )?;
        let wallet_auth = WalletAuthorization::sign_record(method, &record, &wallet)?;
        let device_auth = DeviceBindingAuthorization::sign(&owner, peer_record, device_keypair)?;
        let request = RegisterNodeRequest::new(record, wallet_auth, device_auth);

        self.submit_contract_request(method, &request, &wallet)
            .await
    }

    async fn submit_contract_request<T: Serialize>(
        &self,
        method: RegistryContractMethod,
        request: &T,
        wallet: &DytallixKeypair,
    ) -> Result<RegistrySubmission> {
        let call = encode_contract_call_args(method, request)?;
        let args_hex = call.args_hex.clone();
        let signed = self
            .sign_contract_call(method, args_hex.clone(), wallet)
            .await?;
        let write_config = self.write_config()?;
        let body = contract_call_submission_body(
            method,
            &write_config.contract_address,
            args_hex,
            &signed,
        )?;
        let response = self.post_json_value("/contracts/call", &body).await?;
        validate_registry_submission_response(&response)?;
        let tx_hash = response
            .get("tx_hash")
            .or_else(|| response.get("hash"))
            .and_then(|value| value.as_str())
            .map(str::to_owned);
        Ok(RegistrySubmission { tx_hash, response })
    }

    async fn sign_contract_call(
        &self,
        method: RegistryContractMethod,
        args_hex: String,
        wallet: &DytallixKeypair,
    ) -> Result<dytallix_sdk::transaction::SignedTransaction> {
        let write_config = self.write_config()?;
        let client = DytallixClient::new(&write_config.endpoint)
            .await
            .map_err(dytallix_sdk_error)?;
        let from = DAddr::from_public_key(wallet.public_key()).map_err(|err| {
            QlinkError::InvalidKey(format!("dytallix address derivation failed: {err}"))
        })?;
        let account = client
            .get_account(&from)
            .await
            .map_err(dytallix_sdk_error)?;
        let chain_status = client
            .get_chain_status()
            .await
            .map_err(dytallix_sdk_error)?;
        let message = Message::ContractCall {
            from: from.to_string(),
            address: write_config.contract_address.clone(),
            method: method.as_str().to_owned(),
            args: Some(args_hex),
            gas_limit: CONTRACT_CALL_GAS_LIMIT,
        };
        let (c_gas_limit, b_gas_limit) =
            estimate_default_gas_limits(std::slice::from_ref(&message));
        let tx = Transaction {
            chain_id: chain_status.finalized_checkpoint,
            nonce: account.nonce,
            msgs: vec![message],
            fee: 0,
            memo: String::new(),
            c_gas_limit,
            b_gas_limit,
        };
        let fee = tx.estimate_fee(&client).await.map_err(dytallix_sdk_error)?;
        tx.with_fee_micro(fee.total_cost_drt)
            .sign(wallet)
            .map_err(dytallix_sdk_error)
    }

    fn load_wallet_keypair(&self) -> Result<DytallixKeypair> {
        let write_config = self.write_config()?;
        let keystore =
            Keystore::open(write_config.keystore_path.clone()).map_err(dytallix_sdk_error)?;
        let wallet_name = if let Some(name) = write_config.wallet_name.as_deref() {
            name.to_owned()
        } else {
            keystore
                .active()
                .map(|entry| entry.name.clone())
                .ok_or_else(|| {
                    QlinkError::Protocol("dytallix keystore has no active wallet".into())
                })?
        };
        keystore
            .get_keypair(&wallet_name)
            .map_err(dytallix_sdk_error)
    }

    fn write_config(&self) -> Result<&DytallixRegistryConfig> {
        self.write_config.as_ref().ok_or_else(|| {
            QlinkError::Protocol(
                "dytallix registry write requires wallet configuration; lookup-only registry was configured"
                    .into(),
            )
        })
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let url = self.url(path)?;
        let response = self
            .http
            .get(url.clone())
            .send()
            .await
            .map_err(|err| QlinkError::Protocol(format!("dytallix GET {url} failed: {err}")))?;
        if response.status().is_success() {
            response.json().await.map_err(|err| {
                QlinkError::Protocol(format!("dytallix GET {url} returned invalid JSON: {err}"))
            })
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(QlinkError::Protocol(format!(
                "dytallix GET {url} failed with {status}: {body}"
            )))
        }
    }

    async fn post_json_value<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<serde_json::Value> {
        let url = self.url(path)?;
        let response = self
            .http
            .post(url.clone())
            .json(body)
            .send()
            .await
            .map_err(|err| QlinkError::Protocol(format!("dytallix POST {url} failed: {err}")))?;
        if response.status().is_success() {
            response.json().await.map_err(|err| {
                QlinkError::Protocol(format!("dytallix POST {url} returned invalid JSON: {err}"))
            })
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(QlinkError::Protocol(format!(
                "dytallix POST {url} failed with {status}: {body}"
            )))
        }
    }

    fn url(&self, path: &str) -> Result<Url> {
        let endpoint = self.lookup_config.endpoint.trim_end_matches('/');
        let path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        Url::parse(&format!("{endpoint}{path}"))
            .map_err(|err| QlinkError::Protocol(format!("invalid dytallix endpoint URL: {err}")))
    }
}

#[derive(Serialize)]
struct CanonicalBindingPayload {
    contract: &'static str,
    version: u8,
    owner_daddr: String,
    peer_id: String,
    device_public_key_hash_hex: String,
    node_signing_public_key_hash_hex: String,
    transport_public_key_hash_hex: String,
    latest_peer_record_hash_hex: String,
}

#[derive(Serialize)]
struct CanonicalWalletRecordPayload<'a> {
    contract: &'static str,
    version: u8,
    operation: &'static str,
    record: &'a RegistryNodeRecord,
}

#[derive(Serialize)]
struct CanonicalWalletRevokePayload<'a> {
    contract: &'static str,
    version: u8,
    operation: &'static str,
    peer_id: &'a str,
    block_time: u64,
}

fn verify_peer_record_identity(peer_record: &PeerRecord) -> Result<()> {
    if peer_record.body.device_public_key.peer_id() != peer_record.body.peer_id {
        return Err(QlinkError::Protocol(
            "peer_id does not match device public key".into(),
        ));
    }
    if peer_record.body.expires_at_unix <= now_unix() {
        return Err(QlinkError::RecordExpired);
    }

    peer_record
        .body
        .device_public_key
        .verify(&peer_record.body.canonical_bytes()?, &peer_record.signature)
}

fn normalize_contract_address(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex.len() != 40 || hex::decode(hex).is_err() {
        return Err(QlinkError::Protocol(format!(
            "Invalid contract address `{trimmed}`. Expected a 0x-prefixed 20-byte hex address."
        )));
    }
    Ok(format!("0x{hex}"))
}

fn normalize_lookup_contract_identifier(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed == REGISTRY_CONTRACT_NAME {
        return Ok(REGISTRY_CONTRACT_NAME.to_string());
    }
    normalize_contract_address(trimmed)
}

fn require_match(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(QlinkError::Protocol(format!("{field} mismatch")))
    }
}

fn dytallix_sdk_error(err: impl fmt::Display) -> QlinkError {
    QlinkError::Protocol(format!("dytallix SDK error: {err}"))
}

fn contract_call_submission_body<T: Serialize>(
    method: RegistryContractMethod,
    contract_address: &str,
    args_hex: String,
    signed_tx: &T,
) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "signed_tx": serde_json::to_value(signed_tx)?,
        "address": contract_address,
        "method": method.as_str(),
        "args": args_hex,
    }))
}

fn decode_registry_query_response(value: serde_json::Value) -> Result<RegistryQueryResponse> {
    decode_contract_response(value, "registry")
}

fn decode_contract_response<T: for<'de> Deserialize<'de>>(
    value: serde_json::Value,
    response_kind: &str,
) -> Result<T> {
    if let Some(result_hex) = value.get("result").and_then(|raw| raw.as_str()) {
        let bytes = hex::decode(result_hex).map_err(|err| {
            QlinkError::Protocol(format!(
                "dytallix {response_kind} result is not valid hex: {err}"
            ))
        })?;
        return serde_json::from_slice(&bytes).map_err(|err| {
            QlinkError::Protocol(format!(
                "dytallix {response_kind} result is not valid contract JSON: {err}"
            ))
        });
    }

    serde_json::from_value(value).map_err(|err| {
        QlinkError::Protocol(format!(
            "dytallix {response_kind} response is not valid JSON: {err}"
        ))
    })
}

fn validate_registry_submission_response(value: &serde_json::Value) -> Result<()> {
    if value.get("result").is_none() && value.get("ok").is_none() {
        return Ok(());
    }

    let contract_response = decode_registry_query_response(value.clone())?;
    if contract_response.ok {
        return Ok(());
    }

    Err(QlinkError::Protocol(format!(
        "dytallix registry contract rejected request: {}",
        contract_response
            .error
            .unwrap_or_else(|| "unknown contract error".to_string())
    )))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::DeviceKeypair,
        discovery::{CandidateEndpoint, CandidateType, PeerRecord, UnsignedPeerRecord},
    };
    use dytallix_core::{address::DAddr, keypair::DytallixKeypair, signature::verify_mldsa65};
    use serde_json::json;

    fn fresh_peer_record() -> PeerRecord {
        let keypair = DeviceKeypair::generate().unwrap();
        let body = UnsignedPeerRecord::new(
            "dytallix-mesh",
            "registry-test-node",
            keypair.public_key(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "192.0.2.10".to_string(),
                port: 4433,
                priority: 100,
            }],
            vec!["100.64.10.7/32".to_string()],
            300,
            42,
        )
        .with_device_certificate(b"test-quic-certificate-der".to_vec());
        PeerRecord::signed(body, &keypair).unwrap()
    }

    fn active_registry_record(peer_record: &PeerRecord) -> RegistryNodeRecord {
        RegistryNodeRecord::from_peer_record(
            "daddr:owner:registry-test",
            peer_record,
            RegistryNodeStatus::Active,
            1_725_000_000,
        )
        .unwrap()
    }

    fn dytallix_owner() -> (DytallixKeypair, String) {
        let keypair = DytallixKeypair::generate();
        let owner = DAddr::from_public_key(keypair.public_key())
            .unwrap()
            .to_string();
        (keypair, owner)
    }

    #[test]
    fn rejects_expired_peer_record_even_when_registry_record_matches() {
        let keypair = DeviceKeypair::generate().unwrap();
        let mut body = UnsignedPeerRecord::new(
            "dytallix-mesh",
            "registry-test-node",
            keypair.public_key(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "192.0.2.10".to_string(),
                port: 4433,
                priority: 100,
            }],
            vec!["100.64.10.7/32".to_string()],
            300,
            42,
        )
        .with_device_certificate(b"test-quic-certificate-der".to_vec());
        body.expires_at_unix = crate::discovery::now_unix().saturating_sub(1);
        let peer_record = PeerRecord::signed(body, &keypair).unwrap();
        let registry_record = active_registry_record(&peer_record);

        let err = verify_registry_binding(
            &peer_record,
            Some(&registry_record),
            MeshTrustPolicy::PublicRequired,
        )
        .unwrap_err();

        assert!(matches!(err, QlinkError::RecordExpired));
    }

    #[test]
    fn registry_config_normalizes_raw_contract_address() {
        let config = DytallixRegistryConfig::new(
            "https://dytallix.com",
            "9a9671441249ee2c364f9b4bc8049e61b082449a",
            "/tmp/keystore.json",
            None,
        )
        .unwrap();

        assert_eq!(
            config.contract_address,
            "0x9a9671441249ee2c364f9b4bc8049e61b082449a"
        );
    }

    #[test]
    fn registry_config_accepts_prefixed_contract_address() {
        let config = DytallixRegistryConfig::new(
            "https://dytallix.com",
            "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
            "/tmp/keystore.json",
            None,
        )
        .unwrap();

        assert_eq!(
            config.contract_address,
            "0x9a9671441249ee2c364f9b4bc8049e61b082449a"
        );
    }

    #[test]
    fn contract_call_submission_body_includes_signed_tx_and_route_fields() {
        let body = contract_call_submission_body(
            RegistryContractMethod::RegisterNode,
            "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
            "7b7d".to_string(),
            &json!({ "transaction": "signed" }),
        )
        .unwrap();

        assert_eq!(
            body["address"],
            "0x9a9671441249ee2c364f9b4bc8049e61b082449a"
        );
        assert_eq!(body["method"], "register_node");
        assert_eq!(body["args"], "7b7d");
        assert_eq!(body["signed_tx"]["transaction"], "signed");
    }

    #[test]
    fn registry_query_response_decodes_direct_contract_json() {
        let response = decode_registry_query_response(json!({
            "ok": true,
            "node": null,
            "events": [],
            "error": null
        }))
        .unwrap();

        assert!(response.ok);
        assert!(response.node.is_none());
    }

    #[test]
    fn registry_query_response_decodes_dytallix_result_hex_wrapper() {
        let response_json = br#"{"ok":true,"node":null,"events":[],"error":null}"#;
        let response = decode_registry_query_response(json!({
            "contract_address": "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
            "method": "get_node",
            "result": hex::encode(response_json)
        }))
        .unwrap();

        assert!(response.ok);
        assert!(response.node.is_none());
    }

    #[test]
    fn registry_submission_response_accepts_successful_contract_result() {
        let response_json = br#"{"ok":true,"node":null,"events":[],"error":null}"#;
        validate_registry_submission_response(&json!({
            "tx_hash": "0xabc",
            "result": hex::encode(response_json)
        }))
        .unwrap();
    }

    #[test]
    fn registry_submission_response_rejects_contract_error_result() {
        let response_json =
            br#"{"ok":false,"node":null,"events":[],"error":"node already registered"}"#;
        let err = validate_registry_submission_response(&json!({
            "tx_hash": "0xabc",
            "result": hex::encode(response_json)
        }))
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("dytallix registry contract rejected request: node already registered"));
    }

    #[test]
    fn registry_submission_response_allows_async_ack_without_contract_result() {
        validate_registry_submission_response(&json!({
            "tx_hash": "0xabc"
        }))
        .unwrap();
    }

    #[test]
    fn enrollment_creates_named_wallet_when_missing() {
        let temp = tempfile::tempdir().unwrap();
        let keystore_path = temp.path().join("keystore.json");
        let config = DytallixRegistryConfig::new(
            "https://dytallix.com",
            "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
            &keystore_path,
            Some("quantumlink".to_string()),
        )
        .unwrap();

        let enrollment = ensure_dytallix_enrollment_wallet(&config).unwrap();

        assert!(enrollment.created_wallet);
        assert_eq!(enrollment.wallet_name, "quantumlink");
        assert_eq!(enrollment.keystore_path, keystore_path);
        assert!(enrollment.wallet_address.starts_with("dytallix1"));

        let reopened = Keystore::open(enrollment.keystore_path).unwrap();
        assert!(reopened.get_keypair("quantumlink").is_ok());
        assert_eq!(
            reopened.active().map(|entry| entry.name.as_str()),
            Some("quantumlink")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(temp.path().join("keystore.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn enrollment_reuses_active_wallet_when_name_is_not_specified() {
        let temp = tempfile::tempdir().unwrap();
        let keystore_path = temp.path().join("keystore.json");
        let existing_wallet = DytallixKeypair::generate();
        let mut keystore = Keystore::open_or_create(keystore_path.clone()).unwrap();
        keystore.add_keypair(&existing_wallet, "operator").unwrap();
        keystore.set_active("operator").unwrap();
        keystore.save().unwrap();
        let existing_address = DAddr::from_public_key(existing_wallet.public_key())
            .unwrap()
            .to_string();
        let config = DytallixRegistryConfig::new(
            "https://dytallix.com",
            "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
            &keystore_path,
            None,
        )
        .unwrap();

        let enrollment = ensure_dytallix_enrollment_wallet(&config).unwrap();

        assert!(!enrollment.created_wallet);
        assert_eq!(enrollment.wallet_name, "operator");
        assert_eq!(enrollment.wallet_address, existing_address);
        assert_eq!(Keystore::open(keystore_path).unwrap().list().len(), 1);
    }

    #[test]
    fn registry_lookup_config_decodes_and_normalizes_contract_address() {
        let config: DytallixRegistryLookupConfig = serde_json::from_value(json!({
            "endpoint": "https://dytallix.com",
            "contractAddress": "9a9671441249ee2c364f9b4bc8049e61b082449a",
            "publishWalletAddress": false,
            "networkId": " dytallix-testnet ",
            "chainId": " dytallix-testnet-1 ",
            "allowedRpcEndpoints": [" https://dytallix.com/ ", " "]
        }))
        .unwrap();

        assert_eq!(config.endpoint, "https://dytallix.com");
        assert_eq!(
            config.contract_address,
            "0x9a9671441249ee2c364f9b4bc8049e61b082449a"
        );
        assert_eq!(config.network_id.as_deref(), Some("dytallix-testnet"));
        assert_eq!(config.chain_id.as_deref(), Some("dytallix-testnet-1"));
        assert_eq!(
            config.allowed_rpc_endpoints,
            vec!["https://dytallix.com/".to_string()]
        );
    }

    #[test]
    fn registry_lookup_config_accepts_named_quantumlink_contract() {
        let config: DytallixRegistryLookupConfig = serde_json::from_value(json!({
            "endpoint": "https://dytallix.com",
            "contractAddress": "quantumlink-node-registry",
            "networkId": "dytallix-mainnet",
            "chainId": "dytallix-mainnet-1",
            "allowedRpcEndpoints": ["https://dytallix.com"]
        }))
        .unwrap();

        assert_eq!(config.contract_address, "quantumlink-node-registry");
    }

    #[test]
    fn registry_lookup_config_rejects_endpoint_outside_allowlist() {
        let err = serde_json::from_value::<DytallixRegistryLookupConfig>(json!({
            "endpoint": "https://evil.example",
            "contractAddress": "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
            "networkId": "dytallix-testnet",
            "chainId": "dytallix-testnet-1",
            "allowedRpcEndpoints": ["https://dytallix.com"]
        }))
        .unwrap_err();

        assert!(err.to_string().contains("pinned allowlist"));
    }

    #[test]
    fn registry_lookup_config_rejects_wallet_fields() {
        let err = serde_json::from_value::<DytallixRegistryLookupConfig>(json!({
            "endpoint": "https://dytallix.com",
            "contractAddress": "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
            "keystorePath": "/tmp/keystore.json",
            "walletName": "default"
        }))
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[tokio::test]
    async fn lookup_only_registry_rejects_write_methods_with_protocol_error() {
        let registry = DytallixIdentityRegistry::from_lookup_config(
            DytallixRegistryLookupConfig::new(
                "https://dytallix.com",
                "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
            )
            .unwrap(),
        )
        .unwrap();

        let err = registry
            .revoke("qlink_peer_without_wallet", 1_725_000_000)
            .await
            .unwrap_err();

        assert!(matches!(err, QlinkError::Protocol(_)));
        assert!(err.to_string().contains("lookup-only registry"));
    }

    #[test]
    fn registry_config_rejects_slash_or_query_contract_address() {
        for address in [
            "0x9a9671441249ee2c364f9b4bc8049e61b082449a/../../tx",
            "0x9a9671441249ee2c364f9b4bc8049e61b082449a?args=evil",
        ] {
            let err = DytallixRegistryConfig::new(
                "https://dytallix.com",
                address,
                "/tmp/keystore.json",
                None,
            )
            .unwrap_err();

            assert!(err.to_string().contains("Invalid contract address"));
        }
    }

    #[test]
    fn registry_config_rejects_non_hex_contract_address() {
        let err = DytallixRegistryConfig::new(
            "https://dytallix.com",
            "0x9a9671441249ee2c364f9b4bc8049e61b08244zz",
            "/tmp/keystore.json",
            None,
        )
        .unwrap_err();

        assert!(err.to_string().contains("Invalid contract address"));
    }

    #[test]
    fn registry_config_rejects_short_contract_address() {
        let err = DytallixRegistryConfig::new(
            "https://dytallix.com",
            "0x9a9671441249ee2c364f9b4bc8049e61b08244",
            "/tmp/keystore.json",
            None,
        )
        .unwrap_err();

        assert!(err.to_string().contains("Invalid contract address"));
    }

    #[test]
    fn register_call_args_are_hex_encoded_json() {
        let device_keypair = DeviceKeypair::generate().unwrap();
        let body = UnsignedPeerRecord::new(
            "dytallix-mesh",
            "registry-test-node",
            device_keypair.public_key(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "192.0.2.10".to_string(),
                port: 4433,
                priority: 100,
            }],
            vec!["100.64.10.7/32".to_string()],
            300,
            42,
        )
        .with_device_certificate(b"test-quic-certificate-der".to_vec());
        let peer_record = PeerRecord::signed(body, &device_keypair).unwrap();
        let (wallet_keypair, owner) = dytallix_owner();
        let record = RegistryNodeRecord::from_peer_record(
            owner.clone(),
            &peer_record,
            RegistryNodeStatus::Active,
            1_725_000_000,
        )
        .unwrap();
        let wallet_auth = WalletAuthorization::sign_record(
            RegistryContractMethod::RegisterNode,
            &record,
            &wallet_keypair,
        )
        .unwrap();
        let device_auth =
            DeviceBindingAuthorization::sign(&owner, &peer_record, &device_keypair).unwrap();
        let request = RegisterNodeRequest::new(record, wallet_auth, device_auth);

        let call =
            encode_contract_call_args(RegistryContractMethod::RegisterNode, &request).unwrap();
        assert_eq!(call.method, "register_node");
        let decoded = hex::decode(&call.args_hex).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&decoded).unwrap();

        assert_eq!(value["record"]["peer_id"], peer_record.body.peer_id);
        assert_eq!(value["record"]["owner_daddr"], owner);
        assert!(value["actor_public_key_hex"].as_str().unwrap().len() > 1_000);
        assert!(value["actor_signature_hex"].as_str().unwrap().len() > 1_000);
        assert_eq!(
            value["device_public_key_algorithm"],
            peer_record.body.device_public_key.algorithm
        );
        assert_eq!(
            value["device_public_key_hex"],
            hex::encode(&peer_record.body.device_public_key.bytes)
        );
        assert!(
            value["device_binding_signature_hex"]
                .as_str()
                .unwrap()
                .len()
                > 1_000
        );
    }

    #[test]
    fn wallet_authorization_signs_canonical_contract_payload_with_dytallix_keypair() {
        let peer_record = fresh_peer_record();
        let (wallet_keypair, owner) = dytallix_owner();
        let record = RegistryNodeRecord::from_peer_record(
            owner,
            &peer_record,
            RegistryNodeStatus::Active,
            1_725_000_000,
        )
        .unwrap();

        let auth = WalletAuthorization::sign_record(
            RegistryContractMethod::RegisterNode,
            &record,
            &wallet_keypair,
        )
        .unwrap();
        let payload =
            canonical_wallet_record_payload_bytes(RegistryContractMethod::RegisterNode, &record)
                .unwrap();
        let payload_json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        let signature = hex::decode(&auth.actor_signature_hex).unwrap();

        assert_eq!(payload_json["operation"], "register_node");
        assert!(payload_json.get("method").is_none());
        assert_eq!(
            auth.actor_public_key_hex,
            hex::encode(wallet_keypair.public_key())
        );
        assert!(verify_mldsa65(wallet_keypair.public_key(), &payload, &signature).unwrap());

        let mut changed = record.clone();
        changed.peer_id.push_str("-changed");
        let changed_payload =
            canonical_wallet_record_payload_bytes(RegistryContractMethod::RegisterNode, &changed)
                .unwrap();
        assert!(
            !verify_mldsa65(wallet_keypair.public_key(), &changed_payload, &signature).unwrap()
        );
    }

    #[test]
    fn wallet_revoke_authorization_uses_contract_operation_schema() {
        let (wallet_keypair, _) = dytallix_owner();
        let peer_id = "qlink_registry_revoke_test";
        let block_time = 1_725_000_300;

        let auth = WalletAuthorization::sign_revoke(peer_id, block_time, &wallet_keypair).unwrap();
        let payload = canonical_wallet_revoke_payload_bytes(peer_id, block_time).unwrap();
        let payload_json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        let signature = hex::decode(&auth.actor_signature_hex).unwrap();

        assert_eq!(payload_json["operation"], "revoke_node");
        assert!(payload_json.get("method").is_none());
        assert!(verify_mldsa65(wallet_keypair.public_key(), &payload, &signature).unwrap());
    }

    #[test]
    fn device_binding_authorization_signs_owner_bound_payload_with_quantumlink_keypair() {
        let device_keypair = DeviceKeypair::generate().unwrap();
        let body = UnsignedPeerRecord::new(
            "dytallix-mesh",
            "registry-test-node",
            device_keypair.public_key(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "192.0.2.10".to_string(),
                port: 4433,
                priority: 100,
            }],
            vec!["100.64.10.7/32".to_string()],
            300,
            42,
        )
        .with_device_certificate(b"test-quic-certificate-der".to_vec());
        let peer_record = PeerRecord::signed(body, &device_keypair).unwrap();
        let (_, owner) = dytallix_owner();

        let auth = DeviceBindingAuthorization::sign(&owner, &peer_record, &device_keypair).unwrap();
        let payload = canonical_binding_payload_bytes(&owner, &peer_record).unwrap();
        let signature = hex::decode(&auth.device_binding_signature_hex).unwrap();

        assert_eq!(auth.device_public_key_algorithm, "ML-DSA-65");
        assert_eq!(
            auth.device_public_key_hex,
            hex::encode(&peer_record.body.device_public_key.bytes)
        );
        peer_record
            .body
            .device_public_key
            .verify(&payload, &signature)
            .unwrap();

        let changed_payload =
            canonical_binding_payload_bytes("dytallix1differentowner", &peer_record).unwrap();
        assert!(peer_record
            .body
            .device_public_key
            .verify(&changed_payload, &signature)
            .is_err());
    }

    #[test]
    fn query_response_decodes_registry_node_record() {
        let peer_record = fresh_peer_record();
        let record = active_registry_record(&peer_record);
        let response: RegistryQueryResponse = serde_json::from_value(json!({
            "ok": true,
            "node": record,
            "events": [
                { "type": "node_registered", "peer_id": peer_record.body.peer_id }
            ],
            "error": null
        }))
        .unwrap();

        assert!(response.ok);
        assert_eq!(response.node.unwrap().peer_id, peer_record.body.peer_id);
        assert_eq!(response.events.len(), 1);
        assert!(response.error.is_none());
    }

    #[test]
    fn public_policy_accepts_active_matching_registry_record() {
        let peer_record = fresh_peer_record();
        let registry_record = active_registry_record(&peer_record);

        let decision = verify_registry_binding(
            &peer_record,
            Some(&registry_record),
            MeshTrustPolicy::PublicRequired,
        )
        .unwrap();

        assert_eq!(decision, RegistryDecision::Accepted);
    }

    #[test]
    fn policy_status_helper_accepts_active_registry_status() {
        let decision = evaluate_dytallix_policy_status(
            MeshTrustPolicy::PublicRequired,
            DytallixPolicyStatus::Active,
            false,
        )
        .unwrap();

        assert!(decision.accepted);
        assert!(decision.warning.is_none());
    }

    #[test]
    fn policy_status_helper_warns_for_private_registry_unavailable() {
        let decision = evaluate_dytallix_policy_status(
            MeshTrustPolicy::PrivatePreferred,
            DytallixPolicyStatus::Unavailable,
            false,
        )
        .unwrap();

        assert!(decision.accepted);
        assert!(decision.warning.unwrap().contains("registry unavailable"));
    }

    #[test]
    fn policy_status_helper_rejects_public_or_explicit_verification_gaps() {
        let public_missing = evaluate_dytallix_policy_status(
            MeshTrustPolicy::PublicRequired,
            DytallixPolicyStatus::Missing,
            false,
        )
        .unwrap_err();
        assert!(public_missing.to_string().contains("public mesh policy"));
        assert!(public_missing.to_string().contains("missing"));

        let private_unavailable_required = evaluate_dytallix_policy_status(
            MeshTrustPolicy::PrivatePreferred,
            DytallixPolicyStatus::Unavailable,
            true,
        )
        .unwrap_err();
        assert!(private_unavailable_required
            .to_string()
            .contains("private mesh policy"));
        assert!(private_unavailable_required
            .to_string()
            .contains("registry unavailable"));
    }

    #[test]
    fn policy_status_helper_rejects_non_active_registry_results() {
        for status in [
            DytallixPolicyStatus::Missing,
            DytallixPolicyStatus::Revoked,
            DytallixPolicyStatus::Suspended,
            DytallixPolicyStatus::Mismatched,
            DytallixPolicyStatus::Stale,
        ] {
            let err =
                evaluate_dytallix_policy_status(MeshTrustPolicy::PrivatePreferred, status, false)
                    .unwrap_err();

            assert!(err.to_string().contains("active Dytallix"));
        }
    }

    #[test]
    fn public_policy_rejects_missing_registry_record() {
        let peer_record = fresh_peer_record();

        let err = verify_registry_binding(&peer_record, None, MeshTrustPolicy::PublicRequired)
            .unwrap_err();

        assert!(err.to_string().contains("registry record required"));
    }

    #[test]
    fn private_policy_accepts_valid_peer_record_without_registry() {
        let peer_record = fresh_peer_record();

        let decision =
            verify_registry_binding(&peer_record, None, MeshTrustPolicy::PrivatePreferred).unwrap();

        assert_eq!(decision, RegistryDecision::AcceptedWithoutRegistryPrivate);
    }

    #[test]
    fn development_policy_accepts_valid_peer_record_without_registry() {
        let peer_record = fresh_peer_record();

        let decision =
            verify_registry_binding(&peer_record, None, MeshTrustPolicy::DevelopmentOptional)
                .unwrap();

        assert_eq!(
            decision,
            RegistryDecision::AcceptedWithoutRegistryDevelopment
        );
    }

    #[test]
    fn rejects_revoked_or_suspended_registry_record() {
        let peer_record = fresh_peer_record();

        for (status, expected) in [
            (RegistryNodeStatus::Revoked, "registry record is revoked"),
            (
                RegistryNodeStatus::Suspended,
                "registry record is suspended",
            ),
        ] {
            let mut registry_record = RegistryNodeRecord::from_peer_record(
                "daddr:owner:registry-test",
                &peer_record,
                status,
                crate::discovery::now_unix(),
            )
            .unwrap();
            registry_record.expires_at = Some(crate::discovery::now_unix().saturating_add(300));

            let err = verify_registry_binding(
                &peer_record,
                Some(&registry_record),
                MeshTrustPolicy::PrivatePreferred,
            )
            .unwrap_err();

            assert!(err.to_string().contains(expected));
        }
    }

    #[test]
    fn rejects_expired_registry_record_for_all_policies() {
        let peer_record = fresh_peer_record();
        let mut registry_record = active_registry_record(&peer_record);
        registry_record.expires_at = Some(crate::discovery::now_unix().saturating_sub(1));

        for policy in [
            MeshTrustPolicy::PublicRequired,
            MeshTrustPolicy::PrivatePreferred,
            MeshTrustPolicy::DevelopmentOptional,
        ] {
            let err =
                verify_registry_binding(&peer_record, Some(&registry_record), policy).unwrap_err();

            assert!(err.to_string().contains("registry record has expired"));
        }
    }

    #[test]
    fn rejects_peer_id_mismatch() {
        let peer_record = fresh_peer_record();
        let mut registry_record = active_registry_record(&peer_record);
        registry_record.peer_id = "qlink_wrong-peer-id".to_string();

        let err = verify_registry_binding(
            &peer_record,
            Some(&registry_record),
            MeshTrustPolicy::PublicRequired,
        )
        .unwrap_err();

        assert!(err.to_string().contains("peer_id mismatch"));
    }

    #[test]
    fn rejects_device_key_hash_mismatch() {
        let peer_record = fresh_peer_record();
        let mut registry_record = active_registry_record(&peer_record);
        registry_record.device_public_key_hash_hex = "00".repeat(32);

        let err = verify_registry_binding(
            &peer_record,
            Some(&registry_record),
            MeshTrustPolicy::PublicRequired,
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("device_public_key_hash_hex mismatch"));
    }

    #[test]
    fn rejects_latest_peer_record_hash_mismatch() {
        let peer_record = fresh_peer_record();
        let mut registry_record = active_registry_record(&peer_record);
        registry_record.latest_peer_record_hash_hex = "11".repeat(32);

        let err = verify_registry_binding(
            &peer_record,
            Some(&registry_record),
            MeshTrustPolicy::PublicRequired,
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("latest_peer_record_hash_hex mismatch"));
    }

    #[test]
    fn inbound_registry_policy_accepts_matching_assertion() {
        let keypair = DeviceKeypair::generate().unwrap();
        let body = UnsignedPeerRecord::new(
            "dytallix-mesh",
            "registry-test-node",
            keypair.public_key(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "192.0.2.10".to_string(),
                port: 4433,
                priority: 100,
            }],
            vec!["100.64.10.7/32".to_string()],
            300,
            42,
        )
        .with_device_certificate(b"test-quic-certificate-der".to_vec());
        let peer_record = PeerRecord::signed(body, &keypair).unwrap();
        let registry_record = active_registry_record(&peer_record);
        let assertion =
            crate::inbound_identity::InboundIdentityAssertion::sign(&keypair, "dytallix-mesh")
                .unwrap();

        let decision = verify_inbound_registry_assertion(
            &assertion,
            Some(&registry_record),
            MeshTrustPolicy::PublicRequired,
        )
        .unwrap();

        assert_eq!(decision, RegistryDecision::Accepted);
    }

    #[test]
    fn inbound_public_policy_rejects_missing_registry_record() {
        let keypair = DeviceKeypair::generate().unwrap();
        let assertion =
            crate::inbound_identity::InboundIdentityAssertion::sign(&keypair, "dytallix-mesh")
                .unwrap();

        let err =
            verify_inbound_registry_assertion(&assertion, None, MeshTrustPolicy::PublicRequired)
                .unwrap_err();

        assert!(err.to_string().contains("registry record required"));
    }

    #[test]
    fn rejects_pqc_binding_hash_mismatch() {
        let peer_record = fresh_peer_record();
        let mut registry_record = active_registry_record(&peer_record);
        registry_record.pqc_binding_hash_hex = "22".repeat(32);

        let err = verify_registry_binding(
            &peer_record,
            Some(&registry_record),
            MeshTrustPolicy::PublicRequired,
        )
        .unwrap_err();

        assert!(err.to_string().contains("pqc_binding_hash_hex mismatch"));
    }

    #[test]
    fn rejects_node_signing_public_key_hash_mismatch() {
        let peer_record = fresh_peer_record();
        let mut registry_record = active_registry_record(&peer_record);
        registry_record.node_signing_public_key_hash_hex = "33".repeat(32);

        let err = verify_registry_binding(
            &peer_record,
            Some(&registry_record),
            MeshTrustPolicy::PublicRequired,
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("node_signing_public_key_hash_hex mismatch"));
    }

    #[test]
    fn rejects_transport_public_key_hash_mismatch() {
        let peer_record = fresh_peer_record();
        let mut registry_record = active_registry_record(&peer_record);
        registry_record.transport_public_key_hash_hex = "44".repeat(32);

        let err = verify_registry_binding(
            &peer_record,
            Some(&registry_record),
            MeshTrustPolicy::PublicRequired,
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("transport_public_key_hash_hex mismatch"));
    }

    #[test]
    fn from_peer_record_populates_finalized_contract_fields() {
        let peer_record = fresh_peer_record();
        let registry_record = active_registry_record(&peer_record);

        assert_eq!(registry_record.peer_id, peer_record.body.peer_id);
        assert_eq!(registry_record.owner_daddr, "daddr:owner:registry-test");
        assert_eq!(
            registry_record.device_public_key_hash_hex,
            device_public_key_hash_hex(&peer_record).unwrap()
        );
        assert_eq!(
            registry_record.pqc_binding_hash_hex,
            pqc_binding_hash_hex("daddr:owner:registry-test", &peer_record).unwrap()
        );
        assert_eq!(
            registry_record.node_signing_public_key_hash_hex,
            node_signing_public_key_hash_hex(&peer_record).unwrap()
        );
        assert_eq!(
            registry_record.transport_public_key_hash_hex,
            transport_public_key_hash_hex(&peer_record)
        );
        assert_eq!(
            registry_record.latest_peer_record_hash_hex,
            latest_peer_record_hash_hex(&peer_record).unwrap()
        );
        assert_eq!(registry_record.status, RegistryNodeStatus::Active);
        assert_eq!(registry_record.reputation_score, 0_u64);
        assert_eq!(registry_record.stake_status, None);
        assert_eq!(registry_record.updated_at, 1_725_000_000);
        assert_eq!(
            registry_record.expires_at,
            Some(peer_record.body.expires_at_unix)
        );
        assert_eq!(registry_record.metadata_commitment_hex, None);
    }

    #[test]
    fn pqc_binding_hash_includes_owner_daddr() {
        let peer_record = fresh_peer_record();
        let first_owner = RegistryNodeRecord::from_peer_record(
            "daddr:owner:first",
            &peer_record,
            RegistryNodeStatus::Active,
            1_725_000_000,
        )
        .unwrap();
        let second_owner = RegistryNodeRecord::from_peer_record(
            "daddr:owner:second",
            &peer_record,
            RegistryNodeStatus::Active,
            1_725_000_000,
        )
        .unwrap();

        assert_ne!(
            first_owner.pqc_binding_hash_hex,
            second_owner.pqc_binding_hash_hex
        );
        assert_eq!(
            first_owner.pqc_binding_hash_hex,
            pqc_binding_hash_hex("daddr:owner:first", &peer_record).unwrap()
        );
    }

    #[test]
    fn trust_policy_serializes_as_snake_case() {
        for (policy, json) in [
            (MeshTrustPolicy::PublicRequired, "\"public_required\""),
            (MeshTrustPolicy::PrivatePreferred, "\"private_preferred\""),
            (
                MeshTrustPolicy::DevelopmentOptional,
                "\"development_optional\"",
            ),
        ] {
            assert_eq!(serde_json::to_string(&policy).unwrap(), json);
            assert_eq!(
                serde_json::from_str::<MeshTrustPolicy>(json).unwrap(),
                policy
            );
        }
    }

    #[test]
    fn registry_node_status_serializes_as_snake_case() {
        for (status, json) in [
            (RegistryNodeStatus::Active, "\"active\""),
            (RegistryNodeStatus::Revoked, "\"revoked\""),
            (RegistryNodeStatus::Suspended, "\"suspended\""),
        ] {
            assert_eq!(serde_json::to_string(&status).unwrap(), json);
            assert_eq!(
                serde_json::from_str::<RegistryNodeStatus>(json).unwrap(),
                status
            );
        }
    }
}
