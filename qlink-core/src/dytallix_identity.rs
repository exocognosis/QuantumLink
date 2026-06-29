use crate::{
    crypto::DevicePublicKey,
    discovery::{now_unix, PeerRecord},
    error::{QlinkError, Result},
    inbound_identity::InboundIdentityAssertion,
};
use dytallix_core::{address::DAddr, keypair::DytallixKeypair};
use dytallix_sdk::{
    client::DytallixClient,
    keystore::Keystore,
    transaction::{estimate_default_gas_limits, Message, Transaction},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, future::Future, path::PathBuf, pin::Pin};

pub const REGISTRY_CONTRACT_NAME: &str = "quantumlink-node-registry";
pub const REGISTRY_CONTRACT_VERSION: u8 = 1;
pub const PUBLIC_TESTNET_ENDPOINT: &str = "https://dytallix.com";
const CONTRACT_CALL_GAS_LIMIT: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MeshTrustPolicy {
    #[serde(
        rename = "publicRequired",
        alias = "PublicRequired",
        alias = "public_required"
    )]
    PublicRequired,
    #[serde(
        rename = "privatePreferred",
        alias = "PrivatePreferred",
        alias = "private_preferred"
    )]
    PrivatePreferred,
    #[serde(
        rename = "developmentOptional",
        alias = "DevelopmentOptional",
        alias = "development_optional"
    )]
    DevelopmentOptional,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiscoveryIdentityMode {
    #[serde(rename = "off", alias = "Off")]
    Off,
    #[serde(rename = "verified", alias = "Verified")]
    Verified,
    #[serde(
        rename = "publicWallet",
        alias = "PublicWallet",
        alias = "public_wallet"
    )]
    PublicWallet,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegistryNodeStatus {
    #[serde(rename = "active", alias = "Active")]
    Active,
    #[serde(rename = "revoked", alias = "Revoked")]
    Revoked,
    #[serde(rename = "suspended", alias = "Suspended")]
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistryNodeRecord {
    pub peer_id: String,
    pub owner_daddr: String,
    pub device_public_key_hash: [u8; 32],
    pub latest_peer_record_hash: [u8; 32],
    pub status: RegistryNodeStatus,
    pub updated_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub reputation_score: Option<u64>,
    #[serde(default)]
    pub stake_status: Option<String>,
    #[serde(default)]
    pub metadata_commitment: Option<[u8; 32]>,
}

impl RegistryNodeRecord {
    pub fn from_peer_record(
        owner_daddr: impl Into<String>,
        peer_record: &PeerRecord,
        status: RegistryNodeStatus,
        updated_at: u64,
    ) -> Result<Self> {
        Ok(Self {
            peer_id: peer_record.body.peer_id.clone(),
            owner_daddr: owner_daddr.into(),
            device_public_key_hash: device_public_key_hash(peer_record)?,
            latest_peer_record_hash: latest_peer_record_hash(peer_record)?,
            status,
            updated_at,
            expires_at: Some(peer_record.body.expires_at_unix),
            reputation_score: None,
            stake_status: None,
            metadata_commitment: None,
        })
    }

    pub fn owner_for_diagnostics(&self, mode: DiscoveryIdentityMode, raw: bool) -> String {
        if raw || mode == DiscoveryIdentityMode::PublicWallet {
            self.owner_daddr.clone()
        } else {
            "[redacted-dytallix-wallet]".to_string()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryDecision {
    Accepted,
    AcceptedWithoutRegistryPrivate,
    AcceptedWithoutRegistryDevelopment,
    AcceptedRegistryUnavailablePrivate,
    AcceptedRegistryUnavailableDevelopment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryDecisionSource {
    RegistryRecord,
    RegistryMissing,
    RegistryUnavailable,
    DevelopmentBypass,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegistryRejectionReason {
    #[serde(rename = "rejected_missing_registry")]
    RejectedMissingRegistry,
    #[serde(rename = "rejected_revoked")]
    RejectedRevoked,
    #[serde(rename = "rejected_suspended")]
    RejectedSuspended,
    #[serde(rename = "rejected_key_mismatch")]
    RejectedKeyMismatch,
    #[serde(rename = "rejected_record_hash_mismatch")]
    RejectedRecordHashMismatch,
    #[serde(rename = "registry_unavailable")]
    RegistryUnavailable,
    #[serde(rename = "rejected_expired")]
    RejectedExpired,
    #[serde(rename = "rejected_peer_id_mismatch")]
    RejectedPeerIdMismatch,
    #[serde(rename = "rejected_signature_invalid")]
    RejectedSignatureInvalid,
}

impl RegistryRejectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RejectedMissingRegistry => "rejected_missing_registry",
            Self::RejectedRevoked => "rejected_revoked",
            Self::RejectedSuspended => "rejected_suspended",
            Self::RejectedKeyMismatch => "rejected_key_mismatch",
            Self::RejectedRecordHashMismatch => "rejected_record_hash_mismatch",
            Self::RegistryUnavailable => "registry_unavailable",
            Self::RejectedExpired => "rejected_expired",
            Self::RejectedPeerIdMismatch => "rejected_peer_id_mismatch",
            Self::RejectedSignatureInvalid => "rejected_signature_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryVerificationError {
    pub reason: RegistryRejectionReason,
    pub source: RegistryDecisionSource,
    pub detail: String,
}

impl RegistryVerificationError {
    fn new(
        reason: RegistryRejectionReason,
        source: RegistryDecisionSource,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            reason,
            source,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for RegistryVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.reason.as_str(), self.detail)
    }
}

impl std::error::Error for RegistryVerificationError {}

impl From<RegistryVerificationError> for QlinkError {
    fn from(value: RegistryVerificationError) -> Self {
        QlinkError::Protocol(value.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DytallixRegistryConfig {
    pub endpoint: String,
    pub contract_address: String,
    #[serde(default)]
    pub keystore_path: Option<PathBuf>,
    #[serde(default)]
    pub wallet_name: Option<String>,
    #[serde(default)]
    pub network_id: Option<String>,
    #[serde(default)]
    pub chain_id: Option<String>,
    #[serde(default)]
    pub allowed_rpc_endpoints: Vec<String>,
}

impl DytallixRegistryConfig {
    pub fn new(
        endpoint: impl Into<String>,
        contract_address: impl Into<String>,
        keystore_path: Option<PathBuf>,
        wallet_name: Option<String>,
    ) -> Result<Self> {
        let config = Self {
            endpoint: endpoint.into(),
            contract_address: normalize_contract_address(&contract_address.into())?,
            keystore_path,
            wallet_name,
            network_id: None,
            chain_id: None,
            allowed_rpc_endpoints: Vec::new(),
        };
        config.validate_endpoint_allowlist()?;
        Ok(config)
    }

    pub fn public_testnet(contract_address: impl Into<String>) -> Result<Self> {
        Self::new(
            PUBLIC_TESTNET_ENDPOINT,
            contract_address,
            Some(Keystore::default_path()),
            Some("quantumlink".to_string()),
        )
    }

    pub fn lookup_only(
        endpoint: impl Into<String>,
        contract_address: impl Into<String>,
    ) -> Result<Self> {
        Self::new(endpoint, contract_address, None, None)
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

    pub fn wallet_keystore_path(&self) -> Result<PathBuf> {
        self.keystore_path.clone().ok_or_else(|| {
            QlinkError::Protocol(
                "dytallix registry write requires keystorePath; lookup-only registry was configured"
                    .into(),
            )
        })
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
        Self::sign_payload(
            &canonical_wallet_record_payload_bytes(method, record)?,
            keypair,
        )
    }

    pub fn sign_revoke(peer_id: &str, block_time: u64, keypair: &DytallixKeypair) -> Result<Self> {
        Self::sign_payload(
            &canonical_wallet_revoke_payload_bytes(peer_id, block_time)?,
            keypair,
        )
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

pub trait IdentityRegistryLookup: fmt::Debug + Send + Sync {
    fn lookup_record<'a>(
        &'a self,
        peer_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RegistryNodeRecord>>> + Send + 'a>>;
}

#[derive(Debug)]
pub struct DytallixIdentityRegistry {
    config: DytallixRegistryConfig,
    http: reqwest::Client,
}

impl IdentityRegistryLookup for DytallixIdentityRegistry {
    fn lookup_record<'a>(
        &'a self,
        peer_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RegistryNodeRecord>>> + Send + 'a>> {
        Box::pin(async move { self.lookup(peer_id).await })
    }
}

impl DytallixIdentityRegistry {
    pub fn new(mut config: DytallixRegistryConfig) -> Result<Self> {
        config.contract_address = normalize_contract_address(&config.contract_address)?;
        config.validate_endpoint_allowlist()?;
        let http = reqwest::Client::builder()
            .build()
            .map_err(|err| QlinkError::Protocol(format!("dytallix HTTP client failed: {err}")))?;
        Ok(Self { config, http })
    }

    pub fn config(&self) -> &DytallixRegistryConfig {
        &self.config
    }

    pub async fn lookup(&self, peer_id: &str) -> Result<Option<RegistryNodeRecord>> {
        let request = GetNodeRequest {
            peer_id: peer_id.to_owned(),
        };
        let call = encode_contract_call_args(RegistryContractMethod::GetNode, &request)?;
        let path = format!(
            "/api/contracts/{}/query/{}?args={}",
            self.config.contract_address, call.method, call.args_hex
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

    pub async fn status(&self, peer_id: &str) -> Result<Option<RegistryNodeRecord>> {
        self.lookup(peer_id).await
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
        let wallet_authorization = WalletAuthorization::sign_revoke(peer_id, block_time, &wallet)?;
        let request = RevokeNodeRequest {
            peer_id: peer_id.to_owned(),
            block_time,
            wallet_authorization,
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
        let wallet_authorization = WalletAuthorization::sign_record(method, &record, &wallet)?;
        let device_binding_authorization =
            DeviceBindingAuthorization::sign(&owner, peer_record, device_keypair)?;
        let request = RegisterNodeRequest {
            record,
            wallet_authorization,
            device_binding_authorization,
        };
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
        let signed = self
            .sign_contract_call(method, call.args_hex.clone(), wallet)
            .await?;
        let body = serde_json::json!({
            "signed_tx": signed,
            "address": self.config.contract_address,
            "method": method.as_str(),
            "args": call.args_hex,
        });
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
        let client = DytallixClient::new(&self.config.endpoint)
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
            address: self.config.contract_address.clone(),
            method: method.as_str().to_string(),
            args: Some(args_hex),
            gas_limit: CONTRACT_CALL_GAS_LIMIT,
        };
        let (c_gas_limit, b_gas_limit) =
            estimate_default_gas_limits(std::slice::from_ref(&message));
        let tx = Transaction {
            chain_id: self
                .config
                .chain_id
                .clone()
                .unwrap_or(chain_status.finalized_checkpoint),
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
        let keystore_path = self.config.wallet_keystore_path()?;
        let keystore = Keystore::open(keystore_path).map_err(dytallix_sdk_error)?;
        let wallet_name = if let Some(name) = self.config.wallet_name.as_deref() {
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

    fn url(&self, path: &str) -> Result<reqwest::Url> {
        let endpoint = self.config.endpoint.trim_end_matches('/');
        let path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        reqwest::Url::parse(&format!("{endpoint}{path}"))
            .map_err(|err| QlinkError::Protocol(format!("invalid dytallix endpoint URL: {err}")))
    }
}

pub fn verify_registry_binding(
    peer_record: &PeerRecord,
    registry_record: Option<&RegistryNodeRecord>,
    policy: MeshTrustPolicy,
) -> std::result::Result<RegistryDecision, RegistryVerificationError> {
    verify_peer_record_identity(peer_record)?;

    let Some(registry_record) = registry_record else {
        return match policy {
            MeshTrustPolicy::PublicRequired => Err(RegistryVerificationError::new(
                RegistryRejectionReason::RejectedMissingRegistry,
                RegistryDecisionSource::RegistryMissing,
                "registry record required by public mesh trust policy",
            )),
            MeshTrustPolicy::PrivatePreferred => {
                Ok(RegistryDecision::AcceptedWithoutRegistryPrivate)
            }
            MeshTrustPolicy::DevelopmentOptional => {
                Ok(RegistryDecision::AcceptedWithoutRegistryDevelopment)
            }
        };
    };

    verify_registry_record_status(registry_record)?;

    if registry_record.peer_id != peer_record.body.peer_id {
        return Err(RegistryVerificationError::new(
            RegistryRejectionReason::RejectedPeerIdMismatch,
            RegistryDecisionSource::RegistryRecord,
            "peer_id mismatch",
        ));
    }
    if registry_record.device_public_key_hash != device_public_key_hash(peer_record)? {
        return Err(RegistryVerificationError::new(
            RegistryRejectionReason::RejectedKeyMismatch,
            RegistryDecisionSource::RegistryRecord,
            "device_public_key_hash mismatch",
        ));
    }
    if registry_record.latest_peer_record_hash != latest_peer_record_hash(peer_record)? {
        return Err(RegistryVerificationError::new(
            RegistryRejectionReason::RejectedRecordHashMismatch,
            RegistryDecisionSource::RegistryRecord,
            "latest_peer_record_hash mismatch",
        ));
    }

    Ok(RegistryDecision::Accepted)
}

pub fn verify_inbound_registry_assertion(
    assertion: &InboundIdentityAssertion,
    registry_record: Option<&RegistryNodeRecord>,
    policy: MeshTrustPolicy,
) -> std::result::Result<RegistryDecision, RegistryVerificationError> {
    let Some(registry_record) = registry_record else {
        return match policy {
            MeshTrustPolicy::PublicRequired => Err(RegistryVerificationError::new(
                RegistryRejectionReason::RejectedMissingRegistry,
                RegistryDecisionSource::RegistryMissing,
                "no dytallix registry record for inbound identity assertion",
            )),
            MeshTrustPolicy::PrivatePreferred => {
                Ok(RegistryDecision::AcceptedWithoutRegistryPrivate)
            }
            MeshTrustPolicy::DevelopmentOptional => {
                Ok(RegistryDecision::AcceptedWithoutRegistryDevelopment)
            }
        };
    };

    verify_registry_record_status(registry_record)?;

    if registry_record.peer_id != assertion.peer_id {
        return Err(RegistryVerificationError::new(
            RegistryRejectionReason::RejectedPeerIdMismatch,
            RegistryDecisionSource::RegistryRecord,
            "peer_id mismatch",
        ));
    }
    if registry_record.device_public_key_hash
        != device_public_key_hash_from_public_key(&assertion.device_public_key)?
    {
        return Err(RegistryVerificationError::new(
            RegistryRejectionReason::RejectedKeyMismatch,
            RegistryDecisionSource::RegistryRecord,
            "device_public_key_hash mismatch",
        ));
    }

    Ok(RegistryDecision::Accepted)
}

fn verify_registry_record_status(
    registry_record: &RegistryNodeRecord,
) -> std::result::Result<(), RegistryVerificationError> {
    match registry_record.status {
        RegistryNodeStatus::Active => {}
        RegistryNodeStatus::Revoked => {
            return Err(RegistryVerificationError::new(
                RegistryRejectionReason::RejectedRevoked,
                RegistryDecisionSource::RegistryRecord,
                "registry record is revoked",
            ));
        }
        RegistryNodeStatus::Suspended => {
            return Err(RegistryVerificationError::new(
                RegistryRejectionReason::RejectedSuspended,
                RegistryDecisionSource::RegistryRecord,
                "registry record is suspended",
            ));
        }
    }

    if registry_record
        .expires_at
        .is_some_and(|expires_at| expires_at <= now_unix())
    {
        return Err(RegistryVerificationError::new(
            RegistryRejectionReason::RejectedExpired,
            RegistryDecisionSource::RegistryRecord,
            "registry record has expired",
        ));
    }

    Ok(())
}

pub fn registry_unavailable_decision(
    policy: MeshTrustPolicy,
) -> std::result::Result<RegistryDecision, RegistryVerificationError> {
    match policy {
        MeshTrustPolicy::PublicRequired => Err(RegistryVerificationError::new(
            RegistryRejectionReason::RegistryUnavailable,
            RegistryDecisionSource::RegistryUnavailable,
            "dytallix registry unavailable under public mesh trust policy",
        )),
        MeshTrustPolicy::PrivatePreferred => {
            Ok(RegistryDecision::AcceptedRegistryUnavailablePrivate)
        }
        MeshTrustPolicy::DevelopmentOptional => {
            Ok(RegistryDecision::AcceptedRegistryUnavailableDevelopment)
        }
    }
}

pub async fn verify_with_registry(
    peer_record: &PeerRecord,
    registry: Option<&dyn IdentityRegistryLookup>,
    policy: MeshTrustPolicy,
) -> std::result::Result<RegistryDecision, RegistryVerificationError> {
    if policy == MeshTrustPolicy::DevelopmentOptional && registry.is_none() {
        return verify_registry_binding(peer_record, None, policy);
    }

    let Some(registry) = registry else {
        return verify_registry_binding(peer_record, None, policy);
    };

    match registry.lookup_record(&peer_record.body.peer_id).await {
        Ok(record) => verify_registry_binding(peer_record, record.as_ref(), policy),
        Err(error) => {
            tracing::warn!(%error, "dytallix registry lookup failed");
            registry_unavailable_decision(policy)
        }
    }
}

pub fn device_public_key_hash(
    peer_record: &PeerRecord,
) -> std::result::Result<[u8; 32], RegistryVerificationError> {
    device_public_key_hash_from_public_key(&peer_record.body.device_public_key)
}

pub fn device_public_key_hash_from_public_key(
    device_public_key: &DevicePublicKey,
) -> std::result::Result<[u8; 32], RegistryVerificationError> {
    let bytes = serde_json::to_vec(device_public_key).map_err(|err| {
        RegistryVerificationError::new(
            RegistryRejectionReason::RejectedSignatureInvalid,
            RegistryDecisionSource::RegistryRecord,
            format!("device public key serialization failed: {err}"),
        )
    })?;
    Ok(Sha256::digest(bytes).into())
}

pub fn latest_peer_record_hash(
    peer_record: &PeerRecord,
) -> std::result::Result<[u8; 32], RegistryVerificationError> {
    peer_record.record_hash().map_err(|err| {
        RegistryVerificationError::new(
            RegistryRejectionReason::RejectedSignatureInvalid,
            RegistryDecisionSource::RegistryRecord,
            format!("peer record hash failed: {err}"),
        )
    })
}

pub fn canonical_binding_payload_bytes(
    owner_daddr: &str,
    peer_record: &PeerRecord,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Payload {
        contract: &'static str,
        version: u8,
        owner_daddr: String,
        peer_id: String,
        device_public_key_hash: String,
        latest_peer_record_hash: String,
    }

    let payload = Payload {
        contract: REGISTRY_CONTRACT_NAME,
        version: REGISTRY_CONTRACT_VERSION,
        owner_daddr: owner_daddr.to_string(),
        peer_id: peer_record.body.peer_id.clone(),
        device_public_key_hash: hex::encode(
            device_public_key_hash(peer_record).map_err(QlinkError::from)?,
        ),
        latest_peer_record_hash: hex::encode(
            latest_peer_record_hash(peer_record).map_err(QlinkError::from)?,
        ),
    };
    serde_json::to_vec(&payload).map_err(Into::into)
}

pub fn canonical_wallet_record_payload_bytes(
    operation: RegistryContractMethod,
    record: &RegistryNodeRecord,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Payload<'a> {
        contract: &'static str,
        version: u8,
        operation: &'static str,
        record: &'a RegistryNodeRecord,
    }
    serde_json::to_vec(&Payload {
        contract: REGISTRY_CONTRACT_NAME,
        version: REGISTRY_CONTRACT_VERSION,
        operation: operation.as_str(),
        record,
    })
    .map_err(Into::into)
}

pub fn canonical_wallet_revoke_payload_bytes(peer_id: &str, block_time: u64) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Payload<'a> {
        contract: &'static str,
        version: u8,
        operation: &'static str,
        peer_id: &'a str,
        block_time: u64,
    }
    serde_json::to_vec(&Payload {
        contract: REGISTRY_CONTRACT_NAME,
        version: REGISTRY_CONTRACT_VERSION,
        operation: RegistryContractMethod::RevokeNode.as_str(),
        peer_id,
        block_time,
    })
    .map_err(Into::into)
}

pub fn encode_contract_args<T: Serialize>(request: &T) -> Result<String> {
    Ok(hex::encode(serde_json::to_vec(request)?))
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

pub fn decode_registry_query_response(value: serde_json::Value) -> Result<RegistryQueryResponse> {
    if let Some(result_hex) = value.get("result").and_then(|raw| raw.as_str()) {
        let bytes = hex::decode(result_hex).map_err(|err| {
            QlinkError::Protocol(format!("dytallix registry result is not valid hex: {err}"))
        })?;
        return serde_json::from_slice(&bytes).map_err(|err| {
            QlinkError::Protocol(format!(
                "dytallix registry result is not valid contract JSON: {err}"
            ))
        });
    }
    serde_json::from_value(value).map_err(|err| {
        QlinkError::Protocol(format!(
            "dytallix registry response is not valid JSON: {err}"
        ))
    })
}

pub fn validate_registry_submission_response(value: &serde_json::Value) -> Result<()> {
    if value.get("result").is_none() && value.get("ok").is_none() {
        return Ok(());
    }
    let contract_response = decode_registry_query_response(value.clone())?;
    if contract_response.ok {
        Ok(())
    } else {
        Err(QlinkError::Protocol(format!(
            "dytallix registry contract rejected request: {}",
            contract_response
                .error
                .unwrap_or_else(|| "unknown contract error".to_string())
        )))
    }
}

pub fn ensure_dytallix_enrollment_wallet(
    config: &DytallixRegistryConfig,
) -> Result<DytallixEnrollmentWallet> {
    let keystore_path = config.wallet_keystore_path()?;
    let mut keystore =
        Keystore::open_or_create(keystore_path.clone()).map_err(dytallix_sdk_error)?;
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
            name.to_string()
        }
        None => {
            if let Some(active) = keystore.active() {
                active.name.clone()
            } else {
                let name = "quantumlink";
                let keypair = DytallixKeypair::generate();
                keystore
                    .add_keypair(&keypair, name)
                    .map_err(dytallix_sdk_error)?;
                keystore.set_active(name).map_err(dytallix_sdk_error)?;
                created_wallet = true;
                name.to_string()
            }
        }
    };
    keystore.save().map_err(dytallix_sdk_error)?;
    harden_keystore_permissions(&keystore_path)?;
    let wallet = keystore
        .get_keypair(&wallet_name)
        .map_err(dytallix_sdk_error)?;
    let wallet_address = DAddr::from_public_key(wallet.public_key())
        .map_err(|err| {
            QlinkError::InvalidKey(format!("dytallix address derivation failed: {err}"))
        })?
        .to_string();

    Ok(DytallixEnrollmentWallet {
        keystore_path,
        wallet_name,
        wallet_address,
        created_wallet,
    })
}

fn verify_peer_record_identity(
    peer_record: &PeerRecord,
) -> std::result::Result<(), RegistryVerificationError> {
    if peer_record.body.device_public_key.peer_id() != peer_record.body.peer_id {
        return Err(RegistryVerificationError::new(
            RegistryRejectionReason::RejectedPeerIdMismatch,
            RegistryDecisionSource::RegistryRecord,
            "peer_id does not match device public key",
        ));
    }
    if peer_record.body.expires_at_unix <= now_unix() {
        return Err(RegistryVerificationError::new(
            RegistryRejectionReason::RejectedExpired,
            RegistryDecisionSource::RegistryRecord,
            "peer record has expired",
        ));
    }
    peer_record
        .body
        .device_public_key
        .verify(
            &peer_record.body.canonical_bytes().map_err(|err| {
                RegistryVerificationError::new(
                    RegistryRejectionReason::RejectedSignatureInvalid,
                    RegistryDecisionSource::RegistryRecord,
                    format!("peer record canonicalization failed: {err}"),
                )
            })?,
            &peer_record.signature,
        )
        .map_err(|err| {
            RegistryVerificationError::new(
                RegistryRejectionReason::RejectedSignatureInvalid,
                RegistryDecisionSource::RegistryRecord,
                err.to_string(),
            )
        })
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

fn dytallix_sdk_error(err: impl fmt::Display) -> QlinkError {
    QlinkError::Protocol(format!("dytallix SDK error: {err}"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::DeviceKeypair,
        discovery::{CandidateEndpoint, CandidateType, PeerRecord, UnsignedPeerRecord},
        error::QlinkError,
    };

    fn signed_peer_record() -> PeerRecord {
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

    fn active_record(peer_record: &PeerRecord) -> RegistryNodeRecord {
        RegistryNodeRecord::from_peer_record(
            "dytallix1owner",
            peer_record,
            RegistryNodeStatus::Active,
            crate::discovery::now_unix(),
        )
        .unwrap()
    }

    #[test]
    fn public_policy_accepts_active_matching_registry_record() {
        let peer_record = signed_peer_record();
        let registry_record = active_record(&peer_record);

        let decision = verify_registry_binding(
            &peer_record,
            Some(&registry_record),
            MeshTrustPolicy::PublicRequired,
        )
        .unwrap();

        assert_eq!(decision, RegistryDecision::Accepted);
    }

    #[test]
    fn public_policy_rejects_missing_registry_record() {
        let peer_record = signed_peer_record();

        let err = verify_registry_binding(&peer_record, None, MeshTrustPolicy::PublicRequired)
            .unwrap_err();

        assert!(matches!(
            err.reason,
            RegistryRejectionReason::RejectedMissingRegistry
        ));
        assert!(matches!(
            err.source,
            RegistryDecisionSource::RegistryMissing
        ));
    }

    #[test]
    fn private_and_development_policies_do_not_fail_closed_without_registry() {
        let peer_record = signed_peer_record();

        let private =
            verify_registry_binding(&peer_record, None, MeshTrustPolicy::PrivatePreferred).unwrap();
        let development =
            verify_registry_binding(&peer_record, None, MeshTrustPolicy::DevelopmentOptional)
                .unwrap();

        assert_eq!(private, RegistryDecision::AcceptedWithoutRegistryPrivate);
        assert_eq!(
            development,
            RegistryDecision::AcceptedWithoutRegistryDevelopment
        );
    }

    #[test]
    fn public_policy_rejects_revoked_suspended_key_and_record_hash_mismatch() {
        let peer_record = signed_peer_record();

        let mut revoked = active_record(&peer_record);
        revoked.status = RegistryNodeStatus::Revoked;
        assert_eq!(
            verify_registry_binding(
                &peer_record,
                Some(&revoked),
                MeshTrustPolicy::PublicRequired
            )
            .unwrap_err()
            .reason,
            RegistryRejectionReason::RejectedRevoked
        );

        let mut suspended = active_record(&peer_record);
        suspended.status = RegistryNodeStatus::Suspended;
        assert_eq!(
            verify_registry_binding(
                &peer_record,
                Some(&suspended),
                MeshTrustPolicy::PublicRequired
            )
            .unwrap_err()
            .reason,
            RegistryRejectionReason::RejectedSuspended
        );

        let mut wrong_key = active_record(&peer_record);
        wrong_key.device_public_key_hash = [0_u8; 32];
        assert_eq!(
            verify_registry_binding(
                &peer_record,
                Some(&wrong_key),
                MeshTrustPolicy::PublicRequired
            )
            .unwrap_err()
            .reason,
            RegistryRejectionReason::RejectedKeyMismatch
        );

        let mut wrong_record = active_record(&peer_record);
        wrong_record.latest_peer_record_hash = [9_u8; 32];
        assert_eq!(
            verify_registry_binding(
                &peer_record,
                Some(&wrong_record),
                MeshTrustPolicy::PublicRequired
            )
            .unwrap_err()
            .reason,
            RegistryRejectionReason::RejectedRecordHashMismatch
        );
    }

    #[test]
    fn public_wallet_controls_address_redaction() {
        let record = RegistryNodeRecord {
            peer_id: "qlink_peer".to_string(),
            owner_daddr: "dytallix1verypublicwallet".to_string(),
            device_public_key_hash: [1_u8; 32],
            latest_peer_record_hash: [2_u8; 32],
            status: RegistryNodeStatus::Active,
            updated_at: 10,
            expires_at: None,
            reputation_score: None,
            stake_status: None,
            metadata_commitment: None,
        };

        assert_eq!(
            record.owner_for_diagnostics(DiscoveryIdentityMode::Verified, false),
            "[redacted-dytallix-wallet]"
        );
        assert_eq!(
            record.owner_for_diagnostics(DiscoveryIdentityMode::PublicWallet, false),
            "dytallix1verypublicwallet"
        );
        assert_eq!(
            record.owner_for_diagnostics(DiscoveryIdentityMode::Off, true),
            "dytallix1verypublicwallet"
        );
    }

    #[test]
    fn registry_unavailable_fails_public_and_warns_private() {
        let unavailable =
            registry_unavailable_decision(MeshTrustPolicy::PublicRequired).unwrap_err();
        assert_eq!(
            unavailable.reason,
            RegistryRejectionReason::RegistryUnavailable
        );

        let private = registry_unavailable_decision(MeshTrustPolicy::PrivatePreferred).unwrap();
        assert_eq!(
            private,
            RegistryDecision::AcceptedRegistryUnavailablePrivate
        );
    }

    #[test]
    fn registry_errors_convert_to_protocol_errors_with_stable_reasons() {
        let peer_record = signed_peer_record();
        let err = verify_registry_binding(&peer_record, None, MeshTrustPolicy::PublicRequired)
            .unwrap_err();
        let qlink_error: QlinkError = err.into();

        assert!(qlink_error
            .to_string()
            .contains("rejected_missing_registry"));
    }
}
