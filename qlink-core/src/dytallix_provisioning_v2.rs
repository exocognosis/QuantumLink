use crate::{
    crypto::DeviceKeypair,
    dytallix_identity::{
        DytallixIdentityRegistry, DytallixRegistryBindingVersion, DytallixRegistryConfig,
        DytallixRegistryLookupConfig,
    },
    dytallix_identity_v2::{
        DeviceAuthorizationV2, RegistryIdentityOperationV2, RegistryIdentityRecordV2,
        RegistryIdentityStatusOperationV2, RegistryIdentityStatusV2, WalletAuthorizationV2,
    },
    error::{QlinkError, Result},
};
use dytallix_core::{address::DAddr, keypair::DytallixKeypair};
use dytallix_sdk::{
    client::DytallixClient,
    keystore::Keystore,
    transaction::{estimate_default_gas_limits, Message, Transaction},
    TransactionStatus,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

const CONTRACT_CALL_GAS_LIMIT: u64 = 1_000_000;
const DEFAULT_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StableIdentityPolicyV2 {
    pub authorization_expires_at: Option<u64>,
    pub max_peer_record_ttl_seconds: u64,
    pub mesh_scope: Option<String>,
    pub metadata_commitment_hex: Option<String>,
}

impl Default for StableIdentityPolicyV2 {
    fn default() -> Self {
        Self {
            authorization_expires_at: None,
            max_peer_record_ttl_seconds: 300,
            mesh_scope: None,
            metadata_commitment_hex: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StableIdentityProvisioningConfigV2 {
    pub endpoint: String,
    pub contract_address: String,
    pub network_id: Option<String>,
    pub chain_id: Option<String>,
    pub allowed_rpc_endpoints: Vec<String>,
    pub keystore_path: Option<PathBuf>,
    pub wallet_name: Option<String>,
    pub confirmation_timeout: Duration,
    pub poll_interval: Duration,
}

impl StableIdentityProvisioningConfigV2 {
    pub fn new(
        endpoint: impl Into<String>,
        contract_address: impl Into<String>,
        keystore_path: impl Into<PathBuf>,
        wallet_name: Option<String>,
    ) -> Result<Self> {
        let endpoint = endpoint.into();
        validate_provisioning_endpoint(&endpoint)?;
        let registry = DytallixRegistryConfig::new(
            endpoint.clone(),
            contract_address,
            keystore_path,
            wallet_name.clone(),
        )?;
        Ok(Self {
            endpoint,
            contract_address: registry.contract_address,
            network_id: None,
            chain_id: None,
            allowed_rpc_endpoints: Vec::new(),
            keystore_path: Some(registry.keystore_path),
            wallet_name,
            confirmation_timeout: DEFAULT_CONFIRMATION_TIMEOUT,
            poll_interval: DEFAULT_POLL_INTERVAL,
        })
    }

    pub fn lookup_only(
        endpoint: impl Into<String>,
        contract_address: impl Into<String>,
    ) -> Result<Self> {
        let endpoint = endpoint.into();
        validate_provisioning_endpoint(&endpoint)?;
        let lookup = DytallixRegistryLookupConfig::new(endpoint.clone(), contract_address)?;
        Ok(Self {
            endpoint,
            contract_address: lookup.contract_address,
            network_id: None,
            chain_id: None,
            allowed_rpc_endpoints: Vec::new(),
            keystore_path: None,
            wallet_name: None,
            confirmation_timeout: DEFAULT_CONFIRMATION_TIMEOUT,
            poll_interval: DEFAULT_POLL_INTERVAL,
        })
    }

    pub fn with_network_pins(
        mut self,
        network_id: Option<String>,
        chain_id: Option<String>,
        allowed_rpc_endpoints: Vec<String>,
    ) -> Result<Self> {
        let lookup = DytallixRegistryLookupConfig::new(
            self.endpoint.clone(),
            self.contract_address.clone(),
        )?
        .with_network_pins(network_id, chain_id, allowed_rpc_endpoints)?;
        self.network_id = lookup.network_id;
        self.chain_id = lookup.chain_id;
        self.allowed_rpc_endpoints = lookup.allowed_rpc_endpoints;
        Ok(self)
    }

    pub fn with_confirmation_timing(
        mut self,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<Self> {
        if timeout.is_zero() || poll_interval.is_zero() || poll_interval > timeout {
            return Err(QlinkError::Protocol(
                "confirmation timeout and poll interval must be positive, with poll interval no greater than timeout"
                    .into(),
            ));
        }
        self.confirmation_timeout = timeout;
        self.poll_interval = poll_interval;
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum StableIdentityProvisioningOperationV2 {
    Register,
    Update,
    Suspend,
    Reactivate,
    Revoke,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StableIdentityProvisioningReceiptV2 {
    pub operation: StableIdentityProvisioningOperationV2,
    pub endpoint: String,
    pub contract_address: String,
    pub network_id: Option<String>,
    pub chain_id: Option<String>,
    pub tx_hash: String,
    pub confirmed_block: u64,
    pub chain_checkpoint_observed: String,
    pub readback_verified: bool,
    pub identity: RegistryIdentityRecordV2,
}

#[derive(Serialize)]
struct RecordMutationRequestV2 {
    record: RegistryIdentityRecordV2,
    #[serde(flatten)]
    wallet_authorization: WalletAuthorizationV2,
    #[serde(flatten)]
    device_authorization: DeviceAuthorizationV2,
}

#[derive(Serialize)]
struct StatusMutationRequestV2 {
    peer_id: String,
    identity_revision: u64,
    #[serde(flatten)]
    wallet_authorization: WalletAuthorizationV2,
}

pub struct DytallixStableIdentityProvisionerV2 {
    config: StableIdentityProvisioningConfigV2,
    lookup: DytallixIdentityRegistry,
    http: reqwest::Client,
}

impl DytallixStableIdentityProvisionerV2 {
    pub fn new(config: StableIdentityProvisioningConfigV2) -> Result<Self> {
        let lookup = DytallixIdentityRegistry::from_lookup_config(
            DytallixRegistryLookupConfig::new(
                config.endpoint.clone(),
                config.contract_address.clone(),
            )?
            .with_network_pins(
                config.network_id.clone(),
                config.chain_id.clone(),
                config.allowed_rpc_endpoints.clone(),
            )?
            .with_binding_version(DytallixRegistryBindingVersion::StableIdentityV2),
        )?;
        let http = reqwest::Client::builder().build().map_err(|error| {
            QlinkError::Protocol(format!("Dytallix HTTP client failed: {error}"))
        })?;
        Ok(Self {
            config,
            lookup,
            http,
        })
    }

    pub async fn readback(&self, peer_id: &str) -> Result<Option<RegistryIdentityRecordV2>> {
        match self.lookup.lookup_identity(peer_id).await? {
            Some(crate::dytallix_identity::RegistryIdentityLookupRecord::StableIdentityV2(
                record,
            )) => Ok(Some(record)),
            Some(_) => Err(QlinkError::Protocol(
                "Dytallix v2 readback returned a legacy v1 identity".into(),
            )),
            None => Ok(None),
        }
    }

    pub async fn register(
        &self,
        device_keypair: &DeviceKeypair,
        policy: StableIdentityPolicyV2,
    ) -> Result<StableIdentityProvisioningReceiptV2> {
        let peer_id = device_keypair.public_key().peer_id();
        if self.readback(&peer_id).await?.is_some() {
            return Err(QlinkError::Protocol(
                "stable identity v2 is already registered".into(),
            ));
        }
        let wallet = self.load_wallet_keypair()?;
        let owner = wallet_owner(&wallet)?;
        let record = RegistryIdentityRecordV2::from_device_public_key(
            owner,
            &device_keypair.public_key(),
            RegistryIdentityStatusV2::Active,
            1,
            policy.authorization_expires_at,
            policy.max_peer_record_ttl_seconds,
            policy.mesh_scope.as_deref(),
            policy.metadata_commitment_hex,
        )
        .map_err(stable_identity_error)?;
        let request = RecordMutationRequestV2 {
            wallet_authorization: WalletAuthorizationV2::sign(
                RegistryIdentityOperationV2::Register,
                &record,
                &wallet,
            )
            .map_err(stable_identity_error)?,
            device_authorization: DeviceAuthorizationV2::sign(
                RegistryIdentityOperationV2::Register,
                &record,
                device_keypair,
            )
            .map_err(stable_identity_error)?,
            record: record.clone(),
        };
        self.submit_and_confirm(
            StableIdentityProvisioningOperationV2::Register,
            "register_identity",
            &request,
            &wallet,
            record,
        )
        .await
    }

    pub async fn update(
        &self,
        device_keypair: &DeviceKeypair,
        policy: StableIdentityPolicyV2,
    ) -> Result<StableIdentityProvisioningReceiptV2> {
        self.update_status(
            StableIdentityProvisioningOperationV2::Update,
            device_keypair,
            policy,
        )
        .await
    }

    pub async fn reactivate(
        &self,
        device_keypair: &DeviceKeypair,
        policy: StableIdentityPolicyV2,
    ) -> Result<StableIdentityProvisioningReceiptV2> {
        self.update_status(
            StableIdentityProvisioningOperationV2::Reactivate,
            device_keypair,
            policy,
        )
        .await
    }

    async fn update_status(
        &self,
        operation: StableIdentityProvisioningOperationV2,
        device_keypair: &DeviceKeypair,
        policy: StableIdentityPolicyV2,
    ) -> Result<StableIdentityProvisioningReceiptV2> {
        let peer_id = device_keypair.public_key().peer_id();
        let current = self
            .readback(&peer_id)
            .await?
            .ok_or_else(|| QlinkError::Protocol("stable identity v2 is not registered".into()))?;
        if current.status == RegistryIdentityStatusV2::Revoked {
            return Err(QlinkError::Protocol(
                "stable identity v2 revocation is terminal".into(),
            ));
        }
        if operation == StableIdentityProvisioningOperationV2::Reactivate
            && current.status != RegistryIdentityStatusV2::Suspended
        {
            return Err(QlinkError::Protocol(
                "stable identity v2 must be suspended before reactivation".into(),
            ));
        }
        let revision = current
            .identity_revision
            .checked_add(1)
            .ok_or_else(|| QlinkError::Protocol("stable identity revision is exhausted".into()))?;
        let wallet = self.load_wallet_keypair()?;
        let status = if operation == StableIdentityProvisioningOperationV2::Reactivate {
            RegistryIdentityStatusV2::Active
        } else {
            current.status
        };
        let record = RegistryIdentityRecordV2::from_device_public_key(
            current.owner_daddr,
            &device_keypair.public_key(),
            status,
            revision,
            policy.authorization_expires_at,
            policy.max_peer_record_ttl_seconds,
            policy.mesh_scope.as_deref(),
            policy.metadata_commitment_hex,
        )
        .map_err(stable_identity_error)?;
        let request = RecordMutationRequestV2 {
            wallet_authorization: WalletAuthorizationV2::sign(
                RegistryIdentityOperationV2::Update,
                &record,
                &wallet,
            )
            .map_err(stable_identity_error)?,
            device_authorization: DeviceAuthorizationV2::sign(
                RegistryIdentityOperationV2::Update,
                &record,
                device_keypair,
            )
            .map_err(stable_identity_error)?,
            record: record.clone(),
        };
        self.submit_and_confirm(operation, "update_identity", &request, &wallet, record)
            .await
    }

    pub async fn suspend(
        &self,
        device_peer_id: &str,
    ) -> Result<StableIdentityProvisioningReceiptV2> {
        self.status_mutation(
            StableIdentityProvisioningOperationV2::Suspend,
            RegistryIdentityStatusOperationV2::Suspend,
            "suspend_identity",
            device_peer_id,
            RegistryIdentityStatusV2::Suspended,
        )
        .await
    }

    pub async fn revoke(
        &self,
        device_peer_id: &str,
    ) -> Result<StableIdentityProvisioningReceiptV2> {
        self.status_mutation(
            StableIdentityProvisioningOperationV2::Revoke,
            RegistryIdentityStatusOperationV2::Revoke,
            "revoke_identity",
            device_peer_id,
            RegistryIdentityStatusV2::Revoked,
        )
        .await
    }

    async fn status_mutation(
        &self,
        operation: StableIdentityProvisioningOperationV2,
        status_operation: RegistryIdentityStatusOperationV2,
        method: &'static str,
        peer_id: &str,
        expected_status: RegistryIdentityStatusV2,
    ) -> Result<StableIdentityProvisioningReceiptV2> {
        let current = self
            .readback(peer_id)
            .await?
            .ok_or_else(|| QlinkError::Protocol("stable identity v2 is not registered".into()))?;
        if current.status == RegistryIdentityStatusV2::Revoked {
            return Err(QlinkError::Protocol(
                "stable identity v2 revocation is terminal".into(),
            ));
        }
        let revision = current
            .identity_revision
            .checked_add(1)
            .ok_or_else(|| QlinkError::Protocol("stable identity revision is exhausted".into()))?;
        let wallet = self.load_wallet_keypair()?;
        let request = StatusMutationRequestV2 {
            peer_id: peer_id.to_string(),
            identity_revision: revision,
            wallet_authorization: WalletAuthorizationV2::sign_status(
                status_operation,
                peer_id,
                revision,
                &current.owner_daddr,
                &wallet,
            )
            .map_err(stable_identity_error)?,
        };
        let mut expected = current;
        expected.status = expected_status;
        expected.identity_revision = revision;
        self.submit_and_confirm(operation, method, &request, &wallet, expected)
            .await
    }

    async fn submit_and_confirm<T: Serialize>(
        &self,
        operation: StableIdentityProvisioningOperationV2,
        method: &'static str,
        request: &T,
        wallet: &DytallixKeypair,
        expected: RegistryIdentityRecordV2,
    ) -> Result<StableIdentityProvisioningReceiptV2> {
        let args_hex = hex::encode(serde_json::to_vec(request)?);
        let signed = self
            .sign_contract_call(method, args_hex.clone(), wallet)
            .await?;
        let response = self
            .post_json(
                "/contracts/call",
                &serde_json::json!({
                    "signed_tx": signed,
                    "address": self.config.contract_address,
                    "method": method,
                    "args": args_hex,
                }),
            )
            .await?;
        let tx_hash = response
            .get("tx_hash")
            .or_else(|| response.get("hash"))
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                QlinkError::Protocol(
                    "Dytallix contract submission did not return a transaction hash".into(),
                )
            })?
            .to_string();
        let confirmed_block = self.wait_for_confirmation(&tx_hash).await?;
        let identity = self.wait_for_readback(&expected).await?;
        let chain_checkpoint_observed = DytallixClient::new(&self.config.endpoint)
            .await
            .map_err(dytallix_sdk_error)?
            .get_chain_status()
            .await
            .map_err(dytallix_sdk_error)?
            .finalized_checkpoint;
        Ok(StableIdentityProvisioningReceiptV2 {
            operation,
            endpoint: self.config.endpoint.clone(),
            contract_address: self.config.contract_address.clone(),
            network_id: self.config.network_id.clone(),
            chain_id: self.config.chain_id.clone(),
            tx_hash,
            confirmed_block,
            chain_checkpoint_observed,
            readback_verified: true,
            identity,
        })
    }

    async fn sign_contract_call(
        &self,
        method: &str,
        args_hex: String,
        wallet: &DytallixKeypair,
    ) -> Result<dytallix_sdk::transaction::SignedTransaction> {
        let client = DytallixClient::new(&self.config.endpoint)
            .await
            .map_err(dytallix_sdk_error)?;
        let from = DAddr::from_public_key(wallet.public_key()).map_err(|error| {
            QlinkError::InvalidKey(format!("Dytallix address derivation failed: {error}"))
        })?;
        let account = client
            .get_account(&from)
            .await
            .map_err(dytallix_sdk_error)?;
        let chain_status = client
            .get_chain_status()
            .await
            .map_err(dytallix_sdk_error)?;
        if let Some(expected_chain_id) = self.config.chain_id.as_deref() {
            if chain_status.finalized_checkpoint != expected_chain_id {
                return Err(QlinkError::Protocol(format!(
                    "Dytallix chain ID mismatch: expected {expected_chain_id}, got {}",
                    chain_status.finalized_checkpoint
                )));
            }
        }
        let message = Message::ContractCall {
            from: from.to_string(),
            address: self.config.contract_address.clone(),
            method: method.to_string(),
            args: Some(args_hex),
            gas_limit: CONTRACT_CALL_GAS_LIMIT,
        };
        let (c_gas_limit, b_gas_limit) =
            estimate_default_gas_limits(std::slice::from_ref(&message));
        let transaction = Transaction {
            chain_id: chain_status.finalized_checkpoint,
            nonce: account.nonce,
            msgs: vec![message],
            fee: 0,
            memo: String::new(),
            c_gas_limit,
            b_gas_limit,
        };
        let fee = transaction
            .estimate_fee(&client)
            .await
            .map_err(dytallix_sdk_error)?;
        transaction
            .with_fee_micro(fee.total_cost_drt)
            .sign(wallet)
            .map_err(dytallix_sdk_error)
    }

    async fn wait_for_confirmation(&self, tx_hash: &str) -> Result<u64> {
        let client = DytallixClient::new(&self.config.endpoint)
            .await
            .map_err(dytallix_sdk_error)?;
        let started = Instant::now();
        loop {
            match client.get_transaction(tx_hash).await {
                Ok(receipt) => match receipt.status {
                    TransactionStatus::Confirmed => return Ok(receipt.block),
                    TransactionStatus::Failed(reason) => {
                        return Err(QlinkError::Protocol(format!(
                            "Dytallix transaction {tx_hash} failed: {reason}"
                        )));
                    }
                    TransactionStatus::Pending => {}
                },
                Err(error) if started.elapsed() >= self.config.confirmation_timeout => {
                    return Err(dytallix_sdk_error(error));
                }
                Err(_) => {}
            }
            if started.elapsed() >= self.config.confirmation_timeout {
                return Err(QlinkError::Protocol(format!(
                    "Dytallix transaction {tx_hash} was not confirmed within {} seconds",
                    self.config.confirmation_timeout.as_secs()
                )));
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    async fn wait_for_readback(
        &self,
        expected: &RegistryIdentityRecordV2,
    ) -> Result<RegistryIdentityRecordV2> {
        let started = Instant::now();
        loop {
            if let Some(record) = self.readback(&expected.peer_id).await? {
                if record == *expected {
                    return Ok(record);
                }
                if record.identity_revision > expected.identity_revision {
                    return Err(QlinkError::Protocol(format!(
                        "Dytallix readback advanced past expected identity revision {}",
                        expected.identity_revision
                    )));
                }
            }
            if started.elapsed() >= self.config.confirmation_timeout {
                return Err(QlinkError::Protocol(format!(
                    "Dytallix identity readback did not converge to revision {} within {} seconds",
                    expected.identity_revision,
                    self.config.confirmation_timeout.as_secs()
                )));
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    fn load_wallet_keypair(&self) -> Result<DytallixKeypair> {
        let keystore_path = self.config.keystore_path.as_ref().ok_or_else(|| {
            QlinkError::Protocol("Dytallix wallet keystore is required for this operation".into())
        })?;
        validate_keystore_file(keystore_path)?;
        let keystore = Keystore::open(keystore_path.clone()).map_err(dytallix_sdk_error)?;
        let wallet_name = self
            .config
            .wallet_name
            .as_deref()
            .map(str::to_owned)
            .or_else(|| keystore.active().map(|entry| entry.name.clone()))
            .ok_or_else(|| QlinkError::Protocol("Dytallix keystore has no active wallet".into()))?;
        keystore
            .get_keypair(&wallet_name)
            .map_err(dytallix_sdk_error)
    }

    async fn post_json<T: Serialize>(&self, path: &str, body: &T) -> Result<serde_json::Value> {
        let url = endpoint_url(&self.config.endpoint, path)?;
        let response = self
            .http
            .post(url.clone())
            .json(body)
            .send()
            .await
            .map_err(|error| {
                QlinkError::Protocol(format!("Dytallix POST {url} failed: {error}"))
            })?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(QlinkError::Protocol(format!(
                "Dytallix POST {url} failed with {status}: {body}"
            )));
        }
        response.json().await.map_err(|error| {
            QlinkError::Protocol(format!(
                "Dytallix POST {url} returned invalid JSON: {error}"
            ))
        })
    }
}

fn validate_keystore_file(path: &std::path::Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        QlinkError::Protocol(format!(
            "Dytallix keystore {} cannot be inspected: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(QlinkError::Protocol(format!(
            "Dytallix keystore {} must be a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(QlinkError::Protocol(format!(
                "Dytallix keystore {} must not be group- or world-accessible",
                path.display()
            )));
        }
    }
    Ok(())
}

fn validate_provisioning_endpoint(endpoint: &str) -> Result<()> {
    let url = Url::parse(endpoint)
        .map_err(|error| QlinkError::Protocol(format!("invalid Dytallix endpoint URL: {error}")))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(QlinkError::Protocol(
            "Dytallix provisioning endpoint must use HTTPS (HTTP is allowed only for loopback tests)"
                .into(),
        ));
    }
    Ok(())
}

fn endpoint_url(endpoint: &str, path: &str) -> Result<Url> {
    let endpoint = endpoint.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    Url::parse(&format!("{endpoint}/{path}"))
        .map_err(|error| QlinkError::Protocol(format!("invalid Dytallix endpoint URL: {error}")))
}

fn wallet_owner(wallet: &DytallixKeypair) -> Result<String> {
    DAddr::from_public_key(wallet.public_key())
        .map(|address| address.to_string())
        .map_err(|error| {
            QlinkError::InvalidKey(format!("Dytallix address derivation failed: {error}"))
        })
}

fn stable_identity_error(error: impl std::fmt::Display) -> QlinkError {
    QlinkError::Protocol(format!("Dytallix stable identity v2 error: {error}"))
}

fn dytallix_sdk_error(error: impl std::fmt::Display) -> QlinkError {
    QlinkError::Protocol(format!("Dytallix SDK error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_rejects_insecure_remote_endpoint() {
        let error = StableIdentityProvisioningConfigV2::new(
            "http://registry.example",
            "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
            "/tmp/wallet.json",
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("must use HTTPS"));
    }

    #[test]
    fn provisioning_allows_loopback_http_for_tests() {
        let config = StableIdentityProvisioningConfigV2::new(
            "http://127.0.0.1:9471",
            "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
            "/tmp/wallet.json",
            None,
        )
        .unwrap();
        assert_eq!(config.endpoint, "http://127.0.0.1:9471");
    }

    #[test]
    fn confirmation_timing_must_be_bounded_and_positive() {
        let config = StableIdentityProvisioningConfigV2::new(
            "https://registry.example",
            "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
            "/tmp/wallet.json",
            None,
        )
        .unwrap();
        assert!(config
            .clone()
            .with_confirmation_timing(Duration::ZERO, Duration::from_secs(1))
            .is_err());
        assert!(config
            .with_confirmation_timing(Duration::from_secs(1), Duration::from_secs(2))
            .is_err());
    }
}
