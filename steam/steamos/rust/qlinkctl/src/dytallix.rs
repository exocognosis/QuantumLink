use crate::{load_provisioning_device_keypair, DEFAULT_STATE_DIR};
use qlink_core::dytallix_provisioning_v2::{
    DytallixStableIdentityProvisionerV2, StableIdentityPolicyV2, StableIdentityProvisioningConfigV2,
};
use qlink_proto::{DaemonConfig, DytallixBindingVersion, DytallixIdentityLookupConfig};
use serde::Serialize;
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_FILE: &str = "/etc/quantumlink/config.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DytallixAction {
    Status,
    Register,
    Update,
    Suspend,
    Reactivate,
    Revoke,
}

impl DytallixAction {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "status" => Ok(Self::Status),
            "register" => Ok(Self::Register),
            "update" => Ok(Self::Update),
            "suspend" => Ok(Self::Suspend),
            "reactivate" => Ok(Self::Reactivate),
            "revoke" => Ok(Self::Revoke),
            _ => Err(format!("unknown Dytallix action `{value}`")),
        }
    }

    fn requires_wallet(self) -> bool {
        self != Self::Status
    }

    fn uses_policy(self) -> bool {
        matches!(self, Self::Register | Self::Update | Self::Reactivate)
    }

    fn uses_local_device(self) -> bool {
        matches!(self, Self::Register | Self::Update | Self::Reactivate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DytallixOptions {
    pub action: DytallixAction,
    pub config_file: PathBuf,
    pub state_dir: PathBuf,
    pub keystore_path: Option<PathBuf>,
    pub wallet_name: Option<String>,
    pub peer_id: Option<String>,
    pub confirm_peer_id: Option<String>,
    pub policy: StableIdentityPolicyV2,
    policy_options_set: bool,
}

pub fn parse_dytallix_args<I, S>(args: I) -> Result<DytallixOptions, String>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut args = args.into_iter().map(Into::into);
    let action = args
        .next()
        .ok_or_else(|| "a Dytallix action is required".to_string())?
        .into_string()
        .map_err(|_| "Dytallix action must be valid UTF-8".to_string())
        .and_then(|value| DytallixAction::parse(&value))?;
    let mut options = DytallixOptions {
        action,
        config_file: PathBuf::from(DEFAULT_CONFIG_FILE),
        state_dir: PathBuf::from(DEFAULT_STATE_DIR),
        keystore_path: None,
        wallet_name: None,
        peer_id: None,
        confirm_peer_id: None,
        policy: StableIdentityPolicyV2::default(),
        policy_options_set: false,
    };
    let mut seen = HashSet::new();

    while let Some(flag) = args.next() {
        let flag = flag
            .into_string()
            .map_err(|_| "Dytallix option names must be valid UTF-8".to_string())?;
        if !seen.insert(flag.clone()) {
            return Err(format!("duplicate Dytallix option `{flag}`"));
        }
        let value = args
            .next()
            .ok_or_else(|| format!("Dytallix option `{flag}` requires a value"))?;
        match flag.as_str() {
            "--config" => options.config_file = PathBuf::from(value),
            "--state-dir" => options.state_dir = PathBuf::from(value),
            "--keystore" => options.keystore_path = Some(PathBuf::from(value)),
            "--wallet" => options.wallet_name = Some(required_string(value, &flag)?),
            "--peer-id" => options.peer_id = Some(required_string(value, &flag)?),
            "--confirm-peer-id" => options.confirm_peer_id = Some(required_string(value, &flag)?),
            "--authorization-expires-at" => {
                options.policy_options_set = true;
                options.policy.authorization_expires_at =
                    Some(parse_u64(value, &flag, 1, u64::MAX)?)
            }
            "--max-peer-ttl" => {
                options.policy_options_set = true;
                options.policy.max_peer_record_ttl_seconds = parse_u64(value, &flag, 30, 86_400)?
            }
            "--mesh-scope" => {
                options.policy_options_set = true;
                options.policy.mesh_scope = Some(required_string(value, &flag)?);
            }
            "--metadata-commitment" => {
                options.policy_options_set = true;
                options.policy.metadata_commitment_hex = Some(required_string(value, &flag)?)
            }
            _ => return Err(format!("unknown Dytallix option `{flag}`")),
        }
    }

    validate_options(&options)?;
    Ok(options)
}

pub fn run_dytallix(options: DytallixOptions) -> Result<String, String> {
    let identity_config = load_identity_config(&options.config_file)?;
    let core_config = provisioning_config(&identity_config, &options)?;
    let provisioner =
        DytallixStableIdentityProvisionerV2::new(core_config).map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("failed to start Dytallix command runtime: {error}"))?;

    runtime.block_on(async move {
        match options.action {
            DytallixAction::Status => {
                let peer_id = resolve_peer_id(&options)?;
                let identity = provisioner
                    .readback(&peer_id)
                    .await
                    .map_err(|error| error.to_string())?;
                serde_json::to_string_pretty(&DytallixReadback {
                    endpoint: identity_config.endpoint,
                    contract_address: identity_config.contract_address,
                    network_id: identity_config.network_id,
                    chain_id: identity_config.chain_id,
                    peer_id,
                    identity,
                    transaction_finality_verified: false,
                })
                .map_err(|error| error.to_string())
            }
            DytallixAction::Register => {
                let device = load_device(&options)?;
                serialize_receipt(provisioner.register(&device, options.policy).await)
            }
            DytallixAction::Update => {
                let device = load_device(&options)?;
                serialize_receipt(provisioner.update(&device, options.policy).await)
            }
            DytallixAction::Suspend => {
                let peer_id = resolve_peer_id(&options)?;
                serialize_receipt(provisioner.suspend(&peer_id).await)
            }
            DytallixAction::Reactivate => {
                let device = load_device(&options)?;
                serialize_receipt(provisioner.reactivate(&device, options.policy).await)
            }
            DytallixAction::Revoke => {
                let peer_id = options
                    .peer_id
                    .as_deref()
                    .expect("validated revoke peer id");
                serialize_receipt(provisioner.revoke(peer_id).await)
            }
        }
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DytallixReadback {
    endpoint: String,
    contract_address: String,
    network_id: String,
    chain_id: String,
    peer_id: String,
    identity: Option<qlink_core::dytallix_identity_v2::RegistryIdentityRecordV2>,
    transaction_finality_verified: bool,
}

fn load_identity_config(path: &Path) -> Result<DytallixIdentityLookupConfig, String> {
    let raw = std::fs::read(path)
        .map_err(|error| format!("failed to read config {}: {error}", path.display()))?;
    let config: DaemonConfig = serde_json::from_slice(&raw)
        .map_err(|error| format!("invalid config {}: {error}", path.display()))?;
    config
        .validate()
        .map_err(|error| format!("invalid config {}: {error}", path.display()))?;
    let identity = config
        .dytallix_identity
        .ok_or_else(|| format!("config {} does not define dytallixIdentity", path.display()))?;
    if identity.binding_version != DytallixBindingVersion::StableIdentityV2 {
        return Err("Dytallix provisioning requires bindingVersion=stableIdentityV2".into());
    }
    Ok(identity)
}

fn provisioning_config(
    identity: &DytallixIdentityLookupConfig,
    options: &DytallixOptions,
) -> Result<StableIdentityProvisioningConfigV2, String> {
    let config = match options.keystore_path.as_ref() {
        Some(keystore) => StableIdentityProvisioningConfigV2::new(
            identity.endpoint.clone(),
            identity.contract_address.clone(),
            keystore,
            options.wallet_name.clone(),
        ),
        None => StableIdentityProvisioningConfigV2::lookup_only(
            identity.endpoint.clone(),
            identity.contract_address.clone(),
        ),
    }
    .map_err(|error| error.to_string())?;
    config
        .with_network_pins(
            Some(identity.network_id.clone()),
            Some(identity.chain_id.clone()),
            identity.allowed_rpc_endpoints.clone(),
        )
        .map_err(|error| error.to_string())
}

fn validate_options(options: &DytallixOptions) -> Result<(), String> {
    if options.action.requires_wallet() && options.keystore_path.is_none() {
        return Err(format!(
            "Dytallix {} requires --keystore <path>",
            action_name(options.action)
        ));
    }
    if !options.action.requires_wallet()
        && (options.keystore_path.is_some() || options.wallet_name.is_some())
    {
        return Err("Dytallix status does not accept wallet options".into());
    }
    if !options.action.uses_policy() && options.policy_options_set {
        return Err(format!(
            "Dytallix {} does not accept identity policy options",
            action_name(options.action)
        ));
    }
    if options.action.uses_local_device() && options.peer_id.is_some() {
        return Err(format!(
            "Dytallix {} derives the peer ID from the local device seed",
            action_name(options.action)
        ));
    }
    if options.action == DytallixAction::Revoke {
        let peer_id = options
            .peer_id
            .as_deref()
            .ok_or_else(|| "Dytallix revoke requires --peer-id <id>".to_string())?;
        let confirmation = options.confirm_peer_id.as_deref().ok_or_else(|| {
            "Dytallix revoke requires --confirm-peer-id <id> to confirm the terminal action"
                .to_string()
        })?;
        if peer_id != confirmation {
            return Err("Dytallix revoke peer ID confirmation does not match".into());
        }
    } else if options.confirm_peer_id.is_some() {
        return Err("--confirm-peer-id is accepted only by Dytallix revoke".into());
    }
    Ok(())
}

fn resolve_peer_id(options: &DytallixOptions) -> Result<String, String> {
    match options.peer_id.clone() {
        Some(peer_id) => Ok(peer_id),
        None => Ok(load_device(options)?.public_key().peer_id()),
    }
}

fn load_device(options: &DytallixOptions) -> Result<qlink_core::crypto::DeviceKeypair, String> {
    load_provisioning_device_keypair(&options.state_dir).map_err(|error| error.to_string())
}

fn serialize_receipt(
    receipt: qlink_core::Result<
        qlink_core::dytallix_provisioning_v2::StableIdentityProvisioningReceiptV2,
    >,
) -> Result<String, String> {
    let receipt = receipt.map_err(|error| error.to_string())?;
    serde_json::to_string_pretty(&receipt).map_err(|error| error.to_string())
}

fn required_string(value: OsString, flag: &str) -> Result<String, String> {
    let value = value
        .into_string()
        .map_err(|_| format!("Dytallix option `{flag}` must be valid UTF-8"))?;
    if value.trim().is_empty() {
        return Err(format!("Dytallix option `{flag}` must not be empty"));
    }
    Ok(value)
}

fn parse_u64(value: OsString, flag: &str, min: u64, max: u64) -> Result<u64, String> {
    let value = required_string(value, flag)?;
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("Dytallix option `{flag}` must be an integer"))?;
    if !(min..=max).contains(&parsed) {
        return Err(format!(
            "Dytallix option `{flag}` must be between {min} and {max}"
        ));
    }
    Ok(parsed)
}

fn action_name(action: DytallixAction) -> &'static str {
    match action {
        DytallixAction::Status => "status",
        DytallixAction::Register => "register",
        DytallixAction::Update => "update",
        DytallixAction::Suspend => "suspend",
        DytallixAction::Reactivate => "reactivate",
        DytallixAction::Revoke => "revoke",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_accepts_lookup_only_options() {
        let options =
            parse_dytallix_args(["status", "--peer-id", "qlink_peer", "--config", "/tmp/c"])
                .unwrap();
        assert_eq!(options.action, DytallixAction::Status);
        assert_eq!(options.peer_id.as_deref(), Some("qlink_peer"));
        assert!(options.keystore_path.is_none());
    }

    #[test]
    fn mutations_require_explicit_keystore() {
        let error = parse_dytallix_args(["register"]).unwrap_err();
        assert!(error.contains("--keystore"));
    }

    #[test]
    fn revoke_requires_exact_peer_confirmation() {
        let error = parse_dytallix_args([
            "revoke",
            "--keystore",
            "/tmp/wallet.json",
            "--peer-id",
            "qlink_a",
            "--confirm-peer-id",
            "qlink_b",
        ])
        .unwrap_err();
        assert!(error.contains("does not match"));
    }

    #[test]
    fn parser_rejects_unknown_and_duplicate_options() {
        assert!(parse_dytallix_args(["status", "--bogus", "value"])
            .unwrap_err()
            .contains("unknown"));
        assert!(
            parse_dytallix_args(["status", "--peer-id", "qlink_a", "--peer-id", "qlink_b"])
                .unwrap_err()
                .contains("duplicate")
        );
    }

    #[test]
    fn status_rejects_wallet_material() {
        let error = parse_dytallix_args(["status", "--keystore", "/tmp/wallet.json"]).unwrap_err();
        assert!(error.contains("does not accept wallet"));
    }

    #[test]
    fn policy_options_are_lifecycle_scoped() {
        let error = parse_dytallix_args([
            "suspend",
            "--keystore",
            "/tmp/wallet.json",
            "--max-peer-ttl",
            "300",
        ])
        .unwrap_err();
        assert!(error.contains("does not accept identity policy"));
    }
}
