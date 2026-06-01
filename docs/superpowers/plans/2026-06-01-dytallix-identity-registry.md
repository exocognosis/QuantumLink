# Dytallix Identity Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the full Dytallix-backed QuantumLink identity registry feature with real wallet signing, real Dytallix contract calls, public-mesh enforcement, private/dev policy behavior, and Swift UX controls.

**Architecture:** Add a real Dytallix WASM registry contract, then integrate QuantumLink's Rust mesh connector with a Dytallix SDK-backed registry client that verifies signed peer records before dialing. Swift owns user-visible wallet/identity mode configuration and passes enforcement policy into the Rust transport; no mock, simulation, or stub registry implementation is allowed.

**Tech Stack:** Swift 6 / SwiftUI / XCTest, Rust 2021 / Cargo / Tokio, Dytallix SDK and CLI from `https://github.com/DytallixHQ/dytallix-sdk`, Dytallix WASM contract target, ML-DSA-65 device signatures.

---

## File Structure

- Create `dytallix/quantumlink-node-registry/Cargo.toml`: standalone real WASM contract crate that can be built and deployed with the Dytallix CLI.
- Create `dytallix/quantumlink-node-registry/src/lib.rs`: registry state machine, host-storage-backed contract exports, and contract tests.
- Modify `Cargo.toml`: add the contract crate to the workspace so CI builds it.
- Modify `rust/qlink-core/Cargo.toml`: add `dytallix-sdk`, `dytallix-core`, `reqwest`, `blake3`, `sha3`, and `hex` dependencies needed for real Dytallix client integration.
- Create `rust/qlink-core/src/dytallix_identity.rs`: Dytallix registry types, policy decisions, binding verifier, contract query/call client, and wallet-backed registration/update/revoke flows.
- Modify `rust/qlink-core/src/lib.rs`: export the new module.
- Modify `rust/qlink-core/src/mesh_connection.rs`: enforce registry policy after `PeerRecord::verify` and before direct/relay probing.
- Modify `rust/qlink-core/src/mesh_transport.rs`: add registry configuration to `MeshTransportConfig` and pass it into `MeshConnectorConfig`.
- Modify `rust/qlink-core/src/ffi.rs`: expose registry status helpers and accept registry configuration through the existing JSON config.
- Modify `rust/qlink-core/src/bin/qlinkctl.rs`: add real `identity register`, `identity update`, `identity revoke`, and `identity status` commands.
- Modify `Sources/QuantumLinkKit/Models.swift`: add `MeshTrustPolicy`, `DiscoveryIdentityMode`, and `DytallixIdentityConfiguration`.
- Modify `Sources/QuantumLinkKit/TunnelTransport.swift`: encode registry configuration into `MeshTransportConfiguration`.
- Modify `Sources/QuantumLinkKit/RustCoreBridge.swift`: add registry status and registration bridge functions used by app UX.
- Modify `Sources/QuantumLinkApp/QuantumLinkApp.swift`: add the `Off / Verified / Public Wallet` control and public-mesh guardrails.
- Modify `Tests/QuantumLinkKitTests/*.swift`: add policy encoding, redaction, and UX state tests.
- Add Rust tests in `rust/qlink-core/src/dytallix_identity.rs` and existing mesh connection tests; use real contract state-machine data and real Dytallix encoding, not a mock registry.

## Task 1: Real Dytallix Registry Contract

**Files:**
- Create: `dytallix/quantumlink-node-registry/Cargo.toml`
- Create: `dytallix/quantumlink-node-registry/src/lib.rs`
- Modify: `Cargo.toml`

- [ ] **Step 1: Add failing contract tests**

Create `dytallix/quantumlink-node-registry/src/lib.rs` with tests first. The initial file should define the desired public API in tests before implementation:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn active_record() -> NodeRecord {
        NodeRecord {
            peer_id: "qlink_peer".to_string(),
            owner_daddr: "dytallix1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_string(),
            device_public_key_hash_hex: "11".repeat(32),
            latest_peer_record_hash_hex: "22".repeat(32),
            status: NodeStatus::Active,
            reputation_score: 0,
            stake_status: None,
            updated_at: 100,
            expires_at: Some(1_000),
            metadata_commitment_hex: None,
        }
    }

    #[test]
    fn register_update_revoke_and_lookup_are_real_contract_state_transitions() {
        let mut registry = QuantumLinkNodeRegistry::new();
        let record = active_record();

        registry
            .register_node("dytallix1operator", record.clone(), vec![7, 8, 9])
            .expect("registration should succeed");
        assert_eq!(registry.get_node("qlink_peer").unwrap(), record);

        let mut updated = active_record();
        updated.latest_peer_record_hash_hex = "33".repeat(32);
        updated.updated_at = 200;
        registry
            .update_node("dytallix1operator", updated.clone(), vec![1, 2, 3])
            .expect("owner should update");
        assert_eq!(registry.get_node("qlink_peer").unwrap(), updated);

        registry
            .revoke_node("dytallix1operator", "qlink_peer", 300)
            .expect("owner should revoke");
        assert_eq!(registry.get_node("qlink_peer").unwrap().status, NodeStatus::Revoked);
    }

    #[test]
    fn non_owner_cannot_update_or_revoke() {
        let mut registry = QuantumLinkNodeRegistry::new();
        registry
            .register_node("dytallix1operator", active_record(), vec![1])
            .unwrap();

        assert_eq!(
            registry.update_node("dytallix1other", active_record(), vec![2]),
            Err(RegistryError::Unauthorized)
        );
        assert_eq!(
            registry.revoke_node("dytallix1other", "qlink_peer", 250),
            Err(RegistryError::Unauthorized)
        );
    }
}
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
cargo test --manifest-path dytallix/quantumlink-node-registry/Cargo.toml
```

Expected: FAIL because `NodeRecord`, `NodeStatus`, `QuantumLinkNodeRegistry`, and `RegistryError` are not defined.

- [ ] **Step 3: Add contract manifest**

Create `dytallix/quantumlink-node-registry/Cargo.toml`:

```toml
[package]
name = "quantumlink-node-registry"
version = "0.1.0"
edition = "2021"
license = "MIT"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"

[workspace]
```

- [ ] **Step 4: Implement contract state machine and WASM exports**

Replace the top of `src/lib.rs` with:

```rust
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub latest_peer_record_hash_hex: String,
    pub status: NodeStatus,
    pub reputation_score: u64,
    pub stake_status: Option<String>,
    pub updated_at: u64,
    pub expires_at: Option<u64>,
    pub metadata_commitment_hex: Option<String>,
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
        actor_daddr: &str,
        record: NodeRecord,
        _device_signature: Vec<u8>,
    ) -> Result<(), RegistryError> {
        validate_record(&record)?;
        let mut owned = record;
        owned.owner_daddr = actor_daddr.to_string();
        self.events.push(RegistryEvent {
            peer_id: owned.peer_id.clone(),
            event_type: "registered".to_string(),
            actor_daddr: actor_daddr.to_string(),
            block_time: owned.updated_at,
        });
        self.nodes.insert(owned.peer_id.clone(), owned);
        Ok(())
    }

    pub fn update_node(
        &mut self,
        actor_daddr: &str,
        record: NodeRecord,
        _device_signature: Vec<u8>,
    ) -> Result<(), RegistryError> {
        validate_record(&record)?;
        let existing = self.nodes.get(&record.peer_id).ok_or(RegistryError::NotFound)?;
        if existing.owner_daddr != actor_daddr {
            return Err(RegistryError::Unauthorized);
        }
        self.events.push(RegistryEvent {
            peer_id: record.peer_id.clone(),
            event_type: "updated".to_string(),
            actor_daddr: actor_daddr.to_string(),
            block_time: record.updated_at,
        });
        self.nodes.insert(record.peer_id.clone(), record);
        Ok(())
    }

    pub fn revoke_node(
        &mut self,
        actor_daddr: &str,
        peer_id: &str,
        block_time: u64,
    ) -> Result<(), RegistryError> {
        let record = self.nodes.get_mut(peer_id).ok_or(RegistryError::NotFound)?;
        if record.owner_daddr != actor_daddr {
            return Err(RegistryError::Unauthorized);
        }
        record.status = NodeStatus::Revoked;
        record.updated_at = block_time;
        self.events.push(RegistryEvent {
            peer_id: peer_id.to_string(),
            event_type: "revoked".to_string(),
            actor_daddr: actor_daddr.to_string(),
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
}

fn validate_record(record: &NodeRecord) -> Result<(), RegistryError> {
    if !record.peer_id.starts_with("qlink_") {
        return Err(RegistryError::InvalidPeerId);
    }
    validate_hex32(&record.device_public_key_hash_hex)?;
    validate_hex32(&record.latest_peer_record_hash_hex)?;
    if let Some(commitment) = record.metadata_commitment_hex.as_deref() {
        validate_hex32(commitment)?;
    }
    Ok(())
}

fn validate_hex32(value: &str) -> Result<(), RegistryError> {
    if value.len() == 64 && value.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(RegistryError::InvalidHex)
    }
}
```

Then add host-storage-backed `contract_register_node`, `contract_update_node`, `contract_revoke_node`, and `contract_get_node` exports using Dytallix's `contract_register_node(ptr, len) -> ptr` style ABI. Use `env.storage_get` and `env.storage_set` imports for persistence; use JSON request/response payloads so the Dytallix CLI can pass hex-encoded args directly. The exported methods must call the same `QuantumLinkNodeRegistry` state-machine methods tested above and must return a JSON response padded into the WASM return buffer.

- [ ] **Step 5: Run tests to verify GREEN**

Run:

```bash
cargo test --manifest-path dytallix/quantumlink-node-registry/Cargo.toml
cargo build --manifest-path dytallix/quantumlink-node-registry/Cargo.toml --target wasm32-unknown-unknown --release
```

Expected: PASS, and the build emits `target/wasm32-unknown-unknown/release/quantumlink_node_registry.wasm`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml dytallix/quantumlink-node-registry
git commit -m "feat: add Dytallix node registry contract"
```

## Task 2: Registry Types And Binding Verification In Rust Core

**Files:**
- Create: `rust/qlink-core/src/dytallix_identity.rs`
- Modify: `rust/qlink-core/src/lib.rs`
- Test: `rust/qlink-core/src/dytallix_identity.rs`

- [ ] **Step 1: Write failing verifier tests**

Add tests that construct real `PeerRecord`s and real registry records; do not mock a registry service.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::DeviceKeypair,
        discovery::{CandidateEndpoint, CandidateType, PeerRecord, UnsignedPeerRecord},
    };

    fn signed_record() -> (DeviceKeypair, PeerRecord) {
        let keypair = DeviceKeypair::generate().unwrap();
        let body = UnsignedPeerRecord::new(
            "public-mesh",
            "node",
            keypair.public_key(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Relay,
                address: "relay.quantumlink.invalid".to_string(),
                port: 9472,
                priority: 10,
            }],
            vec!["100.64.0.2/32".to_string()],
            120,
            1,
        );
        (keypair.clone(), PeerRecord::signed(body, &keypair).unwrap())
    }

    #[test]
    fn public_policy_accepts_active_matching_registry_record() {
        let (_keypair, peer_record) = signed_record();
        let registry = RegistryNodeRecord::from_peer_record(
            "dytallix1operator".to_string(),
            &peer_record,
            RegistryNodeStatus::Active,
            0,
        )
        .unwrap();

        let decision = verify_registry_binding(
            &peer_record,
            Some(&registry),
            MeshTrustPolicy::PublicRequired,
        )
        .unwrap();

        assert_eq!(decision, RegistryDecision::Accepted);
    }

    #[test]
    fn public_policy_rejects_missing_registry_record() {
        let (_keypair, peer_record) = signed_record();
        let error = verify_registry_binding(&peer_record, None, MeshTrustPolicy::PublicRequired)
            .unwrap_err();
        assert!(error.to_string().contains("missing Dytallix registry"));
    }

    #[test]
    fn private_policy_accepts_valid_peer_record_without_registry() {
        let (_keypair, peer_record) = signed_record();
        let decision = verify_registry_binding(&peer_record, None, MeshTrustPolicy::PrivatePreferred)
            .unwrap();
        assert_eq!(decision, RegistryDecision::AcceptedWithoutRegistryPrivate);
    }
}
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
cargo test -p qlink-core dytallix_identity --manifest-path Cargo.toml
```

Expected: FAIL because the new module and types do not exist.

- [ ] **Step 3: Implement types and verifier**

Create `rust/qlink-core/src/dytallix_identity.rs`:

```rust
use crate::{discovery::PeerRecord, error::{QlinkError, Result}};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshTrustPolicy {
    PublicRequired,
    PrivatePreferred,
    DevelopmentOptional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryNodeStatus {
    Active,
    Revoked,
    Suspended,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryNodeRecord {
    pub peer_id: String,
    pub owner_daddr: String,
    pub device_public_key_hash_hex: String,
    pub latest_peer_record_hash_hex: String,
    pub status: RegistryNodeStatus,
    pub reputation_score: u64,
    pub stake_status: Option<String>,
    pub updated_at: u64,
    pub expires_at: Option<u64>,
    pub metadata_commitment_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryDecision {
    Accepted,
    AcceptedWithoutRegistryPrivate,
    AcceptedWithoutRegistryDevelopment,
}

impl RegistryNodeRecord {
    pub fn from_peer_record(
        owner_daddr: String,
        peer_record: &PeerRecord,
        status: RegistryNodeStatus,
        updated_at: u64,
    ) -> Result<Self> {
        Ok(Self {
            peer_id: peer_record.body.peer_id.clone(),
            owner_daddr,
            device_public_key_hash_hex: hex32(&serde_json::to_vec(&peer_record.body.device_public_key)?),
            latest_peer_record_hash_hex: hex32(&peer_record.record_hash()?),
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
    let Some(registry_record) = registry_record else {
        return match policy {
            MeshTrustPolicy::PublicRequired => Err(QlinkError::Protocol(
                "missing Dytallix registry record for public mesh peer".into(),
            )),
            MeshTrustPolicy::PrivatePreferred => Ok(RegistryDecision::AcceptedWithoutRegistryPrivate),
            MeshTrustPolicy::DevelopmentOptional => Ok(RegistryDecision::AcceptedWithoutRegistryDevelopment),
        };
    };

    if registry_record.status != RegistryNodeStatus::Active {
        return Err(QlinkError::Protocol(format!(
            "Dytallix registry record for {} is not active",
            peer_record.body.peer_id
        )));
    }
    if registry_record.peer_id != peer_record.body.peer_id {
        return Err(QlinkError::Protocol("Dytallix registry peer_id mismatch".into()));
    }

    let expected_key_hash = hex32(&serde_json::to_vec(&peer_record.body.device_public_key)?);
    if registry_record.device_public_key_hash_hex != expected_key_hash {
        return Err(QlinkError::Protocol("Dytallix registry device key hash mismatch".into()));
    }

    let expected_record_hash = hex32(&peer_record.record_hash()?);
    if registry_record.latest_peer_record_hash_hex != expected_record_hash {
        return Err(QlinkError::Protocol("Dytallix registry peer record hash mismatch".into()));
    }

    Ok(RegistryDecision::Accepted)
}

pub fn hex32(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
```

Modify `rust/qlink-core/src/lib.rs`:

```rust
pub mod dytallix_identity;
```

- [ ] **Step 4: Run tests to verify GREEN**

Run:

```bash
cargo test -p qlink-core dytallix_identity --manifest-path Cargo.toml
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/qlink-core/src/dytallix_identity.rs rust/qlink-core/src/lib.rs
git commit -m "feat: verify Dytallix identity bindings"
```

## Task 3: Real Dytallix SDK Client And Wallet Registration

**Files:**
- Modify: `rust/qlink-core/Cargo.toml`
- Modify: `rust/qlink-core/src/dytallix_identity.rs`
- Modify: `rust/qlink-core/src/bin/qlinkctl.rs`

- [ ] **Step 1: Write failing client encoding tests**

Add tests in `dytallix_identity.rs` that verify contract call payloads are exact JSON and hex encoded for Dytallix contract calls:

```rust
#[test]
fn register_call_args_are_hex_encoded_json() {
    let (_keypair, peer_record) = tests::signed_record();
    let record = RegistryNodeRecord::from_peer_record(
        "dytallix1operator".to_string(),
        &peer_record,
        RegistryNodeStatus::Active,
        10,
    )
    .unwrap();

    let encoded = encode_contract_args("register_node", &record, &[1, 2, 3]).unwrap();
    let decoded = hex::decode(encoded).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&decoded).unwrap();

    assert_eq!(value["method"], "register_node");
    assert_eq!(value["record"]["peer_id"], peer_record.body.peer_id);
    assert_eq!(value["device_signature"], "010203");
}
```

- [ ] **Step 2: Run test to verify RED**

Run:

```bash
cargo test -p qlink-core register_call_args_are_hex_encoded_json --manifest-path Cargo.toml
```

Expected: FAIL because `encode_contract_args` and `hex` dependency are missing.

- [ ] **Step 3: Add real Dytallix dependencies**

Modify `rust/qlink-core/Cargo.toml`:

```toml
dytallix-core = { git = "https://github.com/DytallixHQ/dytallix-sdk.git" }
dytallix-sdk = { git = "https://github.com/DytallixHQ/dytallix-sdk.git", features = ["network"] }
hex = "0.4"
reqwest = { version = "0.12", features = ["json"] }
sha3 = "0.10"
```

- [ ] **Step 4: Implement real client payload encoding and HTTP contract calls**

Add to `dytallix_identity.rs`:

```rust
use dytallix_core::address::DAddr;
use dytallix_core::keypair::DytallixKeypair;
use dytallix_sdk::transaction::{estimate_default_gas_limits, Message, Transaction};
use dytallix_sdk::{DytallixClient, Keystore};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DytallixRegistryConfig {
    pub endpoint: String,
    pub contract_address: String,
    pub keystore_path: Option<String>,
    pub wallet_name: Option<String>,
}

pub fn encode_contract_args(
    method: &str,
    record: &RegistryNodeRecord,
    device_signature: &[u8],
) -> Result<String> {
    let payload = serde_json::json!({
        "method": method,
        "record": record,
        "device_signature": hex::encode(device_signature),
    });
    Ok(hex::encode(serde_json::to_vec(&payload)?))
}

pub struct DytallixIdentityRegistry {
    config: DytallixRegistryConfig,
    http: reqwest::Client,
}

impl DytallixIdentityRegistry {
    pub fn new(config: DytallixRegistryConfig) -> Self {
        Self { config, http: reqwest::Client::new() }
    }

    pub async fn lookup(&self, peer_id: &str) -> Result<Option<RegistryNodeRecord>> {
        let path = format!(
            "{}/api/contracts/{}/query/get_node?args={}",
            self.config.endpoint.trim_end_matches('/'),
            self.config.contract_address,
            hex::encode(peer_id.as_bytes())
        );
        let response = self.http.get(path).send().await.map_err(|err| QlinkError::Protocol(err.to_string()))?;
        if response.status().as_u16() == 404 {
            return Ok(None);
        }
        let value: serde_json::Value = response.json().await.map_err(|err| QlinkError::Protocol(err.to_string()))?;
        if value.is_null() {
            return Ok(None);
        }
        serde_json::from_value(value).map(Some).map_err(Into::into)
    }
}
```

Then add registration/update/revoke methods that load the Dytallix keystore, select the active or named wallet, build `Message::ContractCall`, sign with `DytallixKeypair`, and submit to `/contracts/call` using the same signed transaction shape used by `dytallix-cli`.

- [ ] **Step 5: Add qlinkctl identity commands**

In `rust/qlink-core/src/bin/qlinkctl.rs`, add commands:

```text
qlinkctl identity register --endpoint https://dytallix.com --contract 0x1111111111111111111111111111111111111111 --wallet default --peer-record build/public-mesh-peer-record.json
qlinkctl identity update --endpoint https://dytallix.com --contract 0x1111111111111111111111111111111111111111 --wallet default --peer-record build/public-mesh-peer-record.json
qlinkctl identity revoke --endpoint https://dytallix.com --contract 0x1111111111111111111111111111111111111111 --wallet default --peer-id qlink_peer
qlinkctl identity status --endpoint https://dytallix.com --contract 0x1111111111111111111111111111111111111111 --peer-id qlink_peer
```

The command implementation must call `DytallixIdentityRegistry`; it must not shell out to `dytallix`.

- [ ] **Step 6: Run tests to verify GREEN**

Run:

```bash
cargo test -p qlink-core dytallix_identity --manifest-path Cargo.toml
cargo check -p qlink-core --manifest-path Cargo.toml
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add rust/qlink-core/Cargo.toml Cargo.lock rust/qlink-core/src/dytallix_identity.rs rust/qlink-core/src/bin/qlinkctl.rs
git commit -m "feat: add real Dytallix identity registry client"
```

## Task 4: Enforce Registry Policy Before Dialing

**Files:**
- Modify: `rust/qlink-core/src/mesh_connection.rs`
- Modify: `rust/qlink-core/src/mesh_transport.rs`
- Test: existing Rust mesh connection tests

- [ ] **Step 1: Write failing policy enforcement tests**

Add tests proving public policy fails before any probing when the registry record is missing or mismatched. Use real `RegistryNodeRecord` values and a real signed `PeerRecord`; do not create a fake registry implementation.

```rust
#[tokio::test]
async fn public_mesh_rejects_unregistered_peer_before_probing() {
    let keypair = DeviceKeypair::generate().unwrap();
    let peer_id = keypair.public_key().peer_id();
    let config = MeshConnectorConfig::new("public-mesh", "qlink_local")
        .with_dytallix_policy(MeshTrustPolicy::PublicRequired);

    let decision = config.evaluate_registry_for_record(&peer_id, None);

    assert!(decision.unwrap_err().to_string().contains("missing Dytallix registry"));
}
```

- [ ] **Step 2: Run test to verify RED**

Run:

```bash
cargo test -p qlink-core public_mesh_rejects_unregistered_peer_before_probing --manifest-path Cargo.toml
```

Expected: FAIL because config policy helpers do not exist.

- [ ] **Step 3: Add policy fields and enforcement**

Add to `MeshConnectorConfig`:

```rust
pub dytallix_policy: MeshTrustPolicy,
pub dytallix_registry: Option<Arc<DytallixIdentityRegistry>>,
```

Add builder methods:

```rust
pub fn with_dytallix_policy(mut self, policy: MeshTrustPolicy) -> Self {
    self.dytallix_policy = policy;
    self
}

pub fn with_dytallix_registry(mut self, registry: Arc<DytallixIdentityRegistry>) -> Self {
    self.dytallix_registry = Some(registry);
    self
}
```

In `MeshConnector::connect`, after `record.verify(&self.config.mesh_id)?;`, insert:

```rust
let registry_record = match self.config.dytallix_registry.as_ref() {
    Some(registry) => registry.lookup(&record.body.peer_id).await?,
    None => None,
};
verify_registry_binding(
    &record,
    registry_record.as_ref(),
    self.config.dytallix_policy,
)?;
```

- [ ] **Step 4: Wire `MeshTransportConfig` JSON**

Add JSON fields to `MeshTransportConfig`:

```rust
#[serde(default)]
pub dytallix_policy: Option<MeshTrustPolicy>,
#[serde(default)]
pub dytallix_registry: Option<DytallixRegistryConfig>,
```

When building `MeshConnectorConfig`, pass `dytallix_policy.unwrap_or(MeshTrustPolicy::DevelopmentOptional)` and instantiate `DytallixIdentityRegistry` when config is present.

- [ ] **Step 5: Run tests to verify GREEN**

Run:

```bash
cargo test -p qlink-core mesh_connection dytallix_identity --manifest-path Cargo.toml
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add rust/qlink-core/src/mesh_connection.rs rust/qlink-core/src/mesh_transport.rs
git commit -m "feat: enforce Dytallix registry before mesh dialing"
```

## Task 5: Swift Configuration And Transport Encoding

**Files:**
- Modify: `Sources/QuantumLinkKit/Models.swift`
- Modify: `Sources/QuantumLinkKit/TunnelTransport.swift`
- Modify: `Sources/QuantumLinkKit/ConfigurationValidation.swift`
- Test: `Tests/QuantumLinkKitTests/ConnectionProfileTests.swift`
- Test: `Tests/QuantumLinkKitTests/ConfigurationValidationTests.swift`
- Test: `Tests/QuantumLinkKitTests/RustMeshTransportTests.swift`

- [ ] **Step 1: Write failing Swift tests**

Add tests:

```swift
func testPublicMeshCannotUseOffDiscoveryIdentityMode() throws {
    let config = TunnelConfiguration.defaultDevelopment.with(
        meshTrustPolicy: .publicRequired,
        discoveryIdentityMode: .off
    )

    let report = try ConfigurationValidation.validate(configuration: config)

    XCTAssertTrue(report.warnings.contains { $0.contains("public meshes require Dytallix identity") })
}

func testMeshTransportConfigurationEncodesDytallixRegistry() throws {
    let config = MeshTransportConfiguration(
        meshID: "public-mesh",
        localPeerID: "qlink_local",
        remotePeerID: "qlink_remote",
        rendezvousURL: "127.0.0.1:9471",
        dytallixPolicy: .publicRequired,
        dytallixRegistry: DytallixIdentityConfiguration(
            endpoint: "https://dytallix.com",
            contractAddress: "0x1111111111111111111111111111111111111111",
            walletName: "default",
            publishWalletAddress: false
        )
    )

    let json = String(data: try JSONEncoder().encode(config), encoding: .utf8)!

    XCTAssertTrue(json.contains("\"dytallixPolicy\":\"public_required\""))
    XCTAssertTrue(json.contains("\"contractAddress\":\"0x1111111111111111111111111111111111111111\""))
}
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
swift test --filter ConfigurationValidationTests/testPublicMeshCannotUseOffDiscoveryIdentityMode
swift test --filter RustMeshTransportTests/testMeshTransportConfigurationEncodesDytallixRegistry
```

Expected: FAIL because Swift types and config fields are missing.

- [ ] **Step 3: Add Swift models**

Add to `Models.swift`:

```swift
public enum MeshTrustPolicy: String, Codable, CaseIterable, Sendable {
    case publicRequired = "public_required"
    case privatePreferred = "private_preferred"
    case developmentOptional = "development_optional"
}

public enum DiscoveryIdentityMode: String, Codable, CaseIterable, Sendable {
    case off
    case verified
    case publicWallet = "public_wallet"
}

public struct DytallixIdentityConfiguration: Codable, Equatable, Sendable {
    public let endpoint: String
    public let contractAddress: String
    public let walletName: String?
    public let publishWalletAddress: Bool

    public init(endpoint: String, contractAddress: String, walletName: String? = nil, publishWalletAddress: Bool = false) {
        self.endpoint = endpoint
        self.contractAddress = contractAddress
        self.walletName = walletName
        self.publishWalletAddress = publishWalletAddress
    }
}
```

Add fields to `TunnelConfiguration` and `MeshTransportConfiguration` with defaults:

```swift
public let meshTrustPolicy: MeshTrustPolicy
public let discoveryIdentityMode: DiscoveryIdentityMode
public let dytallixIdentity: DytallixIdentityConfiguration?
```

- [ ] **Step 4: Add validation**

In `ConfigurationValidation.validate(configuration:)`, add:

```swift
if configuration.meshTrustPolicy == .publicRequired,
   configuration.discoveryIdentityMode == .off {
    warnings.append("public meshes require Dytallix identity; Off is only valid for private or development meshes")
}
if configuration.meshTrustPolicy == .publicRequired,
   configuration.dytallixIdentity == nil {
    warnings.append("public meshes require a Dytallix registry endpoint and contract address")
}
```

- [ ] **Step 5: Run tests to verify GREEN**

Run:

```bash
swift test --filter ConfigurationValidationTests
swift test --filter RustMeshTransportTests
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add Sources/QuantumLinkKit/Models.swift Sources/QuantumLinkKit/TunnelTransport.swift Sources/QuantumLinkKit/ConfigurationValidation.swift Tests/QuantumLinkKitTests
git commit -m "feat: encode Dytallix identity policy in Swift config"
```

## Task 6: Swift UX For Discovery Identity Mode

**Files:**
- Modify: `Sources/QuantumLinkApp/QuantumLinkApp.swift`
- Test: Swift tests where practical; otherwise verify by building the app.

- [ ] **Step 1: Add failing persistence/configuration test**

Add a test proving public mesh maps to `.verified` by default and cannot persist `.off`.

```swift
func testPublicDeploymentUsesVerifiedDytallixIdentityByDefault() {
    let config = QuantumLinkDeploymentMode.mesh.configuration(from: .defaultDevelopment)

    XCTAssertEqual(config.meshTrustPolicy, .publicRequired)
    XCTAssertEqual(config.discoveryIdentityMode, .verified)
}
```

- [ ] **Step 2: Run test to verify RED**

Run:

```bash
swift test --filter DeploymentModeTests/testPublicDeploymentUsesVerifiedDytallixIdentityByDefault
```

Expected: FAIL until deployment mapping is updated.

- [ ] **Step 3: Add UX controls**

In `ConfigurationPanel`, add a `ConfigurationCard(title: "Discovery Identity", systemImage: "person.badge.shield.checkmark")` with a segmented `Picker` for `Off`, `Verified`, and `Public Wallet`.

The binding must enforce:

```swift
if deploymentMode == .mesh && newMode == .off {
    discoveryIdentityMode = .verified
} else {
    discoveryIdentityMode = newMode
}
```

Show the wallet address only when `discoveryIdentityMode == .publicWallet`. Otherwise show redacted registry status.

- [ ] **Step 4: Run build and tests**

Run:

```bash
swift test --filter DeploymentModeTests
swift build
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Sources/QuantumLinkApp/QuantumLinkApp.swift Sources/QuantumLinkKit/DeploymentMode.swift Tests/QuantumLinkKitTests/DeploymentModeTests.swift
git commit -m "feat: add Dytallix discovery identity UX"
```

## Task 7: End-To-End Real Dytallix Verification

**Files:**
- Create: `scripts/dytallix-identity-e2e.sh`
- Modify: `docs/pre-apple-development.md`

- [ ] **Step 1: Write e2e script**

Create `scripts/dytallix-identity-e2e.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${DYTALLIX_ENDPOINT:?Set DYTALLIX_ENDPOINT, for example https://dytallix.com or a direct node}"
: "${DYTALLIX_REGISTRY_CONTRACT:?Set DYTALLIX_REGISTRY_CONTRACT to the deployed registry address}"

cargo build -p qlink-core --bin qlinkctl
cargo build --manifest-path dytallix/quantumlink-node-registry/Cargo.toml --target wasm32-unknown-unknown --release

./target/debug/qlinkctl publish-self \
  --mesh-id public-mesh \
  --bind-addr 127.0.0.1:0 \
  --out build/public-mesh-peer-record.json

./target/debug/qlinkctl identity register \
  --endpoint "$DYTALLIX_ENDPOINT" \
  --contract "$DYTALLIX_REGISTRY_CONTRACT" \
  --peer-record build/public-mesh-peer-record.json

./target/debug/qlinkctl identity status \
  --endpoint "$DYTALLIX_ENDPOINT" \
  --contract "$DYTALLIX_REGISTRY_CONTRACT" \
  --peer-record build/public-mesh-peer-record.json
```

- [ ] **Step 2: Run real local checks**

Run:

```bash
chmod +x scripts/dytallix-identity-e2e.sh
cargo test --workspace
swift test
```

Expected: PASS.

- [ ] **Step 3: Run real Dytallix integration when credentials are present**

Run:

```bash
DYTALLIX_ENDPOINT=https://dytallix.com \
DYTALLIX_REGISTRY_CONTRACT=0x1111111111111111111111111111111111111111 \
scripts/dytallix-identity-e2e.sh
```

Expected: registration transaction is submitted, status returns an active record, and the peer-record binding verifies.

- [ ] **Step 4: Document operation**

Add to `docs/pre-apple-development.md`:

```markdown
## Dytallix Identity Registry

Public meshes require a deployed `quantumlink-node-registry` contract. Build the contract with:

```sh
cargo build --manifest-path dytallix/quantumlink-node-registry/Cargo.toml --target wasm32-unknown-unknown --release
```

Deploy with the Dytallix CLI, then set `DYTALLIX_REGISTRY_CONTRACT` to the returned address. Use `qlinkctl identity register` to bind a signed QuantumLink peer record to the active Dytallix wallet.
```

- [ ] **Step 5: Commit**

```bash
git add scripts/dytallix-identity-e2e.sh docs/pre-apple-development.md
git commit -m "docs: add real Dytallix identity registry runbook"
```

## Final Verification

- [ ] Run Rust tests:

```bash
cargo test --workspace
```

Expected: PASS.

- [ ] Run Swift tests:

```bash
swift test
```

Expected: PASS.

- [ ] Build the Dytallix registry contract:

```bash
cargo build --manifest-path dytallix/quantumlink-node-registry/Cargo.toml --target wasm32-unknown-unknown --release
```

Expected: PASS and `.wasm` artifact exists.

- [ ] Run the real Dytallix e2e script with a deployed registry contract:

```bash
DYTALLIX_ENDPOINT=https://dytallix.com \
DYTALLIX_REGISTRY_CONTRACT=0x1111111111111111111111111111111111111111 \
scripts/dytallix-identity-e2e.sh
```

Expected: PASS. Public mesh identity is registered, queried, and verified through the real Dytallix contract path.
