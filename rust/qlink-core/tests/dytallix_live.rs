//! Live integration + activation checks for the deployed QuantumLink
//! node-registry contract on the Dytallix public testnet.
//!
//! The `#[ignore]`d tests hit the live testnet gateway; run them with:
//!
//! ```text
//! cargo test -p qlink-core --test dytallix_live -- --ignored --nocapture
//! ```
//!
//! The non-ignored test validates the shipped public-mesh config and runs in
//! normal CI. The deployed registry contract and gateway can be overridden
//! with `QLINK_DYTALLIX_ENDPOINT` / `QLINK_DYTALLIX_CONTRACT`; the defaults
//! point at the contract deployed 2026-07-12.

use qlink_core::crypto::DeviceKeypair;
use qlink_core::discovery::{CandidateEndpoint, CandidateType, PeerRecord, UnsignedPeerRecord};
use qlink_core::dytallix_identity::{
    verify_registry_binding, DytallixIdentityRegistry, DytallixRegistryLookupConfig, MeshTrustPolicy,
};
use qlink_core::mesh_transport::MeshTransportConfig;

const DEFAULT_ENDPOINT: &str = "https://dytallix.com";
const DEFAULT_CONTRACT: &str = "0xbcb5cf5abb50333ee4bfde91f21bbcc24828673d";

fn live_lookup_config() -> DytallixRegistryLookupConfig {
    DytallixRegistryLookupConfig {
        endpoint: std::env::var("QLINK_DYTALLIX_ENDPOINT")
            .unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string()),
        contract_address: std::env::var("QLINK_DYTALLIX_CONTRACT")
            .unwrap_or_else(|_| DEFAULT_CONTRACT.to_string()),
        network_id: None,
        chain_id: None,
        allowed_rpc_endpoints: Vec::new(),
    }
}

/// Builds a fresh, valid, signed peer record for a node that was never
/// registered on-chain.
fn unregistered_peer_record() -> (DeviceKeypair, PeerRecord) {
    let keypair = DeviceKeypair::generate().expect("generate device keypair");
    let public = keypair.public_key();
    let body = UnsignedPeerRecord::new(
        "quantumlink-public",
        "live-enforcement-probe",
        public.clone(),
        vec![CandidateEndpoint {
            candidate_type: CandidateType::Host,
            address: "127.0.0.1".to_string(),
            port: 4433,
            priority: 100,
        }],
        vec!["100.127.0.2/32".to_string()],
        300,
        1,
    );
    let record = PeerRecord::signed(body, &keypair).expect("sign peer record");
    (keypair, record)
}

/// Activation guard (no network): the shipped public-mesh MeshTransportConfig
/// must parse and enable registry enforcement bound to the deployed contract.
/// If this breaks, the operator/bridge template no longer fails closed.
#[test]
fn public_mesh_example_config_enables_registry_enforcement() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../config/mesh-transport.public.example.json");
    let bytes = std::fs::read(&path).expect("read config/mesh-transport.public.example.json");
    let config: MeshTransportConfig =
        serde_json::from_slice(&bytes).expect("parse public mesh MeshTransportConfig");

    assert_eq!(
        config.mesh_trust_policy,
        MeshTrustPolicy::PublicRequired,
        "public mesh example must set public_required"
    );
    let identity = config
        .dytallix_identity
        .as_ref()
        .expect("public mesh example must configure dytallixIdentity");
    assert_eq!(identity.contract_address, DEFAULT_CONTRACT);
    assert_eq!(identity.endpoint, DEFAULT_ENDPOINT);
}

/// A live, deployed, queryable contract answers a `get_node` for an unknown
/// peer with a well-formed "no such node" (`Ok(None)`) rather than a transport
/// or JSON error. Proves the ported registry code talks to the real on-chain
/// contract through the exact query path used in production.
#[tokio::test]
#[ignore = "hits the live Dytallix testnet"]
async fn live_registry_lookup_unknown_peer_returns_none() {
    let registry = DytallixIdentityRegistry::from_lookup_config(live_lookup_config())
        .expect("registry should build from a valid 0x contract address");

    // Valid peer_id shape (`qlink_` prefix) but not registered on-chain, so the
    // contract returns "no such node" rather than an "invalid peer id" reject.
    match registry
        .lookup("qlink_liveprobeNonexistentPeer00000000")
        .await
    {
        Ok(None) => {}
        Ok(Some(record)) => panic!("unexpectedly found a registered node: {record:?}"),
        Err(err) => panic!("live registry lookup failed (contract unreachable?): {err}"),
    }
}

/// End-to-end live enforcement: an unregistered (but cryptographically valid)
/// peer looked up against the DEPLOYED contract must be rejected by a public
/// mesh (fail closed) and accepted by a development mesh. This exercises the
/// full chain config -> live registry -> lookup -> policy decision.
#[tokio::test]
#[ignore = "hits the live Dytallix testnet"]
async fn live_public_mesh_rejects_unregistered_peer() {
    let registry = DytallixIdentityRegistry::from_lookup_config(live_lookup_config())
        .expect("build registry from deployed-contract config");
    let (keypair, record) = unregistered_peer_record();

    let registry_record = registry
        .lookup(&keypair.public_key().peer_id())
        .await
        .expect("live registry lookup");
    assert!(
        registry_record.is_none(),
        "a freshly generated peer must not be registered on-chain"
    );

    // Public mesh: no active registry record -> fail closed.
    assert!(
        verify_registry_binding(&record, registry_record.as_ref(), MeshTrustPolicy::PublicRequired)
            .is_err(),
        "public mesh must reject an unregistered peer (fail closed)"
    );

    // Development mesh: same peer is accepted without a registry record.
    assert!(
        verify_registry_binding(
            &record,
            registry_record.as_ref(),
            MeshTrustPolicy::DevelopmentOptional,
        )
        .is_ok(),
        "development policy accepts without a registry record"
    );
}
