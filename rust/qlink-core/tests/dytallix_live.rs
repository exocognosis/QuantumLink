//! Live integration checks against the deployed QuantumLink node-registry
//! contract on the Dytallix public testnet.
//!
//! Ignored by default because they require network access to the live testnet
//! gateway. Run explicitly with:
//!
//! ```text
//! cargo test -p qlink-core --test dytallix_live -- --ignored --nocapture
//! ```
//!
//! The deployed registry contract address and gateway can be overridden with
//! the `QLINK_DYTALLIX_ENDPOINT` and `QLINK_DYTALLIX_CONTRACT` env vars; the
//! defaults point at the contract deployed on 2026-07-12.

use qlink_core::dytallix_identity::{DytallixIdentityRegistry, DytallixRegistryLookupConfig};

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

/// A live, deployed, queryable contract answers a `get_node` for an unknown
/// peer with a well-formed "no such node" (`Ok(None)`) rather than a transport
/// or JSON error. This proves the ported registry code talks to the real
/// on-chain contract through the exact query path used in production.
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
