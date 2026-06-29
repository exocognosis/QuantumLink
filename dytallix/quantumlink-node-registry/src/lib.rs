use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    Active,
    Revoked,
    Suspended,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub peer_id: String,
    pub owner_daddr: String,
    pub device_public_key_hash: [u8; 32],
    pub latest_peer_record_hash: [u8; 32],
    pub status: NodeStatus,
    pub updated_at: u64,
    pub expires_at: Option<u64>,
    pub reputation_score: Option<u64>,
    pub stake_status: Option<String>,
    pub metadata_commitment: Option<[u8; 32]>,
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
    #[error("invalid peer id")]
    InvalidPeerId,
    #[error("invalid owner address")]
    InvalidOwner,
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
        mut record: NodeRecord,
        _device_signature: Vec<u8>,
    ) -> Result<(), RegistryError> {
        validate_actor(actor_daddr)?;
        validate_record(&record)?;
        record.owner_daddr = actor_daddr.to_string();
        self.events.push(RegistryEvent {
            peer_id: record.peer_id.clone(),
            event_type: "registered".to_string(),
            actor_daddr: actor_daddr.to_string(),
            block_time: record.updated_at,
        });
        self.nodes.insert(record.peer_id.clone(), record);
        Ok(())
    }

    pub fn update_node(
        &mut self,
        actor_daddr: &str,
        mut record: NodeRecord,
        _device_signature: Vec<u8>,
    ) -> Result<(), RegistryError> {
        validate_actor(actor_daddr)?;
        validate_record(&record)?;
        let existing = self
            .nodes
            .get(&record.peer_id)
            .ok_or(RegistryError::NotFound)?;
        if existing.owner_daddr != actor_daddr {
            return Err(RegistryError::Unauthorized);
        }
        record.owner_daddr = actor_daddr.to_string();
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
        validate_actor(actor_daddr)?;
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

    pub fn matches_hashes(
        &self,
        peer_id: &str,
        device_public_key_hash: &[u8; 32],
        latest_peer_record_hash: &[u8; 32],
    ) -> bool {
        self.nodes.get(peer_id).is_some_and(|record| {
            &record.device_public_key_hash == device_public_key_hash
                && &record.latest_peer_record_hash == latest_peer_record_hash
        })
    }
}

fn validate_record(record: &NodeRecord) -> Result<(), RegistryError> {
    if record.peer_id.trim().is_empty() || !record.peer_id.starts_with("qlink_") {
        return Err(RegistryError::InvalidPeerId);
    }
    validate_actor(&record.owner_daddr)
}

fn validate_actor(actor_daddr: &str) -> Result<(), RegistryError> {
    if actor_daddr.starts_with("dytallix1") {
        Ok(())
    } else {
        Err(RegistryError::InvalidOwner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active_record() -> NodeRecord {
        NodeRecord {
            peer_id: "qlink_peer".to_string(),
            owner_daddr: "dytallix1operator".to_string(),
            device_public_key_hash: [0x11; 32],
            latest_peer_record_hash: [0x22; 32],
            status: NodeStatus::Active,
            updated_at: 100,
            expires_at: Some(1_000),
            reputation_score: Some(0),
            stake_status: None,
            metadata_commitment: None,
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
        updated.latest_peer_record_hash = [0x33; 32];
        updated.updated_at = 200;
        registry
            .update_node("dytallix1operator", updated.clone(), vec![1, 2, 3])
            .expect("owner should update");
        assert_eq!(registry.get_node("qlink_peer").unwrap(), updated);

        registry
            .revoke_node("dytallix1operator", "qlink_peer", 300)
            .expect("owner should revoke");
        assert_eq!(
            registry.get_node("qlink_peer").unwrap().status,
            NodeStatus::Revoked
        );
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

    #[test]
    fn hash_mismatch_lookup_is_detectable_by_contract_query_helpers() {
        let mut registry = QuantumLinkNodeRegistry::new();
        registry
            .register_node("dytallix1operator", active_record(), vec![1])
            .unwrap();

        assert!(registry.matches_hashes("qlink_peer", &[0x11; 32], &[0x22; 32]));
        assert!(!registry.matches_hashes("qlink_peer", &[0x99; 32], &[0x22; 32]));
        assert!(!registry.matches_hashes("qlink_peer", &[0x11; 32], &[0x99; 32]));
    }
}
