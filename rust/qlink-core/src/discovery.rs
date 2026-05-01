use crate::{
    crypto::{DeviceKeypair, DevicePublicKey},
    error::{QlinkError, Result},
    ice::IceCredentials,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateEndpoint {
    pub candidate_type: CandidateType,
    pub address: String,
    pub port: u16,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateType {
    Host,
    ServerReflexive,
    Relay,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedPeerRecord {
    pub mesh_id: String,
    pub peer_id: String,
    pub alias: String,
    pub device_public_key: DevicePublicKey,
    pub endpoints: Vec<CandidateEndpoint>,
    pub routes: Vec<String>,
    pub expires_at_unix: u64,
    pub sequence: u64,
    /// Short-term ICE credentials (RFC 8445 §5.3) used to authenticate
    /// connectivity checks against this peer. Rotated each time the record
    /// is republished. The signed envelope binds these credentials to the
    /// peer's ML-DSA device key, so a passive observer cannot impersonate
    /// the peer without also publishing a forged record.
    pub ice_credentials: IceCredentials,
    /// DER-encoded X.509 certificate that this peer presents on its QUIC
    /// server endpoint. Connectors trust this cert for the duration of the
    /// record (TTL-bounded) and use it to build a per-connection rustls
    /// `ClientConfig`. The cert is covered by the record's ML-DSA
    /// signature: an attacker who tampers with the cert invalidates the
    /// signature, and an attacker who lacks the device private key cannot
    /// mint a valid replacement record.
    ///
    /// Empty bytes mean "this peer has not published a cert yet" — the
    /// connector treats that as a record that cannot be QUIC-connected to
    /// and falls back to relay if available.
    #[serde(default)]
    pub device_certificate_der: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRecord {
    pub body: UnsignedPeerRecord,
    pub signature: Vec<u8>,
}

impl UnsignedPeerRecord {
    pub fn new(
        mesh_id: impl Into<String>,
        alias: impl Into<String>,
        device_public_key: DevicePublicKey,
        endpoints: Vec<CandidateEndpoint>,
        routes: Vec<String>,
        ttl_seconds: u64,
        sequence: u64,
    ) -> Self {
        let credentials = IceCredentials::generate()
            .expect("ICE credential generation requires a working entropy source");
        Self::new_with_ice_credentials(
            mesh_id,
            alias,
            device_public_key,
            endpoints,
            routes,
            ttl_seconds,
            sequence,
            credentials,
        )
    }

    /// Variant that takes a caller-supplied `IceCredentials`. Useful for
    /// deterministic tests; production code should use `new()` to get freshly
    /// generated short-term credentials.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_ice_credentials(
        mesh_id: impl Into<String>,
        _alias: impl Into<String>,
        device_public_key: DevicePublicKey,
        endpoints: Vec<CandidateEndpoint>,
        routes: Vec<String>,
        ttl_seconds: u64,
        sequence: u64,
        ice_credentials: IceCredentials,
    ) -> Self {
        let peer_id = device_public_key.peer_id();
        let alias = privacy_preserving_alias(&peer_id, sequence);
        Self {
            mesh_id: mesh_id.into(),
            peer_id,
            alias,
            device_public_key,
            endpoints,
            routes,
            expires_at_unix: now_unix() + ttl_seconds,
            sequence,
            ice_credentials,
            device_certificate_der: Vec::new(),
        }
    }

    /// Replaces the published QUIC server certificate. Call this after
    /// generating the QUIC server endpoint and before signing the record.
    pub fn with_device_certificate(mut self, certificate_der: Vec<u8>) -> Self {
        self.device_certificate_der = certificate_der;
        self
    }

    /// Strict-privacy variant: drops host and server-reflexive candidates so the
    /// signed record exposes only relay reachability. Use when peer locations
    /// must not leak through rendezvous; direct connectivity then requires a
    /// separate authenticated channel for candidate exchange.
    pub fn new_relay_only(
        mesh_id: impl Into<String>,
        alias: impl Into<String>,
        device_public_key: DevicePublicKey,
        endpoints: Vec<CandidateEndpoint>,
        routes: Vec<String>,
        ttl_seconds: u64,
        sequence: u64,
    ) -> Self {
        let endpoints = endpoints
            .into_iter()
            .filter(|endpoint| endpoint.candidate_type == CandidateType::Relay)
            .collect();
        Self::new(
            mesh_id,
            alias,
            device_public_key,
            endpoints,
            routes,
            ttl_seconds,
            sequence,
        )
    }

    pub fn ice_credentials(&self) -> &IceCredentials {
        &self.ice_credentials
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(Into::into)
    }
}

impl PeerRecord {
    pub fn signed(body: UnsignedPeerRecord, keypair: &DeviceKeypair) -> Result<Self> {
        let signature = keypair.sign(&body.canonical_bytes()?);
        Ok(Self { body, signature })
    }

    pub fn verify(&self, expected_mesh_id: &str) -> Result<()> {
        if self.body.mesh_id != expected_mesh_id {
            return Err(QlinkError::Protocol("peer record mesh id mismatch".into()));
        }
        if self.body.expires_at_unix <= now_unix() {
            return Err(QlinkError::RecordExpired);
        }
        if self.body.device_public_key.peer_id() != self.body.peer_id {
            return Err(QlinkError::Protocol(
                "peer id does not match device public key".into(),
            ));
        }
        self.body
            .device_public_key
            .verify(&self.body.canonical_bytes()?, &self.signature)
    }

    pub fn record_hash(&self) -> Result<[u8; 32]> {
        let bytes = serde_json::to_vec(self)?;
        Ok(Sha256::digest(bytes).into())
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn privacy_preserving_alias(peer_id: &str, sequence: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(peer_id.as_bytes());
    hasher.update(sequence.to_be_bytes());
    let digest = hasher.finalize();
    let suffix = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("peer-{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DeviceKeypair;

    #[test]
    fn peer_record_verifies_and_detects_tampering() {
        let keypair = DeviceKeypair::generate().unwrap();
        let body = UnsignedPeerRecord::new(
            "devmesh",
            "mac",
            keypair.public_key(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "192.168.1.10".to_string(),
                port: 4433,
                priority: 100,
            }],
            vec!["100.127.0.10/32".to_string()],
            60,
            1,
        );
        let mut record = PeerRecord::signed(body, &keypair).unwrap();
        record.verify("devmesh").unwrap();

        record.body.alias = "changed".to_string();
        assert!(record.verify("devmesh").is_err());
    }

    #[test]
    fn peer_record_publishes_all_candidate_types_with_pseudonymous_alias() {
        let keypair = DeviceKeypair::generate().unwrap();
        let body = UnsignedPeerRecord::new(
            "devmesh",
            "ricks-macbook-pro",
            keypair.public_key(),
            vec![
                CandidateEndpoint {
                    candidate_type: CandidateType::Host,
                    address: "192.168.1.10".to_string(),
                    port: 4433,
                    priority: 100,
                },
                CandidateEndpoint {
                    candidate_type: CandidateType::ServerReflexive,
                    address: "203.0.113.20".to_string(),
                    port: 4433,
                    priority: 90,
                },
                CandidateEndpoint {
                    candidate_type: CandidateType::Relay,
                    address: "relay.quantumlink.invalid".to_string(),
                    port: 4433,
                    priority: 10,
                },
            ],
            vec!["100.64.0.10/32".to_string()],
            60,
            7,
        );

        assert_ne!(body.alias, "ricks-macbook-pro");
        assert!(body.alias.starts_with("peer-"));
        let kinds: Vec<_> = body
            .endpoints
            .iter()
            .map(|endpoint| endpoint.candidate_type.clone())
            .collect();
        assert_eq!(
            kinds,
            vec![
                CandidateType::Host,
                CandidateType::ServerReflexive,
                CandidateType::Relay,
            ]
        );
    }

    #[test]
    fn peer_record_carries_device_certificate_under_signature() {
        let keypair = DeviceKeypair::generate().unwrap();
        let dummy_cert = b"dummy-der-bytes-for-test".to_vec();
        let body = UnsignedPeerRecord::new(
            "devmesh",
            "mac",
            keypair.public_key(),
            vec![],
            vec!["100.127.0.10/32".to_string()],
            60,
            1,
        )
        .with_device_certificate(dummy_cert.clone());
        let mut record = PeerRecord::signed(body, &keypair).unwrap();
        record.verify("devmesh").unwrap();
        assert_eq!(record.body.device_certificate_der, dummy_cert);

        // Tampering with the cert must invalidate the ML-DSA signature.
        record.body.device_certificate_der.push(0xff);
        assert!(record.verify("devmesh").is_err());
    }

    #[test]
    fn peer_record_relay_only_constructor_strips_direct_candidates() {
        let keypair = DeviceKeypair::generate().unwrap();
        let body = UnsignedPeerRecord::new_relay_only(
            "devmesh",
            "ricks-macbook-pro",
            keypair.public_key(),
            vec![
                CandidateEndpoint {
                    candidate_type: CandidateType::Host,
                    address: "192.168.1.10".to_string(),
                    port: 4433,
                    priority: 100,
                },
                CandidateEndpoint {
                    candidate_type: CandidateType::Relay,
                    address: "relay.quantumlink.invalid".to_string(),
                    port: 4433,
                    priority: 10,
                },
            ],
            vec!["100.64.0.10/32".to_string()],
            60,
            7,
        );

        assert!(body.alias.starts_with("peer-"));
        assert_eq!(body.endpoints.len(), 1);
        assert_eq!(body.endpoints[0].candidate_type, CandidateType::Relay);
    }

    #[test]
    fn peer_record_alias_rotates_with_sequence() {
        let keypair = DeviceKeypair::generate().unwrap();
        let first = UnsignedPeerRecord::new(
            "devmesh",
            "mac",
            keypair.public_key(),
            vec![],
            vec!["100.64.0.10/32".to_string()],
            60,
            7,
        );
        let second = UnsignedPeerRecord::new(
            "devmesh",
            "mac",
            keypair.public_key(),
            vec![],
            vec!["100.64.0.10/32".to_string()],
            60,
            8,
        );

        assert_ne!(first.alias, second.alias);
    }
}
