use crate::error::{QlinkError, Result};
use hkdf::Hkdf;
use ml_dsa::{
    signature::{Keypair as MlDsaKeypair, Signer as MlDsaSigner, Verifier as MlDsaVerifier},
    EncodedSignature, EncodedVerifyingKey, KeyGen, MlDsa65, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey,
};
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
    ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey},
    MlKem768,
};
use rand_core_06::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use slh_dsa::{
    signature::rand_core::{Infallible as SlhInfallible, TryCryptoRng as SlhTryCryptoRng},
    Sha2_128s, Signature as SlhSignature, SigningKey as SlhSigningKey,
    VerifyingKey as SlhVerifyingKey,
};
use x25519_dalek::{PublicKey, StaticSecret};

pub const SUITE_V1: &str = "QLINK-HYBRID-X25519-MLKEM768-HKDFSHA256-v1";
pub const SUITE_FIPS203: &str = "QLINK-FIPS203-MLKEM768-HKDFSHA256-v1";
pub const SUITE_FIPS204: &str = "QLINK-FIPS204-MLDSA65-HKDFSHA256-v1";
pub const SUITE_FIPS205: &str = "QLINK-FIPS205-SLHDSA-SHA2-128S-HKDFSHA256-v1";
pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QlinkCryptoSuite {
    LegacyHybrid,
    Fips203MlKem,
    Fips204MlDsa,
    Fips205SlhDsa,
}

impl QlinkCryptoSuite {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LegacyHybrid => SUITE_V1,
            Self::Fips203MlKem => SUITE_FIPS203,
            Self::Fips204MlDsa => SUITE_FIPS204,
            Self::Fips205SlhDsa => SUITE_FIPS205,
        }
    }

    fn device_signature_algorithm(self) -> DeviceSignatureAlgorithm {
        match self {
            Self::Fips205SlhDsa => DeviceSignatureAlgorithm::SlhDsaSha2_128s,
            Self::LegacyHybrid | Self::Fips203MlKem | Self::Fips204MlDsa => {
                DeviceSignatureAlgorithm::MlDsa65
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitiatorHello {
    pub version: u8,
    pub suite: String,
    pub initiator_x25519_pub: [u8; 32],
    pub initiator_nonce: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponderHello {
    pub version: u8,
    pub suite: String,
    pub responder_x25519_pub: [u8; 32],
    pub responder_mlkem768_ek: Vec<u8>,
    pub responder_nonce: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitiatorFinish {
    pub version: u8,
    pub suite: String,
    pub mlkem768_ciphertext: Vec<u8>,
    pub transcript_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    pub suite: String,
    pub handshake_hash: [u8; 32],
    pub tx_key: [u8; 32],
    pub rx_key: [u8; 32],
}

pub struct InitiatorState {
    x25519_secret: StaticSecret,
    hello: InitiatorHello,
}

pub struct ResponderState {
    x25519_secret: StaticSecret,
    mlkem768_secret: DecapsulationKey,
    hello: ResponderHello,
}

impl InitiatorState {
    pub fn hello(&self) -> &InitiatorHello {
        &self.hello
    }

    pub fn finish(self, responder: &ResponderHello) -> Result<(InitiatorFinish, SessionKeys)> {
        validate_suite(responder.version, &responder.suite)?;
        if responder.suite != self.hello.suite {
            return Err(QlinkError::Protocol(format!(
                "responder suite {} does not match initiator suite {}",
                responder.suite, self.hello.suite
            )));
        }

        let responder_x25519_pub = PublicKey::from(responder.responder_x25519_pub);
        let x25519_shared = self.x25519_secret.diffie_hellman(&responder_x25519_pub);

        let ek_bytes = responder
            .responder_mlkem768_ek
            .as_slice()
            .try_into()
            .map_err(|_| {
                QlinkError::InvalidKey("invalid ML-KEM-768 encapsulation key size".into())
            })?;
        let ek = EncapsulationKey::new(&ek_bytes)
            .map_err(|_| QlinkError::InvalidKey("invalid ML-KEM-768 encapsulation key".into()))?;
        let (ciphertext, mlkem_shared) = ek.encapsulate();

        let transcript_hash = hash_transcript(&self.hello, responder)?;
        let (tx_key, rx_key) = derive_directional_keys(
            x25519_shared.as_bytes(),
            mlkem_shared.as_slice(),
            &transcript_hash,
            &responder.suite,
            Direction::Initiator,
        )?;

        let finish = InitiatorFinish {
            version: PROTOCOL_VERSION,
            suite: responder.suite.clone(),
            mlkem768_ciphertext: ciphertext.as_slice().to_vec(),
            transcript_hash,
        };

        Ok((
            finish,
            SessionKeys {
                suite: responder.suite.clone(),
                handshake_hash: transcript_hash,
                tx_key,
                rx_key,
            },
        ))
    }
}

impl ResponderState {
    pub fn hello(&self) -> &ResponderHello {
        &self.hello
    }

    pub fn finish(
        self,
        initiator: &InitiatorHello,
        finish: &InitiatorFinish,
    ) -> Result<SessionKeys> {
        validate_suite(finish.version, &finish.suite)?;
        if initiator.suite != self.hello.suite || finish.suite != self.hello.suite {
            return Err(QlinkError::Protocol(
                "handshake suite changed across transcript".into(),
            ));
        }
        let expected_hash = hash_transcript(initiator, &self.hello)?;
        if finish.transcript_hash != expected_hash {
            return Err(QlinkError::Protocol("transcript hash mismatch".into()));
        }

        let initiator_x25519_pub = PublicKey::from(initiator.initiator_x25519_pub);
        let x25519_shared = self.x25519_secret.diffie_hellman(&initiator_x25519_pub);

        let ciphertext: Ciphertext = finish
            .mlkem768_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| QlinkError::InvalidKey("invalid ML-KEM-768 ciphertext size".into()))?;
        let mlkem_shared = self.mlkem768_secret.decapsulate(&ciphertext);

        let (tx_key, rx_key) = derive_directional_keys(
            x25519_shared.as_bytes(),
            mlkem_shared.as_slice(),
            &expected_hash,
            &self.hello.suite,
            Direction::Responder,
        )?;

        Ok(SessionKeys {
            suite: self.hello.suite,
            handshake_hash: expected_hash,
            tx_key,
            rx_key,
        })
    }
}

pub fn start_handshake() -> InitiatorState {
    start_handshake_for_suite(SUITE_FIPS203).expect("default QuantumLink suite is supported")
}

pub fn start_handshake_for_suite(suite: &str) -> Result<InitiatorState> {
    let suite = suite_from_identifier(suite)?;
    let x25519_secret = StaticSecret::random_from_rng(OsRng);
    let x25519_pub = PublicKey::from(&x25519_secret);
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).expect("OS randomness unavailable");

    Ok(InitiatorState {
        x25519_secret,
        hello: InitiatorHello {
            version: PROTOCOL_VERSION,
            suite: suite.as_str().to_string(),
            initiator_x25519_pub: x25519_pub.to_bytes(),
            initiator_nonce: nonce,
        },
    })
}

pub fn answer_handshake(initiator: &InitiatorHello) -> Result<ResponderState> {
    validate_suite(initiator.version, &initiator.suite)?;

    let x25519_secret = StaticSecret::random_from_rng(OsRng);
    let x25519_pub = PublicKey::from(&x25519_secret);
    let (mlkem768_secret, mlkem768_public) = MlKem768::generate_keypair();
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|err| QlinkError::Crypto(err.to_string()))?;

    Ok(ResponderState {
        x25519_secret,
        mlkem768_secret,
        hello: ResponderHello {
            version: PROTOCOL_VERSION,
            suite: initiator.suite.clone(),
            responder_x25519_pub: x25519_pub.to_bytes(),
            responder_mlkem768_ek: mlkem768_public.to_bytes().as_slice().to_vec(),
            responder_nonce: nonce,
        },
    })
}

pub struct DeviceKeypair {
    signing_key: DeviceSigningKey,
    /// Seed used to derive the ML-DSA signing key. Stored so the
    /// keypair can be persisted as a 32-byte secret (Keychain on
    /// macOS, key file for `qlinkctl`) and reloaded across process
    /// restarts. `None` for SLH-DSA keypairs, which use a generation
    /// path that doesn't expose a stable seed; SLH-DSA persistence is
    /// out of scope for v1 since the production default is ML-DSA-65.
    seed: Option<[u8; 32]>,
}

// Debug elides the private key material so accidental log lines never
// dump the secret. The algorithm tag is safe to expose.
impl std::fmt::Debug for DeviceKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let algorithm = match self.signing_key {
            DeviceSigningKey::MlDsa(_) => "ml-dsa-65",
            DeviceSigningKey::SlhDsa(_) => "slh-dsa-128s",
        };
        f.debug_struct("DeviceKeypair")
            .field("algorithm", &algorithm)
            .field("signing_key", &"<elided>")
            .finish()
    }
}

enum DeviceSigningKey {
    MlDsa(ml_dsa::SigningKey<MlDsa65>),
    SlhDsa(SlhSigningKey<Sha2_128s>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceSignatureAlgorithm {
    MlDsa65,
    SlhDsaSha2_128s,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevicePublicKey {
    pub algorithm: String,
    pub bytes: Vec<u8>,
}

impl DeviceKeypair {
    pub fn generate() -> Result<Self> {
        Self::generate_for_suite(SUITE_FIPS204)
    }

    pub fn generate_for_suite(suite: &str) -> Result<Self> {
        let suite = suite_from_identifier(suite)?;
        match suite.device_signature_algorithm() {
            DeviceSignatureAlgorithm::MlDsa65 => Self::generate_ml_dsa(),
            DeviceSignatureAlgorithm::SlhDsaSha2_128s => {
                let mut rng = SlhOsRng;
                Ok(Self {
                    signing_key: DeviceSigningKey::SlhDsa(SlhSigningKey::<Sha2_128s>::new(
                        &mut rng,
                    )),
                    // SLH-DSA's KeyGen API doesn't surface a stable
                    // seed we can persist; v1 doesn't ship SLH-DSA
                    // device keys to disk.
                    seed: None,
                })
            }
        }
    }

    fn generate_ml_dsa() -> Result<Self> {
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed).map_err(|err| QlinkError::Crypto(err.to_string()))?;
        Self::from_seed(seed)
    }

    pub fn from_seed(seed: [u8; 32]) -> Result<Self> {
        let parsed = ml_dsa::B32::try_from(seed.as_slice())
            .map_err(|_| QlinkError::InvalidKey("invalid ML-DSA seed".into()))?;
        Ok(Self {
            signing_key: DeviceSigningKey::MlDsa(MlDsa65::from_seed(&parsed)),
            seed: Some(seed),
        })
    }

    /// Returns the ML-DSA seed bytes that can be passed back to
    /// `from_seed` to reconstruct this keypair. `None` when the
    /// keypair was generated via a non-seedable algorithm (SLH-DSA),
    /// in which case persistence requires re-generating a fresh
    /// keypair on next launch.
    ///
    /// This is the canonical persistent form: 32 bytes is small
    /// enough for Keychain storage and the inverse is exact.
    pub fn seed(&self) -> Option<[u8; 32]> {
        self.seed
    }

    pub fn public_key(&self) -> DevicePublicKey {
        match &self.signing_key {
            DeviceSigningKey::MlDsa(signing_key) => DevicePublicKey {
                algorithm: "ML-DSA-65".to_string(),
                bytes: signing_key.verifying_key().encode().as_slice().to_vec(),
            },
            DeviceSigningKey::SlhDsa(signing_key) => DevicePublicKey {
                algorithm: "SLH-DSA-SHA2-128S".to_string(),
                bytes: signing_key.as_ref().to_bytes().as_slice().to_vec(),
            },
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match &self.signing_key {
            DeviceSigningKey::MlDsa(signing_key) => {
                let signature: MlDsaSignature<MlDsa65> = signing_key.sign(message);
                signature.encode().as_slice().to_vec()
            }
            DeviceSigningKey::SlhDsa(signing_key) => {
                let signature: SlhSignature<Sha2_128s> = signing_key
                    .try_sign_with_context(message, &[], None)
                    .expect("SLH-DSA signing failed");
                signature.to_bytes().as_slice().to_vec()
            }
        }
    }
}

impl DevicePublicKey {
    pub fn peer_id(&self) -> String {
        let digest = Sha256::digest(&self.bytes);
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        format!("qlink_{}", URL_SAFE_NO_PAD.encode(&digest[..16]))
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        match self.algorithm.as_str() {
            "ML-DSA-65" => {
                let vk_bytes = EncodedVerifyingKey::<MlDsa65>::try_from(self.bytes.as_slice())
                    .map_err(|_| {
                        QlinkError::InvalidKey("invalid ML-DSA-65 public key size".into())
                    })?;
                let verifying_key = MlDsaVerifyingKey::<MlDsa65>::decode(&vk_bytes);

                let sig_bytes = EncodedSignature::<MlDsa65>::try_from(signature).map_err(|_| {
                    QlinkError::InvalidKey("invalid ML-DSA-65 signature size".into())
                })?;
                let signature = MlDsaSignature::<MlDsa65>::decode(&sig_bytes)
                    .ok_or(QlinkError::SignatureVerification)?;

                verifying_key
                    .verify(message, &signature)
                    .map_err(|_| QlinkError::SignatureVerification)
            }
            "SLH-DSA-SHA2-128S" => {
                let verifying_key = SlhVerifyingKey::<Sha2_128s>::try_from(self.bytes.as_slice())
                    .map_err(|_| {
                    QlinkError::InvalidKey("invalid SLH-DSA-SHA2-128S public key size".into())
                })?;
                let signature = SlhSignature::<Sha2_128s>::try_from(signature).map_err(|_| {
                    QlinkError::InvalidKey("invalid SLH-DSA-SHA2-128S signature size".into())
                })?;

                verifying_key
                    .try_verify_with_context(message, &[], &signature)
                    .map_err(|_| QlinkError::SignatureVerification)
            }
            algorithm => Err(QlinkError::InvalidKey(format!(
                "unsupported device key algorithm {algorithm}"
            ))),
        }
    }
}

struct SlhOsRng;

impl slh_dsa::signature::rand_core::TryRng for SlhOsRng {
    type Error = SlhInfallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        getrandom::fill(&mut bytes).expect("OS randomness unavailable");
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes).expect("OS randomness unavailable");
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
        getrandom::fill(dst).expect("OS randomness unavailable");
        Ok(())
    }
}

impl SlhTryCryptoRng for SlhOsRng {}

pub fn validate_suite_name(suite: &str) -> Result<()> {
    suite_from_identifier(suite).map(|_| ())
}

pub fn suite_from_identifier(suite: &str) -> Result<QlinkCryptoSuite> {
    match suite {
        SUITE_V1 => Ok(QlinkCryptoSuite::LegacyHybrid),
        SUITE_FIPS203 => Ok(QlinkCryptoSuite::Fips203MlKem),
        SUITE_FIPS204 => Ok(QlinkCryptoSuite::Fips204MlDsa),
        SUITE_FIPS205 => Ok(QlinkCryptoSuite::Fips205SlhDsa),
        _ => Err(QlinkError::Protocol(format!("unsupported suite {suite}"))),
    }
}

fn validate_suite(version: u8, suite: &str) -> Result<QlinkCryptoSuite> {
    if version != PROTOCOL_VERSION {
        return Err(QlinkError::Protocol(format!(
            "unsupported protocol version {version}"
        )));
    }
    suite_from_identifier(suite)
}

fn hash_transcript(initiator: &InitiatorHello, responder: &ResponderHello) -> Result<[u8; 32]> {
    let initiator = serde_json::to_vec(initiator)?;
    let responder = serde_json::to_vec(responder)?;
    let mut hasher = Sha256::new();
    hasher.update(b"QuantumLink transcript v1");
    hasher.update((initiator.len() as u64).to_be_bytes());
    hasher.update(initiator);
    hasher.update((responder.len() as u64).to_be_bytes());
    hasher.update(responder);
    Ok(hasher.finalize().into())
}

enum Direction {
    Initiator,
    Responder,
}

fn derive_directional_keys(
    x25519_shared: &[u8],
    mlkem_shared: &[u8],
    transcript_hash: &[u8; 32],
    suite: &str,
    direction: Direction,
) -> Result<([u8; 32], [u8; 32])> {
    let mut ikm =
        Vec::with_capacity(x25519_shared.len() + mlkem_shared.len() + transcript_hash.len());
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(mlkem_shared);
    ikm.extend_from_slice(transcript_hash);

    let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), &ikm);
    let mut okm = [0_u8; 64];
    let mut info = Vec::with_capacity(b"QuantumLink hybrid session keys v1".len() + suite.len());
    info.extend_from_slice(b"QuantumLink hybrid session keys v1");
    info.extend_from_slice(suite.as_bytes());
    hkdf.expand(&info, &mut okm)
        .map_err(|_| QlinkError::Crypto("HKDF expand failed".into()))?;

    let mut i2r = [0_u8; 32];
    let mut r2i = [0_u8; 32];
    i2r.copy_from_slice(&okm[..32]);
    r2i.copy_from_slice(&okm[32..]);

    Ok(match direction {
        Direction::Initiator => (i2r, r2i),
        Direction::Responder => (r2i, i2r),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_handshake_round_trip() {
        let initiator = start_handshake();
        let responder = answer_handshake(initiator.hello()).unwrap();
        let responder_hello = responder.hello().clone();

        let (finish, _initiator_keys) = initiator.finish(&responder_hello).unwrap();
        let responder_keys = responder
            .finish(
                &InitiatorHello {
                    version: PROTOCOL_VERSION,
                    suite: SUITE_V1.to_string(),
                    initiator_x25519_pub: PublicKey::from([0_u8; 32]).to_bytes(),
                    initiator_nonce: [0_u8; 32],
                },
                &finish,
            )
            .unwrap_err();

        assert!(matches!(responder_keys, QlinkError::Protocol(_)));
    }

    #[test]
    fn hybrid_handshake_establishes_matching_directional_keys() {
        let initiator = start_handshake();
        let initiator_hello = initiator.hello().clone();
        let responder = answer_handshake(&initiator_hello).unwrap();
        let responder_hello = responder.hello().clone();

        let (finish, initiator_keys) = initiator.finish(&responder_hello).unwrap();
        let responder_keys = responder.finish(&initiator_hello, &finish).unwrap();

        assert_eq!(initiator_keys.tx_key, responder_keys.rx_key);
        assert_eq!(initiator_keys.rx_key, responder_keys.tx_key);
        assert_eq!(initiator_keys.handshake_hash, responder_keys.handshake_hash);
    }

    #[test]
    fn handshake_uses_requested_fips_suite() {
        for suite in [SUITE_FIPS203, SUITE_FIPS204, SUITE_FIPS205] {
            let initiator = start_handshake_for_suite(suite).unwrap();
            let initiator_hello = initiator.hello().clone();
            assert_eq!(initiator_hello.suite, suite);

            let responder = answer_handshake(&initiator_hello).unwrap();
            let responder_hello = responder.hello().clone();
            assert_eq!(responder_hello.suite, suite);

            let (finish, initiator_keys) = initiator.finish(&responder_hello).unwrap();
            let responder_keys = responder.finish(&initiator_hello, &finish).unwrap();

            assert_eq!(finish.suite, suite);
            assert_eq!(initiator_keys.suite, suite);
            assert_eq!(responder_keys.suite, suite);
            assert_eq!(initiator_keys.tx_key, responder_keys.rx_key);
            assert_eq!(initiator_keys.rx_key, responder_keys.tx_key);
        }
    }

    #[test]
    fn device_credentials_use_selected_signature_algorithm() {
        for (suite, algorithm) in [
            (SUITE_FIPS203, "ML-DSA-65"),
            (SUITE_FIPS204, "ML-DSA-65"),
            (SUITE_FIPS205, "SLH-DSA-SHA2-128S"),
        ] {
            let keypair = DeviceKeypair::generate_for_suite(suite).unwrap();
            let public = keypair.public_key();
            let message = b"quantumlink peer record";
            let signature = keypair.sign(message);

            assert_eq!(public.algorithm, algorithm);
            public.verify(message, &signature).unwrap();
            assert!(public.verify(b"tampered", &signature).is_err());
            assert!(public.peer_id().starts_with("qlink_"));
        }
    }

    #[test]
    fn device_credentials_sign_and_verify() {
        let keypair = DeviceKeypair::generate().unwrap();
        let public = keypair.public_key();
        let message = b"quantumlink peer record";
        let signature = keypair.sign(message);

        public.verify(message, &signature).unwrap();
        assert!(public.verify(b"tampered", &signature).is_err());
        assert!(public.peer_id().starts_with("qlink_"));
    }

    #[test]
    fn ml_dsa_keypair_round_trips_through_seed_for_persistence() {
        let original = DeviceKeypair::generate().unwrap();
        let seed = original
            .seed()
            .expect("ML-DSA keypair must expose a seed for persistence");
        let restored = DeviceKeypair::from_seed(seed).unwrap();

        // Restored keypair must produce the same peer_id (derived
        // deterministically from the public key) and verify the same
        // signatures — that's the persistence contract.
        assert_eq!(original.public_key().bytes, restored.public_key().bytes);
        assert_eq!(
            original.public_key().peer_id(),
            restored.public_key().peer_id()
        );

        // Cross-verify: a signature from the restored key validates
        // against the original public key.
        let message = b"persistence-round-trip";
        let signature = restored.sign(message);
        original.public_key().verify(message, &signature).unwrap();
    }

    #[test]
    fn slh_dsa_keypair_does_not_expose_a_seed() {
        // SLH-DSA's KeyGen API doesn't surface a stable seed, so
        // `seed()` returns None — callers persist these by
        // re-generating, not by serializing.
        let keypair = DeviceKeypair::generate_for_suite(SUITE_FIPS205).unwrap();
        assert!(keypair.seed().is_none());
    }
}
