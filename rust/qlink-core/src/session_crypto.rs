use crate::{
    crypto::{DeviceKeypair, DevicePublicKey, SessionKeys},
    error::{QlinkError, Result},
};
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
    ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey},
    MlKem768,
};
use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

pub const PQC_SESSION_VERSION: u8 = 1;
pub const PQC_SESSION_SUITE: &str = "QLINK-FIPS203-MLKEM768-SHAKE256-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqcSessionContext {
    pub mesh_id: String,
    pub initiator_peer_id: String,
    pub responder_peer_id: String,
    pub carrier_binding: Vec<u8>,
}

impl PqcSessionContext {
    pub fn new(
        mesh_id: impl Into<String>,
        initiator_peer_id: impl Into<String>,
        responder_peer_id: impl Into<String>,
        carrier_binding: Vec<u8>,
    ) -> Self {
        Self {
            mesh_id: mesh_id.into(),
            initiator_peer_id: initiator_peer_id.into(),
            responder_peer_id: responder_peer_id.into(),
            carrier_binding,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqcInitiatorHello {
    pub version: u8,
    pub suite: String,
    pub context: PqcSessionContext,
    pub initiator_nonce: [u8; 32],
    pub initiator_public_key: DevicePublicKey,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqcResponderHello {
    pub version: u8,
    pub suite: String,
    pub context: PqcSessionContext,
    pub responder_nonce: [u8; 32],
    pub responder_mlkem768_ek: Vec<u8>,
    pub responder_public_key: DevicePublicKey,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqcInitiatorFinish {
    pub version: u8,
    pub suite: String,
    pub mlkem768_ciphertext: Vec<u8>,
    pub transcript_hash: [u8; 32],
    pub signature: Vec<u8>,
}

pub struct PqcInitiatorState {
    hello: PqcInitiatorHello,
}

pub struct PqcResponderState {
    hello: PqcResponderHello,
    initiator_hello: PqcInitiatorHello,
    mlkem768_secret: DecapsulationKey,
}

pub fn start_pqc_session(
    context: PqcSessionContext,
    keypair: &DeviceKeypair,
) -> Result<PqcInitiatorState> {
    let initiator_public_key = keypair.public_key();
    validate_ml_dsa_public_key(&initiator_public_key)?;
    ensure_peer_id(
        &initiator_public_key,
        &context.initiator_peer_id,
        "initiator",
    )?;

    let initiator_nonce = random_nonce()?;
    let signature = keypair.sign(&initiator_hello_signing_bytes(
        PQC_SESSION_VERSION,
        PQC_SESSION_SUITE,
        &context,
        &initiator_nonce,
        &initiator_public_key,
    )?);

    Ok(PqcInitiatorState {
        hello: PqcInitiatorHello {
            version: PQC_SESSION_VERSION,
            suite: PQC_SESSION_SUITE.to_string(),
            context,
            initiator_nonce,
            initiator_public_key,
            signature,
        },
    })
}

pub fn answer_pqc_session(
    hello: &PqcInitiatorHello,
    context: PqcSessionContext,
    keypair: &DeviceKeypair,
) -> Result<PqcResponderState> {
    validate_session_suite(hello.version, &hello.suite)?;
    if hello.context != context {
        return Err(QlinkError::Protocol(
            "initiator hello context does not match responder context".into(),
        ));
    }
    validate_ml_dsa_public_key(&hello.initiator_public_key)?;
    ensure_peer_id(
        &hello.initiator_public_key,
        &context.initiator_peer_id,
        "initiator",
    )?;
    hello.initiator_public_key.verify(
        &initiator_hello_signing_bytes(
            hello.version,
            &hello.suite,
            &hello.context,
            &hello.initiator_nonce,
            &hello.initiator_public_key,
        )?,
        &hello.signature,
    )?;

    let responder_public_key = keypair.public_key();
    validate_ml_dsa_public_key(&responder_public_key)?;
    ensure_peer_id(
        &responder_public_key,
        &context.responder_peer_id,
        "responder",
    )?;

    let (mlkem768_secret, mlkem768_public) = MlKem768::generate_keypair();
    let responder_nonce = random_nonce()?;
    let responder_mlkem768_ek = mlkem768_public.to_bytes().as_slice().to_vec();
    let signature = keypair.sign(&responder_hello_signing_bytes(
        hello,
        PQC_SESSION_VERSION,
        PQC_SESSION_SUITE,
        &context,
        &responder_nonce,
        &responder_mlkem768_ek,
        &responder_public_key,
    )?);

    Ok(PqcResponderState {
        hello: PqcResponderHello {
            version: PQC_SESSION_VERSION,
            suite: PQC_SESSION_SUITE.to_string(),
            context,
            responder_nonce,
            responder_mlkem768_ek,
            responder_public_key,
            signature,
        },
        initiator_hello: hello.clone(),
        mlkem768_secret,
    })
}

impl PqcInitiatorState {
    pub fn hello(&self) -> &PqcInitiatorHello {
        &self.hello
    }

    pub fn finish(
        self,
        responder: &PqcResponderHello,
        keypair: &DeviceKeypair,
    ) -> Result<(PqcInitiatorFinish, SessionKeys)> {
        validate_responder_hello(&self.hello, responder)?;
        let initiator_public_key = keypair.public_key();
        validate_ml_dsa_public_key(&initiator_public_key)?;
        if initiator_public_key != self.hello.initiator_public_key {
            return Err(QlinkError::Protocol(
                "initiator finish keypair does not match initiator hello public key".into(),
            ));
        }

        responder.responder_public_key.verify(
            &responder_hello_signing_bytes(
                &self.hello,
                responder.version,
                &responder.suite,
                &responder.context,
                &responder.responder_nonce,
                &responder.responder_mlkem768_ek,
                &responder.responder_public_key,
            )?,
            &responder.signature,
        )?;

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
        let mlkem768_ciphertext = ciphertext.as_slice().to_vec();
        let transcript_hash = transcript_hash(&self.hello, responder)?;
        let signature = keypair.sign(&initiator_finish_signing_bytes(
            &self.hello,
            responder,
            &mlkem768_ciphertext,
            &transcript_hash,
        )?);
        let (tx_key, rx_key) = derive_directional_keys(
            mlkem_shared.as_slice(),
            &transcript_hash,
            &responder.suite,
            Direction::Initiator,
        )?;

        Ok((
            PqcInitiatorFinish {
                version: PQC_SESSION_VERSION,
                suite: responder.suite.clone(),
                mlkem768_ciphertext,
                transcript_hash,
                signature,
            },
            SessionKeys {
                suite: responder.suite.clone(),
                handshake_hash: transcript_hash,
                tx_key,
                rx_key,
            },
        ))
    }
}

impl PqcResponderState {
    pub fn hello(&self) -> &PqcResponderHello {
        &self.hello
    }

    pub fn finish(self, finish: &PqcInitiatorFinish) -> Result<SessionKeys> {
        validate_session_suite(finish.version, &finish.suite)?;
        if finish.suite != self.hello.suite {
            return Err(QlinkError::Protocol(
                "initiator finish suite does not match responder hello".into(),
            ));
        }

        let expected_hash = transcript_hash(&self.initiator_hello, &self.hello)?;
        if finish.transcript_hash != expected_hash {
            return Err(QlinkError::Protocol("transcript hash mismatch".into()));
        }

        self.initiator_hello.initiator_public_key.verify(
            &initiator_finish_signing_bytes(
                &self.initiator_hello,
                &self.hello,
                &finish.mlkem768_ciphertext,
                &finish.transcript_hash,
            )?,
            &finish.signature,
        )?;

        let ciphertext: Ciphertext = finish
            .mlkem768_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| QlinkError::InvalidKey("invalid ML-KEM-768 ciphertext size".into()))?;
        let mlkem_shared = self.mlkem768_secret.decapsulate(&ciphertext);
        let (tx_key, rx_key) = derive_directional_keys(
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

#[derive(Serialize)]
struct InitiatorHelloSigningFields<'a> {
    tag: &'static str,
    version: u8,
    suite: &'a str,
    context: &'a PqcSessionContext,
    initiator_nonce: &'a [u8; 32],
    initiator_public_key: &'a DevicePublicKey,
}

#[derive(Serialize)]
struct ResponderHelloSigningFields<'a> {
    tag: &'static str,
    initiator_hello: &'a PqcInitiatorHello,
    responder: UnsignedResponderHello<'a>,
}

#[derive(Serialize)]
struct UnsignedResponderHello<'a> {
    version: u8,
    suite: &'a str,
    context: &'a PqcSessionContext,
    responder_nonce: &'a [u8; 32],
    responder_mlkem768_ek: &'a [u8],
    responder_public_key: &'a DevicePublicKey,
}

#[derive(Serialize)]
struct InitiatorFinishSigningFields<'a> {
    tag: &'static str,
    initiator_hello: &'a PqcInitiatorHello,
    responder_hello: &'a PqcResponderHello,
    finish: UnsignedInitiatorFinish<'a>,
}

#[derive(Serialize)]
struct UnsignedInitiatorFinish<'a> {
    version: u8,
    suite: &'a str,
    mlkem768_ciphertext: &'a [u8],
    transcript_hash: &'a [u8; 32],
}

#[derive(Serialize)]
struct TranscriptFields<'a> {
    tag: &'static str,
    initiator_hello: &'a PqcInitiatorHello,
    responder_hello: &'a PqcResponderHello,
}

#[derive(Serialize)]
struct KeyDerivationFields<'a> {
    tag: &'static str,
    suite: &'a str,
    transcript_hash: &'a [u8; 32],
    mlkem_shared: &'a [u8],
}

fn initiator_hello_signing_bytes(
    version: u8,
    suite: &str,
    context: &PqcSessionContext,
    initiator_nonce: &[u8; 32],
    initiator_public_key: &DevicePublicKey,
) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&InitiatorHelloSigningFields {
        tag: "qlink.pqc_session.initiator_hello.v1",
        version,
        suite,
        context,
        initiator_nonce,
        initiator_public_key,
    })?)
}

fn responder_hello_signing_bytes(
    initiator_hello: &PqcInitiatorHello,
    version: u8,
    suite: &str,
    context: &PqcSessionContext,
    responder_nonce: &[u8; 32],
    responder_mlkem768_ek: &[u8],
    responder_public_key: &DevicePublicKey,
) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&ResponderHelloSigningFields {
        tag: "qlink.pqc_session.responder_hello.v1",
        initiator_hello,
        responder: UnsignedResponderHello {
            version,
            suite,
            context,
            responder_nonce,
            responder_mlkem768_ek,
            responder_public_key,
        },
    })?)
}

fn initiator_finish_signing_bytes(
    initiator_hello: &PqcInitiatorHello,
    responder_hello: &PqcResponderHello,
    mlkem768_ciphertext: &[u8],
    transcript_hash: &[u8; 32],
) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&InitiatorFinishSigningFields {
        tag: "qlink.pqc_session.initiator_finish.v1",
        initiator_hello,
        responder_hello,
        finish: UnsignedInitiatorFinish {
            version: PQC_SESSION_VERSION,
            suite: &responder_hello.suite,
            mlkem768_ciphertext,
            transcript_hash,
        },
    })?)
}

fn transcript_hash(
    initiator_hello: &PqcInitiatorHello,
    responder_hello: &PqcResponderHello,
) -> Result<[u8; 32]> {
    let transcript = serde_json::to_vec(&TranscriptFields {
        tag: "qlink.pqc_session.transcript.v1",
        initiator_hello,
        responder_hello,
    })?;
    Ok(shake256_32(&transcript))
}

enum Direction {
    Initiator,
    Responder,
}

fn derive_directional_keys(
    mlkem_shared: &[u8],
    transcript_hash: &[u8; 32],
    suite: &str,
    direction: Direction,
) -> Result<([u8; 32], [u8; 32])> {
    let kdf_input = serde_json::to_vec(&KeyDerivationFields {
        tag: "qlink.pqc_session.keys.v1",
        suite,
        transcript_hash,
        mlkem_shared,
    })?;
    let okm = shake256_64(&kdf_input);
    let mut i2r = [0_u8; 32];
    let mut r2i = [0_u8; 32];
    i2r.copy_from_slice(&okm[..32]);
    r2i.copy_from_slice(&okm[32..]);

    Ok(match direction {
        Direction::Initiator => (i2r, r2i),
        Direction::Responder => (r2i, i2r),
    })
}

fn shake256_32(input: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    shake256(input, &mut out);
    out
}

fn shake256_64(input: &[u8]) -> [u8; 64] {
    let mut out = [0_u8; 64];
    shake256(input, &mut out);
    out
}

fn shake256(input: &[u8], out: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.read(out);
}

fn validate_responder_hello(
    initiator: &PqcInitiatorHello,
    responder: &PqcResponderHello,
) -> Result<()> {
    validate_session_suite(responder.version, &responder.suite)?;
    if responder.suite != initiator.suite {
        return Err(QlinkError::Protocol(
            "responder hello suite does not match initiator hello".into(),
        ));
    }
    if responder.context != initiator.context {
        return Err(QlinkError::Protocol(
            "responder hello context does not match initiator hello".into(),
        ));
    }
    validate_ml_dsa_public_key(&responder.responder_public_key)?;
    ensure_peer_id(
        &responder.responder_public_key,
        &initiator.context.responder_peer_id,
        "responder",
    )
}

fn validate_session_suite(version: u8, suite: &str) -> Result<()> {
    if version != PQC_SESSION_VERSION {
        return Err(QlinkError::Protocol(format!(
            "unsupported PQC session version {version}"
        )));
    }
    if suite != PQC_SESSION_SUITE {
        return Err(QlinkError::Protocol(format!(
            "unsupported PQC session suite {suite}"
        )));
    }
    Ok(())
}

fn validate_ml_dsa_public_key(public_key: &DevicePublicKey) -> Result<()> {
    if public_key.algorithm != "ML-DSA-65" {
        return Err(QlinkError::InvalidKey(format!(
            "PQC session requires ML-DSA-65 device key, got {}",
            public_key.algorithm
        )));
    }
    Ok(())
}

fn ensure_peer_id(public_key: &DevicePublicKey, expected_peer_id: &str, role: &str) -> Result<()> {
    let actual_peer_id = public_key.peer_id();
    if actual_peer_id != expected_peer_id {
        return Err(QlinkError::Protocol(format!(
            "{role} public key peer_id {actual_peer_id} does not match context peer_id {expected_peer_id}"
        )));
    }
    Ok(())
}

fn random_nonce() -> Result<[u8; 32]> {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|err| QlinkError::Crypto(err.to_string()))?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context(initiator: &DeviceKeypair, responder: &DeviceKeypair) -> PqcSessionContext {
        PqcSessionContext::new(
            "mesh-alpha",
            initiator.public_key().peer_id(),
            responder.public_key().peer_id(),
            b"carrier-binding".to_vec(),
        )
    }

    #[test]
    fn authenticated_ml_kem_session_establishes_directional_keys() {
        let initiator = DeviceKeypair::generate().unwrap();
        let responder = DeviceKeypair::generate().unwrap();
        let context = test_context(&initiator, &responder);

        let initiator_state = start_pqc_session(context.clone(), &initiator).unwrap();
        let responder_state =
            answer_pqc_session(initiator_state.hello(), context.clone(), &responder).unwrap();
        let (finish, initiator_keys) = initiator_state
            .finish(responder_state.hello(), &initiator)
            .unwrap();
        let responder_keys = responder_state.finish(&finish).unwrap();

        assert_eq!(initiator_keys.suite, PQC_SESSION_SUITE);
        assert_eq!(responder_keys.suite, PQC_SESSION_SUITE);
        assert_eq!(initiator_keys.tx_key, responder_keys.rx_key);
        assert_eq!(initiator_keys.rx_key, responder_keys.tx_key);
        assert_eq!(initiator_keys.handshake_hash, responder_keys.handshake_hash);
    }

    #[test]
    fn responder_rejects_wrong_initiator_signature() {
        let initiator = DeviceKeypair::generate().unwrap();
        let responder = DeviceKeypair::generate().unwrap();
        let context = test_context(&initiator, &responder);
        let initiator_state = start_pqc_session(context.clone(), &initiator).unwrap();
        let mut tampered_hello = initiator_state.hello().clone();
        tampered_hello.signature[0] ^= 0x01;

        assert!(answer_pqc_session(&tampered_hello, context, &responder).is_err());
    }

    #[test]
    fn responder_rejects_wrong_responder_keypair() {
        let initiator = DeviceKeypair::generate().unwrap();
        let responder = DeviceKeypair::generate().unwrap();
        let wrong_responder = DeviceKeypair::generate().unwrap();
        let context = test_context(&initiator, &responder);

        let initiator_state = start_pqc_session(context.clone(), &initiator).unwrap();
        assert!(answer_pqc_session(initiator_state.hello(), context, &wrong_responder).is_err());
    }

    #[test]
    fn finish_rejects_ciphertext_tampering() {
        let initiator = DeviceKeypair::generate().unwrap();
        let responder = DeviceKeypair::generate().unwrap();
        let context = test_context(&initiator, &responder);

        let initiator_state = start_pqc_session(context.clone(), &initiator).unwrap();
        let responder_state =
            answer_pqc_session(initiator_state.hello(), context, &responder).unwrap();
        let (mut finish, _initiator_keys) = initiator_state
            .finish(responder_state.hello(), &initiator)
            .unwrap();
        finish.mlkem768_ciphertext[0] ^= 0x01;

        assert!(responder_state.finish(&finish).is_err());
    }

    #[test]
    fn initiator_rejects_impostor_responder_hello() {
        let initiator = DeviceKeypair::generate().unwrap();
        let responder = DeviceKeypair::generate().unwrap();
        let impostor = DeviceKeypair::generate().unwrap();
        let context = test_context(&initiator, &responder);

        let initiator_state = start_pqc_session(context.clone(), &initiator).unwrap();
        let responder_state =
            answer_pqc_session(initiator_state.hello(), context, &responder).unwrap();
        let mut impostor_hello = responder_state.hello().clone();
        impostor_hello.responder_public_key = impostor.public_key();

        assert!(initiator_state.finish(&impostor_hello, &initiator).is_err());
    }

    #[test]
    fn initiator_finish_requires_original_keypair() {
        let initiator = DeviceKeypair::generate().unwrap();
        let other_initiator = DeviceKeypair::generate().unwrap();
        let responder = DeviceKeypair::generate().unwrap();
        let context = test_context(&initiator, &responder);

        let initiator_state = start_pqc_session(context.clone(), &initiator).unwrap();
        let responder_state =
            answer_pqc_session(initiator_state.hello(), context, &responder).unwrap();

        assert!(initiator_state
            .finish(responder_state.hello(), &other_initiator)
            .is_err());
    }

    #[test]
    fn deterministic_vectors_guard_canonical_inputs() {
        let initiator_key = DevicePublicKey {
            algorithm: "ML-DSA-65".to_string(),
            bytes: vec![1, 2, 3, 4],
        };
        let responder_key = DevicePublicKey {
            algorithm: "ML-DSA-65".to_string(),
            bytes: vec![5, 6, 7, 8],
        };
        let context = PqcSessionContext::new(
            "mesh-vector",
            "qlink_initiator",
            "qlink_responder",
            vec![9, 10, 11],
        );
        let initiator_nonce = [0x11; 32];
        let responder_nonce = [0x22; 32];
        let responder_ek = vec![0x33, 0x44, 0x55, 0x66];
        let initiator_hello = PqcInitiatorHello {
            version: PQC_SESSION_VERSION,
            suite: PQC_SESSION_SUITE.to_string(),
            context: context.clone(),
            initiator_nonce,
            initiator_public_key: initiator_key.clone(),
            signature: vec![0xaa, 0xbb],
        };
        let responder_hello = PqcResponderHello {
            version: PQC_SESSION_VERSION,
            suite: PQC_SESSION_SUITE.to_string(),
            context: context.clone(),
            responder_nonce,
            responder_mlkem768_ek: responder_ek.clone(),
            responder_public_key: responder_key.clone(),
            signature: vec![0xcc, 0xdd],
        };
        let ciphertext = vec![0xde, 0xad, 0xbe, 0xef];
        let transcript = transcript_hash(&initiator_hello, &responder_hello).unwrap();
        let (i2r, r2i) = derive_directional_keys(
            &[0x42; 32],
            &transcript,
            PQC_SESSION_SUITE,
            Direction::Initiator,
        )
        .unwrap();
        let initiator_signing_bytes = initiator_hello_signing_bytes(
            PQC_SESSION_VERSION,
            PQC_SESSION_SUITE,
            &context,
            &initiator_nonce,
            &initiator_key,
        )
        .unwrap();
        let responder_signing_bytes = responder_hello_signing_bytes(
            &initiator_hello,
            PQC_SESSION_VERSION,
            PQC_SESSION_SUITE,
            &context,
            &responder_nonce,
            &responder_ek,
            &responder_key,
        )
        .unwrap();
        let finish_signing_bytes = initiator_finish_signing_bytes(
            &initiator_hello,
            &responder_hello,
            &ciphertext,
            &transcript,
        )
        .unwrap();

        assert_eq!(
            hex(&shake256_32(&initiator_signing_bytes)),
            "3e3e578b379da5c9446b9af4b99c64835d71152ed3e53bf2630fa1d632af9686"
        );
        assert_eq!(
            hex(&shake256_32(&responder_signing_bytes)),
            "ea6e19d97ade6d82ade1af2351175d7bd96010b9115a2dd1c7c7803ba8e3cd2c"
        );
        assert_eq!(
            hex(&shake256_32(&finish_signing_bytes)),
            "8b1a1e37270c3a2495e2cf0367522b9b46a45676012c0d7b56a26e714ee6272a"
        );
        assert_eq!(
            hex(&transcript),
            "0b6d4d58a8626257a144a1e7eee99686a16bc191aaf91ffce006284f304ee511"
        );
        assert_eq!(
            hex(&i2r),
            "00a6c1bd3f0efa38a7cb13c1dbf43e3ebdec06b1c9c8acb7e9d90f1cacd8be5b"
        );
        assert_eq!(
            hex(&r2i),
            "a4e93ab3bbe662c92a5bf2b0fce0e975553d85965f89797a7876a26cccc374bd"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
