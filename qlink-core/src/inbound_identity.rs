//! Application-layer inbound identity assertions.
//!
//! Today the QUIC handshake authenticates only the *server* (the receiving
//! peer presents the cert that's pinned in their signed rendezvous record).
//! The connecting peer is anonymous to the receiver at handshake time, so
//! a receiver running QuantumLink will accept inbound connections from
//! anyone who knows its rendezvous record. The outbound `PeerAcl` shipped
//! earlier closes the *outbound* half of the auth story; this module
//! closes the inbound half.
//!
//! Flow:
//!
//! 1. Connecting peer (Alice) opens the QUIC connection.
//! 2. Once the datagram session is up, Alice sends an [`InboundIdentityAssertion`]
//!    as the first datagram. The assertion is signed with Alice's ML-DSA
//!    device private key — the same key whose public half is in Alice's
//!    signed rendezvous record.
//! 3. Receiving peer (Bob) calls [`InboundIdentityAssertion::verify`]:
//!    - peer_id must match SHA-256-derived hash of `device_public_key`
//!    - mesh_id must match what Bob expects
//!    - timestamp must be within `max_age` of now (replay window)
//!    - signature must verify against `device_public_key`
//! 4. Bob calls [`evaluate_inbound`] with his inbound `PeerAcl`.
//!    The combined helper returns a single `InboundDecision`:
//!    accepted, rejected by ACL, rejected by crypto, etc.
//! 5. If the decision is `Accepted`, Bob continues processing data frames.
//!    Otherwise he closes the QUIC connection.
//!
//! ## Anti-replay
//!
//! v1 uses a timestamp window only — no nonce cache. This is sufficient
//! when the window is short (default 60 s) and connections are rare. v2
//! should add a small LRU of `(peer_id, nonce)` pairs to detect replays
//! within the window. The nonce field is already in the assertion, so a
//! cache can be bolted on without touching the wire format.
//!
//! ## Privacy
//!
//! The assertion contains the full `device_public_key` (1952 bytes for
//! ML-DSA-65). That's the same key already published in the peer's
//! rendezvous record, so it's not new information. We deliberately do
//! NOT include hostnames, IPs, or alias strings beyond what's already in
//! the receiver's view of the world.

use crate::{
    crypto::{DeviceKeypair, DevicePublicKey},
    discovery::now_unix,
    error::{QlinkError, Result},
    peer_acl::{PeerAcl, PeerAclDecision},
    quic_transport::QuicDatagramSession,
};
use serde::{Deserialize, Serialize};

/// Default replay window: assertions older than this many seconds are
/// rejected. 60 s absorbs typical clock skew between unsynchronized devices
/// without giving an attacker a long replay opportunity.
pub const DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS: u64 = 60;

/// Upper bound on the on-wire size of an inbound assertion. ML-DSA-65
/// signatures are ~3.3 KB and public keys are ~1.9 KB, but the JSON wire
/// encoding inflates each binary field substantially (serde-json renders
/// `Vec<u8>` as a JSON array of decimal numbers — roughly 4× the binary
/// size). A real assertion measures ~19 KB; we cap at 32 KB to leave
/// headroom for future schema fields while still bounding memory
/// exhaustion attacks. v2 should switch to a binary serialization
/// (postcard / bincode) and tighten this back down.
pub const INBOUND_ASSERTION_MAX_WIRE_SIZE: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundIdentityAssertion {
    pub peer_id: String,
    pub mesh_id: String,
    pub timestamp_unix: u64,
    pub nonce: [u8; 16],
    pub device_public_key: DevicePublicKey,
    pub signature: Vec<u8>,
}

impl InboundIdentityAssertion {
    /// Builds and signs a fresh identity assertion for the local peer.
    /// Uses the current wall-clock time and a random 16-byte nonce so the
    /// signed payload is unique per assertion (prerequisite for any future
    /// replay-cache implementation).
    pub fn sign(keypair: &DeviceKeypair, mesh_id: impl Into<String>) -> Result<Self> {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|err| {
            QlinkError::Crypto(format!(
                "inbound assertion nonce entropy unavailable: {err}"
            ))
        })?;
        let timestamp_unix = now_unix();
        let device_public_key = keypair.public_key();
        let peer_id = device_public_key.peer_id();
        let mesh_id = mesh_id.into();

        let canonical = canonical_signing_bytes(&peer_id, &mesh_id, timestamp_unix, &nonce)?;
        let signature = keypair.sign(&canonical);

        Ok(Self {
            peer_id,
            mesh_id,
            timestamp_unix,
            nonce,
            device_public_key,
            signature,
        })
    }

    /// Verifies the assertion against an expected mesh_id and a maximum
    /// age. Returns `Ok(())` if the assertion is well-formed, signed by
    /// the embedded public key, fresh, and addressed to the expected mesh.
    ///
    /// Note: this does NOT consult the ACL. Callers should follow up with
    /// [`evaluate_inbound`] to combine crypto verification with policy
    /// evaluation in a single decision.
    pub fn verify(&self, expected_mesh_id: &str, max_age_seconds: u64) -> Result<()> {
        // peer_id must be derivable from the embedded public key. This
        // protects against an attacker who picks a peer_id and tries to
        // attach somebody else's public key to it.
        let derived_peer_id = self.device_public_key.peer_id();
        if derived_peer_id != self.peer_id {
            return Err(QlinkError::Protocol(format!(
                "inbound assertion peer_id ({}) does not match device_public_key-derived id ({})",
                self.peer_id, derived_peer_id
            )));
        }

        if self.mesh_id != expected_mesh_id {
            return Err(QlinkError::Protocol(format!(
                "inbound assertion mesh_id mismatch: claimed {} but receiver expects {}",
                self.mesh_id, expected_mesh_id
            )));
        }

        let now = now_unix();
        let age = now.saturating_sub(self.timestamp_unix);
        if age > max_age_seconds {
            return Err(QlinkError::Protocol(format!(
                "inbound assertion is {age} s old (max {max_age_seconds} s)"
            )));
        }
        // Reject far-future timestamps too: they'd allow an attacker to
        // mint an assertion that stays "fresh" for an arbitrarily long
        // window once the clock catches up.
        if self.timestamp_unix > now.saturating_add(max_age_seconds) {
            return Err(QlinkError::Protocol(
                "inbound assertion timestamp is too far in the future".into(),
            ));
        }

        let canonical = canonical_signing_bytes(
            &self.peer_id,
            &self.mesh_id,
            self.timestamp_unix,
            &self.nonce,
        )?;
        self.device_public_key.verify(&canonical, &self.signature)?;

        Ok(())
    }
}

/// Combined crypto + policy evaluation. Use this on the receiver side as
/// the single decision point for whether an inbound connection is allowed
/// to continue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundDecision {
    Accepted,
    /// Crypto checks failed (signature, mesh_id, timestamp, peer_id↔pubkey).
    /// Carries the underlying `QlinkError::Protocol` message for
    /// diagnostics; do NOT surface this to the connecting peer (that
    /// leaks information about why we rejected them).
    RejectedByCrypto(String),
    /// Crypto passed, but the inbound ACL denies this peer.
    RejectedByAcl(PeerAclDecision),
}

impl InboundDecision {
    pub fn is_accepted(&self) -> bool {
        matches!(self, InboundDecision::Accepted)
    }

    pub fn reason(&self) -> String {
        match self {
            InboundDecision::Accepted => "accepted".to_string(),
            InboundDecision::RejectedByCrypto(detail) => format!("crypto: {detail}"),
            InboundDecision::RejectedByAcl(decision) => {
                format!("acl: {}", decision.reason())
            }
        }
    }
}

/// One-call helper: verifies the assertion's crypto, then applies the ACL.
/// Returns the unified [`InboundDecision`].
///
/// Order matters: crypto runs first. We never consult the ACL with an
/// unverified peer_id, because a forged assertion could otherwise probe
/// the ACL's contents (e.g. discover whether `qlink_admin` is allowed).
pub fn evaluate_inbound(
    assertion: &InboundIdentityAssertion,
    expected_mesh_id: &str,
    max_age_seconds: u64,
    inbound_acl: Option<&PeerAcl>,
) -> InboundDecision {
    if let Err(error) = assertion.verify(expected_mesh_id, max_age_seconds) {
        return InboundDecision::RejectedByCrypto(error.to_string());
    }

    if let Some(acl) = inbound_acl {
        let decision = acl.evaluate(&assertion.peer_id);
        if !decision.is_allowed() {
            return InboundDecision::RejectedByAcl(decision);
        }
    }

    InboundDecision::Accepted
}

/// Client-side wire helper: signs a fresh assertion and sends it to the
/// receiver as the first uni-stream message on the live QUIC connection.
/// Call this immediately after `connect_with_trusted_cert` succeeds, before
/// any data-plane datagrams. Rejection by the receiver surfaces as a
/// connection close on subsequent reads, not as an explicit response.
pub async fn send_inbound_assertion(
    session: &QuicDatagramSession,
    keypair: &DeviceKeypair,
    mesh_id: &str,
) -> Result<()> {
    let assertion = InboundIdentityAssertion::sign(keypair, mesh_id)?;
    let bytes = serde_json::to_vec(&assertion)?;
    session.send_authenticated_message(bytes).await
}

/// Server-side wire helper: receives the next uni-stream message, decodes
/// it as an [`InboundIdentityAssertion`], and runs the combined
/// crypto + ACL evaluation in [`evaluate_inbound`]. Returns the unified
/// decision plus the parsed assertion (so callers can log the verified
/// peer_id or include it in metrics on successful acceptance).
///
/// Use this from the responder loop right after `accept_one`. On
/// `RejectedByCrypto` or `RejectedByAcl`, close the QUIC connection
/// without further processing — never echo the rejection reason back to
/// the peer (it leaks ACL contents).
pub async fn receive_and_evaluate_inbound(
    session: &QuicDatagramSession,
    expected_mesh_id: &str,
    max_age_seconds: u64,
    inbound_acl: Option<&PeerAcl>,
) -> Result<(InboundDecision, InboundIdentityAssertion)> {
    let bytes = session
        .receive_authenticated_message(INBOUND_ASSERTION_MAX_WIRE_SIZE)
        .await?;
    let assertion: InboundIdentityAssertion = serde_json::from_slice(&bytes)?;
    let decision = evaluate_inbound(&assertion, expected_mesh_id, max_age_seconds, inbound_acl);
    Ok((decision, assertion))
}

/// Canonical bytes for signing. Field-tagged so a future schema addition
/// (e.g. `audience`) can't be confused with existing fields. We use JSON
/// for the wire format AND the signing input to keep the implementation
/// uniform; production should consider a fixed-binary format like postcard
/// for size, but JSON is fine for v1's low-volume control frames.
fn canonical_signing_bytes(
    peer_id: &str,
    mesh_id: &str,
    timestamp_unix: u64,
    nonce: &[u8; 16],
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct CanonicalAssertion<'a> {
        v: u32, // schema version; bump on breaking changes
        peer_id: &'a str,
        mesh_id: &'a str,
        timestamp_unix: u64,
        nonce_hex: String,
    }
    let nonce_hex = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let payload = CanonicalAssertion {
        v: 1,
        peer_id,
        mesh_id,
        timestamp_unix,
        nonce_hex,
    };
    serde_json::to_vec(&payload).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_keypair() -> DeviceKeypair {
        DeviceKeypair::generate().unwrap()
    }

    #[test]
    fn assertion_round_trips_through_signing_and_verification() {
        let keypair = fresh_keypair();
        let assertion = InboundIdentityAssertion::sign(&keypair, "devmesh").unwrap();

        // Crypto verification should pass for the matching mesh_id within
        // the default age window.
        assertion
            .verify("devmesh", DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS)
            .expect("freshly signed assertion must verify");

        // The peer_id matches the public-key-derived id by construction.
        assert_eq!(assertion.peer_id, keypair.public_key().peer_id());
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let keypair = fresh_keypair();
        let mut assertion = InboundIdentityAssertion::sign(&keypair, "devmesh").unwrap();
        // Flip a bit in the signature.
        let len = assertion.signature.len();
        assertion.signature[len - 1] ^= 0x01;
        let error = assertion
            .verify("devmesh", DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS)
            .unwrap_err();
        // The error comes from the underlying ML-DSA verifier, not our
        // checks; we just confirm verification failed.
        assert!(
            error.to_string().to_lowercase().contains("sign")
                || error.to_string().to_lowercase().contains("verif"),
            "expected signature-verification error, got {error}"
        );
    }

    #[test]
    fn tampered_payload_invalidates_signature() {
        let keypair = fresh_keypair();
        let mut assertion = InboundIdentityAssertion::sign(&keypair, "devmesh").unwrap();
        // Mutating mesh_id breaks the signed payload.
        assertion.mesh_id = "different-mesh".to_string();
        let error = assertion
            .verify("different-mesh", DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS)
            .unwrap_err();
        assert!(
            error.to_string().to_lowercase().contains("sign")
                || error.to_string().to_lowercase().contains("verif")
        );
    }

    #[test]
    fn mesh_id_mismatch_is_rejected_before_signature_check() {
        // Signed for "mesh-a", verified against "mesh-b" — the receiver
        // should reject for mesh mismatch, not waste cycles on signature
        // verification of a misaddressed assertion.
        let keypair = fresh_keypair();
        let assertion = InboundIdentityAssertion::sign(&keypair, "mesh-a").unwrap();
        let error = assertion
            .verify("mesh-b", DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS)
            .unwrap_err();
        assert!(error.to_string().contains("mesh_id mismatch"));
    }

    #[test]
    fn expired_assertion_is_rejected() {
        let keypair = fresh_keypair();
        let mut assertion = InboundIdentityAssertion::sign(&keypair, "devmesh").unwrap();
        // Pretend the assertion is 5 minutes old.
        assertion.timestamp_unix = now_unix().saturating_sub(300);
        let error = assertion.verify("devmesh", 60).unwrap_err();
        assert!(error.to_string().contains("old"));
    }

    #[test]
    fn future_timestamp_is_rejected() {
        let keypair = fresh_keypair();
        let mut assertion = InboundIdentityAssertion::sign(&keypair, "devmesh").unwrap();
        // Far future — beyond the max-age skew window.
        assertion.timestamp_unix = now_unix().saturating_add(3_600);
        let error = assertion.verify("devmesh", 60).unwrap_err();
        assert!(error.to_string().contains("future"));
    }

    #[test]
    fn peer_id_must_match_public_key() {
        // Substitute a different peer_id while keeping the original
        // public key. Verification should reject before even checking
        // the signature, because the binding `peer_id == sha256(pubkey)`
        // is the foundation of identity.
        let keypair = fresh_keypair();
        let mut assertion = InboundIdentityAssertion::sign(&keypair, "devmesh").unwrap();
        assertion.peer_id = "qlink_attacker-claimed-id".to_string();
        let error = assertion
            .verify("devmesh", DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS)
            .unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn assertion_serializes_to_json_for_wire_transport() {
        let keypair = fresh_keypair();
        let assertion = InboundIdentityAssertion::sign(&keypair, "devmesh").unwrap();
        let bytes = serde_json::to_vec(&assertion).unwrap();
        let parsed: InboundIdentityAssertion = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, assertion);
        parsed
            .verify("devmesh", DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS)
            .expect("post-serialization assertion must still verify");
    }

    // === Combined evaluate_inbound() tests ===

    #[test]
    fn evaluate_accepts_valid_assertion_with_no_acl() {
        let keypair = fresh_keypair();
        let assertion = InboundIdentityAssertion::sign(&keypair, "devmesh").unwrap();
        let decision = evaluate_inbound(
            &assertion,
            "devmesh",
            DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS,
            None,
        );
        assert_eq!(decision, InboundDecision::Accepted);
        assert!(decision.is_accepted());
    }

    #[test]
    fn evaluate_accepts_when_peer_is_in_inbound_allowlist() {
        let keypair = fresh_keypair();
        let peer_id = keypair.public_key().peer_id();
        let assertion = InboundIdentityAssertion::sign(&keypair, "devmesh").unwrap();
        let acl = PeerAcl::new().with_allow([peer_id.clone()]);
        let decision = evaluate_inbound(
            &assertion,
            "devmesh",
            DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS,
            Some(&acl),
        );
        assert_eq!(decision, InboundDecision::Accepted);
    }

    #[test]
    fn evaluate_rejects_explicit_denylist_match() {
        let keypair = fresh_keypair();
        let peer_id = keypair.public_key().peer_id();
        let assertion = InboundIdentityAssertion::sign(&keypair, "devmesh").unwrap();
        let acl = PeerAcl::new().with_deny([peer_id.clone()]);
        let decision = evaluate_inbound(
            &assertion,
            "devmesh",
            DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS,
            Some(&acl),
        );
        assert!(matches!(decision, InboundDecision::RejectedByAcl(_)));
        assert!(decision.reason().contains("deny"));
    }

    #[test]
    fn evaluate_rejects_peer_not_in_allowlist() {
        let keypair = fresh_keypair();
        let assertion = InboundIdentityAssertion::sign(&keypair, "devmesh").unwrap();
        let acl = PeerAcl::new().with_allow(["qlink_someone-else"]);
        let decision = evaluate_inbound(
            &assertion,
            "devmesh",
            DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS,
            Some(&acl),
        );
        assert!(matches!(decision, InboundDecision::RejectedByAcl(_)));
        assert!(decision.reason().contains("allow"));
    }

    // === Async wire integration: client+server through real QUIC ===

    #[tokio::test]
    async fn responder_accepts_legitimate_inbound_assertion_over_quic() {
        use crate::quic_transport::QuicEndpoint;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[]).unwrap();

        // Server side: accept one connection, run receive_and_evaluate_inbound.
        let server_handle = tokio::spawn(async move {
            let session = server_endpoint.accept_one().await.unwrap();
            receive_and_evaluate_inbound(&session, "devmesh", 60, None)
                .await
                .map(|(decision, assertion)| (decision, assertion.peer_id))
        });

        // Client side: connect, send our assertion.
        let client_keypair = DeviceKeypair::generate().unwrap();
        let expected_peer_id = client_keypair.public_key().peer_id();
        let session = client_endpoint
            .connect_with_trusted_cert(server_addr, &server_cert)
            .await
            .unwrap();
        send_inbound_assertion(&session, &client_keypair, "devmesh")
            .await
            .unwrap();

        let (decision, observed_peer_id) = server_handle.await.unwrap().unwrap();
        assert_eq!(decision, InboundDecision::Accepted);
        assert_eq!(observed_peer_id, expected_peer_id);
    }

    #[tokio::test]
    async fn responder_rejects_inbound_assertion_when_peer_is_in_denylist() {
        use crate::quic_transport::QuicEndpoint;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[]).unwrap();

        let client_keypair = DeviceKeypair::generate().unwrap();
        let banned_peer_id = client_keypair.public_key().peer_id();

        // The server's inbound ACL bans this peer.
        let acl = PeerAcl::new().with_deny([banned_peer_id.clone()]);
        let server_handle = tokio::spawn(async move {
            let session = server_endpoint.accept_one().await.unwrap();
            receive_and_evaluate_inbound(&session, "devmesh", 60, Some(&acl))
                .await
                .map(|(decision, _)| decision)
        });

        let session = client_endpoint
            .connect_with_trusted_cert(server_addr, &server_cert)
            .await
            .unwrap();
        send_inbound_assertion(&session, &client_keypair, "devmesh")
            .await
            .unwrap();

        let decision = server_handle.await.unwrap().unwrap();
        assert!(matches!(decision, InboundDecision::RejectedByAcl(_)));
        assert!(decision.reason().contains("deny"));
    }

    #[tokio::test]
    async fn responder_rejects_inbound_assertion_for_wrong_mesh() {
        use crate::quic_transport::QuicEndpoint;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[]).unwrap();

        // Server is in mesh-b; client is signing for mesh-a. Crypto verify
        // on the receiver should reject for mesh mismatch before any ACL
        // is consulted.
        let server_handle = tokio::spawn(async move {
            let session = server_endpoint.accept_one().await.unwrap();
            receive_and_evaluate_inbound(&session, "mesh-b", 60, None)
                .await
                .map(|(decision, _)| decision)
        });

        let client_keypair = DeviceKeypair::generate().unwrap();
        let session = client_endpoint
            .connect_with_trusted_cert(server_addr, &server_cert)
            .await
            .unwrap();
        send_inbound_assertion(&session, &client_keypair, "mesh-a")
            .await
            .unwrap();

        let decision = server_handle.await.unwrap().unwrap();
        assert!(matches!(decision, InboundDecision::RejectedByCrypto(_)));
        assert!(decision.reason().contains("mesh"));
    }

    #[tokio::test]
    async fn responder_rejects_payload_exceeding_size_limit() {
        // The receiver caps wire size to defend against a malicious peer
        // claiming a huge length to exhaust memory. Send a length-prefix
        // that exceeds the cap and observe an explicit rejection.
        use crate::quic_transport::QuicEndpoint;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[]).unwrap();

        let server_handle = tokio::spawn(async move {
            let session = server_endpoint.accept_one().await.unwrap();
            receive_and_evaluate_inbound(&session, "devmesh", 60, None).await
        });

        // Send 32KB of garbage as one "authenticated message" — bypasses
        // our send_inbound_assertion which would never produce something
        // this large.
        let session = client_endpoint
            .connect_with_trusted_cert(server_addr, &server_cert)
            .await
            .unwrap();
        // Send (cap + 1024) bytes so we cleanly exceed the 32 KB limit.
        let huge_payload = vec![0_u8; INBOUND_ASSERTION_MAX_WIRE_SIZE + 1024];
        session
            .send_authenticated_message(huge_payload)
            .await
            .unwrap();

        let result = server_handle.await.unwrap();
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("max is") || error.to_string().contains("bytes"),
            "expected size-cap rejection, got: {error}"
        );
    }

    #[test]
    fn evaluate_rejects_crypto_before_consulting_acl() {
        // An attacker who can guess valid peer IDs in the ACL but can't
        // forge a signature must not learn ACL membership through
        // differential responses. We verify that crypto failure is the
        // reported reason — never the ACL's reason — when both would
        // independently reject.
        let keypair = fresh_keypair();
        let mut assertion = InboundIdentityAssertion::sign(&keypair, "devmesh").unwrap();
        // Tamper the signature so crypto fails.
        assertion.signature[0] ^= 0xff;
        // Construct an ACL that would also reject, just to confirm the
        // evaluator returns the crypto reason and not the ACL reason.
        let acl = PeerAcl::new().with_deny([assertion.peer_id.clone()]);
        let decision = evaluate_inbound(
            &assertion,
            "devmesh",
            DEFAULT_INBOUND_ASSERTION_MAX_AGE_SECONDS,
            Some(&acl),
        );
        assert!(matches!(decision, InboundDecision::RejectedByCrypto(_)));
        assert!(!decision.reason().contains("acl"));
    }
}
