use crate::{
    carrier_transport::CarrierSession,
    crypto::{DeviceKeypair, SessionKeys},
    error::{QlinkError, Result},
    session_crypto::{
        answer_pqc_session, start_pqc_session, PqcInitiatorFinish, PqcInitiatorHello,
        PqcResponderHello, PqcSessionContext,
    },
};
use serde::{Deserialize, Serialize};

pub const PQC_SESSION_MAX_WIRE_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "message", rename_all = "snake_case")]
enum PqcSessionWireMessage {
    InitiatorHello(PqcInitiatorHello),
    ResponderHello(PqcResponderHello),
    InitiatorFinish(PqcInitiatorFinish),
}

pub async fn run_pqc_session_initiator(
    session: &CarrierSession,
    context: PqcSessionContext,
    keypair: &DeviceKeypair,
) -> Result<SessionKeys> {
    let initiator = start_pqc_session(context, keypair)?;
    send_wire_message(
        session,
        PqcSessionWireMessage::InitiatorHello(initiator.hello().clone()),
    )
    .await?;

    let responder = match receive_wire_message(session).await? {
        PqcSessionWireMessage::ResponderHello(message) => message,
        unexpected => {
            return Err(unexpected_message_error(
                "responder hello",
                message_name(&unexpected),
            ));
        }
    };

    let (finish, session_keys) = initiator.finish(&responder, keypair)?;
    send_wire_message(session, PqcSessionWireMessage::InitiatorFinish(finish)).await?;
    Ok(session_keys)
}

pub async fn run_pqc_session_responder(
    session: &CarrierSession,
    context: PqcSessionContext,
    keypair: &DeviceKeypair,
) -> Result<SessionKeys> {
    let initiator_hello = match receive_wire_message(session).await? {
        PqcSessionWireMessage::InitiatorHello(message) => message,
        unexpected => {
            return Err(unexpected_message_error(
                "initiator hello",
                message_name(&unexpected),
            ));
        }
    };

    let responder = answer_pqc_session(&initiator_hello, context, keypair)?;
    send_wire_message(
        session,
        PqcSessionWireMessage::ResponderHello(responder.hello().clone()),
    )
    .await?;

    let finish = match receive_wire_message(session).await? {
        PqcSessionWireMessage::InitiatorFinish(message) => message,
        unexpected => {
            return Err(unexpected_message_error(
                "initiator finish",
                message_name(&unexpected),
            ));
        }
    };

    responder.finish(&finish)
}

async fn send_wire_message(session: &CarrierSession, message: PqcSessionWireMessage) -> Result<()> {
    let bytes = serde_json::to_vec(&message)?;
    if bytes.len() > PQC_SESSION_MAX_WIRE_SIZE {
        return Err(QlinkError::Protocol(format!(
            "PQC session message is {} bytes; max is {}",
            bytes.len(),
            PQC_SESSION_MAX_WIRE_SIZE
        )));
    }
    session.send_authenticated_message(bytes).await
}

async fn receive_wire_message(session: &CarrierSession) -> Result<PqcSessionWireMessage> {
    let bytes = session
        .receive_authenticated_message(PQC_SESSION_MAX_WIRE_SIZE)
        .await?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn unexpected_message_error(expected: &str, actual: &'static str) -> QlinkError {
    QlinkError::Protocol(format!(
        "unexpected PQC session message order: expected {expected}, got {actual}"
    ))
}

fn message_name(message: &PqcSessionWireMessage) -> &'static str {
    match message {
        PqcSessionWireMessage::InitiatorHello(_) => "initiator hello",
        PqcSessionWireMessage::ResponderHello(_) => "responder hello",
        PqcSessionWireMessage::InitiatorFinish(_) => "initiator finish",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "dev-quic-carrier")]
    use crate::quic_transport::{QuicCertificate, QuicEndpoint};
    use crate::{
        carrier_transport::NativeUdpSession,
        crypto::DeviceKeypair,
        session_crypto::{PqcSessionContext, PQC_SESSION_SUITE},
    };
    #[cfg(feature = "dev-quic-carrier")]
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[cfg(feature = "dev-quic-carrier")]
    #[tokio::test]
    async fn pqc_session_wire_establishes_matching_directional_keys() {
        let initiator_key = DeviceKeypair::generate().unwrap();
        let responder_key = DeviceKeypair::generate().unwrap();
        let responder_peer_id = responder_key.public_key().peer_id();

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server, server_cert) = QuicEndpoint::server(bind).unwrap();
        let server_addr = server.local_addr().unwrap();
        let server_cert_der = server_cert.as_der().to_vec();
        let client = QuicEndpoint::client(bind, &[]).unwrap();

        let responder_context = PqcSessionContext::new(
            "wire-mesh",
            initiator_key.public_key().peer_id(),
            responder_peer_id.clone(),
            server_cert_der.clone(),
        );
        let responder_task = tokio::spawn(async move {
            let session = CarrierSession::from(server.accept_one().await.unwrap());
            run_pqc_session_responder(&session, responder_context, &responder_key)
                .await
                .unwrap()
        });

        let trusted = QuicCertificate::from_der(server_cert_der.clone());
        let session = client
            .connect_with_trusted_cert(server_addr, &trusted)
            .await
            .unwrap();
        let session = CarrierSession::from(session);
        let initiator_context = PqcSessionContext::new(
            "wire-mesh",
            initiator_key.public_key().peer_id(),
            responder_peer_id,
            server_cert_der,
        );
        let initiator_keys = run_pqc_session_initiator(&session, initiator_context, &initiator_key)
            .await
            .unwrap();
        let responder_keys = responder_task.await.unwrap();

        assert_eq!(initiator_keys.suite, PQC_SESSION_SUITE);
        assert_eq!(responder_keys.suite, PQC_SESSION_SUITE);
        assert_eq!(initiator_keys.tx_key, responder_keys.rx_key);
        assert_eq!(initiator_keys.rx_key, responder_keys.tx_key);
        assert_eq!(initiator_keys.handshake_hash, responder_keys.handshake_hash);
    }

    #[tokio::test]
    async fn pqc_session_wire_establishes_keys_over_native_udp_carrier() {
        let initiator_key = DeviceKeypair::generate().unwrap();
        let responder_key = DeviceKeypair::generate().unwrap();
        let responder_peer_id = responder_key.public_key().peer_id();
        let (initiator_session, responder_session) =
            NativeUdpSession::loopback_pair().await.unwrap();
        let initiator_session = crate::carrier_transport::CarrierSession::from(initiator_session);
        let responder_session = crate::carrier_transport::CarrierSession::from(responder_session);
        let carrier_binding = b"native-udp-loopback-test".to_vec();

        let responder_context = PqcSessionContext::new(
            "native-wire-mesh",
            initiator_key.public_key().peer_id(),
            responder_peer_id.clone(),
            carrier_binding.clone(),
        );
        let responder_task = tokio::spawn(async move {
            run_pqc_session_responder(&responder_session, responder_context, &responder_key)
                .await
                .unwrap()
        });

        let initiator_context = PqcSessionContext::new(
            "native-wire-mesh",
            initiator_key.public_key().peer_id(),
            responder_peer_id,
            carrier_binding,
        );
        let initiator_keys =
            run_pqc_session_initiator(&initiator_session, initiator_context, &initiator_key)
                .await
                .unwrap();
        let responder_keys = responder_task.await.unwrap();

        assert_eq!(initiator_keys.suite, PQC_SESSION_SUITE);
        assert_eq!(responder_keys.suite, PQC_SESSION_SUITE);
        assert_eq!(initiator_keys.tx_key, responder_keys.rx_key);
        assert_eq!(initiator_keys.rx_key, responder_keys.tx_key);
        assert_eq!(initiator_keys.handshake_hash, responder_keys.handshake_hash);
    }
}
