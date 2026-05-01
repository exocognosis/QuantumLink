use crate::error::{QlinkError, Result};
use bytes::Bytes;
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{net::SocketAddr, sync::Arc};

const SERVER_NAME: &str = "localhost";

#[derive(Debug, Clone)]
pub struct QuicCertificate {
    der: CertificateDer<'static>,
}

impl QuicCertificate {
    pub fn as_der(&self) -> &[u8] {
        self.der.as_ref()
    }

    /// Constructs a `QuicCertificate` from a caller-supplied DER blob.
    /// Used when peers ship certificates through a side channel (e.g. embedded
    /// in a signed peer record); v1 callers pass the bytes directly.
    pub fn from_der(der: Vec<u8>) -> Self {
        Self {
            der: CertificateDer::from(der),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QuicEndpoint {
    endpoint: Endpoint,
}

#[derive(Debug, Clone)]
pub struct QuicDatagramSession {
    connection: Connection,
}

impl QuicEndpoint {
    pub fn server(bind_addr: SocketAddr) -> Result<(Self, QuicCertificate)> {
        let (server_config, certificate) = dev_server_config()?;
        let endpoint = Endpoint::server(server_config, bind_addr)
            .map_err(|err| QlinkError::Protocol(format!("failed to bind QUIC server: {err}")))?;
        Ok((Self { endpoint }, certificate))
    }

    pub fn client(bind_addr: SocketAddr, trusted_certificates: &[QuicCertificate]) -> Result<Self> {
        let mut endpoint = Endpoint::client(bind_addr)
            .map_err(|err| QlinkError::Protocol(format!("failed to bind QUIC client: {err}")))?;
        // An empty trust list means "no default client config — every
        // connect call must supply its own." Used by `MeshConnector`, which
        // learns per-peer trust from signed rendezvous records and uses
        // `connect_with_trusted_cert`.
        if !trusted_certificates.is_empty() {
            let client_config = client_config(trusted_certificates)?;
            endpoint.set_default_client_config(client_config);
        }
        Ok(Self { endpoint })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr().map_err(|err| {
            QlinkError::Protocol(format!("failed to read QUIC local address: {err}"))
        })
    }

    pub async fn connect(&self, remote: SocketAddr) -> Result<QuicDatagramSession> {
        let connecting = self.endpoint.connect(remote, SERVER_NAME).map_err(|err| {
            QlinkError::Protocol(format!("failed to start QUIC connection: {err}"))
        })?;
        let connection = connecting.await.map_err(|err| {
            QlinkError::Protocol(format!("failed to establish QUIC connection: {err}"))
        })?;
        Ok(QuicDatagramSession { connection })
    }

    /// Per-connection trust variant: trusts only the supplied certificate
    /// for this single connect attempt. Used by `MeshConnector` to honor the
    /// cert published in the remote peer's signed rendezvous record without
    /// pre-baking it into the endpoint at construction time.
    ///
    /// The TLS server name is the fixed `SERVER_NAME` used by the dev cert
    /// generator; rustls validates that the remote's presented cert matches
    /// the one in the per-connect root store. Cert rotation on the server
    /// side requires the peer to republish its record (TTL-bounded).
    pub async fn connect_with_trusted_cert(
        &self,
        remote: SocketAddr,
        trusted: &QuicCertificate,
    ) -> Result<QuicDatagramSession> {
        let config = client_config(std::slice::from_ref(trusted))?;
        let connecting = self
            .endpoint
            .connect_with(config, remote, SERVER_NAME)
            .map_err(|err| {
                QlinkError::Protocol(format!(
                    "failed to start QUIC connection with per-connect trust: {err}"
                ))
            })?;
        let connection = connecting.await.map_err(|err| {
            QlinkError::Protocol(format!(
                "failed to establish QUIC connection with per-connect trust: {err}"
            ))
        })?;
        Ok(QuicDatagramSession { connection })
    }

    pub async fn accept_one(&self) -> Result<QuicDatagramSession> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| QlinkError::Protocol("QUIC endpoint stopped accepting".into()))?;
        let connection = incoming.await.map_err(|err| {
            QlinkError::Protocol(format!("failed to accept QUIC connection: {err}"))
        })?;
        Ok(QuicDatagramSession { connection })
    }
}

impl QuicDatagramSession {
    pub async fn send_frame(&self, frame: Vec<u8>) -> Result<()> {
        self.connection
            .send_datagram_wait(Bytes::from(frame))
            .await
            .map_err(|err| QlinkError::Protocol(format!("failed to send QUIC datagram: {err}")))
    }

    pub async fn receive_frame(&self) -> Result<Vec<u8>> {
        let datagram = self.connection.read_datagram().await.map_err(|err| {
            QlinkError::Protocol(format!("failed to receive QUIC datagram: {err}"))
        })?;
        Ok(datagram.to_vec())
    }

    pub fn close(&self, reason: &[u8]) {
        self.connection.close(0_u32.into(), reason);
    }

    /// Sends a length-prefixed authenticated message on a fresh
    /// unidirectional QUIC stream. Used for control-plane handshakes that
    /// are too big for QUIC datagrams (notably `InboundIdentityAssertion`,
    /// which carries a 1.9KB ML-DSA public key and a 3.3KB signature).
    ///
    /// Wire format: 4-byte big-endian u32 length, followed by `payload`,
    /// followed by clean stream finish.
    pub async fn send_authenticated_message(&self, payload: Vec<u8>) -> Result<()> {
        let mut stream = self.connection.open_uni().await.map_err(|err| {
            QlinkError::Protocol(format!("failed to open auth uni stream: {err}"))
        })?;
        let len: u32 = payload
            .len()
            .try_into()
            .map_err(|_| QlinkError::Protocol("auth message exceeds u32 length prefix".into()))?;
        stream.write_all(&len.to_be_bytes()).await.map_err(|err| {
            QlinkError::Protocol(format!("auth message length write failed: {err}"))
        })?;
        stream.write_all(&payload).await.map_err(|err| {
            QlinkError::Protocol(format!("auth message payload write failed: {err}"))
        })?;
        stream.finish().map_err(|err| {
            QlinkError::Protocol(format!("auth message stream finish failed: {err}"))
        })?;
        // Wait for the peer to acknowledge stream closure so the caller
        // knows the message was actually delivered before proceeding to
        // the data plane.
        let _ = stream.stopped().await;
        Ok(())
    }

    /// Accepts the next unidirectional QUIC stream and reads a
    /// length-prefixed authenticated message off it. Caller supplies a
    /// `max_size` cap to defend against a malicious peer claiming a huge
    /// length to exhaust memory.
    pub async fn receive_authenticated_message(&self, max_size: usize) -> Result<Vec<u8>> {
        let mut stream = self.connection.accept_uni().await.map_err(|err| {
            QlinkError::Protocol(format!("failed to accept auth uni stream: {err}"))
        })?;
        let mut len_buf = [0_u8; 4];
        stream.read_exact(&mut len_buf).await.map_err(|err| {
            QlinkError::Protocol(format!("auth message length read failed: {err}"))
        })?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > max_size {
            return Err(QlinkError::Protocol(format!(
                "auth message claims {len} bytes; max is {max_size}"
            )));
        }
        let mut payload = vec![0_u8; len];
        stream.read_exact(&mut payload).await.map_err(|err| {
            QlinkError::Protocol(format!("auth message payload read failed: {err}"))
        })?;
        Ok(payload)
    }
}

fn dev_server_config() -> Result<(ServerConfig, QuicCertificate)> {
    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.into()])
        .map_err(|err| QlinkError::Crypto(format!("failed to generate QUIC certificate: {err}")))?;
    let cert_der = CertificateDer::from(cert.cert);
    let private_key = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let mut server_config = ServerConfig::with_single_cert(vec![cert_der.clone()], private_key)
        .map_err(|err| QlinkError::Crypto(format!("failed to configure QUIC server: {err}")))?;

    let mut transport_config = TransportConfig::default();
    transport_config
        // Permit a small number of unidirectional streams. Used by the
        // inbound-identity-assertion handshake (one uni-stream per
        // session at session start). 4 is comfortable headroom for any
        // future control-plane messages without inviting flooding.
        .max_concurrent_uni_streams(4_u8.into())
        .datagram_receive_buffer_size(Some(4 * 1024 * 1024))
        .datagram_send_buffer_size(4 * 1024 * 1024);
    server_config.transport_config(Arc::new(transport_config));

    Ok((server_config, QuicCertificate { der: cert_der }))
}

fn client_config(trusted_certificates: &[QuicCertificate]) -> Result<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in trusted_certificates {
        roots.add(certificate.der.clone()).map_err(|err| {
            QlinkError::Crypto(format!("failed to trust QUIC certificate: {err}"))
        })?;
    }

    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots))
        .map_err(|err| QlinkError::Crypto(format!("failed to configure QUIC client: {err}")))?;
    let mut transport_config = TransportConfig::default();
    transport_config
        .datagram_receive_buffer_size(Some(4 * 1024 * 1024))
        .datagram_send_buffer_size(4 * 1024 * 1024);
    client_config.transport_config(Arc::new(transport_config));
    Ok(client_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_core::{FfiRouteMode, PacketTunnelCore, PacketTunnelCoreConfig};
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    #[tokio::test]
    async fn quic_datagram_moves_packet_core_frame() {
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (server_endpoint, server_cert) = QuicEndpoint::server(bind).unwrap();
        let client_endpoint = QuicEndpoint::client(bind, &[server_cert]).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let (client_session, server_session) =
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(
                    client_endpoint.connect(server_addr),
                    server_endpoint.accept_one()
                )
            })
            .await
            .unwrap();
        let client_session = client_session.unwrap();
        let server_session = server_session.unwrap();

        let mut sender = test_core();
        let mut receiver = test_core();
        let packet = test_ipv4_packet([100, 127, 0, 10]);
        sender.submit_tunnel_packet(2, &packet).unwrap();
        let frame = sender.pop_transport_frame().unwrap();

        client_session.send_frame(frame).await.unwrap();
        let received_frame = server_session.receive_frame().await.unwrap();
        receiver.accept_transport_frame(&received_frame).unwrap();

        let restored = receiver.pop_tunnel_packet().unwrap();
        assert_eq!(restored.protocol_family, 2);
        assert_eq!(restored.bytes[16..20], packet[16..20]);
        assert_eq!(ipv4_header_checksum(&restored.bytes), 0);

        client_session.close(b"test done");
        server_session.close(b"test done");
    }

    fn test_core() -> PacketTunnelCore {
        PacketTunnelCore::new(PacketTunnelCoreConfig {
            protected_routes: vec!["100.127.0.0/16".to_string()],
            excluded_routes: vec![],
            route_mode: FfiRouteMode::SplitTunnel,
            mtu: 1280,
            crypto: None,
        })
        .unwrap()
    }

    fn test_ipv4_packet(destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[2] = 0;
        packet[3] = 20;
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[100, 127, 0, 2]);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn ipv4_header_checksum(packet: &[u8]) -> u16 {
        let header_len = ((packet[0] & 0x0f) as usize) * 4;
        let mut sum = 0_u32;
        for chunk in packet[..header_len].chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}
