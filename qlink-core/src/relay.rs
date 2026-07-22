use crate::error::QlinkError;
use crate::error::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    sync::{mpsc, Mutex},
    task::JoinHandle,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayMessage {
    Register {
        peer_id: String,
    },
    Registered {
        peer_id: String,
    },
    Datagram {
        source: String,
        destination: String,
        payload_base64: String,
    },
    Error {
        message: String,
    },
}

#[derive(Default, Clone)]
pub struct RelayRegistry {
    peers: Arc<Mutex<HashMap<String, OwnedWriteHalf>>>,
}

pub async fn run_relay(listen: &str) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let registry = RelayRegistry::default();
    serve_relay(listener, registry).await
}

pub async fn serve_relay(listener: TcpListener, registry: RelayRegistry) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, registry).await {
                tracing::warn!(?error, "relay connection failed");
            }
        });
    }
}

#[derive(Debug)]
pub struct DevRelayServer {
    local_addr: SocketAddr,
    task: JoinHandle<()>,
}

impl DevRelayServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for DevRelayServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_dev_relay() -> Result<DevRelayServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    let registry = RelayRegistry::default();
    let task = tokio::spawn(async move {
        if let Err(error) = serve_relay(listener, registry).await {
            tracing::warn!(?error, "dev relay server stopped");
        }
    });
    Ok(DevRelayServer { local_addr, task })
}

struct RelayClient {
    peer_id: String,
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl RelayClient {
    async fn connect(server: &str, peer_id: impl Into<String>) -> Result<Self> {
        let stream = TcpStream::connect(server).await?;
        let (reader, mut writer) = stream.into_split();
        let peer_id = peer_id.into();
        let register = RelayMessage::Register {
            peer_id: peer_id.clone(),
        };

        writer
            .write_all(serde_json::to_string(&register)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        match serde_json::from_str::<RelayMessage>(line.trim_end())? {
            RelayMessage::Registered { peer_id: confirmed } if confirmed == peer_id => {}
            RelayMessage::Error { message } => return Err(QlinkError::Protocol(message)),
            other => {
                return Err(QlinkError::Protocol(format!(
                    "unexpected relay registration response: {other:?}"
                )))
            }
        }

        Ok(Self {
            peer_id,
            reader,
            writer,
        })
    }

    async fn send_datagram(&mut self, destination: &str, payload: &[u8]) -> Result<()> {
        let message = RelayMessage::Datagram {
            source: self.peer_id.clone(),
            destination: destination.to_string(),
            payload_base64: STANDARD.encode(payload),
        };
        self.writer
            .write_all(serde_json::to_string(&message)?.as_bytes())
            .await?;
        self.writer.write_all(b"\n").await?;
        Ok(())
    }

    async fn receive_datagram(&mut self) -> Result<Option<(String, Vec<u8>)>> {
        let mut line = String::new();
        if self.reader.read_line(&mut line).await? == 0 {
            return Ok(None);
        }

        match serde_json::from_str::<RelayMessage>(line.trim_end())? {
            RelayMessage::Datagram {
                source,
                payload_base64,
                ..
            } => {
                let payload = STANDARD
                    .decode(payload_base64)
                    .map_err(|err| QlinkError::Protocol(format!("invalid relay payload: {err}")))?;
                Ok(Some((source, payload)))
            }
            RelayMessage::Error { message } => Err(QlinkError::Protocol(message)),
            RelayMessage::Register { .. } | RelayMessage::Registered { .. } => Err(
                QlinkError::Protocol("unexpected relay control message".into()),
            ),
        }
    }
}

/// Message-kind prefix so a single relay channel can carry both the PQC
/// handshake's authenticated messages and, afterward, protected data frames —
/// mirroring `NativeUdpSession`'s `MessageKind` so `run_pqc_session_*` and the
/// `PqcFrameProtector` data plane both work unchanged over the relay.
const RELAY_KIND_FRAME: u8 = 0;
const RELAY_KIND_AUTHENTICATED: u8 = 1;

/// A [`crate::carrier_transport::CarrierSession`] transport that tunnels through
/// a relay server. The relay only ever sees base64 blobs keyed by peer_id; the
/// end-to-end PQC session (ML-KEM/ML-DSA handshake + `PqcFrameProtector`) runs
/// on top exactly as it does over the direct carrier, so a relay operator cannot
/// read or forge traffic.
///
/// Two construction modes share one type:
/// - **initiator** ([`connect_initiator`]) owns a dedicated relay TCP
///   connection and reads its own inbound stream, filtered to the remote peer.
/// - **responder** ([`responder`]) is minted by [`RelayResponderListener`]'s
///   demux, which owns the single relay connection and fans inbound datagrams
///   out to a per-source channel; the write half is shared behind a mutex.
///
/// Read and write use independent locks so the full-duplex data plane never
/// deadlocks (a blocked `receive_frame` cannot starve a concurrent `send_frame`).
#[derive(Clone)]
pub struct RelayCarrierSession {
    remote_peer_id: String,
    local_peer_id: String,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    inbound: Arc<Mutex<RelayInboundState>>,
}

struct RelayInboundState {
    source: RelaySource,
    pending_frames: VecDeque<Vec<u8>>,
    pending_authenticated: VecDeque<Vec<u8>>,
}

enum RelaySource {
    /// Initiator: read directly off the relay connection, keeping only
    /// datagrams whose source is the peer we dialed.
    Connection {
        reader: BufReader<OwnedReadHalf>,
        remote_peer_id: String,
    },
    /// Responder: pre-demultiplexed payloads for this one source peer.
    Channel {
        rx: mpsc::UnboundedReceiver<Vec<u8>>,
    },
}

impl RelaySource {
    /// Returns the next `[kind][message]` payload addressed from the remote peer.
    async fn next_payload(&mut self) -> Result<Vec<u8>> {
        match self {
            RelaySource::Connection {
                reader,
                remote_peer_id,
            } => loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await? == 0 {
                    return Err(QlinkError::Protocol("relay connection closed".into()));
                }
                match serde_json::from_str::<RelayMessage>(line.trim_end())? {
                    RelayMessage::Datagram {
                        source,
                        payload_base64,
                        ..
                    } => {
                        if &source != remote_peer_id {
                            continue;
                        }
                        return STANDARD.decode(payload_base64).map_err(|err| {
                            QlinkError::Protocol(format!("invalid relay payload: {err}"))
                        });
                    }
                    RelayMessage::Error { message } => return Err(QlinkError::Protocol(message)),
                    RelayMessage::Register { .. } | RelayMessage::Registered { .. } => continue,
                }
            },
            RelaySource::Channel { rx } => rx
                .recv()
                .await
                .ok_or_else(|| QlinkError::Protocol("relay responder channel closed".into())),
        }
    }
}

impl std::fmt::Debug for RelayCarrierSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayCarrierSession")
            .field("local_peer_id", &self.local_peer_id)
            .field("remote_peer_id", &self.remote_peer_id)
            .finish()
    }
}

impl RelayCarrierSession {
    /// Dials the relay, registers as `local_peer_id`, and returns a session that
    /// exchanges frames with `remote_peer_id`. Used by the connector's relay
    /// fallback (initiator role).
    pub async fn connect_initiator(
        server: &str,
        local_peer_id: impl Into<String>,
        remote_peer_id: impl Into<String>,
    ) -> Result<Self> {
        let local_peer_id = local_peer_id.into();
        let remote_peer_id = remote_peer_id.into();
        let stream = TcpStream::connect(server).await?;
        let (reader, mut writer) = stream.into_split();
        writer
            .write_all(
                serde_json::to_string(&RelayMessage::Register {
                    peer_id: local_peer_id.clone(),
                })?
                .as_bytes(),
            )
            .await?;
        writer.write_all(b"\n").await?;

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        match serde_json::from_str::<RelayMessage>(line.trim_end())? {
            RelayMessage::Registered { peer_id } if peer_id == local_peer_id => {}
            RelayMessage::Error { message } => return Err(QlinkError::Protocol(message)),
            other => {
                return Err(QlinkError::Protocol(format!(
                    "unexpected relay registration response: {other:?}"
                )))
            }
        }

        Ok(Self {
            remote_peer_id: remote_peer_id.clone(),
            local_peer_id,
            writer: Arc::new(Mutex::new(writer)),
            inbound: Arc::new(Mutex::new(RelayInboundState {
                source: RelaySource::Connection {
                    reader,
                    remote_peer_id,
                },
                pending_frames: VecDeque::new(),
                pending_authenticated: VecDeque::new(),
            })),
        })
    }

    /// Responder-side session for one source peer, fed by the demux loop.
    fn responder(
        remote_peer_id: String,
        local_peer_id: String,
        writer: Arc<Mutex<OwnedWriteHalf>>,
        rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> Self {
        Self {
            remote_peer_id,
            local_peer_id,
            writer,
            inbound: Arc::new(Mutex::new(RelayInboundState {
                source: RelaySource::Channel { rx },
                pending_frames: VecDeque::new(),
                pending_authenticated: VecDeque::new(),
            })),
        }
    }

    pub fn remote_peer_id(&self) -> &str {
        &self.remote_peer_id
    }

    pub async fn send_frame(&self, frame: Vec<u8>) -> Result<()> {
        self.send(RELAY_KIND_FRAME, &frame).await
    }

    pub async fn receive_frame(&self) -> Result<Vec<u8>> {
        self.receive(RELAY_KIND_FRAME, usize::MAX).await
    }

    pub async fn send_authenticated_message(&self, payload: Vec<u8>) -> Result<()> {
        self.send(RELAY_KIND_AUTHENTICATED, &payload).await
    }

    pub async fn receive_authenticated_message(&self, max_size: usize) -> Result<Vec<u8>> {
        self.receive(RELAY_KIND_AUTHENTICATED, max_size).await
    }

    /// Relay teardown is handled by dropping the TCP connection; there is no
    /// per-session close datagram, so this is best-effort/no-op.
    pub fn close(&self, _reason: &[u8]) {}

    async fn send(&self, kind: u8, payload: &[u8]) -> Result<()> {
        let mut framed = Vec::with_capacity(payload.len() + 1);
        framed.push(kind);
        framed.extend_from_slice(payload);
        let message = RelayMessage::Datagram {
            source: self.local_peer_id.clone(),
            destination: self.remote_peer_id.clone(),
            payload_base64: STANDARD.encode(&framed),
        };
        let mut line = serde_json::to_string(&message)?;
        line.push('\n');
        let mut writer = self.writer.lock().await;
        writer.write_all(line.as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn receive(&self, wanted: u8, max_size: usize) -> Result<Vec<u8>> {
        let mut state = self.inbound.lock().await;
        if let Some(pending) = pop_pending(&mut state, wanted) {
            return validate_size(pending, max_size);
        }
        loop {
            let payload = state.source.next_payload().await?;
            let Some((kind, message)) = payload.split_first() else {
                return Err(QlinkError::Protocol("empty relay carrier payload".into()));
            };
            let message = message.to_vec();
            if *kind == wanted {
                return validate_size(message, max_size);
            }
            match *kind {
                RELAY_KIND_FRAME => state.pending_frames.push_back(message),
                RELAY_KIND_AUTHENTICATED => state.pending_authenticated.push_back(message),
                other => {
                    return Err(QlinkError::Protocol(format!(
                        "unknown relay carrier message kind {other}"
                    )))
                }
            }
        }
    }
}

fn pop_pending(state: &mut RelayInboundState, wanted: u8) -> Option<Vec<u8>> {
    match wanted {
        RELAY_KIND_FRAME => state.pending_frames.pop_front(),
        RELAY_KIND_AUTHENTICATED => state.pending_authenticated.pop_front(),
        _ => None,
    }
}

fn validate_size(payload: Vec<u8>, max_size: usize) -> Result<Vec<u8>> {
    if payload.len() > max_size {
        return Err(QlinkError::Protocol(format!(
            "relay carrier message is {} bytes; max is {max_size}",
            payload.len()
        )));
    }
    Ok(payload)
}

/// Registers with a relay as `local_peer_id` and demultiplexes inbound
/// datagrams to a fresh [`RelayCarrierSession`] per source peer, emitting each
/// new session (as a [`crate::carrier_transport::CarrierSession`]) so the
/// responder can run the inbound-assertion + PQC-responder flow over it. The
/// single write half is shared across all minted sessions behind a mutex.
pub struct RelayResponderListener;

impl RelayResponderListener {
    /// Runs the demux loop until the relay connection closes, invoking
    /// `on_session` for each new source peer.
    pub async fn run<F>(server: &str, local_peer_id: String, mut on_session: F) -> Result<()>
    where
        F: FnMut(RelayCarrierSession),
    {
        let client = RelayClient::connect(server, local_peer_id.clone()).await?;
        let RelayClient { reader, writer, .. } = client;
        let writer = Arc::new(Mutex::new(writer));
        let mut reader = reader;
        let mut sessions: HashMap<String, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();

        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await? == 0 {
                return Ok(());
            }
            let (source, payload) = match serde_json::from_str::<RelayMessage>(line.trim_end())? {
                RelayMessage::Datagram {
                    source,
                    payload_base64,
                    ..
                } => {
                    let payload = STANDARD.decode(payload_base64).map_err(|err| {
                        QlinkError::Protocol(format!("invalid relay payload: {err}"))
                    })?;
                    (source, payload)
                }
                RelayMessage::Error { message } => return Err(QlinkError::Protocol(message)),
                RelayMessage::Register { .. } | RelayMessage::Registered { .. } => {
                    line.clear();
                    continue;
                }
            };

            let has_live_session = sessions
                .get(&source)
                .map(|tx| !tx.is_closed())
                .unwrap_or(false);
            if has_live_session {
                // Existing session for this peer — forward the payload to it.
                let _ = sessions
                    .get(&source)
                    .expect("checked present")
                    .send(payload);
            } else {
                // New (or ended) source peer — mint a fresh responder session.
                sessions.remove(&source);
                let (tx, rx) = mpsc::unbounded_channel();
                let _ = tx.send(payload);
                sessions.insert(source.clone(), tx);
                on_session(RelayCarrierSession::responder(
                    source,
                    local_peer_id.clone(),
                    writer.clone(),
                    rx,
                ));
            }
            line.clear();
        }
    }
}

async fn handle_connection(stream: TcpStream, registry: RelayRegistry) -> Result<()> {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut registered_peer: Option<String> = None;
    let mut pending_writer = Some(writer);

    while reader.read_line(&mut line).await? != 0 {
        match serde_json::from_str::<RelayMessage>(line.trim_end()) {
            Ok(RelayMessage::Register { peer_id }) => {
                if let Some(mut writer) = pending_writer.take() {
                    let registered = RelayMessage::Registered {
                        peer_id: peer_id.clone(),
                    };
                    writer
                        .write_all(serde_json::to_string(&registered)?.as_bytes())
                        .await?;
                    writer.write_all(b"\n").await?;
                    registry.peers.lock().await.insert(peer_id.clone(), writer);
                    registered_peer = Some(peer_id);
                }
            }
            Ok(RelayMessage::Registered { .. }) => {}
            Ok(RelayMessage::Datagram {
                source,
                destination,
                payload_base64,
            }) => {
                let frame = RelayMessage::Datagram {
                    source,
                    destination: destination.clone(),
                    payload_base64,
                };
                let mut peers = registry.peers.lock().await;
                if let Some(writer) = peers.get_mut(&destination) {
                    writer
                        .write_all(serde_json::to_string(&frame)?.as_bytes())
                        .await?;
                    writer.write_all(b"\n").await?;
                }
            }
            Ok(RelayMessage::Error { .. }) => {}
            Err(error) => {
                if let Some(peer_id) = &registered_peer {
                    registry.peers.lock().await.remove(peer_id);
                }
                return Err(error.into());
            }
        }
        line.clear();
    }

    if let Some(peer_id) = registered_peer {
        registry.peers.lock().await.remove(&peer_id);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn relay_client_forwards_datagrams_between_registered_peers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = RelayRegistry::default();

        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let registry = registry.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, registry).await;
                });
            }
        });

        let mut alice = RelayClient::connect(&addr.to_string(), "alice")
            .await
            .unwrap();
        let mut bob = RelayClient::connect(&addr.to_string(), "bob")
            .await
            .unwrap();

        alice.send_datagram("bob", b"hello").await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), bob.receive_datagram())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(received.0, "alice");
        assert_eq!(received.1, b"hello");
    }

    #[tokio::test]
    async fn relay_carrier_runs_pqc_session_and_protected_frames_end_to_end() {
        use crate::carrier_transport::CarrierSession;
        use crate::crypto::DeviceKeypair;
        use crate::pqc_frame::PqcFrameProtector;
        use crate::pqc_session_wire::{run_pqc_session_initiator, run_pqc_session_responder};
        use crate::session_crypto::PqcSessionContext;

        let server = spawn_dev_relay().await.unwrap();
        let addr = server.local_addr().to_string();

        let initiator_key = DeviceKeypair::generate().unwrap();
        let responder_key = Arc::new(DeviceKeypair::generate().unwrap());
        let initiator_id = initiator_key.public_key().peer_id();
        let responder_id = responder_key.public_key().peer_id();
        let mesh_id = "relay-mesh".to_string();
        // Both sides bind to the responder's identity, mirroring the direct
        // carrier where the binding is the responder's certificate DER.
        let carrier_binding = format!("relay:{responder_id}").into_bytes();

        // Responder: demux listener that runs the responder handshake + one
        // protected-frame round-trip on the first inbound session.
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<bool>();
        let listen_addr = addr.clone();
        let responder_id_task = responder_id.clone();
        let initiator_id_task = initiator_id.clone();
        let mesh_task = mesh_id.clone();
        let binding_task = carrier_binding.clone();
        let listener = tokio::spawn(async move {
            let _ = RelayResponderListener::run(&listen_addr, responder_id_task.clone(), {
                move |session| {
                    let ctx = PqcSessionContext::new(
                        mesh_task.clone(),
                        initiator_id_task.clone(),
                        responder_id_task.clone(),
                        binding_task.clone(),
                    );
                    let key = responder_key.clone();
                    let done = done_tx.clone();
                    tokio::spawn(async move {
                        let session = CarrierSession::from(session);
                        let keys = run_pqc_session_responder(&session, ctx, &key)
                            .await
                            .unwrap();
                        let mut protector = PqcFrameProtector::new(keys);
                        // Receive the initiator's protected frame, verify it.
                        let protected = session.receive_frame().await.unwrap();
                        let plaintext = protector.open(&protected).unwrap();
                        assert_eq!(plaintext, b"relay-payload");
                        let _ = done.send(true);
                    });
                }
            })
            .await;
        });

        // Give the responder a moment to register with the relay.
        tokio::time::sleep(Duration::from_millis(150)).await;

        let session = RelayCarrierSession::connect_initiator(
            &addr,
            initiator_id.clone(),
            responder_id.clone(),
        )
        .await
        .unwrap();
        let session = CarrierSession::from(session);
        let ctx = PqcSessionContext::new(
            mesh_id.clone(),
            initiator_id.clone(),
            responder_id.clone(),
            carrier_binding.clone(),
        );
        let initiator_keys = run_pqc_session_initiator(&session, ctx, &initiator_key)
            .await
            .unwrap();

        // Data plane: send one protected frame the responder must decrypt.
        let mut protector = PqcFrameProtector::new(initiator_keys);
        let protected = protector.protect(b"relay-payload").unwrap();
        session.send_frame(protected).await.unwrap();

        let confirmed = tokio::time::timeout(Duration::from_secs(3), done_rx.recv())
            .await
            .expect("responder did not finish in time")
            .expect("responder channel closed");
        assert!(confirmed);
        listener.abort();
    }
}
