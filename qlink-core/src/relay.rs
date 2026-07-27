#[cfg(feature = "public-edge-tls")]
use crate::control_transport::{load_tls_acceptor, ControlTlsServerConfig};
use crate::{
    admission::{
        service_token_revocation_digest, AdmissionLimiter, ServiceAdmissionConfig, ServiceLimits,
        ServiceLimitsConfig,
    },
    control_transport::{
        connect_control_stream, split_control_stream, BoxedControlReader, BoxedControlWriter,
    },
    error::{QlinkError, Result},
    service_metrics::ServiceMetrics,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::{mpsc, Mutex},
    task::JoinHandle,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayMessage {
    Register {
        peer_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_token: Option<String>,
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
    peers: Arc<Mutex<HashMap<String, BoxedControlWriter>>>,
    peer_auth_token_digests: Arc<Mutex<HashMap<String, String>>>,
    peer_datagram_buckets: Arc<Mutex<HashMap<String, RelayPeerDatagramBucket>>>,
}

#[derive(Debug, Clone)]
struct RelayPeerDatagramBucket {
    window_started: tokio::time::Instant,
    count: u32,
}

pub async fn run_relay(listen: &str) -> Result<()> {
    run_relay_with_config(listen, ServiceAdmissionConfig::default()).await
}

pub async fn run_relay_with_config(listen: &str, admission: ServiceAdmissionConfig) -> Result<()> {
    run_relay_with_metrics_and_limits(
        listen,
        admission,
        ServiceMetrics::default(),
        ServiceLimitsConfig::default(),
    )
    .await
}

pub async fn run_relay_with_metrics(
    listen: &str,
    admission: ServiceAdmissionConfig,
    metrics: ServiceMetrics,
) -> Result<()> {
    run_relay_with_metrics_and_limits(listen, admission, metrics, ServiceLimitsConfig::default())
        .await
}

pub async fn run_relay_with_metrics_and_limits(
    listen: &str,
    admission: ServiceAdmissionConfig,
    metrics: ServiceMetrics,
    limits: ServiceLimitsConfig,
) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let registry = RelayRegistry::default();
    serve_relay_with_config_metrics_and_limits(listener, registry, admission, metrics, limits).await
}

#[cfg(feature = "public-edge-tls")]
pub async fn run_relay_with_optional_tls(
    listen: &str,
    admission: ServiceAdmissionConfig,
    tls: Option<ControlTlsServerConfig>,
) -> Result<()> {
    run_relay_with_optional_tls_and_metrics(listen, admission, tls, ServiceMetrics::default()).await
}

#[cfg(feature = "public-edge-tls")]
pub async fn run_relay_with_optional_tls_and_metrics(
    listen: &str,
    admission: ServiceAdmissionConfig,
    tls: Option<ControlTlsServerConfig>,
    metrics: ServiceMetrics,
) -> Result<()> {
    run_relay_with_optional_tls_metrics_and_limits(
        listen,
        admission,
        tls,
        metrics,
        ServiceLimitsConfig::default(),
    )
    .await
}

#[cfg(feature = "public-edge-tls")]
pub async fn run_relay_with_optional_tls_metrics_and_limits(
    listen: &str,
    admission: ServiceAdmissionConfig,
    tls: Option<ControlTlsServerConfig>,
    metrics: ServiceMetrics,
    limits: ServiceLimitsConfig,
) -> Result<()> {
    match tls {
        Some(tls) => {
            let listener = TcpListener::bind(listen).await?;
            let registry = RelayRegistry::default();
            serve_relay_with_tls_metrics_and_limits(
                listener, registry, admission, tls, metrics, limits,
            )
            .await
        }
        None => run_relay_with_metrics_and_limits(listen, admission, metrics, limits).await,
    }
}

pub async fn serve_relay(listener: TcpListener, registry: RelayRegistry) -> Result<()> {
    serve_relay_with_config(listener, registry, ServiceAdmissionConfig::default()).await
}

pub async fn serve_relay_with_config(
    listener: TcpListener,
    registry: RelayRegistry,
    admission: ServiceAdmissionConfig,
) -> Result<()> {
    serve_relay_with_config_and_metrics(listener, registry, admission, ServiceMetrics::default())
        .await
}

pub async fn serve_relay_with_config_and_metrics(
    listener: TcpListener,
    registry: RelayRegistry,
    admission: ServiceAdmissionConfig,
    metrics: ServiceMetrics,
) -> Result<()> {
    serve_relay_with_config_metrics_and_limits(
        listener,
        registry,
        admission,
        metrics,
        ServiceLimitsConfig::default(),
    )
    .await
}

pub async fn serve_relay_with_config_metrics_and_limits(
    listener: TcpListener,
    registry: RelayRegistry,
    admission: ServiceAdmissionConfig,
    metrics: ServiceMetrics,
    limits: ServiceLimitsConfig,
) -> Result<()> {
    let limiter = AdmissionLimiter::new(&admission);
    let service_limits = ServiceLimits::new(limits);
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let connection_permit = match service_limits.try_start_connection("relay") {
            Ok(permit) => permit,
            Err(error) => {
                metrics.connection_limit_rejection();
                tracing::warn!(?error, %peer_addr, "relay connection rejected");
                continue;
            }
        };
        let registry = registry.clone();
        let admission = admission.clone();
        let limiter = limiter.clone();
        let metrics = metrics.clone();
        let limits = service_limits.config();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            let _connection = metrics.connection_started();
            if let Err(error) = handle_connection(
                stream, registry, admission, limiter, peer_addr, metrics, limits,
            )
            .await
            {
                tracing::warn!(?error, "relay connection failed");
            }
        });
    }
}

#[cfg(feature = "public-edge-tls")]
pub async fn serve_relay_with_tls(
    listener: TcpListener,
    registry: RelayRegistry,
    admission: ServiceAdmissionConfig,
    tls: ControlTlsServerConfig,
) -> Result<()> {
    serve_relay_with_tls_and_metrics(
        listener,
        registry,
        admission,
        tls,
        ServiceMetrics::default(),
    )
    .await
}

#[cfg(feature = "public-edge-tls")]
pub async fn serve_relay_with_tls_and_metrics(
    listener: TcpListener,
    registry: RelayRegistry,
    admission: ServiceAdmissionConfig,
    tls: ControlTlsServerConfig,
    metrics: ServiceMetrics,
) -> Result<()> {
    serve_relay_with_tls_metrics_and_limits(
        listener,
        registry,
        admission,
        tls,
        metrics,
        ServiceLimitsConfig::default(),
    )
    .await
}

#[cfg(feature = "public-edge-tls")]
pub async fn serve_relay_with_tls_metrics_and_limits(
    listener: TcpListener,
    registry: RelayRegistry,
    admission: ServiceAdmissionConfig,
    tls: ControlTlsServerConfig,
    metrics: ServiceMetrics,
    limits: ServiceLimitsConfig,
) -> Result<()> {
    let acceptor = load_tls_acceptor(&tls)?;
    let limiter = AdmissionLimiter::new(&admission);
    let service_limits = ServiceLimits::new(limits);
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let connection_permit = match service_limits.try_start_connection("relay") {
            Ok(permit) => permit,
            Err(error) => {
                metrics.connection_limit_rejection();
                tracing::warn!(?error, %peer_addr, "relay TLS connection rejected");
                continue;
            }
        };
        let registry = registry.clone();
        let admission = admission.clone();
        let limiter = limiter.clone();
        let acceptor = acceptor.clone();
        let metrics = metrics.clone();
        let limits = service_limits.config();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            let _connection = metrics.connection_started();
            let result = async {
                let stream = acceptor.accept(stream).await.map_err(|err| {
                    QlinkError::Protocol(format!("relay TLS handshake failed: {err}"))
                })?;
                handle_connection(
                    stream, registry, admission, limiter, peer_addr, metrics, limits,
                )
                .await
            }
            .await;
            if let Err(error) = result {
                tracing::warn!(?error, "relay TLS connection failed");
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

pub async fn probe_relay_registration(
    server: &str,
    peer_id: impl Into<String>,
    auth_token: Option<&str>,
) -> Result<()> {
    RelayClient::connect_with_auth(server, peer_id, auth_token)
        .await
        .map(|_| ())
}

struct RelayClient {
    #[cfg(test)]
    peer_id: String,
    reader: BufReader<BoxedControlReader>,
    writer: BoxedControlWriter,
}

impl RelayClient {
    #[cfg(test)]
    async fn connect(server: &str, peer_id: impl Into<String>) -> Result<Self> {
        Self::connect_with_auth(server, peer_id, None).await
    }

    async fn connect_with_auth(
        server: &str,
        peer_id: impl Into<String>,
        auth_token: Option<&str>,
    ) -> Result<Self> {
        let stream = connect_control_stream(server, None).await?;
        let (reader, mut writer) = split_control_stream(stream);
        let peer_id = peer_id.into();
        let register = RelayMessage::Register {
            peer_id: peer_id.clone(),
            auth_token: auth_token.map(|token| token.to_string()),
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
            #[cfg(test)]
            peer_id,
            reader,
            writer,
        })
    }

    #[cfg(test)]
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

    #[cfg(test)]
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
    writer: Arc<Mutex<BoxedControlWriter>>,
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
        reader: BufReader<BoxedControlReader>,
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
        Self::connect_initiator_with_auth(server, local_peer_id, remote_peer_id, None).await
    }

    pub async fn connect_initiator_with_auth(
        server: &str,
        local_peer_id: impl Into<String>,
        remote_peer_id: impl Into<String>,
        auth_token: Option<&str>,
    ) -> Result<Self> {
        let local_peer_id = local_peer_id.into();
        let remote_peer_id = remote_peer_id.into();
        let stream = connect_control_stream(server, None).await?;
        let (reader, mut writer) = split_control_stream(stream);
        writer
            .write_all(
                serde_json::to_string(&RelayMessage::Register {
                    peer_id: local_peer_id.clone(),
                    auth_token: auth_token.map(|token| token.to_string()),
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
        writer: Arc<Mutex<BoxedControlWriter>>,
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
    pub async fn run<F>(server: &str, local_peer_id: String, on_session: F) -> Result<()>
    where
        F: FnMut(RelayCarrierSession),
    {
        Self::run_with_auth(server, local_peer_id, None, on_session).await
    }

    pub async fn run_with_auth<F>(
        server: &str,
        local_peer_id: String,
        auth_token: Option<&str>,
        mut on_session: F,
    ) -> Result<()>
    where
        F: FnMut(RelayCarrierSession),
    {
        let client =
            RelayClient::connect_with_auth(server, local_peer_id.clone(), auth_token).await?;
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

async fn handle_connection(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    registry: RelayRegistry,
    admission: ServiceAdmissionConfig,
    limiter: AdmissionLimiter,
    peer_addr: SocketAddr,
    metrics: ServiceMetrics,
    limits: ServiceLimitsConfig,
) -> Result<()> {
    let (reader, writer) = split_control_stream(stream);
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    let mut registered_peer: Option<String> = None;
    let mut pending_writer = Some(writer);

    loop {
        match read_bounded_line(&mut reader, &mut line, limits, "relay", &metrics).await {
            Ok(true) => {}
            Ok(false) => break,
            Err(error) => {
                if let Some(writer) = pending_writer.as_mut() {
                    write_relay_error(writer, &error.to_string()).await?;
                }
                break;
            }
        }
        if let Err(error) = limiter.check(peer_addr, "relay").await {
            metrics.rate_limited();
            if let Some(writer) = pending_writer.as_mut() {
                write_relay_error(writer, &error.to_string()).await?;
            }
            break;
        }
        match serde_json::from_slice::<RelayMessage>(trim_line(&line)) {
            Ok(RelayMessage::Register {
                peer_id,
                auth_token,
            }) => {
                if peer_id.len() > limits.relay_max_peer_id_bytes {
                    metrics.relay_registration_rejection();
                    if let Some(writer) = pending_writer.as_mut() {
                        write_relay_error(
                            writer,
                            &format!(
                                "relay peer ID exceeds {} bytes",
                                limits.relay_max_peer_id_bytes
                            ),
                        )
                        .await?;
                    }
                    break;
                }
                if admission.token_is_revoked(auth_token.as_deref())? {
                    metrics.auth_revocation();
                    if let Some(writer) = pending_writer.as_mut() {
                        write_relay_error(writer, "relay authentication failed").await?;
                    }
                    break;
                }
                if let Err(error) = admission.require_token(auth_token.as_deref(), "relay") {
                    metrics.auth_failure();
                    if let Some(writer) = pending_writer.as_mut() {
                        write_relay_error(writer, &error.to_string()).await?;
                    }
                    break;
                }
                if let Some(mut writer) = pending_writer.take() {
                    let mut peers = registry.peers.lock().await;
                    if peers.contains_key(&peer_id) {
                        metrics.relay_duplicate_registration_rejection();
                        write_relay_error(&mut writer, "relay peer ID is already registered")
                            .await?;
                        break;
                    }
                    if peers.len() >= limits.relay_max_registered_peers {
                        metrics.relay_registration_rejection();
                        write_relay_error(
                            &mut writer,
                            &format!(
                                "relay registered peer limit exceeded: {}",
                                limits.relay_max_registered_peers
                            ),
                        )
                        .await?;
                        break;
                    }
                    let registered = RelayMessage::Registered {
                        peer_id: peer_id.clone(),
                    };
                    writer
                        .write_all(serde_json::to_string(&registered)?.as_bytes())
                        .await?;
                    writer.write_all(b"\n").await?;
                    peers.insert(peer_id.clone(), writer);
                    if let Some(auth_token) = auth_token.as_deref() {
                        registry
                            .peer_auth_token_digests
                            .lock()
                            .await
                            .insert(peer_id.clone(), service_token_revocation_digest(auth_token));
                    }
                    metrics.relay_registration();
                    metrics.request_succeeded();
                    registered_peer = Some(peer_id);
                }
            }
            Ok(RelayMessage::Registered { .. }) => {}
            Ok(RelayMessage::Datagram {
                source,
                destination,
                payload_base64,
            }) => {
                if source.len() > limits.relay_max_peer_id_bytes
                    || destination.len() > limits.relay_max_peer_id_bytes
                {
                    metrics.malformed_request();
                    if let Some(peer_id) = &registered_peer {
                        end_relay_registration(&registry, peer_id, &metrics).await;
                    }
                    return Err(QlinkError::Protocol(format!(
                        "relay peer ID exceeds {} bytes",
                        limits.relay_max_peer_id_bytes
                    )));
                }
                if encoded_payload_exceeds_limit(&payload_base64, limits.relay_max_payload_bytes) {
                    metrics.relay_payload_too_large();
                    if let Some(peer_id) = &registered_peer {
                        end_relay_registration(&registry, peer_id, &metrics).await;
                    }
                    return Err(QlinkError::Protocol(format!(
                        "relay datagram payload exceeds {} bytes",
                        limits.relay_max_payload_bytes
                    )));
                }
                if registered_peer.as_deref() != Some(source.as_str()) {
                    metrics.relay_spoofed_source_rejection();
                    if let Some(peer_id) = &registered_peer {
                        end_relay_registration(&registry, peer_id, &metrics).await;
                    }
                    return Err(QlinkError::Protocol(
                        "relay datagram source does not match registered peer".into(),
                    ));
                }
                if registered_relay_peer_is_revoked(&registry, &admission, &source).await? {
                    metrics.auth_revocation();
                    end_relay_registration(&registry, &source, &metrics).await;
                    return Err(QlinkError::Protocol("relay authentication failed".into()));
                }
                if let Err(error) =
                    check_peer_datagram_quota(&registry, &source, limits, &metrics).await
                {
                    if let Some(peer_id) = &registered_peer {
                        end_relay_registration(&registry, peer_id, &metrics).await;
                    }
                    return Err(error);
                }
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
                    metrics.relay_forwarded_datagram();
                    metrics.request_succeeded();
                } else {
                    metrics.relay_unknown_destination_drop();
                }
            }
            Ok(RelayMessage::Error { .. }) => {}
            Err(error) => {
                metrics.malformed_request();
                if let Some(peer_id) = &registered_peer {
                    end_relay_registration(&registry, peer_id, &metrics).await;
                }
                return Err(error.into());
            }
        }
        line.clear();
    }

    if let Some(peer_id) = registered_peer {
        end_relay_registration(&registry, &peer_id, &metrics).await;
    }

    Ok(())
}

async fn check_peer_datagram_quota(
    registry: &RelayRegistry,
    peer_id: &str,
    limits: ServiceLimitsConfig,
    metrics: &ServiceMetrics,
) -> Result<()> {
    if limits.relay_max_peer_datagrams_per_window == 0
        || limits.relay_peer_datagram_window.is_zero()
    {
        return Ok(());
    }
    let now = tokio::time::Instant::now();
    let mut buckets = registry.peer_datagram_buckets.lock().await;
    let bucket = buckets
        .entry(peer_id.to_string())
        .or_insert_with(|| RelayPeerDatagramBucket {
            window_started: now,
            count: 0,
        });
    if now.duration_since(bucket.window_started) >= limits.relay_peer_datagram_window {
        bucket.window_started = now;
        bucket.count = 0;
    }
    if bucket.count >= limits.relay_max_peer_datagrams_per_window {
        metrics.relay_peer_rate_limited();
        return Err(QlinkError::Protocol(format!(
            "relay peer datagram rate exceeded: {} per {}s",
            limits.relay_max_peer_datagrams_per_window,
            limits.relay_peer_datagram_window.as_secs()
        )));
    }
    bucket.count += 1;
    Ok(())
}

async fn end_relay_registration(registry: &RelayRegistry, peer_id: &str, metrics: &ServiceMetrics) {
    registry.peers.lock().await.remove(peer_id);
    registry
        .peer_auth_token_digests
        .lock()
        .await
        .remove(peer_id);
    registry.peer_datagram_buckets.lock().await.remove(peer_id);
    metrics.relay_registration_ended();
}

async fn registered_relay_peer_is_revoked(
    registry: &RelayRegistry,
    admission: &ServiceAdmissionConfig,
    peer_id: &str,
) -> Result<bool> {
    let digest = registry
        .peer_auth_token_digests
        .lock()
        .await
        .get(peer_id)
        .cloned();
    admission.token_digest_is_revoked(digest.as_deref())
}

async fn read_bounded_line<R: AsyncRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
    limits: ServiceLimitsConfig,
    service: &str,
    metrics: &ServiceMetrics,
) -> Result<bool> {
    line.clear();
    loop {
        let mut byte = [0_u8; 1];
        let read = if limits.idle_timeout.is_zero() {
            reader.read(&mut byte).await?
        } else {
            match tokio::time::timeout(limits.idle_timeout, reader.read(&mut byte)).await {
                Ok(result) => result?,
                Err(_) => {
                    metrics.idle_timeout();
                    return Err(QlinkError::Protocol(format!(
                        "{service} idle timeout exceeded"
                    )));
                }
            }
        };
        if read == 0 {
            return Ok(!line.is_empty());
        }
        line.push(byte[0]);
        if line.len() > limits.max_request_line_bytes {
            metrics.request_too_large();
            return Err(QlinkError::Protocol(format!(
                "{service} request line exceeds {} bytes",
                limits.max_request_line_bytes
            )));
        }
        if byte[0] == b'\n' {
            return Ok(true);
        }
    }
}

fn trim_line(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn encoded_payload_exceeds_limit(payload_base64: &str, max_payload_bytes: usize) -> bool {
    decoded_payload_len_upper_bound(payload_base64) > max_payload_bytes
}

fn decoded_payload_len_upper_bound(payload_base64: &str) -> usize {
    let padding = payload_base64
        .as_bytes()
        .iter()
        .rev()
        .take_while(|byte| **byte == b'=')
        .count()
        .min(2);
    payload_base64
        .len()
        .saturating_add(3)
        .saturating_div(4)
        .saturating_mul(3)
        .saturating_sub(padding)
}

async fn write_relay_error(writer: &mut BoxedControlWriter, message: &str) -> Result<()> {
    let response = RelayMessage::Error {
        message: message.to_string(),
    };
    writer
        .write_all(serde_json::to_string(&response)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn spawn_configured_relay(
        admission: ServiceAdmissionConfig,
    ) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = RelayRegistry::default();
        let task = tokio::spawn(async move {
            let _ = serve_relay_with_config(listener, registry, admission).await;
        });
        (addr, task)
    }

    async fn spawn_limited_relay(
        admission: ServiceAdmissionConfig,
        limits: ServiceLimitsConfig,
        metrics: ServiceMetrics,
    ) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = RelayRegistry::default();
        let task = tokio::spawn(async move {
            let _ = serve_relay_with_config_metrics_and_limits(
                listener, registry, admission, metrics, limits,
            )
            .await;
        });
        (addr, task)
    }

    #[tokio::test]
    async fn relay_client_forwards_datagrams_between_registered_peers() {
        let (addr, _task) = spawn_configured_relay(ServiceAdmissionConfig::open()).await;

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
    async fn relay_registration_requires_configured_auth_token() {
        let (addr, _task) =
            spawn_configured_relay(ServiceAdmissionConfig::open().with_auth_token("relay-secret"))
                .await;

        let missing = match RelayClient::connect(&addr.to_string(), "alice").await {
            Ok(_) => panic!("relay accepted registration without auth token"),
            Err(error) => error,
        };
        assert!(missing.to_string().contains("authentication failed"));

        RelayClient::connect_with_auth(&addr.to_string(), "alice", Some("relay-secret"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn relay_rejects_spoofed_datagram_source() {
        let (addr, _task) = spawn_configured_relay(ServiceAdmissionConfig::open()).await;
        let mut alice = RelayClient::connect(&addr.to_string(), "alice")
            .await
            .unwrap();
        let mut bob = RelayClient::connect(&addr.to_string(), "bob")
            .await
            .unwrap();
        let spoofed = RelayMessage::Datagram {
            source: "mallory".to_string(),
            destination: "bob".to_string(),
            payload_base64: STANDARD.encode(b"spoofed"),
        };
        alice
            .writer
            .write_all(serde_json::to_string(&spoofed).unwrap().as_bytes())
            .await
            .unwrap();
        alice.writer.write_all(b"\n").await.unwrap();

        let received =
            tokio::time::timeout(Duration::from_millis(100), bob.receive_datagram()).await;
        assert!(received.is_err());
    }

    #[tokio::test]
    async fn relay_rate_limits_per_client_ip() {
        let (addr, _task) = spawn_configured_relay(
            ServiceAdmissionConfig::open().with_rate_limit(1, Duration::from_secs(60)),
        )
        .await;

        let mut alice = RelayClient::connect(&addr.to_string(), "alice")
            .await
            .unwrap();
        alice.send_datagram("bob", b"blocked").await.unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(2), alice.receive_datagram())
            .await
            .unwrap()
            .unwrap();
        assert!(closed.is_none());
    }

    #[tokio::test]
    async fn relay_records_service_metrics() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = RelayRegistry::default();
        let metrics = ServiceMetrics::default();
        let metrics_for_server = metrics.clone();
        let admission = ServiceAdmissionConfig::open().with_auth_token("relay-secret");
        let _task = tokio::spawn(async move {
            let _ = serve_relay_with_config_and_metrics(
                listener,
                registry,
                admission,
                metrics_for_server,
            )
            .await;
        });

        let missing = match RelayClient::connect(&addr.to_string(), "unauth").await {
            Ok(_) => panic!("relay accepted registration without auth token"),
            Err(error) => error,
        };
        assert!(missing.to_string().contains("authentication failed"));

        let mut alice =
            RelayClient::connect_with_auth(&addr.to_string(), "alice", Some("relay-secret"))
                .await
                .unwrap();
        let mut bob =
            RelayClient::connect_with_auth(&addr.to_string(), "bob", Some("relay-secret"))
                .await
                .unwrap();

        alice.send_datagram("bob", b"hello").await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), bob.receive_datagram())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(received.1, b"hello");

        alice.send_datagram("missing", b"dropped").await.unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;

        let rendered = metrics.snapshot("relay").render_open_metrics();
        assert!(rendered.contains("quantumlink_relay_auth_failures_total 1"));
        assert!(rendered.contains("quantumlink_relay_registrations_total 2"));
        assert!(rendered.contains("quantumlink_relay_forwarded_datagrams_total 1"));
        assert!(rendered.contains("quantumlink_relay_unknown_destination_drops_total 1"));
        assert!(rendered.contains("quantumlink_relay_requests_succeeded_total 3"));
    }

    #[tokio::test]
    async fn relay_rejects_revoked_auth_token() {
        let dir = tempfile::tempdir().unwrap();
        let revoked_path = dir.path().join("revoked-service-token-digests");
        std::fs::write(
            &revoked_path,
            service_token_revocation_digest("relay-secret"),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = RelayRegistry::default();
        let metrics = ServiceMetrics::default();
        let metrics_for_server = metrics.clone();
        let admission = ServiceAdmissionConfig::open()
            .with_auth_token("relay-secret")
            .with_revoked_token_digest_file(&revoked_path);
        let _task = tokio::spawn(async move {
            let _ = serve_relay_with_config_and_metrics(
                listener,
                registry,
                admission,
                metrics_for_server,
            )
            .await;
        });

        let error =
            match RelayClient::connect_with_auth(&addr.to_string(), "alice", Some("relay-secret"))
                .await
            {
                Ok(_) => panic!("relay accepted registration with a revoked auth token"),
                Err(error) => error,
            };
        assert!(error.to_string().contains("authentication failed"));

        let rendered = metrics.snapshot("relay").render_open_metrics();
        assert!(rendered.contains("quantumlink_relay_auth_revocations_total 1"));
        assert!(rendered.contains("quantumlink_relay_auth_failures_total 1"));
    }

    #[tokio::test]
    async fn relay_rejects_duplicate_registrations_and_oversized_payloads() {
        let metrics = ServiceMetrics::default();
        let limits = ServiceLimitsConfig::default().with_relay_max_payload_bytes(3);
        let (addr, _task) =
            spawn_limited_relay(ServiceAdmissionConfig::open(), limits, metrics.clone()).await;

        let mut alice = RelayClient::connect(&addr.to_string(), "alice")
            .await
            .unwrap();
        let duplicate = match RelayClient::connect(&addr.to_string(), "alice").await {
            Ok(_) => panic!("relay accepted duplicate registration"),
            Err(error) => error,
        };
        assert!(duplicate.to_string().contains("already registered"));

        alice.send_datagram("bob", b"oversized").await.unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(2), alice.receive_datagram())
            .await
            .unwrap()
            .unwrap();
        assert!(closed.is_none());
        tokio::time::sleep(Duration::from_millis(25)).await;

        let rendered = metrics.snapshot("relay").render_open_metrics();
        assert!(rendered.contains("quantumlink_relay_duplicate_registration_rejections_total 1"));
        assert!(rendered.contains("quantumlink_relay_payload_too_large_total 1"));
        assert!(rendered.contains("quantumlink_relay_registered_peers 0"));
    }

    #[tokio::test]
    async fn relay_rejects_per_peer_datagram_saturation() {
        let metrics = ServiceMetrics::default();
        let limits = ServiceLimitsConfig::default()
            .with_relay_max_peer_datagrams_per_window(1)
            .with_relay_peer_datagram_window(Duration::from_secs(60));
        let (addr, _task) =
            spawn_limited_relay(ServiceAdmissionConfig::open(), limits, metrics.clone()).await;

        let mut alice = RelayClient::connect(&addr.to_string(), "alice")
            .await
            .unwrap();

        alice.send_datagram("missing", b"first").await.unwrap();
        alice.send_datagram("missing", b"second").await.unwrap();

        let closed = tokio::time::timeout(Duration::from_secs(2), alice.receive_datagram())
            .await
            .unwrap()
            .unwrap();
        assert!(closed.is_none());
        tokio::time::sleep(Duration::from_millis(25)).await;

        let rendered = metrics.snapshot("relay").render_open_metrics();
        assert!(rendered.contains("quantumlink_relay_peer_rate_limited_total 1"));
        assert!(rendered.contains("quantumlink_relay_unknown_destination_drops_total 1"));
        assert!(rendered.contains("quantumlink_relay_registered_peers 0"));
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
