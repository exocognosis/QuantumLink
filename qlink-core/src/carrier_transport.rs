use crate::error::{QlinkError, Result};
#[cfg(feature = "dev-quic-carrier")]
use crate::quic_transport::QuicDatagramSession;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex},
    task::JoinHandle,
};

const CARRIER_MAGIC: &[u8; 6] = b"QLCAR1";
const CARRIER_VERSION: u8 = 1;
const CARRIER_HEADER_LEN: usize = CARRIER_MAGIC.len() + 1 + 1 + 4;
const MAX_UDP_DATAGRAM_LEN: usize = 1_200;
const MAX_CARRIER_PAYLOAD_LEN: usize = MAX_UDP_DATAGRAM_LEN - CARRIER_HEADER_LEN;
const FRAGMENT_HEADER_LEN: usize = 8 + 4 + 2 + 2;
const MAX_FRAGMENT_PAYLOAD_LEN: usize = MAX_CARRIER_PAYLOAD_LEN - FRAGMENT_HEADER_LEN;
const MAX_REASSEMBLED_MESSAGE_LEN: usize = 1024 * 1024;
const MAX_REASSEMBLY_ENTRIES: usize = 64;
const REASSEMBLY_TTL: Duration = Duration::from_secs(30);
const MAX_COMPLETED_FRAGMENT_KEYS: usize = 256;
const MAX_PENDING_MESSAGES: usize = 64;
const MAX_PENDING_AUTHENTICATED_MESSAGE_LEN: usize = 64 * 1024;
const MAX_LISTENER_SESSIONS: usize = 1_024;
const LISTENER_SESSION_QUEUE_DEPTH: usize = 256;
const LISTENER_ACCEPT_QUEUE_DEPTH: usize = 64;

#[derive(Debug, Clone)]
pub enum CarrierSession {
    #[cfg(feature = "dev-quic-carrier")]
    Quic(QuicDatagramSession),
    NativeUdp(NativeUdpSession),
}

impl CarrierSession {
    pub async fn send_frame(&self, frame: Vec<u8>) -> Result<()> {
        match self {
            #[cfg(feature = "dev-quic-carrier")]
            Self::Quic(session) => session.send_frame(frame).await,
            Self::NativeUdp(session) => session.send_frame(frame).await,
        }
    }

    pub async fn receive_frame(&self) -> Result<Vec<u8>> {
        match self {
            #[cfg(feature = "dev-quic-carrier")]
            Self::Quic(session) => session.receive_frame().await,
            Self::NativeUdp(session) => session.receive_frame().await,
        }
    }

    pub async fn send_authenticated_message(&self, payload: Vec<u8>) -> Result<()> {
        match self {
            #[cfg(feature = "dev-quic-carrier")]
            Self::Quic(session) => session.send_authenticated_message(payload).await,
            Self::NativeUdp(session) => session.send_authenticated_message(payload).await,
        }
    }

    pub async fn receive_authenticated_message(&self, max_size: usize) -> Result<Vec<u8>> {
        match self {
            #[cfg(feature = "dev-quic-carrier")]
            Self::Quic(session) => session.receive_authenticated_message(max_size).await,
            Self::NativeUdp(session) => session.receive_authenticated_message(max_size).await,
        }
    }

    pub fn close(&self, reason: &[u8]) {
        match self {
            #[cfg(feature = "dev-quic-carrier")]
            Self::Quic(session) => session.close(reason),
            Self::NativeUdp(session) => session.close(reason),
        }
    }
}

#[cfg(feature = "dev-quic-carrier")]
impl From<QuicDatagramSession> for CarrierSession {
    fn from(session: QuicDatagramSession) -> Self {
        Self::Quic(session)
    }
}

impl From<NativeUdpSession> for CarrierSession {
    fn from(session: NativeUdpSession) -> Self {
        Self::NativeUdp(session)
    }
}

#[derive(Debug, Clone)]
pub struct NativeUdpSession {
    socket: Arc<UdpSocket>,
    remote_addr: Option<SocketAddr>,
    listener_rx: Option<Arc<Mutex<mpsc::Receiver<Vec<u8>>>>>,
    listener_sessions: Option<Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>>,
    recv_lock: Arc<Mutex<()>>,
    pending_frames: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pending_authenticated: Arc<Mutex<VecDeque<Vec<u8>>>>,
    reassembly: Arc<Mutex<HashMap<FragmentKey, FragmentBuffer>>>,
    completed_fragments: Arc<Mutex<CompletedFragmentKeys>>,
    next_message_id: Arc<AtomicU64>,
}

/// Multiplexes successive native UDP sessions on one stable responder socket.
/// Each remote address receives a bounded queue and an independent session
/// object; malformed datagrams never allocate a session.
pub struct NativeUdpListener {
    accept_rx: Mutex<mpsc::Receiver<(NativeUdpSession, SocketAddr)>>,
    dispatcher: JoinHandle<()>,
}

impl NativeUdpListener {
    pub fn new(socket: UdpSocket) -> Self {
        let socket = Arc::new(socket);
        let sessions = Arc::new(Mutex::new(
            HashMap::<SocketAddr, mpsc::Sender<Vec<u8>>>::new(),
        ));
        let (accept_tx, accept_rx) = mpsc::channel(LISTENER_ACCEPT_QUEUE_DEPTH);
        let dispatcher_socket = socket.clone();
        let dispatcher_sessions = sessions.clone();
        let dispatcher = tokio::spawn(async move {
            let mut buffer = vec![0_u8; MAX_UDP_DATAGRAM_LEN + 1];
            loop {
                let Ok((len, peer_addr)) = dispatcher_socket.recv_from(&mut buffer).await else {
                    break;
                };
                if len > MAX_UDP_DATAGRAM_LEN {
                    continue;
                }
                let bytes = buffer[..len].to_vec();
                let Ok(datagram) = decode_datagram(&bytes) else {
                    continue;
                };

                let mut sessions_guard = dispatcher_sessions.lock().await;
                if let Some(sender) = sessions_guard.get(&peer_addr).cloned() {
                    if sender.try_send(bytes.clone()).is_ok() {
                        if datagram.kind == DatagramKind::Close {
                            sessions_guard.remove(&peer_addr);
                        }
                        continue;
                    } else {
                        sessions_guard.remove(&peer_addr);
                    }
                }
                if datagram.kind == DatagramKind::Close
                    || sessions_guard.len() >= MAX_LISTENER_SESSIONS
                {
                    continue;
                }

                let (session_tx, session_rx) = mpsc::channel(LISTENER_SESSION_QUEUE_DEPTH);
                if session_tx.try_send(bytes).is_err() {
                    continue;
                }
                sessions_guard.insert(peer_addr, session_tx);
                let session = NativeUdpSession::from_listener(
                    dispatcher_socket.clone(),
                    peer_addr,
                    session_rx,
                    dispatcher_sessions.clone(),
                );
                if accept_tx.try_send((session, peer_addr)).is_err() {
                    sessions_guard.remove(&peer_addr);
                }
            }
        });
        Self {
            accept_rx: Mutex::new(accept_rx),
            dispatcher,
        }
    }

    pub async fn accept(&self) -> Result<(NativeUdpSession, SocketAddr)> {
        self.accept_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| QlinkError::Protocol("native UDP listener stopped".into()))
    }
}

impl Drop for NativeUdpListener {
    fn drop(&mut self) {
        self.dispatcher.abort();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MessageKind {
    Frame,
    AuthenticatedMessage,
}

impl MessageKind {
    fn complete_datagram_kind(self) -> DatagramKind {
        match self {
            Self::Frame => DatagramKind::Frame,
            Self::AuthenticatedMessage => DatagramKind::AuthenticatedMessage,
        }
    }

    fn fragment_datagram_kind(self) -> DatagramKind {
        match self {
            Self::Frame => DatagramKind::FrameFragment,
            Self::AuthenticatedMessage => DatagramKind::AuthenticatedFragment,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatagramKind {
    Frame,
    AuthenticatedMessage,
    Close,
    FrameFragment,
    AuthenticatedFragment,
}

impl DatagramKind {
    fn wire_value(self) -> u8 {
        match self {
            Self::Frame => 1,
            Self::AuthenticatedMessage => 2,
            Self::Close => 3,
            Self::FrameFragment => 4,
            Self::AuthenticatedFragment => 5,
        }
    }

    fn from_wire(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Frame),
            2 => Ok(Self::AuthenticatedMessage),
            3 => Ok(Self::Close),
            4 => Ok(Self::FrameFragment),
            5 => Ok(Self::AuthenticatedFragment),
            _ => Err(QlinkError::Protocol(format!(
                "unsupported native carrier datagram kind {value}"
            ))),
        }
    }

    fn message_kind(self) -> Option<MessageKind> {
        match self {
            Self::Frame | Self::FrameFragment => Some(MessageKind::Frame),
            Self::AuthenticatedMessage | Self::AuthenticatedFragment => {
                Some(MessageKind::AuthenticatedMessage)
            }
            Self::Close => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ReceiveLimits {
    authenticated_message_max: usize,
}

impl ReceiveLimits {
    fn new(authenticated_message_max: usize) -> Self {
        Self {
            authenticated_message_max,
        }
    }

    fn for_wanted(wanted: MessageKind, max_size: usize) -> Self {
        match wanted {
            MessageKind::AuthenticatedMessage => Self::new(max_size),
            MessageKind::Frame => Self::new(MAX_PENDING_AUTHENTICATED_MESSAGE_LEN),
        }
    }
}

impl NativeUdpSession {
    pub async fn loopback_pair() -> Result<(Self, Self)> {
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let left = UdpSocket::bind(bind).await.map_err(|err| {
            QlinkError::Protocol(format!("failed to bind native UDP left socket: {err}"))
        })?;
        let right = UdpSocket::bind(bind).await.map_err(|err| {
            QlinkError::Protocol(format!("failed to bind native UDP right socket: {err}"))
        })?;
        let left_addr = left.local_addr().map_err(|err| {
            QlinkError::Protocol(format!("failed to read native UDP left address: {err}"))
        })?;
        let right_addr = right.local_addr().map_err(|err| {
            QlinkError::Protocol(format!("failed to read native UDP right address: {err}"))
        })?;
        left.connect(right_addr).await.map_err(|err| {
            QlinkError::Protocol(format!("failed to connect native UDP left socket: {err}"))
        })?;
        right.connect(left_addr).await.map_err(|err| {
            QlinkError::Protocol(format!("failed to connect native UDP right socket: {err}"))
        })?;

        Ok((Self::from_socket(left), Self::from_socket(right)))
    }

    pub async fn connect(bind_addr: SocketAddr, remote_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await.map_err(|err| {
            QlinkError::Protocol(format!("failed to bind native UDP socket: {err}"))
        })?;
        socket.connect(remote_addr).await.map_err(|err| {
            QlinkError::Protocol(format!(
                "failed to connect native UDP socket to {remote_addr}: {err}"
            ))
        })?;
        Ok(Self::from_socket(socket))
    }

    pub async fn accept_on(socket: UdpSocket) -> Result<(Self, SocketAddr)> {
        let mut buf = vec![0_u8; MAX_UDP_DATAGRAM_LEN + 1];
        let (len, peer_addr) = socket.recv_from(&mut buf).await.map_err(|err| {
            QlinkError::Protocol(format!("failed to accept native UDP datagram: {err}"))
        })?;
        if len > MAX_UDP_DATAGRAM_LEN {
            return Err(QlinkError::Protocol(format!(
                "native UDP carrier datagram exceeds {MAX_UDP_DATAGRAM_LEN} bytes"
            )));
        }
        let datagram = decode_datagram(&buf[..len])?;
        socket.connect(peer_addr).await.map_err(|err| {
            QlinkError::Protocol(format!(
                "failed to connect native UDP accepted socket to {peer_addr}: {err}"
            ))
        })?;

        let session = Self::from_socket(socket);
        if let Some((kind, payload)) = session
            .accept_datagram(
                datagram,
                ReceiveLimits::new(MAX_PENDING_AUTHENTICATED_MESSAGE_LEN),
            )
            .await?
        {
            session.push_pending(kind, payload).await?;
        }
        Ok((session, peer_addr))
    }

    fn from_socket(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
            remote_addr: None,
            listener_rx: None,
            listener_sessions: None,
            recv_lock: Arc::new(Mutex::new(())),
            pending_frames: Arc::new(Mutex::new(VecDeque::new())),
            pending_authenticated: Arc::new(Mutex::new(VecDeque::new())),
            reassembly: Arc::new(Mutex::new(HashMap::new())),
            completed_fragments: Arc::new(Mutex::new(CompletedFragmentKeys::default())),
            next_message_id: Arc::new(AtomicU64::new(1)),
        }
    }

    fn from_listener(
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        listener_rx: mpsc::Receiver<Vec<u8>>,
        listener_sessions: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
    ) -> Self {
        Self {
            socket,
            remote_addr: Some(remote_addr),
            listener_rx: Some(Arc::new(Mutex::new(listener_rx))),
            listener_sessions: Some(listener_sessions),
            recv_lock: Arc::new(Mutex::new(())),
            pending_frames: Arc::new(Mutex::new(VecDeque::new())),
            pending_authenticated: Arc::new(Mutex::new(VecDeque::new())),
            reassembly: Arc::new(Mutex::new(HashMap::new())),
            completed_fragments: Arc::new(Mutex::new(CompletedFragmentKeys::default())),
            next_message_id: Arc::new(AtomicU64::new(1)),
        }
    }

    async fn send_datagram(&self, kind: DatagramKind, payload: Vec<u8>) -> Result<()> {
        let datagram = encode_datagram(kind, &payload)?;
        if let Some(remote_addr) = self.remote_addr {
            self.socket
                .send_to(&datagram, remote_addr)
                .await
                .map_err(|err| {
                    QlinkError::Protocol(format!("failed to send native UDP datagram: {err}"))
                })?;
        } else {
            self.socket.send(&datagram).await.map_err(|err| {
                QlinkError::Protocol(format!("failed to send native UDP datagram: {err}"))
            })?;
        }
        Ok(())
    }

    pub async fn send_frame(&self, frame: Vec<u8>) -> Result<()> {
        self.send_message(MessageKind::Frame, frame).await
    }

    pub async fn receive_frame(&self) -> Result<Vec<u8>> {
        self.receive_message(MessageKind::Frame, usize::MAX).await
    }

    pub async fn send_authenticated_message(&self, payload: Vec<u8>) -> Result<()> {
        self.send_message(MessageKind::AuthenticatedMessage, payload)
            .await
    }

    pub async fn receive_authenticated_message(&self, max_size: usize) -> Result<Vec<u8>> {
        self.receive_message(MessageKind::AuthenticatedMessage, max_size)
            .await
    }

    pub fn close(&self, reason: &[u8]) {
        let Ok(datagram) = encode_datagram(DatagramKind::Close, reason) else {
            return;
        };
        if let Some(remote_addr) = self.remote_addr {
            let _ = self.socket.try_send_to(&datagram, remote_addr);
            if let Some(sessions) = self.listener_sessions.as_ref() {
                if let Ok(mut sessions) = sessions.try_lock() {
                    sessions.remove(&remote_addr);
                }
            }
        } else {
            let _ = self.socket.try_send(&datagram);
        }
    }

    async fn send_message(&self, kind: MessageKind, payload: Vec<u8>) -> Result<()> {
        if payload.len() <= MAX_CARRIER_PAYLOAD_LEN {
            return self
                .send_datagram(kind.complete_datagram_kind(), payload)
                .await;
        }

        let total_len = u32::try_from(payload.len()).map_err(|_| {
            QlinkError::Protocol("native UDP carrier message exceeds u32 length".into())
        })?;
        if payload.len() > MAX_REASSEMBLED_MESSAGE_LEN {
            return Err(QlinkError::Protocol(format!(
                "native UDP carrier message is too large: {} bytes",
                payload.len()
            )));
        }
        let chunk_count = payload.len().div_ceil(MAX_FRAGMENT_PAYLOAD_LEN);
        let chunk_count_u16 = u16::try_from(chunk_count).map_err(|_| {
            QlinkError::Protocol("native UDP carrier message has too many fragments".into())
        })?;
        let message_id = self.next_message_id.fetch_add(1, Ordering::Relaxed);

        for (index, chunk) in payload.chunks(MAX_FRAGMENT_PAYLOAD_LEN).enumerate() {
            let fragment = encode_fragment_payload(
                message_id,
                total_len,
                u16::try_from(index).expect("chunk_count_u16 check bounds fragment index"),
                chunk_count_u16,
                chunk,
            )?;
            self.send_datagram(kind.fragment_datagram_kind(), fragment)
                .await?;
        }
        Ok(())
    }

    async fn receive_message(&self, wanted: MessageKind, max_size: usize) -> Result<Vec<u8>> {
        let limits = ReceiveLimits::for_wanted(wanted, max_size);
        if let Some(pending) = self.pop_pending(wanted).await {
            return validate_received_size(wanted, pending, max_size);
        }

        loop {
            let received = {
                let _guard = self.recv_lock.lock().await;
                if let Some(pending) = self.pop_pending(wanted).await {
                    Some(pending)
                } else {
                    loop {
                        let datagram = self.receive_datagram().await?;
                        let Some((kind, payload)) = self.accept_datagram(datagram, limits).await?
                        else {
                            continue;
                        };
                        if kind == wanted {
                            break Some(payload);
                        }
                        self.push_pending(kind, payload).await?;
                        break None;
                    }
                }
            };
            let Some(payload) = received else {
                tokio::task::yield_now().await;
                continue;
            };
            return validate_received_size(wanted, payload, max_size);
        }
    }

    async fn receive_datagram(&self) -> Result<CarrierDatagram> {
        if let Some(listener_rx) = self.listener_rx.as_ref() {
            let bytes = listener_rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| QlinkError::Protocol("native UDP carrier closed".into()))?;
            return decode_datagram(&bytes);
        }
        let mut buf = vec![0_u8; MAX_UDP_DATAGRAM_LEN + 1];
        let len = self.socket.recv(&mut buf).await.map_err(|err| {
            QlinkError::Protocol(format!("failed to receive native UDP datagram: {err}"))
        })?;
        if len > MAX_UDP_DATAGRAM_LEN {
            return Err(QlinkError::Protocol(format!(
                "native UDP carrier datagram exceeds {MAX_UDP_DATAGRAM_LEN} bytes"
            )));
        }
        decode_datagram(&buf[..len])
    }

    async fn accept_datagram(
        &self,
        datagram: CarrierDatagram,
        limits: ReceiveLimits,
    ) -> Result<Option<(MessageKind, Vec<u8>)>> {
        match datagram.kind {
            DatagramKind::Close => Err(QlinkError::Protocol("native UDP carrier closed".into())),
            DatagramKind::Frame | DatagramKind::AuthenticatedMessage => {
                let kind = datagram
                    .kind
                    .message_kind()
                    .expect("complete datagram kinds map to message kinds");
                validate_message_with_limits(kind, datagram.payload.len(), limits)?;
                Ok(Some((kind, datagram.payload)))
            }
            DatagramKind::FrameFragment | DatagramKind::AuthenticatedFragment => {
                let kind = datagram
                    .kind
                    .message_kind()
                    .expect("fragment datagram kinds map to message kinds");
                let fragment = decode_fragment_payload(&datagram.payload)?;
                let key = FragmentKey {
                    kind,
                    message_id: fragment.message_id,
                };
                if self.completed_fragments.lock().await.contains(&key) {
                    return Ok(None);
                }
                validate_fragment_shape(&fragment)?;
                validate_message_with_limits(kind, fragment.total_len, limits)?;
                let mut reassembly = self.reassembly.lock().await;
                prune_expired_reassembly(&mut reassembly, Instant::now());
                if !reassembly.contains_key(&key) && reassembly.len() >= MAX_REASSEMBLY_ENTRIES {
                    return Err(QlinkError::Protocol(format!(
                        "native UDP carrier has too many in-flight fragmented messages: {}",
                        reassembly.len()
                    )));
                }
                let entry = reassembly.entry(key).or_insert_with(|| {
                    FragmentBuffer::new(fragment.total_len, fragment.chunk_count)
                });
                let completed = match entry.insert(fragment) {
                    Ok(completed) => completed,
                    Err(error) => {
                        reassembly.remove(&key);
                        return Err(error);
                    }
                };
                if let Some(message) = completed {
                    reassembly.remove(&key);
                    drop(reassembly);
                    self.completed_fragments.lock().await.insert(key);
                    Ok(Some((kind, message)))
                } else {
                    Ok(None)
                }
            }
        }
    }

    async fn pop_pending(&self, kind: MessageKind) -> Option<Vec<u8>> {
        match kind {
            MessageKind::Frame => self.pending_frames.lock().await.pop_front(),
            MessageKind::AuthenticatedMessage => {
                self.pending_authenticated.lock().await.pop_front()
            }
        }
    }

    async fn push_pending(&self, kind: MessageKind, payload: Vec<u8>) -> Result<()> {
        match kind {
            MessageKind::Frame => {
                let mut pending = self.pending_frames.lock().await;
                push_bounded_pending(
                    &mut pending,
                    payload,
                    "native UDP carrier pending frame queue is full",
                )
            }
            MessageKind::AuthenticatedMessage => {
                let mut pending = self.pending_authenticated.lock().await;
                push_bounded_pending(
                    &mut pending,
                    payload,
                    "native UDP carrier pending authenticated queue is full",
                )
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FragmentKey {
    kind: MessageKind,
    message_id: u64,
}

#[derive(Debug, Default)]
struct CompletedFragmentKeys {
    order: VecDeque<FragmentKey>,
    set: HashSet<FragmentKey>,
}

impl CompletedFragmentKeys {
    fn contains(&self, key: &FragmentKey) -> bool {
        self.set.contains(key)
    }

    fn insert(&mut self, key: FragmentKey) {
        if !self.set.insert(key) {
            return;
        }
        self.order.push_back(key);
        while self.order.len() > MAX_COMPLETED_FRAGMENT_KEYS {
            if let Some(evicted) = self.order.pop_front() {
                self.set.remove(&evicted);
            }
        }
    }
}

#[derive(Debug)]
struct FragmentBuffer {
    total_len: usize,
    chunks: Vec<Option<Vec<u8>>>,
    received_len: usize,
    created_at: Instant,
}

impl FragmentBuffer {
    fn new(total_len: usize, chunk_count: u16) -> Self {
        Self {
            total_len,
            chunks: vec![None; chunk_count as usize],
            received_len: 0,
            created_at: Instant::now(),
        }
    }

    fn insert(&mut self, fragment: FragmentPayload) -> Result<Option<Vec<u8>>> {
        if fragment.total_len != self.total_len {
            return Err(QlinkError::Protocol(
                "native UDP carrier fragment total length changed".into(),
            ));
        }
        if fragment.total_len > MAX_REASSEMBLED_MESSAGE_LEN {
            return Err(QlinkError::Protocol(format!(
                "native UDP carrier fragmented message is too large: {} bytes",
                fragment.total_len
            )));
        }
        if fragment.chunk_count as usize != self.chunks.len() {
            return Err(QlinkError::Protocol(
                "native UDP carrier fragment count changed".into(),
            ));
        }
        let index = fragment.chunk_index as usize;
        if index >= self.chunks.len() {
            return Err(QlinkError::Protocol(
                "native UDP carrier fragment index out of range".into(),
            ));
        }
        if self.chunks[index].is_some() {
            return Ok(None);
        }

        self.received_len += fragment.payload.len();
        if self.received_len > self.total_len {
            return Err(QlinkError::Protocol(
                "native UDP carrier fragments exceed declared length".into(),
            ));
        }
        self.chunks[index] = Some(fragment.payload);

        if self.chunks.iter().all(Option::is_some) {
            let mut message = Vec::with_capacity(self.total_len);
            for chunk in &mut self.chunks {
                message.extend_from_slice(chunk.take().expect("all chunks are present").as_slice());
            }
            if message.len() != self.total_len {
                return Err(QlinkError::Protocol(
                    "native UDP carrier reassembled length mismatch".into(),
                ));
            }
            Ok(Some(message))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CarrierDatagram {
    kind: DatagramKind,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FragmentPayload {
    message_id: u64,
    total_len: usize,
    chunk_index: u16,
    chunk_count: u16,
    payload: Vec<u8>,
}

fn validate_received_size(kind: MessageKind, payload: Vec<u8>, max_size: usize) -> Result<Vec<u8>> {
    if kind == MessageKind::AuthenticatedMessage && payload.len() > max_size {
        return Err(QlinkError::Protocol(format!(
            "native UDP authenticated message is {} bytes; max is {max_size}",
            payload.len()
        )));
    }
    Ok(payload)
}

fn validate_message_with_limits(
    kind: MessageKind,
    len: usize,
    limits: ReceiveLimits,
) -> Result<()> {
    if kind == MessageKind::AuthenticatedMessage && len > limits.authenticated_message_max {
        return Err(QlinkError::Protocol(format!(
            "native UDP authenticated message is {len} bytes; max is {}",
            limits.authenticated_message_max
        )));
    }
    Ok(())
}

fn push_bounded_pending(
    queue: &mut VecDeque<Vec<u8>>,
    payload: Vec<u8>,
    error_message: &'static str,
) -> Result<()> {
    if queue.len() >= MAX_PENDING_MESSAGES {
        return Err(QlinkError::Protocol(error_message.into()));
    }
    queue.push_back(payload);
    Ok(())
}

fn prune_expired_reassembly(reassembly: &mut HashMap<FragmentKey, FragmentBuffer>, now: Instant) {
    reassembly.retain(|_, buffer| now.duration_since(buffer.created_at) <= REASSEMBLY_TTL);
}

fn encode_datagram(kind: DatagramKind, payload: &[u8]) -> Result<Vec<u8>> {
    let payload_len = u32::try_from(payload.len()).map_err(|_| {
        QlinkError::Protocol("native UDP carrier payload exceeds u32 length".into())
    })?;
    if payload.len() > MAX_CARRIER_PAYLOAD_LEN {
        return Err(QlinkError::Protocol(format!(
            "native UDP carrier payload is too large: {} bytes",
            payload.len()
        )));
    }

    let mut datagram = Vec::with_capacity(CARRIER_HEADER_LEN + payload.len());
    datagram.extend_from_slice(CARRIER_MAGIC);
    datagram.push(CARRIER_VERSION);
    datagram.push(kind.wire_value());
    datagram.extend_from_slice(&payload_len.to_be_bytes());
    datagram.extend_from_slice(payload);
    Ok(datagram)
}

fn decode_datagram(input: &[u8]) -> Result<CarrierDatagram> {
    if input.len() < CARRIER_HEADER_LEN {
        return Err(QlinkError::Protocol(
            "native UDP carrier datagram too short".into(),
        ));
    }
    if &input[..CARRIER_MAGIC.len()] != CARRIER_MAGIC {
        return Err(QlinkError::Protocol(
            "invalid native UDP carrier datagram magic".into(),
        ));
    }
    if input[CARRIER_MAGIC.len()] != CARRIER_VERSION {
        return Err(QlinkError::Protocol(format!(
            "unsupported native UDP carrier version {}",
            input[CARRIER_MAGIC.len()]
        )));
    }
    let kind = DatagramKind::from_wire(input[CARRIER_MAGIC.len() + 1])?;
    let mut len = [0_u8; 4];
    len.copy_from_slice(&input[CARRIER_MAGIC.len() + 2..CARRIER_HEADER_LEN]);
    let payload_len = u32::from_be_bytes(len) as usize;
    if input.len() != CARRIER_HEADER_LEN + payload_len {
        return Err(QlinkError::Protocol(
            "native UDP carrier datagram length mismatch".into(),
        ));
    }
    Ok(CarrierDatagram {
        kind,
        payload: input[CARRIER_HEADER_LEN..].to_vec(),
    })
}

fn encode_fragment_payload(
    message_id: u64,
    total_len: u32,
    chunk_index: u16,
    chunk_count: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if chunk_count == 0 {
        return Err(QlinkError::Protocol(
            "native UDP carrier fragment count cannot be zero".into(),
        ));
    }
    validate_fragment_shape_parts(total_len as usize, chunk_index, chunk_count, payload.len())?;
    if chunk_index >= chunk_count {
        return Err(QlinkError::Protocol(
            "native UDP carrier fragment index out of range".into(),
        ));
    }
    if payload.len() > MAX_FRAGMENT_PAYLOAD_LEN {
        return Err(QlinkError::Protocol(format!(
            "native UDP carrier fragment payload is too large: {} bytes",
            payload.len()
        )));
    }

    let mut out = Vec::with_capacity(FRAGMENT_HEADER_LEN + payload.len());
    out.extend_from_slice(&message_id.to_be_bytes());
    out.extend_from_slice(&total_len.to_be_bytes());
    out.extend_from_slice(&chunk_index.to_be_bytes());
    out.extend_from_slice(&chunk_count.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn decode_fragment_payload(input: &[u8]) -> Result<FragmentPayload> {
    if input.len() < FRAGMENT_HEADER_LEN {
        return Err(QlinkError::Protocol(
            "native UDP carrier fragment too short".into(),
        ));
    }
    let mut message_id = [0_u8; 8];
    message_id.copy_from_slice(&input[..8]);
    let mut total_len = [0_u8; 4];
    total_len.copy_from_slice(&input[8..12]);
    let mut chunk_index = [0_u8; 2];
    chunk_index.copy_from_slice(&input[12..14]);
    let mut chunk_count = [0_u8; 2];
    chunk_count.copy_from_slice(&input[14..16]);
    let chunk_count = u16::from_be_bytes(chunk_count);
    if chunk_count == 0 {
        return Err(QlinkError::Protocol(
            "native UDP carrier fragment count cannot be zero".into(),
        ));
    }
    Ok(FragmentPayload {
        message_id: u64::from_be_bytes(message_id),
        total_len: u32::from_be_bytes(total_len) as usize,
        chunk_index: u16::from_be_bytes(chunk_index),
        chunk_count,
        payload: input[FRAGMENT_HEADER_LEN..].to_vec(),
    })
}

fn validate_fragment_shape(fragment: &FragmentPayload) -> Result<()> {
    validate_fragment_shape_parts(
        fragment.total_len,
        fragment.chunk_index,
        fragment.chunk_count,
        fragment.payload.len(),
    )
}

fn validate_fragment_shape_parts(
    total_len: usize,
    chunk_index: u16,
    chunk_count: u16,
    payload_len: usize,
) -> Result<()> {
    if total_len <= MAX_CARRIER_PAYLOAD_LEN {
        return Err(QlinkError::Protocol(
            "native UDP carrier fragment total length does not require fragmentation".into(),
        ));
    }
    if total_len > MAX_REASSEMBLED_MESSAGE_LEN {
        return Err(QlinkError::Protocol(format!(
            "native UDP carrier fragmented message is too large: {total_len} bytes"
        )));
    }
    let expected_chunks = total_len.div_ceil(MAX_FRAGMENT_PAYLOAD_LEN);
    let chunk_count = chunk_count as usize;
    if chunk_count != expected_chunks {
        return Err(QlinkError::Protocol(
            "native UDP carrier fragment count does not match total length".into(),
        ));
    }
    let chunk_index = chunk_index as usize;
    if chunk_index >= chunk_count {
        return Err(QlinkError::Protocol(
            "native UDP carrier fragment index out of range".into(),
        ));
    }
    let expected_payload_len = if chunk_index + 1 == chunk_count {
        total_len - (MAX_FRAGMENT_PAYLOAD_LEN * chunk_index)
    } else {
        MAX_FRAGMENT_PAYLOAD_LEN
    };
    if payload_len != expected_payload_len {
        return Err(QlinkError::Protocol(
            "native UDP carrier fragment payload length does not match position".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn native_udp_session_round_trips_frames_and_authenticated_messages() {
        let (left, right) = NativeUdpSession::loopback_pair().await.unwrap();
        let left = CarrierSession::from(left);
        let right = CarrierSession::from(right);

        left.send_authenticated_message(b"identity".to_vec())
            .await
            .unwrap();
        assert_eq!(
            right.receive_authenticated_message(64).await.unwrap(),
            b"identity"
        );

        right.send_frame(b"protected-frame".to_vec()).await.unwrap();
        assert_eq!(left.receive_frame().await.unwrap(), b"protected-frame");
    }

    #[tokio::test]
    async fn native_udp_listener_accepts_successive_sessions() {
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let socket = UdpSocket::bind(bind).await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let listener = NativeUdpListener::new(socket);

        for index in 0..2_u8 {
            let client = NativeUdpSession::connect(bind, server_addr).await.unwrap();
            client
                .send_authenticated_message(vec![index])
                .await
                .unwrap();
            let (server, _) = listener.accept().await.unwrap();
            assert_eq!(
                server.receive_authenticated_message(1).await.unwrap(),
                vec![index]
            );
            server.send_frame(vec![index + 1]).await.unwrap();
            assert_eq!(client.receive_frame().await.unwrap(), vec![index + 1]);
            server.close(b"rotate");
        }
    }

    #[tokio::test]
    async fn native_udp_session_rejects_oversized_authenticated_messages() {
        let (left, right) = NativeUdpSession::loopback_pair().await.unwrap();
        let left = CarrierSession::from(left);
        let right = CarrierSession::from(right);

        left.send_authenticated_message(vec![0x42; 32])
            .await
            .unwrap();
        let error = right.receive_authenticated_message(8).await.unwrap_err();
        assert!(error.to_string().contains("authenticated message"));
    }

    #[tokio::test]
    async fn native_udp_session_reassembles_large_authenticated_messages() {
        let (left, right) = NativeUdpSession::loopback_pair().await.unwrap();
        let left = CarrierSession::from(left);
        let right = CarrierSession::from(right);
        let message = vec![0x7a; 90_000];

        left.send_authenticated_message(message.clone())
            .await
            .unwrap();

        assert_eq!(
            right
                .receive_authenticated_message(message.len() + 1)
                .await
                .unwrap(),
            message
        );
    }

    #[tokio::test]
    async fn native_udp_session_reassembles_large_frames() {
        let (left, right) = NativeUdpSession::loopback_pair().await.unwrap();
        let left = CarrierSession::from(left);
        let right = CarrierSession::from(right);
        let frame = vec![0x55; 4_096];

        left.send_frame(frame.clone()).await.unwrap();

        assert_eq!(right.receive_frame().await.unwrap(), frame);
    }

    #[tokio::test]
    async fn native_udp_session_preserves_interleaved_authenticated_message_for_later_receive() {
        let (left, right) = NativeUdpSession::loopback_pair().await.unwrap();
        let left = CarrierSession::from(left);
        let right = CarrierSession::from(right);

        left.send_authenticated_message(b"auth-before-frame".to_vec())
            .await
            .unwrap();
        left.send_frame(b"frame".to_vec()).await.unwrap();

        assert_eq!(right.receive_frame().await.unwrap(), b"frame");
        assert_eq!(
            right.receive_authenticated_message(64).await.unwrap(),
            b"auth-before-frame"
        );
    }

    #[tokio::test]
    async fn native_udp_session_reassembles_authenticated_fragments_out_of_order() {
        let (left, right) = NativeUdpSession::loopback_pair().await.unwrap();
        let message = vec![0x31; MAX_FRAGMENT_PAYLOAD_LEN + 17];
        let first = encode_fragment_payload(
            7,
            message.len() as u32,
            0,
            2,
            &message[..MAX_FRAGMENT_PAYLOAD_LEN],
        )
        .unwrap();
        let second = encode_fragment_payload(
            7,
            message.len() as u32,
            1,
            2,
            &message[MAX_FRAGMENT_PAYLOAD_LEN..],
        )
        .unwrap();

        left.send_datagram(DatagramKind::AuthenticatedFragment, second)
            .await
            .unwrap();
        left.send_datagram(DatagramKind::AuthenticatedFragment, first)
            .await
            .unwrap();

        assert_eq!(
            right
                .receive_authenticated_message(message.len() + 1)
                .await
                .unwrap(),
            message
        );
    }

    #[tokio::test]
    async fn native_udp_session_bounds_in_flight_reassembly_entries() {
        let (session, _) = NativeUdpSession::loopback_pair().await.unwrap();
        let limits = ReceiveLimits::new(MAX_REASSEMBLED_MESSAGE_LEN);
        let payload = vec![0x44; MAX_FRAGMENT_PAYLOAD_LEN];
        let total_len = (MAX_FRAGMENT_PAYLOAD_LEN + 17) as u32;

        for message_id in 0..MAX_REASSEMBLY_ENTRIES {
            let fragment =
                encode_fragment_payload(message_id as u64, total_len, 0, 2, &payload).unwrap();
            let datagram = CarrierDatagram {
                kind: DatagramKind::FrameFragment,
                payload: fragment,
            };
            assert!(session
                .accept_datagram(datagram, limits)
                .await
                .unwrap()
                .is_none());
        }

        let fragment = encode_fragment_payload(999, total_len, 0, 2, &payload).unwrap();
        let datagram = CarrierDatagram {
            kind: DatagramKind::FrameFragment,
            payload: fragment,
        };
        let error = session.accept_datagram(datagram, limits).await.unwrap_err();

        assert!(error.to_string().contains("too many in-flight"));
    }

    #[tokio::test]
    async fn native_udp_session_ignores_duplicate_completed_fragment_sets() {
        let (session, _) = NativeUdpSession::loopback_pair().await.unwrap();
        let limits = ReceiveLimits::new(MAX_REASSEMBLED_MESSAGE_LEN);
        let message = vec![0x51; MAX_FRAGMENT_PAYLOAD_LEN + 17];
        let first = CarrierDatagram {
            kind: DatagramKind::AuthenticatedFragment,
            payload: encode_fragment_payload(
                77,
                message.len() as u32,
                0,
                2,
                &message[..MAX_FRAGMENT_PAYLOAD_LEN],
            )
            .unwrap(),
        };
        let second = CarrierDatagram {
            kind: DatagramKind::AuthenticatedFragment,
            payload: encode_fragment_payload(
                77,
                message.len() as u32,
                1,
                2,
                &message[MAX_FRAGMENT_PAYLOAD_LEN..],
            )
            .unwrap(),
        };

        assert!(session
            .accept_datagram(first.clone(), limits)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            session
                .accept_datagram(second.clone(), limits)
                .await
                .unwrap(),
            Some((MessageKind::AuthenticatedMessage, message))
        );
        assert!(session
            .accept_datagram(first, limits)
            .await
            .unwrap()
            .is_none());
        assert!(session
            .accept_datagram(second, limits)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn native_udp_session_reclaims_stale_reassembly_entries() {
        let (session, _) = NativeUdpSession::loopback_pair().await.unwrap();
        let limits = ReceiveLimits::new(MAX_REASSEMBLED_MESSAGE_LEN);
        let payload = vec![0x44; MAX_FRAGMENT_PAYLOAD_LEN];
        let total_len = (MAX_FRAGMENT_PAYLOAD_LEN + 17) as u32;

        for message_id in 0..MAX_REASSEMBLY_ENTRIES {
            let fragment =
                encode_fragment_payload(message_id as u64, total_len, 0, 2, &payload).unwrap();
            let datagram = CarrierDatagram {
                kind: DatagramKind::FrameFragment,
                payload: fragment,
            };
            assert!(session
                .accept_datagram(datagram, limits)
                .await
                .unwrap()
                .is_none());
        }
        {
            let mut reassembly = session.reassembly.lock().await;
            for buffer in reassembly.values_mut() {
                buffer.created_at = buffer
                    .created_at
                    .checked_sub(REASSEMBLY_TTL + std::time::Duration::from_secs(1))
                    .unwrap();
            }
        }

        let fragment = encode_fragment_payload(999, total_len, 0, 2, &payload).unwrap();
        let datagram = CarrierDatagram {
            kind: DatagramKind::FrameFragment,
            payload: fragment,
        };

        assert!(session
            .accept_datagram(datagram, limits)
            .await
            .unwrap()
            .is_none());
        assert_eq!(session.reassembly.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn native_udp_session_rejects_fragmented_authenticated_messages_over_receive_limit() {
        let (session, _) = NativeUdpSession::loopback_pair().await.unwrap();
        let message = vec![0x61; MAX_FRAGMENT_PAYLOAD_LEN + 17];
        let fragment = CarrierDatagram {
            kind: DatagramKind::AuthenticatedFragment,
            payload: encode_fragment_payload(
                88,
                message.len() as u32,
                0,
                2,
                &message[..MAX_FRAGMENT_PAYLOAD_LEN],
            )
            .unwrap(),
        };

        let error = session
            .accept_datagram(fragment, ReceiveLimits::new(64))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("authenticated message"));
        assert!(session.reassembly.lock().await.is_empty());
    }

    #[tokio::test]
    async fn native_udp_session_drops_poisoned_fragment_entry_for_later_valid_message() {
        let (session, _) = NativeUdpSession::loopback_pair().await.unwrap();
        let limits = ReceiveLimits::new(MAX_REASSEMBLED_MESSAGE_LEN);
        let poison = CarrierDatagram {
            kind: DatagramKind::FrameFragment,
            payload: encode_fragment_payload(
                99,
                (MAX_FRAGMENT_PAYLOAD_LEN + 17) as u32,
                0,
                2,
                &vec![0x22; MAX_FRAGMENT_PAYLOAD_LEN],
            )
            .unwrap(),
        };
        assert!(session
            .accept_datagram(poison, limits)
            .await
            .unwrap()
            .is_none());

        let message = vec![0x33; (MAX_FRAGMENT_PAYLOAD_LEN * 2) + 17];
        let valid_first = CarrierDatagram {
            kind: DatagramKind::FrameFragment,
            payload: encode_fragment_payload(
                99,
                message.len() as u32,
                0,
                3,
                &message[..MAX_FRAGMENT_PAYLOAD_LEN],
            )
            .unwrap(),
        };
        let error = session
            .accept_datagram(valid_first.clone(), limits)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("changed"));

        assert!(session
            .accept_datagram(valid_first, limits)
            .await
            .unwrap()
            .is_none());
        let valid_second = CarrierDatagram {
            kind: DatagramKind::FrameFragment,
            payload: encode_fragment_payload(
                99,
                message.len() as u32,
                1,
                3,
                &message[MAX_FRAGMENT_PAYLOAD_LEN..MAX_FRAGMENT_PAYLOAD_LEN * 2],
            )
            .unwrap(),
        };
        let valid_third = CarrierDatagram {
            kind: DatagramKind::FrameFragment,
            payload: encode_fragment_payload(
                99,
                message.len() as u32,
                2,
                3,
                &message[MAX_FRAGMENT_PAYLOAD_LEN * 2..],
            )
            .unwrap(),
        };

        assert!(session
            .accept_datagram(valid_second, limits)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            session.accept_datagram(valid_third, limits).await.unwrap(),
            Some((MessageKind::Frame, message))
        );
    }

    #[tokio::test]
    async fn native_udp_session_rejects_oversized_udp_datagrams() {
        let (left, right) = NativeUdpSession::loopback_pair().await.unwrap();
        let mut oversized =
            encode_datagram(DatagramKind::Frame, &vec![0x99; MAX_CARRIER_PAYLOAD_LEN]).unwrap();
        oversized.push(0xaa);
        left.socket.send(&oversized).await.unwrap();

        let error = right.receive_frame().await.unwrap_err();

        assert!(error.to_string().contains("datagram exceeds"));
    }
}
