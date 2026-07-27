#[cfg(feature = "public-edge-tls")]
use crate::control_transport::{load_tls_acceptor, ControlTlsServerConfig};
use crate::{
    admission::{AdmissionLimiter, ServiceAdmissionConfig, ServiceLimits, ServiceLimitsConfig},
    control_transport::{connect_control_stream, split_control_stream},
    discovery::{now_unix, PeerRecord},
    error::{QlinkError, Result},
    service_metrics::ServiceMetrics,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::RwLock,
    task::JoinHandle,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RendezvousRequest {
    Publish {
        mesh_id: String,
        record: PeerRecord,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_token: Option<String>,
    },
    Lookup {
        mesh_id: String,
        peer_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_token: Option<String>,
    },
}

impl RendezvousRequest {
    fn auth_token(&self) -> Option<&str> {
        match self {
            Self::Publish { auth_token, .. } | Self::Lookup { auth_token, .. } => {
                auth_token.as_deref()
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RendezvousResponse {
    Published { peer_id: String },
    Found { record: PeerRecord },
    NotFound,
    Error { message: String },
}

#[derive(Default, Clone)]
pub struct RendezvousStore {
    records: Arc<RwLock<HashMap<(String, String), PeerRecord>>>,
}

impl RendezvousStore {
    pub async fn publish(&self, mesh_id: &str, record: PeerRecord) -> Result<()> {
        record.verify(mesh_id)?;
        self.records
            .write()
            .await
            .insert((mesh_id.to_string(), record.body.peer_id.clone()), record);
        Ok(())
    }

    pub async fn lookup(&self, mesh_id: &str, peer_id: &str) -> Option<PeerRecord> {
        let mut records = self.records.write().await;
        records.retain(|_, record| record.body.expires_at_unix > now_unix());
        records
            .get(&(mesh_id.to_string(), peer_id.to_string()))
            .cloned()
    }
}

pub async fn run_rendezvous(listen: &str) -> Result<()> {
    run_rendezvous_with_config(listen, ServiceAdmissionConfig::default()).await
}

pub async fn run_rendezvous_with_config(
    listen: &str,
    admission: ServiceAdmissionConfig,
) -> Result<()> {
    run_rendezvous_with_metrics_and_limits(
        listen,
        admission,
        ServiceMetrics::default(),
        ServiceLimitsConfig::default(),
    )
    .await
}

pub async fn run_rendezvous_with_metrics(
    listen: &str,
    admission: ServiceAdmissionConfig,
    metrics: ServiceMetrics,
) -> Result<()> {
    run_rendezvous_with_metrics_and_limits(
        listen,
        admission,
        metrics,
        ServiceLimitsConfig::default(),
    )
    .await
}

pub async fn run_rendezvous_with_metrics_and_limits(
    listen: &str,
    admission: ServiceAdmissionConfig,
    metrics: ServiceMetrics,
    limits: ServiceLimitsConfig,
) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let store = RendezvousStore::default();
    serve_rendezvous_with_config_metrics_and_limits(listener, store, admission, metrics, limits)
        .await
}

#[cfg(feature = "public-edge-tls")]
pub async fn run_rendezvous_with_optional_tls(
    listen: &str,
    admission: ServiceAdmissionConfig,
    tls: Option<ControlTlsServerConfig>,
) -> Result<()> {
    run_rendezvous_with_optional_tls_and_metrics(listen, admission, tls, ServiceMetrics::default())
        .await
}

#[cfg(feature = "public-edge-tls")]
pub async fn run_rendezvous_with_optional_tls_and_metrics(
    listen: &str,
    admission: ServiceAdmissionConfig,
    tls: Option<ControlTlsServerConfig>,
    metrics: ServiceMetrics,
) -> Result<()> {
    run_rendezvous_with_optional_tls_metrics_and_limits(
        listen,
        admission,
        tls,
        metrics,
        ServiceLimitsConfig::default(),
    )
    .await
}

#[cfg(feature = "public-edge-tls")]
pub async fn run_rendezvous_with_optional_tls_metrics_and_limits(
    listen: &str,
    admission: ServiceAdmissionConfig,
    tls: Option<ControlTlsServerConfig>,
    metrics: ServiceMetrics,
    limits: ServiceLimitsConfig,
) -> Result<()> {
    match tls {
        Some(tls) => {
            let listener = TcpListener::bind(listen).await?;
            let store = RendezvousStore::default();
            serve_rendezvous_with_tls_metrics_and_limits(
                listener, store, admission, tls, metrics, limits,
            )
            .await
        }
        None => run_rendezvous_with_metrics_and_limits(listen, admission, metrics, limits).await,
    }
}

pub async fn serve_rendezvous(listener: TcpListener, store: RendezvousStore) -> Result<()> {
    serve_rendezvous_with_config(listener, store, ServiceAdmissionConfig::default()).await
}

pub async fn serve_rendezvous_with_config(
    listener: TcpListener,
    store: RendezvousStore,
    admission: ServiceAdmissionConfig,
) -> Result<()> {
    serve_rendezvous_with_config_and_metrics(listener, store, admission, ServiceMetrics::default())
        .await
}

pub async fn serve_rendezvous_with_config_and_metrics(
    listener: TcpListener,
    store: RendezvousStore,
    admission: ServiceAdmissionConfig,
    metrics: ServiceMetrics,
) -> Result<()> {
    serve_rendezvous_with_config_metrics_and_limits(
        listener,
        store,
        admission,
        metrics,
        ServiceLimitsConfig::default(),
    )
    .await
}

pub async fn serve_rendezvous_with_config_metrics_and_limits(
    listener: TcpListener,
    store: RendezvousStore,
    admission: ServiceAdmissionConfig,
    metrics: ServiceMetrics,
    limits: ServiceLimitsConfig,
) -> Result<()> {
    let limiter = AdmissionLimiter::new(&admission);
    let service_limits = ServiceLimits::new(limits);
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let connection_permit = match service_limits.try_start_connection("rendezvous") {
            Ok(permit) => permit,
            Err(error) => {
                metrics.connection_limit_rejection();
                tracing::warn!(?error, %peer_addr, "rendezvous connection rejected");
                continue;
            }
        };
        let store = store.clone();
        let admission = admission.clone();
        let limiter = limiter.clone();
        let metrics = metrics.clone();
        let limits = service_limits.config();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            let _connection = metrics.connection_started();
            if let Err(error) = handle_connection(
                stream, store, admission, limiter, peer_addr, metrics, limits,
            )
            .await
            {
                tracing::warn!(?error, "rendezvous connection failed");
            }
        });
    }
}

#[cfg(feature = "public-edge-tls")]
pub async fn serve_rendezvous_with_tls(
    listener: TcpListener,
    store: RendezvousStore,
    admission: ServiceAdmissionConfig,
    tls: ControlTlsServerConfig,
) -> Result<()> {
    serve_rendezvous_with_tls_and_metrics(
        listener,
        store,
        admission,
        tls,
        ServiceMetrics::default(),
    )
    .await
}

#[cfg(feature = "public-edge-tls")]
pub async fn serve_rendezvous_with_tls_and_metrics(
    listener: TcpListener,
    store: RendezvousStore,
    admission: ServiceAdmissionConfig,
    tls: ControlTlsServerConfig,
    metrics: ServiceMetrics,
) -> Result<()> {
    serve_rendezvous_with_tls_metrics_and_limits(
        listener,
        store,
        admission,
        tls,
        metrics,
        ServiceLimitsConfig::default(),
    )
    .await
}

#[cfg(feature = "public-edge-tls")]
pub async fn serve_rendezvous_with_tls_metrics_and_limits(
    listener: TcpListener,
    store: RendezvousStore,
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
        let connection_permit = match service_limits.try_start_connection("rendezvous") {
            Ok(permit) => permit,
            Err(error) => {
                metrics.connection_limit_rejection();
                tracing::warn!(?error, %peer_addr, "rendezvous TLS connection rejected");
                continue;
            }
        };
        let store = store.clone();
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
                    QlinkError::Protocol(format!("rendezvous TLS handshake failed: {err}"))
                })?;
                handle_connection(
                    stream, store, admission, limiter, peer_addr, metrics, limits,
                )
                .await
            }
            .await;
            if let Err(error) = result {
                tracing::warn!(?error, "rendezvous TLS connection failed");
            }
        });
    }
}

#[derive(Debug)]
pub struct DevRendezvousServer {
    local_addr: SocketAddr,
    task: JoinHandle<()>,
}

impl DevRendezvousServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for DevRendezvousServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_dev_rendezvous() -> Result<DevRendezvousServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    let store = RendezvousStore::default();
    let task = tokio::spawn(async move {
        if let Err(error) = serve_rendezvous(listener, store).await {
            tracing::warn!(?error, "dev rendezvous server stopped");
        }
    });
    Ok(DevRendezvousServer { local_addr, task })
}

#[derive(Debug, Clone)]
pub struct RendezvousClient {
    server: String,
    auth_token: Option<String>,
}

impl RendezvousClient {
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            auth_token: None,
        }
    }

    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    pub fn with_optional_auth_token(mut self, token: Option<String>) -> Self {
        self.auth_token = token;
        self
    }

    pub async fn publish(&self, mesh_id: &str, record: PeerRecord) -> Result<String> {
        match self
            .request(RendezvousRequest::Publish {
                mesh_id: mesh_id.to_string(),
                record,
                auth_token: None,
            })
            .await?
        {
            RendezvousResponse::Published { peer_id } => Ok(peer_id),
            RendezvousResponse::Error { message } => Err(QlinkError::Protocol(message)),
            other => Err(QlinkError::Protocol(format!(
                "unexpected rendezvous publish response: {other:?}"
            ))),
        }
    }

    pub async fn lookup(&self, mesh_id: &str, peer_id: &str) -> Result<Option<PeerRecord>> {
        match self
            .request(RendezvousRequest::Lookup {
                mesh_id: mesh_id.to_string(),
                peer_id: peer_id.to_string(),
                auth_token: None,
            })
            .await?
        {
            RendezvousResponse::Found { record } => Ok(Some(record)),
            RendezvousResponse::NotFound => Ok(None),
            RendezvousResponse::Error { message } => Err(QlinkError::Protocol(message)),
            other => Err(QlinkError::Protocol(format!(
                "unexpected rendezvous lookup response: {other:?}"
            ))),
        }
    }

    async fn request(&self, mut request: RendezvousRequest) -> Result<RendezvousResponse> {
        if let Some(token) = self.auth_token.as_ref() {
            match &mut request {
                RendezvousRequest::Publish { auth_token, .. }
                | RendezvousRequest::Lookup { auth_token, .. } => {
                    *auth_token = Some(token.clone());
                }
            }
        }
        let stream = connect_control_stream(&self.server, None).await?;
        let (reader, mut writer) = split_control_stream(stream);
        writer
            .write_all(serde_json::to_string(&request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        // Do NOT half-close the write half here. The server frames requests by
        // newline and replies immediately, so a shutdown() is unnecessary — and
        // over a real RTT it surfaces a premature EOF on the read half, so the
        // response is never read and the socket is reset. `writer` stays in
        // scope (connection open) until the response has been read.

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let response = serde_json::from_str(line.trim_end())?;
        Ok(response)
    }
}

async fn handle_connection(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    store: RendezvousStore,
    admission: ServiceAdmissionConfig,
    limiter: AdmissionLimiter,
    peer_addr: SocketAddr,
    metrics: ServiceMetrics,
    limits: ServiceLimitsConfig,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();

    loop {
        match read_bounded_line(&mut reader, &mut line, limits, "rendezvous", &metrics).await {
            Ok(true) => {}
            Ok(false) => break,
            Err(error) => {
                let response = RendezvousResponse::Error {
                    message: error.to_string(),
                };
                writer
                    .write_all(serde_json::to_string(&response)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                break;
            }
        }
        if let Err(error) = limiter.check(peer_addr, "rendezvous").await {
            metrics.rate_limited();
            let response = RendezvousResponse::Error {
                message: error.to_string(),
            };
            writer
                .write_all(serde_json::to_string(&response)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
            line.clear();
            continue;
        }
        let response = match serde_json::from_slice::<RendezvousRequest>(trim_line(&line)) {
            Ok(request) => {
                if admission.token_is_revoked(request.auth_token())? {
                    metrics.auth_revocation();
                    RendezvousResponse::Error {
                        message: "rendezvous authentication failed".into(),
                    }
                } else if let Err(error) =
                    admission.require_token(request.auth_token(), "rendezvous")
                {
                    metrics.auth_failure();
                    RendezvousResponse::Error {
                        message: error.to_string(),
                    }
                } else {
                    match request {
                        RendezvousRequest::Publish {
                            mesh_id, record, ..
                        } => {
                            let peer_id = record.body.peer_id.clone();
                            match store.publish(&mesh_id, record).await {
                                Ok(()) => {
                                    metrics.rendezvous_publish();
                                    metrics.request_succeeded();
                                    RendezvousResponse::Published { peer_id }
                                }
                                Err(error) => {
                                    metrics.rendezvous_publish_failed();
                                    RendezvousResponse::Error {
                                        message: error.to_string(),
                                    }
                                }
                            }
                        }
                        RendezvousRequest::Lookup {
                            mesh_id, peer_id, ..
                        } => match store.lookup(&mesh_id, &peer_id).await {
                            Some(record) => {
                                metrics.rendezvous_lookup();
                                metrics.request_succeeded();
                                RendezvousResponse::Found { record }
                            }
                            None => {
                                metrics.rendezvous_lookup();
                                metrics.rendezvous_lookup_not_found();
                                metrics.request_succeeded();
                                RendezvousResponse::NotFound
                            }
                        },
                    }
                }
            }
            Err(error) => {
                metrics.malformed_request();
                RendezvousResponse::Error {
                    message: QlinkError::Json(error).to_string(),
                }
            }
        };

        writer
            .write_all(serde_json::to_string(&response)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        line.clear();
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admission::service_token_revocation_digest,
        crypto::DeviceKeypair,
        discovery::{CandidateEndpoint, CandidateType, UnsignedPeerRecord},
    };
    use std::time::Duration;

    fn signed_record() -> (String, PeerRecord) {
        let keypair = DeviceKeypair::generate().unwrap();
        let body = UnsignedPeerRecord::new(
            "devmesh",
            "mac",
            keypair.public_key(),
            vec![CandidateEndpoint {
                candidate_type: CandidateType::Host,
                address: "127.0.0.1".to_string(),
                port: 4433,
                priority: 120,
            }],
            vec!["100.127.0.2/32".to_string()],
            60,
            1,
        );
        let record = PeerRecord::signed(body, &keypair).unwrap();
        (record.body.peer_id.clone(), record)
    }

    async fn spawn_configured_rendezvous(
        admission: ServiceAdmissionConfig,
    ) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = RendezvousStore::default();
        let task = tokio::spawn(async move {
            let _ = serve_rendezvous_with_config(listener, store, admission).await;
        });
        (addr, task)
    }

    async fn spawn_limited_rendezvous(
        admission: ServiceAdmissionConfig,
        limits: ServiceLimitsConfig,
        metrics: ServiceMetrics,
    ) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = RendezvousStore::default();
        let task = tokio::spawn(async move {
            let _ = serve_rendezvous_with_config_metrics_and_limits(
                listener, store, admission, metrics, limits,
            )
            .await;
        });
        (addr, task)
    }

    #[tokio::test]
    async fn rendezvous_client_publishes_and_looks_up_peer() {
        let (addr, _task) = spawn_configured_rendezvous(ServiceAdmissionConfig::open()).await;
        let (peer_id, record) = signed_record();
        let client = RendezvousClient::new(addr.to_string());

        assert_eq!(client.publish("devmesh", record).await.unwrap(), peer_id);
        let found = client.lookup("devmesh", &peer_id).await.unwrap().unwrap();
        assert_eq!(found.body.peer_id, peer_id);
    }

    #[tokio::test]
    async fn rendezvous_requires_configured_auth_token() {
        let (addr, _task) = spawn_configured_rendezvous(
            ServiceAdmissionConfig::open().with_auth_token("edge-secret"),
        )
        .await;
        let (peer_id, record) = signed_record();

        let missing = RendezvousClient::new(addr.to_string())
            .publish("devmesh", record.clone())
            .await
            .unwrap_err();
        assert!(missing.to_string().contains("authentication failed"));

        let client = RendezvousClient::new(addr.to_string()).with_auth_token("edge-secret");
        assert_eq!(client.publish("devmesh", record).await.unwrap(), peer_id);
        assert!(client.lookup("devmesh", &peer_id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn rendezvous_rate_limits_per_client_ip() {
        let (addr, _task) = spawn_configured_rendezvous(
            ServiceAdmissionConfig::open().with_rate_limit(1, Duration::from_secs(60)),
        )
        .await;
        let (_, record) = signed_record();
        let client = RendezvousClient::new(addr.to_string());

        client.publish("devmesh", record).await.unwrap();
        let error = client.lookup("devmesh", "qlink_missing").await.unwrap_err();
        assert!(error.to_string().contains("rate limit exceeded"));
    }

    #[tokio::test]
    async fn rendezvous_records_service_metrics() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = RendezvousStore::default();
        let metrics = ServiceMetrics::default();
        let metrics_for_server = metrics.clone();
        let admission = ServiceAdmissionConfig::open().with_auth_token("edge-secret");
        let _task = tokio::spawn(async move {
            let _ = serve_rendezvous_with_config_and_metrics(
                listener,
                store,
                admission,
                metrics_for_server,
            )
            .await;
        });
        let (peer_id, record) = signed_record();

        let missing_auth = RendezvousClient::new(addr.to_string())
            .publish("devmesh", record.clone())
            .await
            .unwrap_err();
        assert!(missing_auth.to_string().contains("authentication failed"));

        let client = RendezvousClient::new(addr.to_string()).with_auth_token("edge-secret");
        client.publish("devmesh", record).await.unwrap();
        assert!(client.lookup("devmesh", &peer_id).await.unwrap().is_some());
        assert!(client
            .lookup("devmesh", "qlink_missing")
            .await
            .unwrap()
            .is_none());

        let rendered = metrics.snapshot("rendezvous").render_open_metrics();
        assert!(rendered.contains("quantumlink_rendezvous_auth_failures_total 1"));
        assert!(rendered.contains("quantumlink_rendezvous_publishes_total 1"));
        assert!(rendered.contains("quantumlink_rendezvous_lookups_total 2"));
        assert!(rendered.contains("quantumlink_rendezvous_lookup_not_found_total 1"));
        assert!(rendered.contains("quantumlink_rendezvous_requests_succeeded_total 3"));
    }

    #[tokio::test]
    async fn rendezvous_rejects_revoked_auth_token() {
        let dir = tempfile::tempdir().unwrap();
        let revoked_path = dir.path().join("revoked-service-token-digests");
        std::fs::write(
            &revoked_path,
            service_token_revocation_digest("edge-secret"),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = RendezvousStore::default();
        let metrics = ServiceMetrics::default();
        let metrics_for_server = metrics.clone();
        let admission = ServiceAdmissionConfig::open()
            .with_auth_token("edge-secret")
            .with_revoked_token_digest_file(&revoked_path);
        let _task = tokio::spawn(async move {
            let _ = serve_rendezvous_with_config_and_metrics(
                listener,
                store,
                admission,
                metrics_for_server,
            )
            .await;
        });

        let (_peer_id, record) = signed_record();
        let error = RendezvousClient::new(addr.to_string())
            .with_auth_token("edge-secret")
            .publish("devmesh", record)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("authentication failed"));

        let rendered = metrics.snapshot("rendezvous").render_open_metrics();
        assert!(rendered.contains("quantumlink_rendezvous_auth_revocations_total 1"));
        assert!(rendered.contains("quantumlink_rendezvous_auth_failures_total 1"));
    }

    #[tokio::test]
    async fn rendezvous_rejects_oversized_request_lines() {
        let metrics = ServiceMetrics::default();
        let limits = ServiceLimitsConfig::default().with_max_request_line_bytes(8);
        let (addr, _task) =
            spawn_limited_rendezvous(ServiceAdmissionConfig::open(), limits, metrics.clone()).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"{\"too_long\":true}\n").await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(response.contains("request line exceeds 8 bytes"));

        let rendered = metrics.snapshot("rendezvous").render_open_metrics();
        assert!(rendered.contains("quantumlink_rendezvous_request_too_large_total 1"));
    }
}
