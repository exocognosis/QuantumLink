//! Off-by-default OpenMetrics text exporter.
//!
//! Per the QuantumLink privacy spec, telemetry must remain opt-in. This
//! endpoint binds to a caller-supplied address (typically `127.0.0.1:0` for
//! debug or an MDM-controlled port for managed fleets) and serves a single
//! resource — `GET /metrics` — in the OpenMetrics text exposition format
//! understood by Prometheus, OpenTelemetry collectors, and friends.
//!
//! The exporter accepts a `MetricsSnapshotProvider` callback so the surface
//! it exposes is whatever the tunnel/connector layer chooses to publish.
//! Nothing here phones home.

use crate::error::{QlinkError, Result};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    task::JoinHandle,
};

#[derive(Debug, Clone)]
pub struct LabeledValue {
    pub labels: BTreeMap<String, String>,
    pub value: f64,
}

impl LabeledValue {
    pub fn unlabeled(value: f64) -> Self {
        Self {
            labels: BTreeMap::new(),
            value,
        }
    }
}

#[derive(Debug, Clone)]
pub enum MetricKind {
    Counter,
    Gauge,
}

#[derive(Debug, Clone)]
pub struct MetricFamily {
    pub name: String,
    pub help: String,
    pub kind: MetricKind,
    pub samples: Vec<LabeledValue>,
}

#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    pub families: Vec<MetricFamily>,
}

impl MetricsSnapshot {
    pub fn push_counter(&mut self, name: impl Into<String>, help: impl Into<String>, value: f64) {
        self.families.push(MetricFamily {
            name: name.into(),
            help: help.into(),
            kind: MetricKind::Counter,
            samples: vec![LabeledValue::unlabeled(value)],
        });
    }

    pub fn push_gauge(&mut self, name: impl Into<String>, help: impl Into<String>, value: f64) {
        self.families.push(MetricFamily {
            name: name.into(),
            help: help.into(),
            kind: MetricKind::Gauge,
            samples: vec![LabeledValue::unlabeled(value)],
        });
    }

    pub fn render_open_metrics(&self) -> String {
        let mut output = String::new();
        for family in &self.families {
            output.push_str(&format!("# HELP {} {}\n", family.name, family.help));
            output.push_str(&format!(
                "# TYPE {} {}\n",
                family.name,
                match family.kind {
                    MetricKind::Counter => "counter",
                    MetricKind::Gauge => "gauge",
                }
            ));
            for sample in &family.samples {
                if sample.labels.is_empty() {
                    output.push_str(&format!("{} {}\n", family.name, format_value(sample.value)));
                } else {
                    let label_str = sample
                        .labels
                        .iter()
                        .map(|(k, v)| format!("{}=\"{}\"", k, escape_label_value(v)))
                        .collect::<Vec<_>>()
                        .join(",");
                    output.push_str(&format!(
                        "{}{{{}}} {}\n",
                        family.name,
                        label_str,
                        format_value(sample.value)
                    ));
                }
            }
        }
        output
    }
}

fn format_value(value: f64) -> String {
    if value.is_nan() {
        "NaN".into()
    } else if value.is_infinite() {
        if value > 0.0 {
            "+Inf".into()
        } else {
            "-Inf".into()
        }
    } else if value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('"', r#"\""#)
        .replace('\n', r"\n")
}

pub type MetricsSnapshotProvider = Arc<dyn Fn() -> MetricsSnapshot + Send + Sync + 'static>;

#[derive(Debug)]
pub struct MetricsEndpoint {
    local_addr: SocketAddr,
    last_request: Arc<Mutex<Option<SystemTime>>>,
    task: JoinHandle<()>,
}

impl MetricsEndpoint {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn last_request(&self) -> Option<SystemTime> {
        *self.last_request.lock().await
    }

    pub fn shutdown(&self) {
        self.task.abort();
    }
}

impl Drop for MetricsEndpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_metrics_endpoint(
    bind_addr: SocketAddr,
    provider: MetricsSnapshotProvider,
) -> Result<MetricsEndpoint> {
    let listener = TcpListener::bind(bind_addr).await?;
    let local_addr = listener.local_addr()?;
    let last_request = Arc::new(Mutex::new(None));
    let last_request_for_task = last_request.clone();

    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let provider = provider.clone();
                    let last_request = last_request_for_task.clone();
                    tokio::spawn(async move {
                        if let Err(error) = handle_request(stream, provider, last_request).await {
                            tracing::warn!(?error, "metrics endpoint request failed");
                        }
                    });
                }
                Err(error) => {
                    tracing::warn!(?error, "metrics endpoint listener stopped");
                    break;
                }
            }
        }
    });

    Ok(MetricsEndpoint {
        local_addr,
        last_request,
        task,
    })
}

async fn handle_request(
    stream: TcpStream,
    provider: MetricsSnapshotProvider,
    last_request: Arc<Mutex<Option<SystemTime>>>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut request_line = String::new();
    tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut request_line))
        .await
        .map_err(|_| QlinkError::Protocol("metrics request line timed out".into()))??;

    *last_request.lock().await = Some(SystemTime::now());

    // Best-effort drain of remaining headers so the client doesn't see EPIPE.
    loop {
        let mut header_line = String::new();
        let read = match tokio::time::timeout(
            Duration::from_millis(250),
            reader.read_line(&mut header_line),
        )
        .await
        {
            Ok(Ok(n)) => n,
            Ok(Err(_)) | Err(_) => 0,
        };
        if read == 0 || header_line == "\r\n" || header_line == "\n" {
            break;
        }
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let path = parts.get(1).copied().unwrap_or("/");

    if !request_line.to_uppercase().starts_with("GET") {
        write_response(
            &mut writer,
            405,
            "text/plain; charset=utf-8",
            b"method not allowed",
        )
        .await?;
        return Ok(());
    }

    if path != "/metrics" {
        write_response(&mut writer, 404, "text/plain; charset=utf-8", b"not found").await?;
        return Ok(());
    }

    let snapshot = provider();
    let body = snapshot.render_open_metrics();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let body = format!("{body}# generated_unix {timestamp}\n");
    write_response(
        &mut writer,
        200,
        "application/openmetrics-text; version=1.0.0; charset=utf-8",
        body.as_bytes(),
    )
    .await
}

async fn write_response(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
        len = body.len()
    );
    writer.write_all(header.as_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await?;
    let _ = writer.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    #[test]
    fn open_metrics_renders_counter_and_gauge() {
        let mut snapshot = MetricsSnapshot::default();
        snapshot.push_counter("qlink_frames_sent_total", "frames sent", 42.0);
        snapshot.push_gauge("qlink_peers", "peer count", 3.0);
        let rendered = snapshot.render_open_metrics();
        assert!(rendered.contains("# TYPE qlink_frames_sent_total counter"));
        assert!(rendered.contains("qlink_frames_sent_total 42"));
        assert!(rendered.contains("# TYPE qlink_peers gauge"));
        assert!(rendered.contains("qlink_peers 3"));
    }

    #[test]
    fn label_values_are_escaped() {
        let mut labels = BTreeMap::new();
        labels.insert("path".into(), "with \"quotes\" and\\backslash".into());
        let family = MetricFamily {
            name: "qlink_label_test".into(),
            help: "help".into(),
            kind: MetricKind::Gauge,
            samples: vec![LabeledValue { labels, value: 1.0 }],
        };
        let snapshot = MetricsSnapshot {
            families: vec![family],
        };
        let rendered = snapshot.render_open_metrics();
        assert!(rendered.contains(r#"path="with \"quotes\" and\\backslash""#));
    }

    #[tokio::test]
    async fn endpoint_serves_metrics_for_get_requests() {
        let snapshot_provider: MetricsSnapshotProvider = Arc::new(|| {
            let mut snapshot = MetricsSnapshot::default();
            snapshot.push_counter("qlink_test_total", "test counter", 7.0);
            snapshot
        });
        let endpoint = spawn_metrics_endpoint(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            snapshot_provider,
        )
        .await
        .unwrap();

        let body = http_get(endpoint.local_addr(), "/metrics").await;
        assert!(body.contains("qlink_test_total 7"));
        assert!(body.contains("# generated_unix"));
        assert!(endpoint.last_request().await.is_some());
    }

    #[tokio::test]
    async fn endpoint_rejects_non_metrics_paths() {
        let provider: MetricsSnapshotProvider = Arc::new(MetricsSnapshot::default);
        let endpoint = spawn_metrics_endpoint(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            provider,
        )
        .await
        .unwrap();

        let response = http_request(
            endpoint.local_addr(),
            "GET /foo HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 404"));
    }

    #[tokio::test]
    async fn endpoint_rejects_non_get_methods() {
        let provider: MetricsSnapshotProvider = Arc::new(MetricsSnapshot::default);
        let endpoint = spawn_metrics_endpoint(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            provider,
        )
        .await
        .unwrap();

        let response = http_request(
            endpoint.local_addr(),
            "POST /metrics HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 405"));
    }

    async fn http_get(addr: SocketAddr, path: &str) -> String {
        let request = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        let response = http_request(addr, &request).await;
        response.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
    }

    async fn http_request(addr: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.shutdown().await.ok();
        let mut buffer = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8_lossy(&buffer).to_string()
    }
}
