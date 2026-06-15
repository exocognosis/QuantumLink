use qlink_proto::{ConnectionPhase, DaemonConfig, DaemonStatus, PeerStatus};
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::Duration;

const MAX_CONTROL_REQUEST_BYTES: usize = 1024;
const CONTROL_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonPaths {
    pub config_file: PathBuf,
    pub state_dir: PathBuf,
    pub socket: PathBuf,
}

impl Default for DaemonPaths {
    fn default() -> Self {
        Self {
            config_file: PathBuf::from("/etc/quantumlink/config.json"),
            state_dir: PathBuf::from("/var/lib/quantumlink"),
            socket: PathBuf::from("/run/quantumlink/qlinkd.sock"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkRuntimeState {
    NotStarted,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DaemonRuntimeState {
    pub phase: ConnectionPhase,
    pub active_party: Option<String>,
    pub peers: Vec<PeerStatus>,
    pub kill_switch: bool,
    pub network: NetworkRuntimeState,
}

impl DaemonRuntimeState {
    pub fn idle(kill_switch: bool) -> Self {
        Self {
            phase: ConnectionPhase::Idle,
            active_party: None,
            peers: Vec::new(),
            kill_switch,
            network: NetworkRuntimeState::NotStarted,
        }
    }

    pub fn status(&self) -> DaemonStatus {
        DaemonStatus {
            phase: self.phase,
            active_party: self.active_party.clone(),
            peers: self.peers.clone(),
            kill_switch: self.kill_switch,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DaemonEngine {
    config: DaemonConfig,
    paths: DaemonPaths,
    runtime: DaemonRuntimeState,
}

impl DaemonEngine {
    pub fn new(config: DaemonConfig, paths: DaemonPaths) -> Self {
        let runtime = DaemonRuntimeState::idle(config.kill_switch);
        Self {
            config,
            paths,
            runtime,
        }
    }

    pub fn status(&self) -> DaemonStatus {
        self.runtime.status()
    }

    pub fn runtime_state(&self) -> &DaemonRuntimeState {
        &self.runtime
    }

    pub fn config(&self) -> &DaemonConfig {
        &self.config
    }

    pub fn paths(&self) -> &DaemonPaths {
        &self.paths
    }

    pub fn mark_preparing(&mut self) {
        self.runtime.phase = ConnectionPhase::Preparing;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    RunResident,
    CheckConfig,
}

impl RuntimeMode {
    pub fn from_args<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if args.into_iter().any(|arg| arg.as_ref() == "--check") {
            Self::CheckConfig
        } else {
            Self::RunResident
        }
    }
}

#[cfg(unix)]
pub fn serve_status_stream(mut stream: UnixStream, engine: &DaemonEngine) -> std::io::Result<()> {
    stream.set_read_timeout(Some(CONTROL_REQUEST_READ_TIMEOUT))?;
    let request = match read_control_request(&stream) {
        Ok(request) => request,
        Err(error) => {
            let message = error.to_string();
            let _ = write_control_error(&mut stream, &message);
            return Err(error);
        }
    };

    if request.trim() == r#"{"type":"status"}"# || request.trim() == "status" {
        serde_json::to_writer(&mut stream, &engine.status())?;
        stream.write_all(b"\n")?;
    } else {
        write_control_error(&mut stream, "unsupported request")?;
    }
    Ok(())
}

#[cfg(unix)]
fn read_control_request(stream: &UnixStream) -> std::io::Result<String> {
    let reader = BufReader::new(stream);
    let mut limited_reader = reader.take((MAX_CONTROL_REQUEST_BYTES + 1) as u64);
    let mut request = Vec::new();
    limited_reader.read_until(b'\n', &mut request)?;

    if request.len() > MAX_CONTROL_REQUEST_BYTES {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("request too large; max {MAX_CONTROL_REQUEST_BYTES} bytes"),
        ));
    }

    String::from_utf8(request).map_err(|error| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("control request must be UTF-8: {error}"),
        )
    })
}

#[cfg(unix)]
fn write_control_error(stream: &mut UnixStream, message: &str) -> std::io::Result<()> {
    serde_json::to_writer(
        &mut *stream,
        &serde_json::json!({
            "type": "error",
            "message": message,
        }),
    )?;
    stream.write_all(b"\n")
}

#[cfg(unix)]
fn serve_status_streams<I>(streams: I, engine: &DaemonEngine) -> std::io::Result<()>
where
    I: IntoIterator<Item = std::io::Result<UnixStream>>,
{
    for stream in streams {
        match stream {
            Ok(stream) => {
                if let Err(error) = serve_status_stream(stream, engine) {
                    eprintln!("qlinkd client error: {error}");
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(unix)]
pub fn run_resident(engine: DaemonEngine) -> std::io::Result<()> {
    let socket = engine.paths().socket.clone();
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if socket.exists() {
        std::fs::remove_file(&socket)?;
    }

    let listener = UnixListener::bind(&socket)?;
    serve_status_streams(listener.incoming(), &engine)
}

pub fn load_config_or_default(paths: &DaemonPaths) -> std::io::Result<DaemonConfig> {
    match std::fs::read(&paths.config_file) {
        Ok(bytes) => {
            let config = serde_json::from_slice(&bytes).map_err(|error| {
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to parse {}: {error}", paths.config_file.display()),
                )
            })?;
            validate_loaded_config(config, &paths.config_file.display().to_string())
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            validate_loaded_config(DaemonConfig::default(), "default config")
        }
        Err(error) => Err(error),
    }
}

fn validate_loaded_config(config: DaemonConfig, source: &str) -> std::io::Result<DaemonConfig> {
    config.validate().map_err(|error| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("invalid qlinkd config {source}: {error}"),
        )
    })?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_paths_match_linux_service_layout() {
        let paths = DaemonPaths::default();

        assert_eq!(
            paths.config_file.display().to_string(),
            "/etc/quantumlink/config.json"
        );
        assert_eq!(
            paths.state_dir.display().to_string(),
            "/var/lib/quantumlink"
        );
        assert_eq!(
            paths.socket.display().to_string(),
            "/run/quantumlink/qlinkd.sock"
        );
    }

    #[test]
    fn engine_status_starts_idle_with_kill_switch_enabled() {
        let engine = DaemonEngine::new(DaemonConfig::default(), DaemonPaths::default());
        let status = engine.status();

        assert_eq!(status.phase, ConnectionPhase::Idle);
        assert!(status.kill_switch);
        assert!(status.peers.is_empty());
    }

    #[test]
    fn engine_runtime_state_starts_without_network_side_effects() {
        let engine = DaemonEngine::new(DaemonConfig::default(), DaemonPaths::default());
        let runtime = engine.runtime_state();

        assert_eq!(runtime.phase, ConnectionPhase::Idle);
        assert_eq!(runtime.network, NetworkRuntimeState::NotStarted);
        assert!(runtime.peers.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn serve_status_stream_rejects_overlong_control_request_without_panicking() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let engine = DaemonEngine::new(DaemonConfig::default(), DaemonPaths::default());
        let (server, mut client) = UnixStream::pair().unwrap();
        let mut request = "x".repeat(4096);
        request.push('\n');
        client.write_all(request.as_bytes()).unwrap();

        let error = serve_status_stream(server, &engine).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(error.to_string().contains("request too large"));
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.contains("request too large"));
    }

    #[cfg(unix)]
    #[test]
    fn serve_status_streams_continues_after_bad_request() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let engine = DaemonEngine::new(DaemonConfig::default(), DaemonPaths::default());
        let (bad_server, mut bad_client) = UnixStream::pair().unwrap();
        let (status_server, mut status_client) = UnixStream::pair().unwrap();
        let mut bad_request = "x".repeat(4096);
        bad_request.push('\n');
        bad_client.write_all(bad_request.as_bytes()).unwrap();
        status_client.write_all(b"status\n").unwrap();

        serve_status_streams(vec![Ok(bad_server), Ok(status_server)], &engine).unwrap();

        let mut bad_response = String::new();
        bad_client.read_to_string(&mut bad_response).unwrap();
        assert!(bad_response.contains("request too large"));

        let mut status_response = String::new();
        status_client.read_to_string(&mut status_response).unwrap();
        assert!(status_response.contains(r#""phase":"idle""#));
    }

    #[test]
    fn default_runtime_mode_is_resident_daemon() {
        assert_eq!(
            RuntimeMode::from_args(std::iter::empty::<&str>()),
            RuntimeMode::RunResident
        );
        assert_eq!(
            RuntimeMode::from_args(["--check"]),
            RuntimeMode::CheckConfig
        );
    }

    #[test]
    fn load_config_reads_operator_config_file() {
        let temp = tempfile::tempdir().unwrap();
        let paths = DaemonPaths {
            config_file: temp.path().join("config.json"),
            state_dir: temp.path().join("state"),
            socket: temp.path().join("qlinkd.sock"),
        };
        std::fs::write(
            &paths.config_file,
            r#"{
                "interfaceName": "qltest0",
                "overlayCidr": "100.64.0.0/10",
                "overlayIpv4Address": "100.64.10.9",
                "routeMode": "gameOnly",
                "rendezvousServers": ["127.0.0.1:9471"],
                "relayServers": ["127.0.0.1:9472"],
                "killSwitch": true,
                "lowLatency": false,
                "voiceChatSafe": true
            }"#,
        )
        .unwrap();

        let config = load_config_or_default(&paths).unwrap();

        assert_eq!(config.interface_name, "qltest0");
        assert_eq!(config.overlay_ipv4_address, "100.64.10.9");
        assert!(!config.low_latency);
    }

    #[test]
    fn load_config_defaults_when_config_file_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let paths = DaemonPaths {
            config_file: temp.path().join("missing.json"),
            state_dir: temp.path().join("state"),
            socket: temp.path().join("qlinkd.sock"),
        };

        let config = load_config_or_default(&paths).unwrap();

        assert_eq!(config, DaemonConfig::default());
    }

    #[test]
    fn load_config_rejects_invalid_operator_config_file() {
        let temp = tempfile::tempdir().unwrap();
        let paths = DaemonPaths {
            config_file: temp.path().join("config.json"),
            state_dir: temp.path().join("state"),
            socket: temp.path().join("qlinkd.sock"),
        };
        std::fs::write(
            &paths.config_file,
            r#"{
                "interfaceName": "qlink/bad",
                "overlayCidr": "100.64.0.0/10",
                "overlayIpv4Address": "100.64.10.9",
                "routeMode": "gameOnly",
                "rendezvousServers": [],
                "relayServers": [],
                "killSwitch": true,
                "lowLatency": false,
                "voiceChatSafe": true
            }"#,
        )
        .unwrap();

        let error = load_config_or_default(&paths).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(error.to_string().contains("invalid qlinkd config"));
        assert!(error.to_string().contains("interfaceName"));
    }
}
