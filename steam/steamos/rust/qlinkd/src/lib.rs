use qlink_linux::{
    LinuxRuntimePlan, NetworkApplyError, NetworkExecutor, NetworkPlanError, NftablesExecutor,
};
use qlink_proto::{
    ConnectionPhase, DaemonConfig, DaemonStatus, NetworkPlanState, NetworkStatus, PeerStatus,
    RouteMode,
};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRuntimePlan {
    pub interface_name: String,
    pub route_mode: RouteMode,
    pub protected_cidr: String,
    pub commands: Vec<String>,
    pub nftables_rules: Vec<String>,
}

impl NetworkRuntimePlan {
    fn from_plan(config: &DaemonConfig, plan: &LinuxRuntimePlan) -> Self {
        Self {
            interface_name: config.interface_name.clone(),
            route_mode: config.route_mode,
            protected_cidr: plan.protected_cidr().to_string(),
            commands: plan.network.commands.clone(),
            nftables_rules: plan.nftables.rules.clone(),
        }
    }

    fn status(
        &self,
        state: NetworkPlanState,
        dry_run: bool,
        error: Option<String>,
    ) -> NetworkStatus {
        NetworkStatus {
            state,
            interface_name: Some(self.interface_name.clone()),
            route_mode: Some(self.route_mode),
            protected_cidr: Some(self.protected_cidr.clone()),
            dry_run,
            commands: self.commands.clone(),
            nftables_rules: self.nftables_rules.clone(),
            error,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkRuntimeState {
    NotStarted,
    Planned(NetworkRuntimePlan),
    Applied(NetworkRuntimePlan),
    ApplyFailed {
        plan: NetworkRuntimePlan,
        error: String,
    },
}

impl NetworkRuntimeState {
    fn planned(config: &DaemonConfig, plan: &LinuxRuntimePlan) -> Self {
        Self::Planned(NetworkRuntimePlan::from_plan(config, plan))
    }

    fn status(&self) -> NetworkStatus {
        match self {
            Self::NotStarted => NetworkStatus::not_started(),
            Self::Planned(plan) => plan.status(NetworkPlanState::Planned, true, None),
            Self::Applied(plan) => plan.status(NetworkPlanState::Applied, false, None),
            Self::ApplyFailed { plan, error } => {
                plan.status(NetworkPlanState::ApplyFailed, false, Some(error.clone()))
            }
        }
    }
}

#[derive(Debug)]
pub enum DaemonInitError {
    NetworkPlan(NetworkPlanError),
}

impl std::fmt::Display for DaemonInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkPlan(error) => write!(f, "failed to plan SteamOS networking: {error}"),
        }
    }
}

impl std::error::Error for DaemonInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NetworkPlan(error) => Some(error),
        }
    }
}

impl From<NetworkPlanError> for DaemonInitError {
    fn from(error: NetworkPlanError) -> Self {
        Self::NetworkPlan(error)
    }
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
            network: self.network.status(),
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

    pub fn try_new(config: DaemonConfig, paths: DaemonPaths) -> Result<Self, DaemonInitError> {
        let plan = LinuxRuntimePlan::from_config(&config)?;
        let runtime = DaemonRuntimeState {
            phase: ConnectionPhase::Idle,
            active_party: None,
            peers: Vec::new(),
            kill_switch: config.kill_switch,
            network: NetworkRuntimeState::planned(&config, &plan),
        };
        Ok(Self {
            config,
            paths,
            runtime,
        })
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

    pub fn apply_network_with<NE, NF>(
        &mut self,
        network_executor: &mut NE,
        nftables_executor: &mut NF,
    ) -> Result<(), NetworkApplyError>
    where
        NE: NetworkExecutor,
        NF: NftablesExecutor,
    {
        self.activate_network_with(network_executor, nftables_executor)
    }

    pub fn activate_network_with<NE, NF>(
        &mut self,
        network_executor: &mut NE,
        nftables_executor: &mut NF,
    ) -> Result<(), NetworkApplyError>
    where
        NE: NetworkExecutor,
        NF: NftablesExecutor,
    {
        let plan = LinuxRuntimePlan::from_config(&self.config).map_err(|error| {
            NetworkApplyError::new(format!("failed to plan SteamOS networking: {error}"))
        })?;
        let runtime_plan = NetworkRuntimePlan::from_plan(&self.config, &plan);

        if self.config.route_mode == RouteMode::FullTunnel {
            let error = NetworkApplyError::new(
                "full-tunnel activation requires underlay exemptions before real apply",
            );
            self.runtime.network = NetworkRuntimeState::ApplyFailed {
                plan: runtime_plan,
                error: error.message().to_string(),
            };
            return Err(error);
        }

        match plan.apply_with_rollback(network_executor, nftables_executor) {
            Ok(()) => {
                self.runtime.network = NetworkRuntimeState::Applied(runtime_plan);
                Ok(())
            }
            Err(error) => {
                self.runtime.network = NetworkRuntimeState::ApplyFailed {
                    plan: runtime_plan,
                    error: error.message().to_string(),
                };
                Err(error)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    RunResident { activate_network: bool },
    CheckConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeModeError {
    ConflictingFlags,
}

impl std::fmt::Display for RuntimeModeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConflictingFlags => {
                write!(f, "cannot combine --check with --activate-network")
            }
        }
    }
}

impl std::error::Error for RuntimeModeError {}

impl RuntimeMode {
    pub fn from_args<I, S>(args: I) -> Result<Self, RuntimeModeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut check_config = false;
        let mut activate_network = false;

        for arg in args {
            match arg.as_ref() {
                "--check" => check_config = true,
                "--activate-network" => activate_network = true,
                _ => {}
            }
        }

        if check_config && activate_network {
            Err(RuntimeModeError::ConflictingFlags)
        } else if check_config {
            Ok(Self::CheckConfig)
        } else {
            Ok(Self::RunResident { activate_network })
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
    use qlink_linux::{
        NetworkApplyError, NetworkExecutor, NetworkOperation, NftablesExecutor, NftablesOperation,
    };

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

    #[test]
    fn engine_try_new_builds_dry_run_network_plan_from_config() {
        let engine = DaemonEngine::try_new(DaemonConfig::default(), DaemonPaths::default())
            .expect("default config should produce a dry-run network plan");
        let status = engine.status();

        assert_eq!(status.network.state, NetworkPlanState::Planned);
        assert_eq!(status.network.interface_name.as_deref(), Some("qlink0"));
        assert_eq!(
            status.network.protected_cidr.as_deref(),
            Some("100.64.0.0/10")
        );
        assert!(status.network.dry_run);
        assert!(status
            .network
            .commands
            .iter()
            .any(|command| command == "ip addr add 100.64.10.2/32 dev qlink0"));
        assert!(status
            .network
            .nftables_rules
            .iter()
            .any(|rule| rule.contains("ip daddr 100.64.0.0/10")));
    }

    #[derive(Default)]
    struct RecordingNetworkExecutor {
        operations: Vec<NetworkOperation>,
        fail_on_call: Option<usize>,
    }

    impl NetworkExecutor for RecordingNetworkExecutor {
        fn apply(&mut self, operation: &NetworkOperation) -> Result<(), NetworkApplyError> {
            self.operations.push(operation.clone());
            if self.fail_on_call == Some(self.operations.len()) {
                return Err(NetworkApplyError::new("network apply failed"));
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingNftablesExecutor {
        operations: Vec<NftablesOperation>,
        fail_on_call: Option<usize>,
    }

    impl NftablesExecutor for RecordingNftablesExecutor {
        fn apply_nftables(
            &mut self,
            operation: &NftablesOperation,
        ) -> Result<(), NetworkApplyError> {
            self.operations.push(operation.clone());
            if self.fail_on_call == Some(self.operations.len()) {
                return Err(NetworkApplyError::new("nftables apply failed"));
            }
            Ok(())
        }
    }

    #[test]
    fn engine_try_new_still_only_plans_network() {
        let network_executor = RecordingNetworkExecutor::default();
        let nftables_executor = RecordingNftablesExecutor::default();

        let engine = DaemonEngine::try_new(DaemonConfig::default(), DaemonPaths::default())
            .expect("default config should produce a dry-run network plan");
        let status = engine.status();

        assert_eq!(status.network.state, NetworkPlanState::Planned);
        assert!(status.network.dry_run);
        assert!(network_executor.operations.is_empty());
        assert!(nftables_executor.operations.is_empty());
        assert!(status.network.error.is_none());
    }

    #[test]
    fn activate_network_with_fake_executors_marks_applied() {
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), DaemonPaths::default())
            .expect("default config should produce a dry-run network plan");
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();

        engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .expect("fake executors should apply");
        let status = engine.status();

        assert_eq!(network_executor.operations.len(), 5);
        assert_eq!(nftables_executor.operations.len(), 5);
        assert_eq!(status.network.state, NetworkPlanState::Applied);
        assert!(!status.network.dry_run);
        assert!(status.network.error.is_none());
        assert!(status
            .network
            .commands
            .iter()
            .any(|command| { command == "ip route add 100.64.0.0/10 dev qlink0 table 51820" }));
    }

    #[test]
    fn activate_network_rolls_back_network_failure_and_marks_apply_failed() {
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), DaemonPaths::default())
            .expect("default config should produce a dry-run network plan");
        let mut network_executor = RecordingNetworkExecutor {
            fail_on_call: Some(1),
            ..RecordingNetworkExecutor::default()
        };
        let mut nftables_executor = RecordingNftablesExecutor::default();

        let error = engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .unwrap_err();
        let status = engine.status();

        assert!(error
            .message()
            .contains("runtime apply failed: network apply failed"));
        assert_eq!(network_executor.operations.len(), 1);
        assert!(nftables_executor.operations.is_empty());
        assert_eq!(status.network.state, NetworkPlanState::ApplyFailed);
        assert!(!status.network.dry_run);
        assert!(status
            .network
            .error
            .as_deref()
            .expect("activation failure should be recorded")
            .contains("runtime apply failed: network apply failed"));
        assert!(status
            .network
            .commands
            .iter()
            .any(|command| command == "ip tuntap add dev qlink0 mode tun"));
    }

    #[test]
    fn activate_network_rolls_back_completed_network_when_nftables_fails() {
        let mut engine = DaemonEngine::try_new(DaemonConfig::default(), DaemonPaths::default())
            .expect("default config should produce a dry-run network plan");
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor {
            fail_on_call: Some(1),
            ..RecordingNftablesExecutor::default()
        };

        let error = engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .unwrap_err();
        let status = engine.status();

        assert!(error
            .message()
            .contains("runtime apply failed: nftables apply failed"));
        assert_eq!(network_executor.operations.len(), 8);
        assert!(network_executor.operations.iter().any(|operation| matches!(
            operation,
            NetworkOperation::RemoveRule {
                fwmark: 0x514c,
                table: 51820
            }
        )));
        assert!(network_executor.operations.iter().any(|operation| matches!(
            operation,
            NetworkOperation::DeleteTun { name } if name == "qlink0"
        )));
        assert_eq!(nftables_executor.operations.len(), 1);
        assert_eq!(status.network.state, NetworkPlanState::ApplyFailed);
        assert!(!status.network.dry_run);
        assert!(status
            .network
            .error
            .as_deref()
            .expect("activation failure should be recorded")
            .contains("runtime apply failed: nftables apply failed"));
    }

    #[test]
    fn activate_network_blocks_full_tunnel_before_executor_calls() {
        let config = DaemonConfig {
            route_mode: RouteMode::FullTunnel,
            ..DaemonConfig::default()
        };
        let mut engine = DaemonEngine::try_new(config, DaemonPaths::default())
            .expect("full tunnel remains valid for dry-run planning");
        let mut network_executor = RecordingNetworkExecutor::default();
        let mut nftables_executor = RecordingNftablesExecutor::default();

        let error = engine
            .activate_network_with(&mut network_executor, &mut nftables_executor)
            .unwrap_err();
        let status = engine.status();

        assert!(error.message().contains("full-tunnel activation"));
        assert!(network_executor.operations.is_empty());
        assert!(nftables_executor.operations.is_empty());
        assert_eq!(status.network.state, NetworkPlanState::ApplyFailed);
        assert_eq!(status.network.route_mode, Some(RouteMode::FullTunnel));
        assert_eq!(status.network.protected_cidr.as_deref(), Some("0.0.0.0/0"));
        assert!(!status.network.commands.is_empty());
        assert!(!status.network.dry_run);
        assert!(status
            .network
            .error
            .as_deref()
            .expect("activation failure should be recorded")
            .contains("full-tunnel activation"));
    }

    #[test]
    fn try_new_full_tunnel_still_plans_dry_run_without_activation() {
        let config = DaemonConfig {
            route_mode: RouteMode::FullTunnel,
            ..DaemonConfig::default()
        };

        let engine = DaemonEngine::try_new(config, DaemonPaths::default())
            .expect("full tunnel remains valid for dry-run planning");
        let status = engine.status();

        assert_eq!(status.network.state, NetworkPlanState::Planned);
        assert_eq!(status.network.route_mode, Some(RouteMode::FullTunnel));
        assert_eq!(status.network.protected_cidr.as_deref(), Some("0.0.0.0/0"));
        assert!(status.network.dry_run);
    }

    #[test]
    fn engine_try_new_rejects_invalid_config_before_runtime_starts() {
        let config = DaemonConfig {
            interface_name: "qlink/bad".to_string(),
            ..DaemonConfig::default()
        };

        let error = DaemonEngine::try_new(config, DaemonPaths::default()).unwrap_err();

        assert!(error.to_string().contains("interfaceName"));
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
            RuntimeMode::from_args(std::iter::empty::<&str>()).unwrap(),
            RuntimeMode::RunResident {
                activate_network: false
            }
        );
    }

    #[test]
    fn runtime_mode_parses_explicit_network_activation() {
        assert_eq!(
            RuntimeMode::from_args(["--activate-network"]).unwrap(),
            RuntimeMode::RunResident {
                activate_network: true
            }
        );
    }

    #[test]
    fn runtime_mode_parses_check_config() {
        assert_eq!(
            RuntimeMode::from_args(["--check"]).unwrap(),
            RuntimeMode::CheckConfig
        );
    }

    #[test]
    fn runtime_mode_rejects_check_with_network_activation() {
        let error = RuntimeMode::from_args(["--check", "--activate-network"]).unwrap_err();

        assert_eq!(error, RuntimeModeError::ConflictingFlags);
        assert!(error.to_string().contains("cannot combine"));
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
