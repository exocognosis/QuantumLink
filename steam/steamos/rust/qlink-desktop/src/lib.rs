use qlink_proto::{DaemonStatus, GameProfileStatus, PeerStore};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_CONTROL_OUTPUT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ControlSnapshot {
    pub daemon: Option<DaemonStatus>,
    pub daemon_error: Option<String>,
    pub peer_store: PeerStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityAction {
    Status,
    Register,
    Update,
    Suspend,
    Reactivate,
    Revoke,
}

impl IdentityAction {
    pub fn command_name(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Register => "register",
            Self::Update => "update",
            Self::Suspend => "suspend",
            Self::Reactivate => "reactivate",
            Self::Revoke => "revoke",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct IdentityInput {
    pub config_file: String,
    pub state_dir: String,
    pub keystore_path: String,
    pub wallet_name: String,
    pub peer_id: String,
    pub max_peer_ttl_seconds: String,
    pub mesh_scope: String,
}

#[derive(Debug, Clone)]
pub enum ControlRequest {
    Refresh,
    Doctor,
    StartService,
    RestartService,
    Connect {
        peer_id: String,
    },
    Disconnect,
    ImportInvite {
        encoded: String,
    },
    SelectPeer {
        peer_id: String,
    },
    ClearPeerSelection,
    SelectProfile {
        profile_id: String,
    },
    ClearProfile,
    RevokePeer {
        peer_id: String,
    },
    RemovePeer {
        peer_id: String,
    },
    Identity {
        action: IdentityAction,
        input: IdentityInput,
    },
    SupportBundle {
        output: String,
    },
}

#[derive(Debug, Clone)]
pub enum ControlResult {
    Snapshot(ControlSnapshot),
    Action {
        message: String,
        snapshot: ControlSnapshot,
    },
    Identity {
        action: IdentityAction,
        document: Value,
    },
    SupportBundle {
        output: String,
        snapshot: ControlSnapshot,
    },
    Diagnostic {
        output: String,
        snapshot: ControlSnapshot,
    },
}

pub trait CommandRunner: Send + Sync + 'static {
    fn run(&self, args: &[String]) -> Result<String, String>;
}

#[derive(Debug, Clone)]
pub struct QlinkCtlRunner {
    executable: PathBuf,
}

impl QlinkCtlRunner {
    pub fn discover() -> Self {
        let executable = std::env::var_os("QLINKCTL_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/usr/local/bin/qlinkctl"));
        Self { executable }
    }

    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self {
            executable: path.into(),
        }
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }
}

impl CommandRunner for QlinkCtlRunner {
    fn run(&self, args: &[String]) -> Result<String, String> {
        let output = Command::new(&self.executable)
            .args(args)
            .output()
            .map_err(|error| format!("failed to run {}: {error}", self.executable.display()))?;
        if output.stdout.len() > MAX_CONTROL_OUTPUT_BYTES
            || output.stderr.len() > MAX_CONTROL_OUTPUT_BYTES
        {
            return Err("qlinkctl response exceeded the 2 MiB limit".to_string());
        }
        if output.status.success() {
            return String::from_utf8(output.stdout)
                .map(|text| text.trim().to_string())
                .map_err(|_| "qlinkctl returned non-UTF-8 output".to_string());
        }

        let error = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if error.is_empty() {
            format!("qlinkctl exited with {}", output.status)
        } else {
            error
        })
    }
}

pub fn execute_request<R: CommandRunner>(
    runner: &R,
    request: ControlRequest,
) -> Result<ControlResult, String> {
    match request {
        ControlRequest::Refresh => refresh_snapshot(runner).map(ControlResult::Snapshot),
        ControlRequest::Doctor => {
            let output = runner.run(&args(&["doctor"]))?;
            Ok(ControlResult::Diagnostic {
                output,
                snapshot: refresh_snapshot(runner)?,
            })
        }
        ControlRequest::StartService => service_action(runner, "start", "Service started"),
        ControlRequest::RestartService => service_action(runner, "restart", "Service restarted"),
        ControlRequest::Connect { peer_id } => {
            require_value("peer ID", &peer_id)?;
            runner.run(&args(&["peer", "select", &peer_id]))?;
            runner.run(&args(&["service", "restart"]))?;
            Ok(ControlResult::Action {
                message: "Connection started".to_string(),
                snapshot: refresh_snapshot(runner)?,
            })
        }
        ControlRequest::Disconnect => {
            runner.run(&args(&["service", "stop"]))?;
            Ok(ControlResult::Action {
                message: "Connection stopped".to_string(),
                snapshot: refresh_snapshot(runner)?,
            })
        }
        ControlRequest::ImportInvite { encoded } => {
            require_value("invite code", &encoded)?;
            runner.run(&args(&["invite", "import", encoded.trim()]))?;
            Ok(ControlResult::Action {
                message: "Invite imported".to_string(),
                snapshot: refresh_snapshot(runner)?,
            })
        }
        ControlRequest::SelectPeer { peer_id } => {
            require_value("peer ID", &peer_id)?;
            runner.run(&args(&["peer", "select", &peer_id]))?;
            Ok(ControlResult::Action {
                message: "Peer selected".to_string(),
                snapshot: refresh_snapshot(runner)?,
            })
        }
        ControlRequest::ClearPeerSelection => {
            runner.run(&args(&["peer", "clear"]))?;
            Ok(ControlResult::Action {
                message: "Peer selection cleared".to_string(),
                snapshot: refresh_snapshot(runner)?,
            })
        }
        ControlRequest::SelectProfile { profile_id } => {
            require_value("profile ID", &profile_id)?;
            let profile_status = parse_profile_status(&runner.run(&args(&[
                "profile",
                "select",
                profile_id.trim(),
            ]))?)?;
            let restarted = restart_for_profile_change(runner, &profile_status)?;
            Ok(ControlResult::Action {
                message: if restarted {
                    "Game profile selected and service restarted".to_string()
                } else {
                    "Game profile selected".to_string()
                },
                snapshot: refresh_snapshot(runner)?,
            })
        }
        ControlRequest::ClearProfile => {
            let profile_status = parse_profile_status(&runner.run(&args(&["profile", "clear"]))?)?;
            let restarted = restart_for_profile_change(runner, &profile_status)?;
            Ok(ControlResult::Action {
                message: if restarted {
                    "Game profile cleared and service restarted".to_string()
                } else {
                    "Game profile cleared".to_string()
                },
                snapshot: refresh_snapshot(runner)?,
            })
        }
        ControlRequest::RevokePeer { peer_id } => {
            require_value("peer ID", &peer_id)?;
            runner.run(&args(&["peer", "revoke", &peer_id]))?;
            Ok(ControlResult::Action {
                message: "Peer revoked".to_string(),
                snapshot: refresh_snapshot(runner)?,
            })
        }
        ControlRequest::RemovePeer { peer_id } => {
            require_value("peer ID", &peer_id)?;
            runner.run(&args(&["peer", "remove", &peer_id]))?;
            Ok(ControlResult::Action {
                message: "Peer removed".to_string(),
                snapshot: refresh_snapshot(runner)?,
            })
        }
        ControlRequest::Identity { action, input } => {
            let command = identity_args(action, &input)?;
            let raw = runner.run(&command)?;
            let document = serde_json::from_str(&raw)
                .map_err(|error| format!("invalid Dytallix response: {error}"))?;
            Ok(ControlResult::Identity { action, document })
        }
        ControlRequest::SupportBundle { output } => {
            require_value("support bundle path", &output)?;
            runner.run(&args(&["support-bundle", "--output", output.trim()]))?;
            Ok(ControlResult::SupportBundle {
                output,
                snapshot: refresh_snapshot(runner)?,
            })
        }
    }
}

fn service_action<R: CommandRunner>(
    runner: &R,
    action: &str,
    message: &str,
) -> Result<ControlResult, String> {
    runner.run(&args(&["service", action]))?;
    Ok(ControlResult::Action {
        message: message.to_string(),
        snapshot: refresh_snapshot(runner)?,
    })
}

fn parse_profile_status(raw: &str) -> Result<GameProfileStatus, String> {
    serde_json::from_str(raw).map_err(|error| format!("invalid game profile response: {error}"))
}

fn restart_for_profile_change<R: CommandRunner>(
    runner: &R,
    status: &GameProfileStatus,
) -> Result<bool, String> {
    if !status.port_enforcement.restart_required {
        return Ok(false);
    }
    runner.run(&args(&["service", "restart"]))?;
    Ok(true)
}

pub fn refresh_snapshot<R: CommandRunner>(runner: &R) -> Result<ControlSnapshot, String> {
    let (daemon, daemon_error) = match runner.run(&args(&["status"])) {
        Ok(raw) => (
            Some(
                serde_json::from_str(&raw)
                    .map_err(|error| format!("invalid daemon status: {error}"))?,
            ),
            None,
        ),
        Err(error) => (None, Some(error)),
    };
    let peer_raw = runner.run(&args(&["peer", "state"]))?;
    let peer_store =
        serde_json::from_str(&peer_raw).map_err(|error| format!("invalid peer state: {error}"))?;

    Ok(ControlSnapshot {
        daemon,
        daemon_error,
        peer_store,
    })
}

pub fn identity_args(action: IdentityAction, input: &IdentityInput) -> Result<Vec<String>, String> {
    let mut command = args(&["dytallix", action.command_name()]);
    push_option(&mut command, "--config", &input.config_file);
    push_option(&mut command, "--state-dir", &input.state_dir);

    if action != IdentityAction::Status {
        require_value("Dytallix keystore path", &input.keystore_path)?;
        push_option(&mut command, "--keystore", &input.keystore_path);
        push_option(&mut command, "--wallet", &input.wallet_name);
    }

    if matches!(action, IdentityAction::Suspend | IdentityAction::Revoke) {
        require_value("peer ID", &input.peer_id)?;
        push_option(&mut command, "--peer-id", &input.peer_id);
    }
    if action == IdentityAction::Revoke {
        push_option(&mut command, "--confirm-peer-id", &input.peer_id);
    }
    if matches!(
        action,
        IdentityAction::Register | IdentityAction::Update | IdentityAction::Reactivate
    ) {
        push_option(&mut command, "--max-peer-ttl", &input.max_peer_ttl_seconds);
        push_option(&mut command, "--mesh-scope", &input.mesh_scope);
    }

    Ok(command)
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn push_option(command: &mut Vec<String>, flag: &str, value: &str) {
    if !value.trim().is_empty() {
        command.push(flag.to_string());
        command.push(value.trim().to_string());
    }
}

fn require_value(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct FakeRunner {
        responses: Mutex<VecDeque<Result<String, String>>>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl FakeRunner {
        fn new(responses: Vec<Result<&str, &str>>) -> Self {
            Self {
                responses: Mutex::new(
                    responses
                        .into_iter()
                        .map(|result| result.map(str::to_string).map_err(str::to_string))
                        .collect(),
                ),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, args: &[String]) -> Result<String, String> {
            self.calls.lock().unwrap().push(args.to_vec());
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("fake response")
        }
    }

    fn idle_status() -> &'static str {
        r#"{
            "phase":"idle","activeParty":null,"peers":[],"killSwitch":true,
            "network":{"state":"notStarted","interfaceName":null,"routeMode":null,
              "protectedCidr":null,"dryRun":true,"ownershipRecordPresent":false,
              "commands":[],"nftablesRules":[],"error":null},
            "dataPlane":{"interfaceName":null,"state":"notStarted",
              "packetIoAvailable":false,"transportReady":false,"transportPath":null,
              "peerSessionReady":false,"lastTransportError":null,
              "metrics":{"observedPackets":0,"queuedPackets":0,"droppedPackets":0,
                "emittedPackets":0,"acceptedPackets":0,"rejectedPackets":0,
                "transportErrors":0},"error":null},
            "publication":{"state":"notStarted"}
        }"#
    }

    fn profile_status(restart_required: bool) -> String {
        format!(
            r#"{{"availableProfiles":[],"selectedProfile":null,"selectionWarning":null,"portEnforcement":{{"state":"planned","profileId":null,"udpPorts":[],"restartRequired":{restart_required}}}}}"#
        )
    }

    #[test]
    fn refresh_accepts_stopped_daemon_and_reads_peer_state() {
        let runner = FakeRunner::new(vec![
            Err("qlinkd is unavailable"),
            Ok(r#"{"selectedPeerId":null,"peers":[]}"#),
        ]);

        let snapshot = refresh_snapshot(&runner).unwrap();

        assert!(snapshot.daemon.is_none());
        assert_eq!(
            snapshot.daemon_error.as_deref(),
            Some("qlinkd is unavailable")
        );
    }

    #[test]
    fn connect_selects_peer_before_service_restart() {
        let runner = FakeRunner::new(vec![
            Ok("peer-a"),
            Ok("restart"),
            Ok(idle_status()),
            Ok(r#"{"selectedPeerId":"peer-a","peers":[]}"#),
        ]);

        execute_request(
            &runner,
            ControlRequest::Connect {
                peer_id: "peer-a".to_string(),
            },
        )
        .unwrap();

        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls[0], args(&["peer", "select", "peer-a"]));
        assert_eq!(calls[1], args(&["service", "restart"]));
    }

    #[test]
    fn revoke_identity_requires_exact_peer_confirmation() {
        let command = identity_args(
            IdentityAction::Revoke,
            &IdentityInput {
                keystore_path: "/secure/wallet.json".to_string(),
                peer_id: "qlink_peer".to_string(),
                ..IdentityInput::default()
            },
        )
        .unwrap();

        assert!(command
            .windows(2)
            .any(|pair| pair == ["--peer-id", "qlink_peer"]));
        assert!(command
            .windows(2)
            .any(|pair| pair == ["--confirm-peer-id", "qlink_peer"]));
        assert!(!command.iter().any(|value| value.contains("seed")));
    }

    #[test]
    fn profile_selection_uses_the_qlinkctl_control_boundary() {
        let responses = vec![
            Ok(profile_status(false)),
            Ok(idle_status().to_string()),
            Ok(r#"{"selectedPeerId":null,"peers":[]}"#.to_string()),
        ];
        let runner = FakeRunner {
            responses: Mutex::new(responses.into()),
            calls: Mutex::new(Vec::new()),
        };

        execute_request(
            &runner,
            ControlRequest::SelectProfile {
                profile_id: "factorio".to_string(),
            },
        )
        .unwrap();

        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls[0], args(&["profile", "select", "factorio"]));
        assert_eq!(calls[1], args(&["status"]));
    }

    #[test]
    fn active_profile_selection_restarts_through_fixed_service_command() {
        let responses = vec![
            Ok(profile_status(true)),
            Ok("restart".to_string()),
            Ok(idle_status().to_string()),
            Ok(r#"{"selectedPeerId":null,"peers":[]}"#.to_string()),
        ];
        let runner = FakeRunner {
            responses: Mutex::new(responses.into()),
            calls: Mutex::new(Vec::new()),
        };

        execute_request(
            &runner,
            ControlRequest::SelectProfile {
                profile_id: "factorio".to_string(),
            },
        )
        .unwrap();

        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls[0], args(&["profile", "select", "factorio"]));
        assert_eq!(calls[1], args(&["service", "restart"]));
        assert_eq!(calls[2], args(&["status"]));
    }

    #[test]
    fn service_and_diagnostic_controls_use_fixed_qlinkctl_commands() {
        let runner = FakeRunner::new(vec![
            Ok("start"),
            Ok(idle_status()),
            Ok(r#"{"selectedPeerId":null,"peers":[]}"#),
            Ok("all checks passed"),
            Ok(idle_status()),
            Ok(r#"{"selectedPeerId":null,"peers":[]}"#),
        ]);

        execute_request(&runner, ControlRequest::StartService).unwrap();
        let result = execute_request(&runner, ControlRequest::Doctor).unwrap();

        assert!(matches!(
            result,
            ControlResult::Diagnostic { ref output, .. } if output == "all checks passed"
        ));
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls[0], args(&["service", "start"]));
        assert_eq!(calls[3], args(&["doctor"]));
    }

    #[test]
    fn peer_selection_clear_uses_the_peer_store_boundary() {
        let runner = FakeRunner::new(vec![
            Ok("cleared"),
            Ok(idle_status()),
            Ok(r#"{"selectedPeerId":null,"peers":[]}"#),
        ]);

        execute_request(&runner, ControlRequest::ClearPeerSelection).unwrap();

        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls[0], args(&["peer", "clear"]));
    }
}
