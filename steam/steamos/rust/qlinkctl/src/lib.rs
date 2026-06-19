use qlink_proto::{ConnectionPhase, DaemonStatus, NetworkPlanState, RouteMode};
use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("qlinkd is unavailable at {path}: {source}")]
    Unavailable {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to send status request: {0}")]
    Write(#[from] std::io::Error),
    #[error("invalid qlinkd status response: {0}")]
    Json(#[from] serde_json::Error),
    #[error("qlinkd returned an error: {0}")]
    Daemon(String),
}

#[cfg(unix)]
pub fn status_from_daemon(socket: &Path) -> Result<DaemonStatus, ControlError> {
    let mut stream = UnixStream::connect(socket).map_err(|source| ControlError::Unavailable {
        path: socket.display().to_string(),
        source,
    })?;
    stream.write_all(br#"{"type":"status"}"#)?;
    stream.write_all(b"\n")?;

    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut line)?;
    parse_status_response(line.trim_end())
}

pub fn format_status(status: &DaemonStatus) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(status)
}

pub fn format_doctor(status: &DaemonStatus) -> String {
    let network = &status.network;
    let phase = phase_label(status.phase);
    let state = network_state_label(network.state);
    let mode = if network.dry_run {
        "dry-run"
    } else if network.state == NetworkPlanState::Applied {
        "activated"
    } else {
        "unknown"
    };
    let ownership_record = if network.ownership_record_present {
        "present"
    } else {
        "absent"
    };
    let apply_error = network.error.as_deref().unwrap_or("none");
    let network_verdict = match (
        network.state,
        network.dry_run,
        network.ownership_record_present,
    ) {
        (NetworkPlanState::ApplyFailed, _, _) => match network.error.as_deref() {
            Some(error) => format!("FAIL - network apply failed: {error}"),
            None => "FAIL - network apply failed".to_string(),
        },
        (NetworkPlanState::Applied, _, false) => {
            "FAIL - applied networking without ownership record".to_string()
        }
        (NetworkPlanState::Planned, true, false) => "OK - dry-run planning healthy".to_string(),
        (NetworkPlanState::Applied, false, true) => {
            "OK - activated networking has teardown ownership".to_string()
        }
        (NetworkPlanState::NotStarted, _, true)
        | (NetworkPlanState::Planned, _, true)
        | (_, true, true) => "WARN - ownership record present; teardown may be pending".to_string(),
        _ => format!("WARN - network state {state} with mode {mode}"),
    };
    let verdict = match status.phase {
        ConnectionPhase::Failed => "FAIL - daemon phase failed".to_string(),
        ConnectionPhase::Degraded if !network_verdict.starts_with("FAIL") => {
            "WARN - daemon phase degraded".to_string()
        }
        _ => network_verdict,
    };

    format!(
        "verdict: {verdict}\n\
         phase: {phase}\n\
         kill switch: {kill_switch}\n\
         network state: {state}\n\
         mode: {mode}\n\
         interface: {interface}\n\
         route mode: {route_mode}\n\
         protected CIDR: {protected_cidr}\n\
         ownership record: {ownership_record}\n\
         apply error: {apply_error}",
        kill_switch = if status.kill_switch {
            "enabled"
        } else {
            "disabled"
        },
        interface = network.interface_name.as_deref().unwrap_or("unknown"),
        route_mode = network
            .route_mode
            .map(route_mode_label)
            .unwrap_or("unknown"),
        protected_cidr = network.protected_cidr.as_deref().unwrap_or("unknown"),
    )
}

fn phase_label(phase: ConnectionPhase) -> &'static str {
    match phase {
        ConnectionPhase::Idle => "idle",
        ConnectionPhase::Preparing => "preparing",
        ConnectionPhase::Connecting => "connecting",
        ConnectionPhase::Connected => "connected",
        ConnectionPhase::Degraded => "degraded",
        ConnectionPhase::Failed => "failed",
    }
}

fn network_state_label(state: NetworkPlanState) -> &'static str {
    match state {
        NetworkPlanState::NotStarted => "notStarted",
        NetworkPlanState::Planned => "planned",
        NetworkPlanState::ApplyFailed => "applyFailed",
        NetworkPlanState::Applied => "applied",
    }
}

fn route_mode_label(route_mode: RouteMode) -> &'static str {
    match route_mode {
        RouteMode::GameOnly => "gameOnly",
        RouteMode::ProtectedPrefixesOnly => "protectedPrefixesOnly",
        RouteMode::FullTunnel => "fullTunnel",
    }
}

fn parse_status_response(line: &str) -> Result<DaemonStatus, ControlError> {
    let value = serde_json::from_str::<serde_json::Value>(line)?;
    if value.get("type").and_then(serde_json::Value::as_str) == Some("error") {
        let message = value
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown daemon error")
            .to_string();
        return Err(ControlError::Daemon(message));
    }
    serde_json::from_value(value).map_err(ControlError::Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlink_proto::{NetworkPlanState, NetworkStatus, RouteMode};
    use std::path::PathBuf;

    fn status_with_network(
        state: NetworkPlanState,
        dry_run: bool,
        ownership_record_present: bool,
        error: Option<&str>,
    ) -> DaemonStatus {
        let mut status = DaemonStatus::idle(true);
        status.network = NetworkStatus {
            state,
            interface_name: Some("qlink0".to_string()),
            route_mode: Some(RouteMode::GameOnly),
            protected_cidr: Some("100.64.0.0/10".to_string()),
            dry_run,
            ownership_record_present,
            commands: Vec::new(),
            nftables_rules: Vec::new(),
            error: error.map(str::to_string),
        };
        status
    }

    #[test]
    fn status_reports_daemon_unavailable_when_socket_is_missing() {
        let missing = PathBuf::from("/tmp/qlinkctl-missing-test.sock");
        let error = status_from_daemon(&missing).unwrap_err();

        assert!(error.to_string().contains("qlinkd is unavailable"));
    }

    #[test]
    fn format_status_includes_network_plan_details() {
        let mut status = DaemonStatus::idle(true);
        status.network = NetworkStatus {
            state: NetworkPlanState::Planned,
            interface_name: Some("qlink0".to_string()),
            route_mode: Some(RouteMode::GameOnly),
            protected_cidr: Some("100.64.0.0/10".to_string()),
            dry_run: true,
            ownership_record_present: false,
            commands: vec!["ip tuntap add dev qlink0 mode tun".to_string()],
            nftables_rules: vec!["add table inet qlink".to_string()],
            error: None,
        };

        let json = format_status(&status).unwrap();

        assert!(json.contains("\"network\""));
        assert!(json.contains("\"state\": \"planned\""));
        assert!(json.contains("\"protectedCidr\": \"100.64.0.0/10\""));
        assert!(json.contains("\"dryRun\": true"));
    }

    #[test]
    fn format_doctor_reports_ok_for_healthy_dry_run_plan() {
        let status = status_with_network(NetworkPlanState::Planned, true, false, None);

        assert_eq!(
            format_doctor(&status),
            "verdict: OK - dry-run planning healthy\n\
             phase: idle\n\
             kill switch: enabled\n\
             network state: planned\n\
             mode: dry-run\n\
             interface: qlink0\n\
             route mode: gameOnly\n\
             protected CIDR: 100.64.0.0/10\n\
             ownership record: absent\n\
             apply error: none"
        );
    }

    #[test]
    fn format_doctor_fails_when_daemon_phase_failed() {
        let mut status = status_with_network(NetworkPlanState::Planned, true, false, None);
        status.phase = ConnectionPhase::Failed;

        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: FAIL - daemon phase failed"));
        assert!(doctor.contains("phase: failed"));
        assert!(doctor.contains("network state: planned"));
    }

    #[test]
    fn format_doctor_warns_when_daemon_phase_degraded() {
        let mut status = status_with_network(NetworkPlanState::Planned, true, false, None);
        status.phase = ConnectionPhase::Degraded;

        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: WARN - daemon phase degraded"));
        assert!(doctor.contains("phase: degraded"));
        assert!(doctor.contains("network state: planned"));
    }

    #[test]
    fn format_doctor_reports_ok_for_activated_network_with_ownership() {
        let status = status_with_network(NetworkPlanState::Applied, false, true, None);
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: OK - activated networking has teardown ownership"));
        assert!(doctor.contains("network state: applied"));
        assert!(doctor.contains("mode: activated"));
        assert!(doctor.contains("ownership record: present"));
    }

    #[test]
    fn format_doctor_warns_when_ownership_record_is_present_before_activation() {
        let status = status_with_network(NetworkPlanState::Planned, true, true, None);
        let doctor = format_doctor(&status);

        assert!(
            doctor.contains("verdict: WARN - ownership record present; teardown may be pending")
        );
        assert!(doctor.contains("network state: planned"));
        assert!(doctor.contains("mode: dry-run"));
        assert!(doctor.contains("ownership record: present"));
    }

    #[test]
    fn format_doctor_fails_apply_failed_status_with_error() {
        let status = status_with_network(
            NetworkPlanState::ApplyFailed,
            false,
            false,
            Some("nftables apply failed"),
        );
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: FAIL - network apply failed: nftables apply failed"));
        assert!(doctor.contains("network state: applyFailed"));
        assert!(doctor.contains("mode: unknown"));
        assert!(doctor.contains("apply error: nftables apply failed"));
    }

    #[test]
    fn format_doctor_fails_applied_status_without_ownership_record() {
        let status = status_with_network(NetworkPlanState::Applied, false, false, None);
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: FAIL - applied networking without ownership record"));
        assert!(doctor.contains("network state: applied"));
        assert!(doctor.contains("mode: activated"));
        assert!(doctor.contains("ownership record: absent"));
    }

    #[test]
    fn format_doctor_warns_with_state_and_mode_for_other_combinations() {
        let status = status_with_network(NetworkPlanState::Planned, false, false, None);
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: WARN - network state planned with mode unknown"));
        assert!(doctor.contains("mode: unknown"));
    }

    #[test]
    fn format_doctor_handles_legacy_not_started_status_without_panic() {
        let status = DaemonStatus::idle(false);
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: WARN - network state notStarted with mode dry-run"));
        assert!(doctor.contains("kill switch: disabled"));
        assert!(doctor.contains("network state: notStarted"));
        assert!(doctor.contains("interface: unknown"));
        assert!(doctor.contains("route mode: unknown"));
        assert!(doctor.contains("protected CIDR: unknown"));
        assert!(doctor.contains("ownership record: absent"));
    }

    #[test]
    fn format_status_includes_applied_network_state() {
        let mut status = DaemonStatus::idle(true);
        status.network = NetworkStatus {
            state: NetworkPlanState::Applied,
            interface_name: Some("qlink0".to_string()),
            route_mode: Some(RouteMode::GameOnly),
            protected_cidr: Some("100.64.0.0/10".to_string()),
            dry_run: false,
            ownership_record_present: true,
            commands: vec!["ip tuntap add dev qlink0 mode tun".to_string()],
            nftables_rules: vec!["add table inet qlink".to_string()],
            error: None,
        };

        let json = format_status(&status).unwrap();

        assert!(json.contains("\"state\": \"applied\""));
        assert!(json.contains("\"dryRun\": false"));
        assert!(json.contains("\"ownershipRecordPresent\": true"));
    }

    #[test]
    fn format_status_includes_apply_failed_error() {
        let mut status = DaemonStatus::idle(true);
        status.network = NetworkStatus {
            state: NetworkPlanState::ApplyFailed,
            interface_name: Some("qlink0".to_string()),
            route_mode: Some(RouteMode::GameOnly),
            protected_cidr: Some("100.64.0.0/10".to_string()),
            dry_run: false,
            ownership_record_present: true,
            commands: vec!["ip tuntap add dev qlink0 mode tun".to_string()],
            nftables_rules: vec!["add table inet qlink".to_string()],
            error: Some("nftables apply failed".to_string()),
        };

        let json = format_status(&status).unwrap();

        assert!(json.contains("\"state\": \"applyFailed\""));
        assert!(json.contains("\"error\": \"nftables apply failed\""));
    }

    #[test]
    fn parse_status_response_reports_daemon_error_envelope() {
        let error = parse_status_response(r#"{"type":"error","message":"unsupported request"}"#)
            .unwrap_err();

        assert!(error.to_string().contains("unsupported request"));
    }
}
