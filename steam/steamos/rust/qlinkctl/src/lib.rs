use qlink_proto::{
    ConnectionPhase, DaemonStatus, DataPlaneState, NetworkPlanState, PathKind, RouteMode,
};

#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
};

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
    let data_plane = &status.data_plane;
    let phase = phase_label(status.phase);
    let state = network_state_label(network.state);
    let data_plane_state = data_plane_state_label(data_plane.state);
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
    let data_plane_verdict =
        data_plane_health_verdict(data_plane.state, data_plane.error.as_deref());
    let verdict = match status.phase {
        ConnectionPhase::Failed => "FAIL - daemon phase failed".to_string(),
        _ if data_plane_verdict
            .as_deref()
            .is_some_and(|verdict| verdict.starts_with("FAIL")) =>
        {
            data_plane_verdict.unwrap()
        }
        _ if network_verdict.starts_with("FAIL") => network_verdict,
        ConnectionPhase::Degraded => "WARN - daemon phase degraded".to_string(),
        _ if data_plane_verdict
            .as_deref()
            .is_some_and(|verdict| verdict.starts_with("WARN")) =>
        {
            data_plane_verdict.unwrap()
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
         apply error: {apply_error}\n\
         data-plane state: {data_plane_state}\n\
         data-plane interface: {data_plane_interface}\n\
         packet I/O: {packet_io}\n\
         transport ready: {transport_ready}\n\
         transport path: {transport_path}\n\
         peer session: {peer_session}\n\
         last transport error: {last_transport_error}\n\
         packet counters: observed={observed_packets} queued={queued_packets} dropped={dropped_packets} emitted={emitted_packets} accepted={accepted_packets} rejected={rejected_packets} transportErrors={transport_errors}\n\
         data-plane error: {data_plane_error}",
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
        data_plane_interface = data_plane.interface_name.as_deref().unwrap_or("unknown"),
        packet_io = if data_plane.packet_io_available {
            "available"
        } else {
            "unavailable"
        },
        transport_ready = if data_plane.transport_ready {
            "yes"
        } else {
            "no"
        },
        transport_path = data_plane
            .transport_path
            .map(path_kind_label)
            .unwrap_or("unknown"),
        peer_session = if data_plane.peer_session_ready {
            "ready"
        } else {
            "not ready"
        },
        last_transport_error = data_plane
            .last_transport_error
            .as_deref()
            .unwrap_or("none"),
        observed_packets = data_plane.metrics.observed_packets,
        queued_packets = data_plane.metrics.queued_packets,
        dropped_packets = data_plane.metrics.dropped_packets,
        emitted_packets = data_plane.metrics.emitted_packets,
        accepted_packets = data_plane.metrics.accepted_packets,
        rejected_packets = data_plane.metrics.rejected_packets,
        transport_errors = data_plane.metrics.transport_errors,
        data_plane_error = data_plane.error.as_deref().unwrap_or("none"),
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

fn data_plane_state_label(state: DataPlaneState) -> &'static str {
    match state {
        DataPlaneState::NotStarted => "notStarted",
        DataPlaneState::Starting => "starting",
        DataPlaneState::Ready => "ready",
        DataPlaneState::Degraded => "degraded",
        DataPlaneState::Failed => "failed",
    }
}

fn data_plane_health_verdict(state: DataPlaneState, error: Option<&str>) -> Option<String> {
    match (state, error) {
        (DataPlaneState::Failed, Some(error)) => Some(format!("FAIL - data plane failed: {error}")),
        (DataPlaneState::Failed, None) => Some("FAIL - data plane failed".to_string()),
        (DataPlaneState::Degraded, Some(error)) => {
            Some(format!("WARN - data plane degraded: {error}"))
        }
        (DataPlaneState::Degraded, None) => Some("WARN - data plane degraded".to_string()),
        _ => None,
    }
}

fn route_mode_label(route_mode: RouteMode) -> &'static str {
    match route_mode {
        RouteMode::GameOnly => "gameOnly",
        RouteMode::ProtectedPrefixesOnly => "protectedPrefixesOnly",
        RouteMode::FullTunnel => "fullTunnel",
    }
}

fn path_kind_label(path: PathKind) -> &'static str {
    match path {
        PathKind::Direct => "direct",
        PathKind::Relay => "relay",
        PathKind::Probing => "probing",
        PathKind::Unavailable => "unavailable",
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
    use qlink_proto::{
        DataPlaneState, DataPlaneStatus, NetworkPlanState, NetworkStatus, PacketPumpMetrics,
        RouteMode,
    };
    #[cfg(unix)]
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

    fn packet_pump_metrics() -> PacketPumpMetrics {
        PacketPumpMetrics {
            observed_packets: 18,
            queued_packets: 17,
            dropped_packets: 1,
            emitted_packets: 16,
            accepted_packets: 15,
            rejected_packets: 2,
            transport_errors: 1,
        }
    }

    fn status_with_data_plane(
        state: DataPlaneState,
        packet_io_available: bool,
        transport_ready: bool,
        error: Option<&str>,
    ) -> DaemonStatus {
        let mut status = status_with_network(NetworkPlanState::Planned, true, false, None);
        status.data_plane = DataPlaneStatus {
            interface_name: Some("qlink0".to_string()),
            state,
            packet_io_available,
            transport_ready,
            transport_path: if transport_ready {
                Some(PathKind::Direct)
            } else {
                Some(PathKind::Unavailable)
            },
            peer_session_ready: transport_ready,
            last_transport_error: None,
            metrics: packet_pump_metrics(),
            error: error.map(str::to_string),
        };
        status
    }

    #[cfg(unix)]
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
             apply error: none\n\
             data-plane state: notStarted\n\
             data-plane interface: unknown\n\
             packet I/O: unavailable\n\
             transport ready: no\n\
             transport path: unknown\n\
             peer session: not ready\n\
             last transport error: none\n\
             packet counters: observed=0 queued=0 dropped=0 emitted=0 accepted=0 rejected=0 transportErrors=0\n\
             data-plane error: none"
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
        assert!(doctor.contains("data-plane state: notStarted"));
        assert!(doctor.contains("packet I/O: unavailable"));
        assert!(doctor.contains("transport ready: no"));
        assert!(doctor.contains("transport path: unknown"));
        assert!(doctor.contains("peer session: not ready"));
        assert!(doctor.contains("packet counters: observed=0 queued=0 dropped=0 emitted=0 accepted=0 rejected=0 transportErrors=0"));
    }

    #[test]
    fn format_doctor_reports_starting_data_plane_without_peer_transport_claims() {
        let status = status_with_data_plane(DataPlaneState::Starting, true, false, None);
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: OK - dry-run planning healthy"));
        assert!(doctor.contains("data-plane state: starting"));
        assert!(doctor.contains("data-plane interface: qlink0"));
        assert!(doctor.contains("packet I/O: available"));
        assert!(doctor.contains("transport ready: no"));
        assert!(doctor.contains("transport path: unavailable"));
        assert!(doctor.contains("peer session: not ready"));
        assert!(doctor.contains("packet counters: observed=18 queued=17 dropped=1 emitted=16 accepted=15 rejected=2 transportErrors=1"));
        assert!(!doctor.contains("peer transport ready"));
    }

    #[test]
    fn format_doctor_fails_when_data_plane_failed() {
        let status = status_with_data_plane(
            DataPlaneState::Failed,
            false,
            false,
            Some("packet pump stopped"),
        );
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: FAIL - data plane failed: packet pump stopped"));
        assert!(doctor.contains("data-plane state: failed"));
        assert!(doctor.contains("data-plane error: packet pump stopped"));
        assert!(doctor.contains("last transport error: none"));
    }

    #[test]
    fn format_doctor_warns_when_data_plane_degraded() {
        let status = status_with_data_plane(
            DataPlaneState::Degraded,
            true,
            false,
            Some("transport backpressure"),
        );
        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: WARN - data plane degraded: transport backpressure"));
        assert!(doctor.contains("data-plane state: degraded"));
        assert!(doctor.contains("transport ready: no"));
        assert!(doctor.contains("transport path: unavailable"));
    }

    #[test]
    fn format_doctor_keeps_fail_precedence_over_data_plane_degraded_warning() {
        let mut status = status_with_data_plane(DataPlaneState::Degraded, true, false, None);
        status.network.state = NetworkPlanState::ApplyFailed;
        status.network.dry_run = false;
        status.network.error = Some("nftables apply failed".to_string());

        let doctor = format_doctor(&status);

        assert!(doctor.contains("verdict: FAIL - network apply failed: nftables apply failed"));
        assert!(doctor.contains("data-plane state: degraded"));
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
