use qlink_proto::DaemonStatus;
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
    fn parse_status_response_reports_daemon_error_envelope() {
        let error = parse_status_response(r#"{"type":"error","message":"unsupported request"}"#)
            .unwrap_err();

        assert!(error.to_string().contains("unsupported request"));
    }
}
