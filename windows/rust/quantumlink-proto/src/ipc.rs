//! UI <-> service IPC schema — Rust port of `TunnelMessages.swift`,
//! extended with a request/response envelope for the Windows named-pipe
//! transport.
//!
//! Wire format: newline-delimited JSON (one object per line, UTF-8, no
//! embedded newlines). The UI writes a [`PipeRequest`], the service
//! responds with one [`PipeResponse`] carrying the same `id`. The service
//! may additionally push unsolicited [`PipeResponse`]s with `id: 0` for
//! status-change notifications.
//!
//! Pipe name: [`PIPE_NAME`]. The pipe ACL is configured by the service so
//! that interactive users can connect but only the service process can
//! create the pipe (first-instance semantics prevent squatting).

use crate::models::{TunnelConfiguration, TunnelStatus};
use serde::{Deserialize, Serialize};

/// Named-pipe path the service listens on.
pub const PIPE_NAME: &str = r"\\.\pipe\QuantumLinkService";

/// Bump when the wire schema changes incompatibly. The service rejects
/// clients whose `hello` carries a different major version.
pub const IPC_SCHEMA_VERSION: u32 = 1;

/// Commands the UI can issue. Mirrors `TunnelCommand` in
/// `TunnelMessages.swift` plus Windows service extras.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "command",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum TunnelCommand {
    /// Schema/version handshake. Must be the first request on a
    /// connection.
    Hello {
        schema_version: u32,
    },
    /// Bring the tunnel up with the supplied configuration (or the
    /// persisted one when `configuration` is omitted).
    Connect {
        #[serde(default)]
        configuration: Option<TunnelConfiguration>,
    },
    Disconnect,
    ReloadConfiguration {
        configuration: TunnelConfiguration,
    },
    Status,
    ExportDiagnostics,
    /// Per-peer state probe (multi-peer surface).
    PeerState {
        peer_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PipeRequest {
    /// Client-chosen correlation id; echoed in the response. Must be > 0.
    pub id: u64,
    #[serde(flatten)]
    pub command: TunnelCommand,
}

/// Mirrors `TunnelProviderMessage` in `TunnelMessages.swift`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum TunnelProviderMessage {
    Status {
        status: TunnelStatus,
    },
    Diagnostic {
        text: String,
    },
    Error {
        message: String,
    },
    /// Handshake acknowledgement.
    HelloAck {
        schema_version: u32,
        service_version: String,
    },
    /// Generic success for commands without a payload.
    Ok,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PipeResponse {
    /// Correlation id of the request, or 0 for unsolicited pushes.
    pub id: u64,
    #[serde(flatten)]
    pub message: TunnelProviderMessage,
}

impl PipeResponse {
    pub fn error(id: u64, message: impl Into<String>) -> Self {
        Self {
            id,
            message: TunnelProviderMessage::Error {
                message: message.into(),
            },
        }
    }
}

/// Encodes a value as one newline-terminated JSON line.
pub fn encode_line<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_shape_is_flat() {
        let request = PipeRequest {
            id: 7,
            command: TunnelCommand::Status,
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["id"], 7);
        assert_eq!(json["command"], "status");
    }

    #[test]
    fn connect_round_trips_without_configuration() {
        let line = br#"{"id":1,"command":"connect"}"#;
        let request: PipeRequest = serde_json::from_slice(line).unwrap();
        assert_eq!(
            request.command,
            TunnelCommand::Connect {
                configuration: None
            }
        );
    }

    #[test]
    fn status_response_round_trips() {
        let response = PipeResponse {
            id: 3,
            message: TunnelProviderMessage::Status {
                status: TunnelStatus::idle(),
            },
        };
        let bytes = encode_line(&response).unwrap();
        assert!(bytes.ends_with(b"\n"));
        let decoded: PipeResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, response);
    }
}
