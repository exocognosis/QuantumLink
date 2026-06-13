//! IPC command dispatch — the service side of the UI <-> service named
//! pipe protocol defined in `quantumlink-proto::ipc`.
//!
//! This module is transport-agnostic: [`serve_connection`] works over any
//! `AsyncRead + AsyncWrite` stream, so the protocol is unit-tested with
//! in-memory duplex pipes on any host while production uses the Windows
//! named-pipe server in [`win::pipe_server`](crate::win).
//!
//! Security invariants:
//! - The UI process is unprivileged. Every admin-level action (routes,
//!   WFP, adapter) happens in the service on the UI's *behalf*, after
//!   the request deserializes into the typed schema. Unknown commands
//!   and malformed JSON get an error response, never a crash.
//! - `hello` must precede any other command so schema mismatches fail
//!   fast with a versioned error instead of silent misbehavior.

use crate::engine::TunnelEngine;
use quantumlink_proto::ipc::{
    encode_line, PipeRequest, PipeResponse, TunnelCommand, TunnelProviderMessage,
    IPC_SCHEMA_VERSION,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

const MAX_LINE_BYTES: usize = 1_048_576;

pub struct IpcContext {
    pub engine: Arc<TunnelEngine>,
    pub state_dir: PathBuf,
}

/// Serves one client connection until EOF. Each request line yields
/// exactly one response line with the same correlation id.
pub async fn serve_connection<S>(stream: S, context: Arc<IpcContext>) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut lines = BufReader::new(read_half).lines();
    let mut handshaken = false;

    while let Some(line) = lines.next_line().await? {
        if line.len() > MAX_LINE_BYTES {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<PipeRequest>(&line) {
            Ok(request) => {
                if !handshaken && !matches!(request.command, TunnelCommand::Hello { .. }) {
                    PipeResponse::error(request.id, "hello required before other commands")
                } else {
                    if matches!(request.command, TunnelCommand::Hello { .. }) {
                        handshaken = true;
                    }
                    dispatch(request, &context).await
                }
            }
            Err(error) => PipeResponse::error(0, format!("malformed request: {error}")),
        };
        let bytes = encode_line(&response)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        write_half.write_all(&bytes).await?;
        write_half.flush().await?;
    }
    Ok(())
}

async fn dispatch(request: PipeRequest, context: &IpcContext) -> PipeResponse {
    let id = request.id;
    let engine = Arc::clone(&context.engine);
    let state_dir = context.state_dir.clone();

    // Engine calls are synchronous and may block (thread joins, adapter
    // teardown), so run them off the IPC reactor.
    let message = tokio::task::spawn_blocking(move || -> TunnelProviderMessage {
        match request.command {
            TunnelCommand::Hello { schema_version } => {
                if schema_version != IPC_SCHEMA_VERSION {
                    TunnelProviderMessage::Error {
                        message: format!(
                            "schema version mismatch: client {schema_version}, service {IPC_SCHEMA_VERSION}"
                        ),
                    }
                } else {
                    TunnelProviderMessage::HelloAck {
                        schema_version: IPC_SCHEMA_VERSION,
                        service_version: env!("CARGO_PKG_VERSION").to_string(),
                    }
                }
            }
            TunnelCommand::Connect { configuration } => {
                let config = configuration
                    .unwrap_or_else(|| crate::config::load_or_default(&state_dir));
                match engine.connect(config.clone()) {
                    Ok(status) => {
                        if let Err(error) = crate::config::save_configuration(&state_dir, &config)
                        {
                            tracing::warn!(%error, "config persist failed after connect");
                        }
                        TunnelProviderMessage::Status { status }
                    }
                    Err(error) => TunnelProviderMessage::Error {
                        message: error.to_string(),
                    },
                }
            }
            TunnelCommand::Disconnect => TunnelProviderMessage::Status {
                status: engine.disconnect(),
            },
            TunnelCommand::ReloadConfiguration { configuration } => {
                match crate::config::save_configuration(&state_dir, &configuration) {
                    Ok(()) => TunnelProviderMessage::Ok,
                    Err(error) => TunnelProviderMessage::Error {
                        message: format!("configuration persist failed: {error}"),
                    },
                }
            }
            TunnelCommand::Status => TunnelProviderMessage::Status {
                status: engine.status(),
            },
            TunnelCommand::ExportDiagnostics => TunnelProviderMessage::Diagnostic {
                text: engine.diagnostics(),
            },
            TunnelCommand::PeerState { peer_id } => match engine.peer_state_code(&peer_id) {
                Some(code) => TunnelProviderMessage::Diagnostic {
                    text: format!("{code}"),
                },
                None => TunnelProviderMessage::Error {
                    message: "peer not active".to_string(),
                },
            },
        }
    })
    .await
    .unwrap_or_else(|join_error| TunnelProviderMessage::Error {
        message: format!("internal dispatch failure: {join_error}"),
    });

    PipeResponse { id, message }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{DevPlatform, TunnelEngine};
    use crate::secret_store::InMemorySecretStore;
    use quantumlink_proto::models::ConnectionPhase;
    use tokio::io::AsyncReadExt;

    fn test_context() -> Arc<IpcContext> {
        let dir = std::env::temp_dir().join(format!("qlink-ipc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(IpcContext {
            engine: Arc::new(TunnelEngine::new(
                Arc::new(InMemorySecretStore::default()),
                Arc::new(DevPlatform::default()),
                dir.clone(),
            )),
            state_dir: dir,
        })
    }

    async fn roundtrip(requests: &[&str]) -> Vec<PipeResponse> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let context = test_context();
        let server_task = tokio::spawn(serve_connection(server, context));

        let (mut client_read, mut client_write) = tokio::io::split(client);
        for request in requests {
            client_write
                .write_all(format!("{request}\n").as_bytes())
                .await
                .unwrap();
        }
        drop(client_write);

        let mut raw = String::new();
        client_read.read_to_string(&mut raw).await.unwrap();
        server_task.await.unwrap().unwrap();
        raw.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn hello_is_required_first() {
        let responses = roundtrip(&[r#"{"id":1,"command":"status"}"#]).await;
        assert!(matches!(
            responses[0].message,
            TunnelProviderMessage::Error { .. }
        ));
    }

    #[tokio::test]
    async fn hello_status_connect_disconnect_flow() {
        let responses = roundtrip(&[
            r#"{"id":1,"command":"hello","schemaVersion":1}"#,
            r#"{"id":2,"command":"status"}"#,
            r#"{"id":3,"command":"connect"}"#,
            r#"{"id":4,"command":"disconnect"}"#,
        ])
        .await;

        assert!(matches!(
            responses[0].message,
            TunnelProviderMessage::HelloAck { .. }
        ));
        let TunnelProviderMessage::Status { status } = &responses[1].message else {
            panic!("expected status, got {:?}", responses[1].message);
        };
        assert_eq!(status.phase, ConnectionPhase::Idle);
        let TunnelProviderMessage::Status { status } = &responses[2].message else {
            panic!("expected status, got {:?}", responses[2].message);
        };
        assert_eq!(status.phase, ConnectionPhase::Connected);
        let TunnelProviderMessage::Status { status } = &responses[3].message else {
            panic!("expected status, got {:?}", responses[3].message);
        };
        assert_eq!(status.phase, ConnectionPhase::Idle);
    }

    #[tokio::test]
    async fn schema_mismatch_is_rejected() {
        let responses = roundtrip(&[r#"{"id":1,"command":"hello","schemaVersion":999}"#]).await;
        let TunnelProviderMessage::Error { message } = &responses[0].message else {
            panic!("expected error");
        };
        assert!(message.contains("schema version mismatch"));
    }

    #[tokio::test]
    async fn malformed_json_yields_error_not_disconnect() {
        let responses = roundtrip(&[
            r#"{"id":1,"command":"hello","schemaVersion":1}"#,
            r#"{this is not json"#,
            r#"{"id":2,"command":"status"}"#,
        ])
        .await;
        assert!(matches!(
            responses[1].message,
            TunnelProviderMessage::Error { .. }
        ));
        assert!(matches!(
            responses[2].message,
            TunnelProviderMessage::Status { .. }
        ));
    }
}
