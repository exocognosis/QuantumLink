use quantumlink_proto::ipc::{PipeResponse, TunnelProviderMessage};
use quantumlink_proto::models::ConnectionPhase;
use quantumlink_service::engine::{DevPlatform, TunnelEngine};
use quantumlink_service::ipc::{serve_connection, IpcContext};
use quantumlink_service::secret_store::InMemorySecretStore;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

fn test_context() -> Arc<IpcContext> {
    let dir = tempfile::tempdir().unwrap().keep();
    Arc::new(IpcContext {
        engine: Arc::new(TunnelEngine::new(
            Arc::new(InMemorySecretStore::default()),
            Arc::new(DevPlatform::default()),
            dir.clone(),
        )),
        state_dir: dir,
    })
}

async fn read_response<R>(reader: &mut BufReader<R>) -> PipeResponse
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut line = String::new();
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        reader.read_line(&mut line),
    )
    .await
    .expect("timed out waiting for IPC response")
    .unwrap();
    assert!(bytes > 0, "server closed before response");
    serde_json::from_str(line.trim_end()).unwrap()
}

async fn run_ipc_script(frames: &[&[u8]]) -> Vec<PipeResponse> {
    let (client, server) = tokio::io::duplex(128 * 1024);
    let server_task = tokio::spawn(serve_connection(server, test_context()));
    let (client_read, mut client_write) = tokio::io::split(client);
    let mut reader = BufReader::new(client_read);
    let mut responses = Vec::new();

    for frame in frames {
        client_write.write_all(frame).await.unwrap();
        client_write.write_all(b"\n").await.unwrap();
        client_write.flush().await.unwrap();
        responses.push(read_response(&mut reader).await);
    }

    client_write.shutdown().await.unwrap();
    let mut remaining = Vec::new();
    reader.read_to_end(&mut remaining).await.unwrap();
    server_task.await.unwrap().unwrap();
    responses
}

fn assert_error_contains(response: &PipeResponse, needle: &str) {
    let TunnelProviderMessage::Error { message } = &response.message else {
        panic!("expected error response, got {:?}", response.message);
    };
    assert!(
        message.contains(needle),
        "expected error message containing {needle:?}, got {message:?}"
    );
}

#[tokio::test]
async fn malformed_schema_and_unknown_command_mutations_do_not_close_pipe() {
    let responses = run_ipc_script(&[
        br#"{"id":1,"command":"hello","schemaVersion":1}"#,
        br#"{"id":2,"command":"status"}"#,
        br#"{"id":3,"command":"unknownCommand"}"#,
        br#"{"id":4,"command":"connect","configuration":{"protectedRoutes":"not-an-array"}}"#,
        br#"{"id":5,"command":"status"}"#,
        b"{not-json",
        br#"{"id":6,"command":"status"}"#,
        br#"{"id":7,"command":"disconnect"}"#,
    ])
    .await;

    assert!(matches!(
        responses[0].message,
        TunnelProviderMessage::HelloAck { .. }
    ));
    let TunnelProviderMessage::Status { status } = &responses[1].message else {
        panic!(
            "expected status after hello, got {:?}",
            responses[1].message
        );
    };
    assert_eq!(status.phase, ConnectionPhase::Idle);
    assert_error_contains(&responses[2], "unknown variant");
    assert_error_contains(&responses[3], "invalid type");
    assert!(matches!(
        responses[4].message,
        TunnelProviderMessage::Status { .. }
    ));
    assert_error_contains(&responses[5], "malformed request");
    assert!(matches!(
        responses[6].message,
        TunnelProviderMessage::Status { .. }
    ));
    let TunnelProviderMessage::Status { status } = &responses[7].message else {
        panic!("expected disconnect status, got {:?}", responses[7].message);
    };
    assert_eq!(status.phase, ConnectionPhase::Idle);
}

#[tokio::test]
async fn rejected_schema_mismatch_does_not_authorize_later_commands() {
    let responses = run_ipc_script(&[
        br#"{"id":1,"command":"hello","schemaVersion":999}"#,
        br#"{"id":2,"command":"status"}"#,
        br#"{"id":3,"command":"hello","schemaVersion":1}"#,
        br#"{"id":4,"command":"status"}"#,
    ])
    .await;

    assert_error_contains(&responses[0], "schema version mismatch");
    assert_error_contains(&responses[1], "hello required");
    assert!(matches!(
        responses[2].message,
        TunnelProviderMessage::HelloAck { .. }
    ));
    let TunnelProviderMessage::Status { status } = &responses[3].message else {
        panic!(
            "expected status after valid hello, got {:?}",
            responses[3].message
        );
    };
    assert_eq!(status.phase, ConnectionPhase::Idle);
}

#[tokio::test]
async fn crlf_frames_are_accepted_in_command_sequence() {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(serve_connection(server, test_context()));
    let (client_read, mut client_write) = tokio::io::split(client);
    let mut reader = BufReader::new(client_read);

    client_write
        .write_all(br#"{"id":1,"command":"hello","schemaVersion":1}"#)
        .await
        .unwrap();
    client_write.write_all(b"\r\n").await.unwrap();
    let hello = read_response(&mut reader).await;

    client_write
        .write_all(br#"{"id":2,"command":"status"}"#)
        .await
        .unwrap();
    client_write.write_all(b"\r\n").await.unwrap();
    let status = read_response(&mut reader).await;

    client_write.shutdown().await.unwrap();
    server_task.await.unwrap().unwrap();

    assert!(matches!(
        hello.message,
        TunnelProviderMessage::HelloAck { .. }
    ));
    assert!(matches!(
        status.message,
        TunnelProviderMessage::Status { .. }
    ));
}

#[tokio::test]
async fn invalid_utf8_and_oversized_frames_fail_closed() {
    let (client, server) = tokio::io::duplex(2 * 1024 * 1024);
    let server_task = tokio::spawn(serve_connection(server, test_context()));
    let (mut client_read, mut client_write) = tokio::io::split(client);

    client_write.write_all(&[0xff, b'\n']).await.unwrap();
    client_write.flush().await.unwrap();
    let mut raw = Vec::new();
    client_read.read_to_end(&mut raw).await.unwrap();
    assert!(
        raw.is_empty(),
        "invalid UTF-8 should not receive a response"
    );
    let error = server_task.await.unwrap().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    let (client, server) = tokio::io::duplex(2 * 1024 * 1024);
    let server_task = tokio::spawn(serve_connection(server, test_context()));
    let (mut client_read, mut client_write) = tokio::io::split(client);
    client_write
        .write_all(&vec![b'a'; 1_048_577])
        .await
        .unwrap();
    client_write.write_all(b"\n").await.unwrap();
    client_write.flush().await.unwrap();
    let mut raw = Vec::new();
    client_read.read_to_end(&mut raw).await.unwrap();
    assert!(
        raw.is_empty(),
        "oversized frame should not receive a response"
    );
    let error = server_task.await.unwrap().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}
