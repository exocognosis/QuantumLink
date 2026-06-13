//! Named-pipe IPC server — the Windows replacement for the macOS
//! app <-> tunnel-extension provider-message channel.
//!
//! Listens on [`quantumlink_proto::ipc::PIPE_NAME`] and serves each
//! client connection with the shared, transport-agnostic
//! [`crate::ipc::serve_connection`] dispatcher.
//!
//! Security:
//! - `first_pipe_instance(true)` on every instance prevents a local
//!   attacker from squatting the pipe name to impersonate the service.
//! - `reject_remote_clients(true)` keeps the control plane local.
//! - The default pipe ACL allows interactive users to *connect* (the
//!   UI runs unprivileged) but creation stays with the service. Per-
//!   command authorization is the dispatcher's job; today every local
//!   user may control tunnel state, which matches the macOS app's
//!   posture for the primary user. Enterprise lock-down (SDDL limiting
//!   connect to a group) is an installer option documented in the
//!   deployment guide.

use crate::ipc::IpcContext;
use quantumlink_proto::ipc::PIPE_NAME;
use std::sync::Arc;
use tokio::net::windows::named_pipe::ServerOptions;

pub async fn run(context: Arc<IpcContext>) -> std::io::Result<()> {
    // Hold the first instance up front so the name is claimed for the
    // service's whole lifetime.
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(PIPE_NAME)?;

    loop {
        server.connect().await?;
        let connected = server;
        // Create the next listener instance before serving the current
        // client so there is no window with no listener.
        server = ServerOptions::new()
            .reject_remote_clients(true)
            .create(PIPE_NAME)?;

        let connection_context = Arc::clone(&context);
        tokio::spawn(async move {
            if let Err(error) = crate::ipc::serve_connection(connected, connection_context).await {
                tracing::debug!(%error, "pipe connection ended with error");
            }
        });
    }
}
