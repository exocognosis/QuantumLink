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
//! - The pipe security descriptor comes from
//!   `windowsSecurity.pipeSddl` in `config.json`. The default ACL allows
//!   interactive users to connect while SYSTEM and Administrators retain
//!   full access; enterprise deployments can replace the interactive-user
//!   ACE with a group SID.

use crate::ipc::IpcContext;
use quantumlink_proto::ipc::PIPE_NAME;
use std::io;
use std::sync::Arc;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::core::HSTRING;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

pub async fn run(context: Arc<IpcContext>) -> std::io::Result<()> {
    let pipe_sddl = crate::config::load_pipe_sddl(&context.state_dir)?;

    // Hold the first instance up front so the name is claimed for the
    // service's whole lifetime.
    let mut server = create_pipe_server(true, &pipe_sddl)?;

    loop {
        server.connect().await?;
        let connected = server;
        // Create the next listener instance before serving the current
        // client so there is no window with no listener.
        server = create_pipe_server(false, &pipe_sddl)?;

        let connection_context = Arc::clone(&context);
        tokio::spawn(async move {
            if let Err(error) = crate::ipc::serve_connection(connected, connection_context).await {
                tracing::debug!(%error, "pipe connection ended with error");
            }
        });
    }
}

fn create_pipe_server(first_instance: bool, pipe_sddl: &str) -> io::Result<NamedPipeServer> {
    let mut options = ServerOptions::new();
    options.reject_remote_clients(true);
    if first_instance {
        options.first_pipe_instance(true);
    }

    let mut security = PipeSecurityAttributes::from_sddl(pipe_sddl)?;
    unsafe {
        options.create_with_security_attributes_raw(
            PIPE_NAME,
            security.as_mut_ptr() as *mut std::ffi::c_void,
        )
    }
}

struct PipeSecurityAttributes {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

impl PipeSecurityAttributes {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &HSTRING::from(sddl),
                SDDL_REVISION,
                &mut descriptor,
                None,
            )
        }
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("windowsSecurity.pipeSddl is invalid: {error}"),
            )
        })?;

        Ok(Self {
            descriptor,
            attributes: SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: false.into(),
            },
        })
    }

    fn as_mut_ptr(&mut self) -> *mut SECURITY_ATTRIBUTES {
        &mut self.attributes
    }
}

impl Drop for PipeSecurityAttributes {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
        }
    }
}
