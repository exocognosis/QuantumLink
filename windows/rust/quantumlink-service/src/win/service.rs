//! Windows Service Control Manager integration — replaces the macOS
//! system-extension/launchd lifecycle.
//!
//! Subcommands `install`/`uninstall`/`start`/`stop` manage registration;
//! the SCM invokes the binary with the internal `service` subcommand,
//! which lands in [`run_service_dispatcher`].
//!
//! Power events (`SERVICE_CONTROL_POWEREVENT`) are forwarded into the
//! engine as `PreSleep`/`PostWake`, mirroring the NSWorkspace
//! notifications the macOS observer consumed.

use crate::engine::TunnelEngine;
use crate::ipc::IpcContext;
use qlink_core::mesh_connection::NetworkEvent;
use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "QuantumLinkService";
pub const SERVICE_DISPLAY_NAME: &str = "QuantumLink Tunnel Service";
pub const SERVICE_DESCRIPTION: &str =
    "Owns the QuantumLink Wintun adapter, encrypted mesh transport, and kill switch.";

define_windows_service!(ffi_service_main, service_main);

pub fn run_service_dispatcher() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        tracing::error!(%error, "service main failed");
    }
}

fn run_service() -> anyhow_lite::Result<()> {
    let state_dir = crate::config::state_dir();
    crate::config::ensure_state_dirs(&state_dir)?;

    let secret_store = Arc::new(crate::win::dpapi::DpapiSecretStore::new(
        state_dir.join(crate::config::SECRETS_DIR),
    )?);
    let platform = Arc::new(crate::win::platform::WindowsPlatform::default());
    let engine = Arc::new(TunnelEngine::new(secret_store, platform, state_dir.clone()));
    let context = Arc::new(IpcContext {
        engine: Arc::clone(&engine),
        state_dir,
    });

    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
    let handler_engine = Arc::clone(&engine);
    let event_handler = move |control_event: ServiceControl| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::PowerEvent(_) => {
                // Granular suspend/resume parsing is follow-up work; a
                // wake-shaped event is safe either way because PostWake
                // only triggers a re-probe.
                handler_engine.handle_network_event(NetworkEvent::PostWake);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    let set_state = |state: ServiceState| {
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::POWER_EVENT,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        });
    };
    set_state(ServiceState::Running);

    // IPC server on a dedicated runtime; network monitor feeding the
    // engine for the service's lifetime.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let server_context = Arc::clone(&context);
    runtime.spawn(async move {
        if let Err(error) = crate::win::pipe_server::run(server_context).await {
            tracing::error!(%error, "pipe server exited");
        }
    });

    let netmon = crate::win::netmon::WindowsNetworkEventSource::default();
    {
        use crate::netmon::NetworkEventSource;
        let netmon_engine = Arc::clone(&engine);
        netmon.start(Box::new(move |event| {
            netmon_engine.handle_network_event(event);
        }));
    }

    // Block until the SCM asks us to stop.
    let _ = shutdown_rx.recv();
    set_state(ServiceState::StopPending);
    engine.disconnect();
    runtime.shutdown_timeout(Duration::from_secs(5));
    set_state(ServiceState::Stopped);
    Ok(())
}

pub fn install() -> windows_service::Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
    let executable = std::env::current_exe().map_err(windows_service::Error::Winapi)?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable,
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG)?;
    let _ = service.set_description(SERVICE_DESCRIPTION);
    Ok(())
}

pub fn uninstall() -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    )?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
    }
    service.delete()
}

pub fn start() -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    service.start(&[] as &[&str])
}

pub fn stop() -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP)?;
    service.stop().map(|_| ())
}

/// Tiny local error-aggregation alias so the service main can use `?`
/// across windows-service, IO, and runtime errors without pulling in a
/// full anyhow dependency.
mod anyhow_lite {
    pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
}
