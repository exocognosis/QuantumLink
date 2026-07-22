//! QuantumLink Windows service binary.
//!
//! Subcommands:
//! - `run`        console mode (development): engine + IPC in the
//!                foreground, Ctrl+C to exit. Works on non-Windows dev
//!                hosts with the loopback platform.
//! - `service`    internal SCM entry point (Windows only).
//! - `install` / `uninstall` / `start` / `stop`   service management
//!                (Windows only, requires elevation).
//! - `smoke`      local data-plane smoke test (the Windows analog of
//!                `qlinkctl quic-loopback`); exits non-zero on failure.
//! - `security-probe` bounded Windows runtime proof hooks for Wintun,
//!                DPAPI, WFP, and network monitor lifecycle safety.

use clap::{Parser, Subcommand};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "quantumlink-service", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the service in the foreground (development console mode).
    Run,
    /// Internal: entry point used by the Windows Service Control Manager.
    Service,
    /// Register the Windows service (requires elevation).
    Install,
    /// Remove the Windows service (requires elevation).
    Uninstall,
    /// Start the installed Windows service.
    Start,
    /// Stop the installed Windows service.
    Stop,
    /// Run the local loopback data-plane smoke test and print JSON.
    Smoke,
    /// Run bounded Windows-native security proof hooks and print JSON.
    #[cfg(windows)]
    SecurityProbe,
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run => {
            init_tracing();
            run_console()
        }
        Commands::Service => {
            #[cfg(windows)]
            {
                // SCM provides no console; tracing goes to the log file
                // via the default subscriber the dispatcher sets up.
                init_tracing();
                match quantumlink_service::win::service::run_service_dispatcher() {
                    Ok(()) => std::process::ExitCode::SUCCESS,
                    Err(error) => {
                        eprintln!("service dispatcher failed: {error}");
                        std::process::ExitCode::FAILURE
                    }
                }
            }
            #[cfg(not(windows))]
            {
                eprintln!("`service` is only available on Windows");
                std::process::ExitCode::FAILURE
            }
        }
        Commands::Install | Commands::Uninstall | Commands::Start | Commands::Stop => {
            init_tracing();
            #[cfg(windows)]
            {
                use quantumlink_service::win::service;
                let result = match cli.command {
                    Commands::Install => service::install(),
                    Commands::Uninstall => service::uninstall(),
                    Commands::Start => service::start(),
                    Commands::Stop => service::stop(),
                    _ => unreachable!(),
                };
                match result {
                    Ok(()) => {
                        println!("ok");
                        std::process::ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("service control failed: {error}");
                        std::process::ExitCode::FAILURE
                    }
                }
            }
            #[cfg(not(windows))]
            {
                eprintln!("service management is only available on Windows");
                std::process::ExitCode::FAILURE
            }
        }
        Commands::Smoke => {
            init_tracing();
            // The smoke runs the full connect path — including PQC device
            // keypair generation — inline. Those crypto routines use large
            // stack buffers that exceed the 1 MiB default *main*-thread
            // stack on Windows (in production this work runs on the engine's
            // worker threads, which get the larger default thread stack).
            // Run it on a dedicated thread with a generous stack so the CLI
            // smoke gate behaves the same on every platform.
            let report = std::thread::Builder::new()
                .name("qlink-smoke".into())
                .stack_size(8 * 1024 * 1024)
                .spawn(quantumlink_service::smoke::run_loopback_smoke)
                .expect("spawn smoke thread")
                .join()
                .expect("smoke thread panicked");
            println!(
                "{}",
                serde_json::to_string_pretty(&report.summary).unwrap_or_default()
            );
            if report.passed {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            }
        }
        #[cfg(windows)]
        Commands::SecurityProbe => {
            init_tracing();
            let report = quantumlink_service::win::probe::run_runtime_probe();
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
            if report.passed {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            }
        }
    }
}

fn run_console() -> std::process::ExitCode {
    use quantumlink_service::engine::TunnelEngine;
    use quantumlink_service::ipc::IpcContext;

    let state_dir = quantumlink_service::config::state_dir();
    if let Err(error) = quantumlink_service::config::ensure_state_dirs(&state_dir) {
        eprintln!("state dir setup failed: {error}");
        return std::process::ExitCode::FAILURE;
    }

    #[cfg(windows)]
    let (secret_store, platform): (
        Arc<dyn quantumlink_service::secret_store::SecretStore>,
        Arc<dyn quantumlink_service::engine::PlatformNetwork>,
    ) = {
        let store = quantumlink_service::win::dpapi::DpapiSecretStore::new(
            state_dir.join(quantumlink_service::config::SECRETS_DIR),
        )
        .expect("DPAPI store");
        (
            Arc::new(store),
            Arc::new(quantumlink_service::win::platform::WindowsPlatform::default()),
        )
    };
    #[cfg(not(windows))]
    let (secret_store, platform): (
        Arc<dyn quantumlink_service::secret_store::SecretStore>,
        Arc<dyn quantumlink_service::engine::PlatformNetwork>,
    ) = (
        Arc::new(quantumlink_service::secret_store::InMemorySecretStore::default()),
        Arc::new(quantumlink_service::engine::DevPlatform::default()),
    );

    let engine = Arc::new(TunnelEngine::new(secret_store, platform, state_dir.clone()));
    let context = Arc::new(IpcContext {
        engine: Arc::clone(&engine),
        state_dir,
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");

    runtime.block_on(async move {
        #[cfg(windows)]
        {
            tracing::info!(
                pipe = quantumlink_proto::ipc::PIPE_NAME,
                "console mode: IPC listening"
            );
            tokio::select! {
                result = quantumlink_service::win::pipe_server::run(context) => {
                    if let Err(error) = result {
                        tracing::error!(%error, "pipe server exited");
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("ctrl-c received; shutting down");
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = context;
            tracing::info!(
                "console mode on a non-Windows host: engine available, no named-pipe IPC. \
                 Use `smoke` for the data-plane check. Ctrl+C to exit."
            );
            let _ = tokio::signal::ctrl_c().await;
        }
    });

    engine.disconnect();
    std::process::ExitCode::SUCCESS
}
