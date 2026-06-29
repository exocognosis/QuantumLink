#[cfg(unix)]
use qlink_linux::{
    LinuxTunDevice, StdCommandRunner, SystemNetworkExecutor, SystemNftablesExecutor,
};
#[cfg(unix)]
use qlinkd::{deactivate_network_with, run_resident};
use qlinkd::{load_config_or_default, DaemonEngine, DaemonPaths, RuntimeMode};

fn main() {
    let mode = match RuntimeMode::from_args(std::env::args().skip(1)) {
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("qlinkd argument error: {error}");
            std::process::exit(2);
        }
    };
    let paths = DaemonPaths::default();
    if mode == RuntimeMode::DeactivateNetwork {
        deactivate_network_command(&paths);
        return;
    }

    let config = match load_config_or_default(&paths) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("qlinkd config error: {error}");
            std::process::exit(1);
        }
    };
    let engine = match DaemonEngine::try_new(config, paths) {
        Ok(engine) => engine,
        Err(error) => {
            eprintln!("qlinkd startup error: {error}");
            std::process::exit(1);
        }
    };
    match mode {
        RuntimeMode::CheckConfig => {
            println!(
                "qlinkd phase={:?} network={:?} socket={}",
                engine.status().phase,
                engine.status().network.state,
                engine.paths().socket.display()
            );
        }
        RuntimeMode::DeactivateNetwork => unreachable!("deactivation exits before config loading"),
        RuntimeMode::RunResident { activate_network } => {
            run_resident_command(engine, activate_network)
        }
    }
}

#[cfg(unix)]
fn deactivate_network_command(paths: &DaemonPaths) {
    let mut network_executor = SystemNetworkExecutor::new(StdCommandRunner);
    let mut nftables_executor = SystemNftablesExecutor::new(StdCommandRunner);
    if let Err(error) =
        deactivate_network_with(paths, &mut network_executor, &mut nftables_executor)
    {
        eprintln!("qlinkd network deactivation failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn deactivate_network_command(_paths: &DaemonPaths) {
    eprintln!("qlinkd network deactivation is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}

#[cfg(unix)]
fn run_resident_command(mut engine: DaemonEngine, activate_network: bool) {
    if activate_network {
        let mut network_executor = SystemNetworkExecutor::new(StdCommandRunner);
        let mut nftables_executor = SystemNftablesExecutor::new(StdCommandRunner);
        if let Err(error) = engine.activate_network_and_start_data_plane_with(
            &mut network_executor,
            &mut nftables_executor,
            |config| LinuxTunDevice::open(config).map_err(Into::into),
        ) {
            eprintln!("qlinkd activation failed: {error}");
            std::process::exit(1);
        }
    }

    if let Err(error) = run_resident(engine) {
        eprintln!("qlinkd failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn run_resident_command(_engine: DaemonEngine, _activate_network: bool) {
    eprintln!("qlinkd resident mode is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}
