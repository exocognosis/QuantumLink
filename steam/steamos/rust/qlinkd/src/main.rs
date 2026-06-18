use qlink_linux::{StdCommandRunner, SystemNetworkExecutor, SystemNftablesExecutor};
use qlinkd::{
    deactivate_network_with, load_config_or_default, run_resident, DaemonEngine, DaemonPaths,
    RuntimeMode,
};

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
        let mut network_executor = SystemNetworkExecutor::new(StdCommandRunner);
        let mut nftables_executor = SystemNftablesExecutor::new(StdCommandRunner);
        if let Err(error) =
            deactivate_network_with(&paths, &mut network_executor, &mut nftables_executor)
        {
            eprintln!("qlinkd network deactivation failed: {error}");
            std::process::exit(1);
        }
        return;
    }

    let config = match load_config_or_default(&paths) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("qlinkd config error: {error}");
            std::process::exit(1);
        }
    };
    let mut engine = match DaemonEngine::try_new(config, paths) {
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
            if activate_network {
                let mut network_executor = SystemNetworkExecutor::new(StdCommandRunner);
                let mut nftables_executor = SystemNftablesExecutor::new(StdCommandRunner);
                if let Err(error) =
                    engine.activate_network_with(&mut network_executor, &mut nftables_executor)
                {
                    eprintln!("qlinkd network activation failed: {error}");
                    std::process::exit(1);
                }
            }

            if let Err(error) = run_resident(engine) {
                eprintln!("qlinkd failed: {error}");
                std::process::exit(1);
            }
        }
    }
}
