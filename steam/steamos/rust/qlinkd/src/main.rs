#[cfg(unix)]
use qlinkd::run_resident;
use qlinkd::{load_config_or_default, DaemonEngine, DaemonPaths, RuntimeMode};

fn main() {
    let mode = RuntimeMode::from_args(std::env::args().skip(1));
    let paths = DaemonPaths::default();
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
        RuntimeMode::RunResident => run_resident_command(engine),
    }
}

#[cfg(unix)]
fn run_resident_command(engine: DaemonEngine) {
    if let Err(error) = run_resident(engine) {
        eprintln!("qlinkd failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn run_resident_command(_engine: DaemonEngine) {
    eprintln!("qlinkd resident mode is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}
