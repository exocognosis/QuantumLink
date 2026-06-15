use qlinkd::{load_config_or_default, run_resident, DaemonEngine, DaemonPaths, RuntimeMode};

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
    let engine = DaemonEngine::new(config, paths);
    match mode {
        RuntimeMode::CheckConfig => {
            println!(
                "qlinkd phase={:?} socket={}",
                engine.status().phase,
                engine.paths().socket.display()
            );
        }
        RuntimeMode::RunResident => {
            if let Err(error) = run_resident(engine) {
                eprintln!("qlinkd failed: {error}");
                std::process::exit(1);
            }
        }
    }
}
