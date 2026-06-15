use clap::{Parser, Subcommand};
use qlink_core::replay::ReplayWindow;

#[derive(Debug, Parser)]
#[command(
    name = "qlink-devctl",
    about = "QuantumLink shared-core protocol smoke CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Exercise local replay-window logic without network side effects.
    ReplaySmoke,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("qlink-devctl: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::ReplaySmoke => replay_smoke(),
    }
}

fn replay_smoke() -> Result<(), String> {
    let mut window = ReplayWindow::new();

    require(window.observe(10), "first packet should be accepted")?;
    require(!window.observe(10), "duplicate packet should be rejected")?;
    require(window.observe(11), "newer packet should be accepted")?;
    require(
        window.observe(9),
        "in-window older packet should be accepted",
    )?;
    require(
        !window.observe(9),
        "replayed older packet should be rejected",
    )?;
    require(window.observe(200), "large forward jump should be accepted")?;
    require(!window.observe(11), "stale packet should be rejected")?;

    println!("qlink-devctl: replay smoke passed");
    Ok(())
}

fn require(condition: bool, message: &'static str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
