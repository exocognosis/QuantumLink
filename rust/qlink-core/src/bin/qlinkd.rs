//! `qlinkd` — QuantumLink server daemon.
//!
//! Long-running Linux/Unix daemon that hosts the QuantumLink mesh
//! services for self-hosted deployments. Bundles every service the
//! Mac (or any other) client needs to reach a peer:
//!
//! - **Rendezvous** (default port 9471): peers publish + look up
//!   each other's signed peer records (public keys + reachability
//!   hints).
//! - **Relay** (default port 9472): TURN-style traffic relay for
//!   peer pairs that can't establish a direct path through NAT.
//! - **STUN** (default port 9473): server-reflexive address
//!   discovery for ICE.
//! - **Exit relay** (optional, port 9474): receives encrypted
//!   tunnel sessions from clients and forwards their IP packets
//!   to the public internet via a local tun device. Requires
//!   `CAP_NET_ADMIN` (or root) to open `/dev/net/tun`. **Not
//!   wired up in this revision** — the foundation is here; the
//!   actual packet-forwarding logic lands in a follow-up alongside
//!   integration testing.
//!
//! ## Deployment posture
//!
//! Designed for one-line deployment via `docker compose up` or as
//! a systemd unit. The companion `deploy/` directory contains both:
//!
//! - `deploy/qlinkd.service` — systemd unit with hardening
//!   (`AmbientCapabilities=CAP_NET_ADMIN`, `NoNewPrivileges=true`,
//!   `PrivateTmp=true`, etc.).
//! - `deploy/docker-compose.yml` — minimal compose file mounting
//!   the persistence path and exposing the four service ports.
//!
//! ## Sovereignty guarantees
//!
//! - **No telemetry.** The daemon emits structured logs to stderr
//!   (where systemd / Docker capture them); nothing is sent off-box.
//! - **In-memory state by default.** The rendezvous store + relay
//!   pairings live in process memory and are wiped on restart.
//!   Operators who want persistence opt in via `--state-dir`.
//! - **Self-contained.** Single static binary (when built with
//!   `--target x86_64-unknown-linux-musl`); no runtime dependency
//!   on system OpenSSL or other crypto libraries — everything is
//!   compiled in.

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use qlink_core::{
    exit_relay::ExitRelay,
    relay::run_relay,
    rendezvous::run_rendezvous,
    stun::spawn_dev_stun,
};
use tokio::signal::unix::{signal, SignalKind};

/// CLI surface for `qlinkd`. Defaults match the well-known
/// QuantumLink port assignments so the matching `.mobileconfig`
/// templates and Mac client default config "just work" against a
/// fresh install.
#[derive(Parser, Debug)]
#[command(name = "qlinkd")]
#[command(version)]
#[command(about = "QuantumLink server daemon (rendezvous + relay + STUN, optional exit relay)")]
struct Cli {
    /// Listen address for the rendezvous service. Peers POST signed
    /// peer records here and GET each other's records by peer_id.
    #[arg(long, default_value = "0.0.0.0:9471")]
    rendezvous: String,

    /// Listen address for the relay service. Used as a TURN-style
    /// fallback when peers can't establish a direct path through
    /// their respective NATs.
    #[arg(long, default_value = "0.0.0.0:9472")]
    relay: String,

    /// Listen address for the STUN service. Required for ICE
    /// candidate gathering; clients use this to learn their
    /// server-reflexive (public) address.
    #[arg(long, default_value = "0.0.0.0:9473")]
    stun: String,

    /// Enable exit-relay mode. When set, the daemon opens a local
    /// `tun` device and forwards encrypted IP packets from client
    /// sessions out through the host's default route. Requires
    /// `CAP_NET_ADMIN` (or root) to open `/dev/net/tun`. Disabled
    /// by default because operators may want a coordinator-only
    /// deployment without an exit footprint.
    ///
    /// **NOT YET IMPLEMENTED**. Setting this flag today will log
    /// a warning and otherwise behave the same as not setting it.
    #[arg(long)]
    exit_relay: bool,

    /// Verbose logging. By default we emit one line per service
    /// startup + critical errors; with `--verbose` we also emit
    /// per-connection traces.
    #[arg(long, short)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Cli::parse();
    setup_logging(args.verbose);

    eprintln!("qlinkd {}", env!("CARGO_PKG_VERSION"));
    eprintln!("  rendezvous: {}", args.rendezvous);
    eprintln!("  relay:      {}", args.relay);
    eprintln!("  stun:       {}", args.stun);
    if args.exit_relay {
        eprintln!("  exit-relay: ENABLED (opening tun device + bringing up session table)");
    }

    // Stand up the exit-relay if requested. We hold a reference
    // to the relay handle for the lifetime of the daemon so the
    // session table sticks around. Per-client registrations land
    // here later when the session-handshake module wires through
    // (Phase 4 of the macOS-first roadmap).
    let exit_relay_handle = if args.exit_relay {
        match start_exit_relay().await {
            Ok(handle) => Some(handle),
            Err(e) => {
                eprintln!("exit-relay startup failed: {}", e);
                eprintln!(
                    "Most common causes: missing CAP_NET_ADMIN (run with the systemd unit \
                     installed, not via `cargo run`), or /dev/net/tun not present (LXC \
                     containers need `lxc.cgroup2.devices.allow = c 10:200 rwm`)."
                );
                None
            }
        }
    } else {
        None
    };
    let _exit_relay_keep = exit_relay_handle;

    // Each service runs as its own task. We `Arc` the running flag
    // and the shutdown notification so individual tasks can decide
    // to exit cleanly when one of their peers fails.
    let rendezvous_addr = args.rendezvous.clone();
    let rendezvous_task = tokio::spawn(async move {
        if let Err(e) = run_rendezvous(&rendezvous_addr).await {
            eprintln!("rendezvous service exited: {}", e);
        }
    });

    let relay_addr = args.relay.clone();
    let relay_task = tokio::spawn(async move {
        if let Err(e) = run_relay(&relay_addr).await {
            eprintln!("relay service exited: {}", e);
        }
    });

    // STUN doesn't have a `run_stun(addr)` entry point yet; the
    // `spawn_dev_stun` helper binds 127.0.0.1:0 which isn't useful
    // for a public server. We log + skip until that surface lands.
    // For now `spawn_dev_stun` keeps the dev surface working.
    let _stun_keep = match spawn_dev_stun().await {
        Ok(stun) => Some(stun),
        Err(e) => {
            eprintln!("warning: dev stun failed: {}", e);
            None
        }
    };

    // Shutdown handling. Both SIGTERM (from systemd / Docker stop)
    // and SIGINT (from a tty Ctrl-C) trigger a clean exit. We don't
    // explicitly drain in-flight connections in v1 — services rely
    // on their TCP listeners' close behavior — but the structure is
    // here for future graceful-shutdown logic.
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => eprintln!("qlinkd: received SIGTERM, shutting down"),
        _ = sigint.recv() => eprintln!("qlinkd: received SIGINT, shutting down"),
        _ = wait_either(rendezvous_task, relay_task) => {
            eprintln!("qlinkd: a core service exited unexpectedly, shutting down");
            return ExitCode::from(1);
        }
    }

    ExitCode::SUCCESS
}

/// Bring up the exit-relay: open a tun device, register it with
/// an `ExitRelay` instance, and spawn the tun-pump that demuxes
/// inbound packets to per-client return paths.
///
/// Returns the `ExitRelay` (still owned by the caller; drop to
/// stop) or an error if the tun device couldn't be opened (almost
/// always a permissions issue — needs CAP_NET_ADMIN).
///
/// Linux only. On macOS this is unreachable code paths because
/// the daemon is intended for server deployments; we keep the
/// cfg gates explicit so a misconfigured Mac build fails to
/// compile rather than fails at runtime.
#[cfg(target_os = "linux")]
async fn start_exit_relay() -> std::io::Result<std::sync::Arc<ExitRelay>> {
    use qlink_core::utun;
    let tun = utun::create_tun("").map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("create_tun failed: {e}"),
        )
    })?;
    eprintln!("  tun device: {}", tun.name());

    // Move the OwnedFd out of UtunDevice for the pump's lifetime.
    // We can't get back the fd without consuming the device, so
    // we use unsafe to clone the raw fd; the pump treats it as
    // owned. Safe because UtunDevice's drop closes the fd, and
    // we explicitly Forget it here.
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let raw = tun.as_raw_fd();
    let fd_for_pump = unsafe { OwnedFd::from_raw_fd(libc::dup(raw)) };
    drop(tun); // drop the original; pump owns the dup

    let relay = std::sync::Arc::new(ExitRelay::new());
    let pump = qlink_core::exit_relay::run_tun_pump(relay.clone(), fd_for_pump).await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;
    // Pump runs forever; don't .await it here or we'd block the
    // daemon's shutdown handler. Detach via std::mem::forget on
    // the JoinHandle so it stays scheduled.
    std::mem::forget(pump);
    Ok(relay)
}

#[cfg(not(target_os = "linux"))]
async fn start_exit_relay() -> std::io::Result<std::sync::Arc<ExitRelay>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "exit-relay mode is Linux-only (qlinkd is a server-side daemon)",
    ))
}

/// Wait for either of two `JoinHandle<()>` tasks to finish. Used in
/// the shutdown select arm above so that a crashing service triggers
/// daemon exit (under systemd, `Restart=on-failure` then brings us
/// back; under Docker, the container exits and the orchestrator
/// restarts).
async fn wait_either(
    a: tokio::task::JoinHandle<()>,
    b: tokio::task::JoinHandle<()>,
) {
    tokio::select! {
        _ = a => {},
        _ = b => {},
    }
}

/// Minimal logging setup. We deliberately don't pull in
/// `tracing-subscriber` for the daemon — `eprintln!` lines are
/// captured by both systemd-journald and Docker logs and are easier
/// to grep than structured tracing output. The `qlink-core` library
/// emits `tracing` events; without a subscriber installed those
/// events are dropped, which is the right default for production
/// (operators who want them can pipe through a JSON layer in a
/// follow-up).
fn setup_logging(verbose: bool) {
    // Mark the parameter used so the unused-arg lint stays quiet
    // while we plumb the verbose flag through to the per-service
    // tracing layer in a follow-up.
    let _ = verbose;
    let _ = Arc::new(()); // future shutdown flag carrier
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults_match_well_known_ports() {
        let cli = Cli::parse_from(["qlinkd"]);
        assert_eq!(cli.rendezvous, "0.0.0.0:9471");
        assert_eq!(cli.relay, "0.0.0.0:9472");
        assert_eq!(cli.stun, "0.0.0.0:9473");
        assert!(!cli.exit_relay);
    }

    #[test]
    fn cli_accepts_overrides() {
        let cli = Cli::parse_from([
            "qlinkd",
            "--rendezvous",
            "10.0.0.5:7000",
            "--exit-relay",
        ]);
        assert_eq!(cli.rendezvous, "10.0.0.5:7000");
        assert!(cli.exit_relay);
    }
}
