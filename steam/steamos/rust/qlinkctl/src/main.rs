use qlink_proto::InviteCode;
use qlinkctl::dytallix::{parse_dytallix_args, run_dytallix};
#[cfg(unix)]
use qlinkctl::{
    begin_game_process, build_game_launch_plan, clear_game_profile, clear_peer_selection_in_store,
    current_unix_seconds, end_game_process, format_doctor, format_game_profile_status,
    format_peer_list, format_peer_state, format_peer_trust, format_status, import_invite_to_store,
    load_peer_store_for_state_dir, peer_from_store, remove_peer_from_store, revoke_peer_in_store,
    select_game_profile, select_peer_in_store, status_from_daemon, write_support_bundle,
    SupportBundleOptions, SupportBundleReleaseInfo, DEFAULT_STATE_DIR,
};
use qlinkctl::{format_guide, format_onboarding_checklist, run_service_action, ServiceAction};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(unix)]
use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("guide") => println!("{}", format_guide()),
        Some("onboarding") => onboarding_command(),
        Some("status") => status_command(),
        Some("doctor") => doctor_command(),
        Some("dytallix") => match parse_dytallix_args(args) {
            Ok(options) => match run_dytallix(options) {
                Ok(output) => println!("{output}"),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            },
            Err(error) => {
                eprintln!("{error}");
                eprintln!("{}", dytallix_usage());
                std::process::exit(2);
            }
        },
        Some("support-bundle") => {
            let Some(flag) = args.next() else {
                eprintln!("usage: qlinkctl support-bundle --output <path>");
                std::process::exit(2);
            };
            if flag != "--output" {
                eprintln!("usage: qlinkctl support-bundle --output <path>");
                std::process::exit(2);
            }
            let Some(output) = args.next() else {
                eprintln!("usage: qlinkctl support-bundle --output <path>");
                std::process::exit(2);
            };
            support_bundle_command(&output);
        }
        Some("profile") => match args.next().as_deref() {
            Some("list") => {
                reject_extra_args(args, "usage: qlinkctl profile list");
                profile_list_command();
            }
            Some("status") => {
                reject_extra_args(args, "usage: qlinkctl profile status");
                profile_status_command();
            }
            Some("select") => {
                let Some(profile_id) = args.next() else {
                    eprintln!("usage: qlinkctl profile select <profile-id>");
                    std::process::exit(2);
                };
                reject_extra_args(args, "usage: qlinkctl profile select <profile-id>");
                profile_select_command(&profile_id);
            }
            Some("clear") => {
                reject_extra_args(args, "usage: qlinkctl profile clear");
                profile_clear_command();
            }
            _ => {
                eprintln!("usage: qlinkctl profile <list|status|select|clear> [profile-id]");
                std::process::exit(2);
            }
        },
        Some("game") => match args.next().as_deref() {
            Some("launch") => game_launch_command(args.collect()),
            Some("enter") => game_enter_command(args.collect()),
            _ => {
                eprintln!("usage: qlinkctl game launch -- <command> [args...]");
                std::process::exit(2);
            }
        },
        Some("invite") => match args.next().as_deref() {
            Some("import") => {
                let Some(encoded) = args.next() else {
                    eprintln!("usage: qlinkctl invite import <encoded-invite>");
                    std::process::exit(2);
                };
                invite_import_command(&encoded);
            }
            Some("decode") => {
                let Some(encoded) = args.next() else {
                    eprintln!("usage: qlinkctl invite decode <code>");
                    std::process::exit(2);
                };
                match InviteCode::decode(&encoded) {
                    Ok(invite) => println!(
                        "{}",
                        serde_json::to_string_pretty(&invite).expect("invite serializes")
                    ),
                    Err(error) => {
                        eprintln!("{error}");
                        std::process::exit(1);
                    }
                }
            }
            _ => {
                eprintln!("usage: qlinkctl invite <decode|import> <code>");
                std::process::exit(2);
            }
        },
        Some("peer") => match args.next().as_deref() {
            Some("list") => peer_list_command(),
            Some("state") => peer_state_command(),
            Some("clear") => peer_clear_command(),
            Some("remove") => {
                let Some(peer_id) = args.next() else {
                    eprintln!("usage: qlinkctl peer remove <peer-id>");
                    std::process::exit(2);
                };
                peer_remove_command(&peer_id);
            }
            Some("revoke") => {
                let Some(peer_id) = args.next() else {
                    eprintln!("usage: qlinkctl peer revoke <peer-id>");
                    std::process::exit(2);
                };
                peer_revoke_command(&peer_id);
            }
            Some("select") => {
                let Some(peer_id) = args.next() else {
                    eprintln!("usage: qlinkctl peer select <peer-id>");
                    std::process::exit(2);
                };
                peer_select_command(&peer_id);
            }
            Some("trust") => {
                let Some(peer_id) = args.next() else {
                    eprintln!("usage: qlinkctl peer trust <peer-id>");
                    std::process::exit(2);
                };
                peer_trust_command(&peer_id);
            }
            _ => {
                eprintln!(
                    "usage: qlinkctl peer <list|state|clear|remove|revoke|select|trust> [peer-id]"
                );
                std::process::exit(2);
            }
        },
        Some("service") => {
            let Some(action) = args.next() else {
                eprintln!("usage: qlinkctl service <start|stop|restart>");
                std::process::exit(2);
            };
            if args.next().is_some() {
                eprintln!("usage: qlinkctl service <start|stop|restart>");
                std::process::exit(2);
            }
            match ServiceAction::parse(&action).and_then(run_service_action) {
                Ok(()) => println!("{action}"),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!(
                "usage: qlinkctl <guide|onboarding|status|doctor|dytallix|support-bundle --output|profile|game|invite|peer|service>"
            );
            std::process::exit(2);
        }
    }
}

#[cfg(unix)]
fn game_launch_command(args: Vec<String>) {
    let (command, command_args) = parse_game_command(&args, 0);
    let socket = Path::new("/run/quantumlink/qlinkd.sock");
    let status = status_from_daemon(socket).unwrap_or_else(|error| command_error(error));
    let qlinkctl_path = std::env::current_exe().unwrap_or_else(|error| {
        eprintln!("failed to resolve qlinkctl path: {error}");
        std::process::exit(1);
    });
    let session_id = new_game_session_id();
    let plan = build_game_launch_plan(
        &status.game_profile,
        &session_id,
        &qlinkctl_path,
        command,
        command_args,
    )
    .unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });

    let run_status = std::process::Command::new("/usr/bin/systemd-run")
        .args(&plan.systemd_run_args)
        .status();
    let cleanup = end_game_process(socket, &session_id);
    if let Err(error) = cleanup {
        eprintln!("failed to remove game process classification: {error}");
        std::process::exit(1);
    }
    match run_status {
        Ok(status) if status.success() => {}
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(error) => {
            eprintln!("failed to start systemd game scope: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(unix))]
fn game_launch_command(_args: Vec<String>) {
    unsupported_profile_command();
}

#[cfg(unix)]
fn game_enter_command(args: Vec<String>) {
    if args.len() < 4 {
        eprintln!("invalid internal game launch request");
        std::process::exit(2);
    }
    let profile_id = &args[0];
    let session_id = &args[1];
    let (command, command_args) = parse_game_command(&args, 2);
    let socket = Path::new("/run/quantumlink/qlinkd.sock");
    if let Err(error) = begin_game_process(socket, profile_id, command, session_id) {
        command_error(error);
    }

    let error = std::process::Command::new(command)
        .args(command_args)
        .exec();
    eprintln!("failed to execute game command: {error}");
    std::process::exit(1);
}

#[cfg(not(unix))]
fn game_enter_command(_args: Vec<String>) {
    unsupported_profile_command();
}

fn parse_game_command(args: &[String], prefix_len: usize) -> (&str, &[String]) {
    if args.get(prefix_len).map(String::as_str) != Some("--") {
        eprintln!("usage: qlinkctl game launch -- <command> [args...]");
        std::process::exit(2);
    }
    let Some(command) = args.get(prefix_len + 1) else {
        eprintln!("usage: qlinkctl game launch -- <command> [args...]");
        std::process::exit(2);
    };
    (command, &args[prefix_len + 2..])
}

fn new_game_session_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("s{:x}{nanos:x}", std::process::id())
}

fn reject_extra_args(mut args: impl Iterator<Item = String>, usage: &str) {
    if args.next().is_some() {
        eprintln!("{usage}");
        std::process::exit(2);
    }
}

#[cfg(unix)]
fn profile_list_command() {
    match status_from_daemon(Path::new("/run/quantumlink/qlinkd.sock")) {
        Ok(status) => println!(
            "{}",
            serde_json::to_string_pretty(&status.game_profile.available_profiles)
                .expect("profiles serialize")
        ),
        Err(error) => command_error(error),
    }
}

#[cfg(not(unix))]
fn profile_list_command() {
    unsupported_profile_command();
}

#[cfg(unix)]
fn profile_status_command() {
    match status_from_daemon(Path::new("/run/quantumlink/qlinkd.sock")) {
        Ok(status) => println!(
            "{}",
            format_game_profile_status(&status.game_profile).expect("profile status serializes")
        ),
        Err(error) => command_error(error),
    }
}

#[cfg(not(unix))]
fn profile_status_command() {
    unsupported_profile_command();
}

#[cfg(unix)]
fn profile_select_command(profile_id: &str) {
    match select_game_profile(Path::new("/run/quantumlink/qlinkd.sock"), profile_id) {
        Ok(status) => println!(
            "{}",
            format_game_profile_status(&status.game_profile).expect("profile status serializes")
        ),
        Err(error) => command_error(error),
    }
}

#[cfg(not(unix))]
fn profile_select_command(_profile_id: &str) {
    unsupported_profile_command();
}

#[cfg(unix)]
fn profile_clear_command() {
    match clear_game_profile(Path::new("/run/quantumlink/qlinkd.sock")) {
        Ok(status) => println!(
            "{}",
            format_game_profile_status(&status.game_profile).expect("profile status serializes")
        ),
        Err(error) => command_error(error),
    }
}

#[cfg(not(unix))]
fn profile_clear_command() {
    unsupported_profile_command();
}

#[cfg(unix)]
fn command_error(error: impl std::fmt::Display) -> ! {
    eprintln!("{error}");
    std::process::exit(1);
}

#[cfg(not(unix))]
fn unsupported_profile_command() -> ! {
    eprintln!("qlinkctl profile is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}

fn dytallix_usage() -> &'static str {
    "usage: qlinkctl dytallix <status|register|update|suspend|reactivate|revoke> \
     [--config <path>] [--state-dir <path>] [--keystore <path>] [--wallet <name>] \
     [--peer-id <id>] [--confirm-peer-id <id>] [--authorization-expires-at <unix>] \
     [--max-peer-ttl <seconds>] [--mesh-scope <scope>] [--metadata-commitment <sha256-hex>]"
}

#[cfg(unix)]
fn onboarding_command() {
    let status = match status_from_daemon(Path::new("/run/quantumlink/qlinkd.sock")) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };
    let peer_store = match load_peer_store_for_state_dir(Path::new(DEFAULT_STATE_DIR)) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("failed to load peer store: {error}");
            std::process::exit(1);
        }
    };
    println!("{}", format_onboarding_checklist(&status, &peer_store));
}

#[cfg(not(unix))]
fn onboarding_command() {
    eprintln!("qlinkctl onboarding is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}

#[cfg(unix)]
fn status_command() {
    match status_from_daemon(Path::new("/run/quantumlink/qlinkd.sock")) {
        Ok(status) => println!("{}", format_status(&status).expect("status serializes")),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(unix))]
fn status_command() {
    eprintln!("qlinkctl status is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}

#[cfg(unix)]
fn doctor_command() {
    match status_from_daemon(Path::new("/run/quantumlink/qlinkd.sock")) {
        Ok(status) => println!("{}", format_doctor(&status)),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(unix))]
fn doctor_command() {
    eprintln!("qlinkctl doctor is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}

#[cfg(unix)]
fn support_bundle_command(output: &str) {
    let status = match status_from_daemon(Path::new("/run/quantumlink/qlinkd.sock")) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };

    match write_support_bundle(SupportBundleOptions {
        output: output.into(),
        status,
        release_info: SupportBundleReleaseInfo::current(),
    }) {
        Ok(()) => println!("{output}"),
        Err(error) => {
            eprintln!("failed to write support bundle: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(unix)]
fn invite_import_command(encoded: &str) {
    match import_invite_to_store(
        Path::new(DEFAULT_STATE_DIR),
        encoded,
        current_unix_seconds(),
    ) {
        Ok(peer) => println!("{}", peer.peer_id),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(unix))]
fn invite_import_command(_encoded: &str) {
    eprintln!("qlinkctl invite import is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}

#[cfg(unix)]
fn peer_list_command() {
    match load_peer_store_for_state_dir(Path::new(DEFAULT_STATE_DIR))
        .and_then(|store| format_peer_list(&store).map_err(Into::into))
    {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(unix)]
fn peer_state_command() {
    match load_peer_store_for_state_dir(Path::new(DEFAULT_STATE_DIR))
        .and_then(|store| format_peer_state(&store).map_err(Into::into))
    {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(unix))]
fn peer_state_command() {
    eprintln!("qlinkctl peer state is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}

#[cfg(unix)]
fn peer_clear_command() {
    match clear_peer_selection_in_store(Path::new(DEFAULT_STATE_DIR)) {
        Ok(()) => println!("cleared"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(unix))]
fn peer_clear_command() {
    eprintln!("qlinkctl peer clear is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}

#[cfg(not(unix))]
fn peer_list_command() {
    eprintln!("qlinkctl peer list is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}

#[cfg(unix)]
fn peer_remove_command(peer_id: &str) {
    match remove_peer_from_store(Path::new(DEFAULT_STATE_DIR), peer_id) {
        Ok(()) => println!("{peer_id}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(unix))]
fn peer_remove_command(_peer_id: &str) {
    eprintln!("qlinkctl peer remove is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}

#[cfg(unix)]
fn peer_revoke_command(peer_id: &str) {
    match revoke_peer_in_store(Path::new(DEFAULT_STATE_DIR), peer_id) {
        Ok(()) => println!("{peer_id}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(unix)]
fn peer_select_command(peer_id: &str) {
    match select_peer_in_store(
        Path::new(DEFAULT_STATE_DIR),
        peer_id,
        current_unix_seconds(),
    ) {
        Ok(()) => println!("{peer_id}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(unix))]
fn peer_select_command(_peer_id: &str) {
    eprintln!("qlinkctl peer select is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}

#[cfg(not(unix))]
fn peer_revoke_command(_peer_id: &str) {
    eprintln!("qlinkctl peer revoke is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}

#[cfg(unix)]
fn peer_trust_command(peer_id: &str) {
    match peer_from_store(Path::new(DEFAULT_STATE_DIR), peer_id) {
        Ok(peer) => println!("{}", format_peer_trust(&peer)),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(unix))]
fn peer_trust_command(_peer_id: &str) {
    eprintln!("qlinkctl peer trust is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}

#[cfg(not(unix))]
fn support_bundle_command(_output: &str) {
    eprintln!("qlinkctl support-bundle is only supported on Unix-like SteamOS hosts");
    std::process::exit(2);
}
