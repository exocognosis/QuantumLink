use qlink_proto::InviteCode;
#[cfg(unix)]
use qlinkctl::{
    current_unix_seconds, format_doctor, format_peer_list, format_peer_trust, format_status,
    import_invite_to_store, load_peer_store_for_state_dir, peer_from_store, remove_peer_from_store,
    revoke_peer_in_store, status_from_daemon, write_support_bundle, SupportBundleOptions,
    SupportBundleReleaseInfo, DEFAULT_STATE_DIR,
};
use qlinkctl::{format_guide, format_onboarding_checklist};
#[cfg(unix)]
use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("guide") => println!("{}", format_guide()),
        Some("onboarding") => onboarding_command(),
        Some("status") => status_command(),
        Some("doctor") => doctor_command(),
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
            Some("trust") => {
                let Some(peer_id) = args.next() else {
                    eprintln!("usage: qlinkctl peer trust <peer-id>");
                    std::process::exit(2);
                };
                peer_trust_command(&peer_id);
            }
            _ => {
                eprintln!("usage: qlinkctl peer <list|remove|revoke|trust> [peer-id]");
                std::process::exit(2);
            }
        },
        _ => {
            eprintln!(
                "usage: qlinkctl <guide|onboarding|status|doctor|support-bundle --output|invite|peer>"
            );
            std::process::exit(2);
        }
    }
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
