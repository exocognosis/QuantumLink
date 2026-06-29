use qlink_proto::InviteCode;
#[cfg(unix)]
use qlinkctl::{format_doctor, format_status, status_from_daemon};
#[cfg(unix)]
use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("status") => status_command(),
        Some("doctor") => doctor_command(),
        Some("invite") => match args.next().as_deref() {
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
                eprintln!("usage: qlinkctl invite decode <code>");
                std::process::exit(2);
            }
        },
        _ => {
            eprintln!("usage: qlinkctl <status|doctor|invite decode>");
            std::process::exit(2);
        }
    }
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
