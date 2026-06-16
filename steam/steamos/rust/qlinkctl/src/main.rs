use qlink_proto::InviteCode;
use qlinkctl::{format_status, status_from_daemon};
use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("status") => match status_from_daemon(Path::new("/run/quantumlink/qlinkd.sock")) {
            Ok(status) => println!("{}", format_status(&status).expect("status serializes")),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        },
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
            eprintln!("usage: qlinkctl <status|invite decode>");
            std::process::exit(2);
        }
    }
}
