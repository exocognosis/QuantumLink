//! Overlay IP, MTU, route, and DNS programming for the Wintun adapter —
//! the Windows replacement for `NEIPv4Settings`/`NEDNSSettings` in
//! `PacketTunnelProvider.swift`.
//!
//! v1 uses `netsh` child processes keyed by the adapter alias. This is
//! deliberate: netsh is stable across Windows 10/11, trivially auditable
//! in logs, and avoids a large unsafe IP Helper surface while the
//! product is in beta. Each call is logged with its full argument list.
//! Migration to `CreateUnicastIpAddressEntry`/`CreateIpForwardEntry2` is
//! tracked for post-beta.
//!
//! Everything here requires elevation; only the service calls it.

use crate::engine::EngineError;
use quantumlink_proto::models::{DnsMode, TunnelConfiguration};
use std::process::Command;

fn run_netsh(args: &[&str]) -> Result<(), EngineError> {
    tracing::info!(?args, "netsh");
    let output = Command::new("netsh")
        .args(args)
        .output()
        .map_err(|error| EngineError::Platform(format!("netsh spawn failed: {error}")))?;
    if !output.status.success() {
        return Err(EngineError::Platform(format!(
            "netsh {:?} failed ({}): {}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stdout).trim()
        )));
    }
    Ok(())
}

/// Validates a dotted-quad or CIDR string before it is passed to a
/// shell-adjacent API. Rejects anything that is not digits, dots, and
/// at most one slash-prefix.
fn validate_route(route: &str) -> Result<(String, u8), EngineError> {
    let (address, prefix) = match route.split_once('/') {
        Some((address, prefix)) => {
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| EngineError::Config(format!("bad prefix in route {route:?}")))?;
            (address, prefix)
        }
        None => (route, 32),
    };
    if prefix > 32 {
        return Err(EngineError::Config(format!("prefix too long: {route:?}")));
    }
    let octets: Vec<&str> = address.split('.').collect();
    if octets.len() != 4 || octets.iter().any(|o| o.parse::<u8>().is_err()) {
        return Err(EngineError::Config(format!("bad IPv4 in route {route:?}")));
    }
    Ok((address.to_string(), prefix))
}

pub fn apply(adapter_alias: &str, config: &TunnelConfiguration) -> Result<(), EngineError> {
    let (overlay_address, _) = validate_route(&config.overlay_ipv4_address)?;

    // Overlay address. /32 host address; reachability of the overlay
    // range comes from the explicit routes below, mirroring how the
    // macOS provider set includedRoutes rather than an interface mask.
    run_netsh(&[
        "interface", "ip", "set", "address",
        &format!("name={adapter_alias}"),
        "source=static",
        &format!("addr={overlay_address}"),
        "mask=255.255.255.255",
    ])?;

    // MTU.
    run_netsh(&[
        "interface", "ipv4", "set", "subinterface",
        &format!("\"{adapter_alias}\""),
        &format!("mtu={}", config.mtu),
        "store=active",
    ])?;

    // Protected routes -> tunnel.
    for route in &config.protected_routes {
        let (address, prefix) = validate_route(route)?;
        run_netsh(&[
            "interface", "ipv4", "add", "route",
            &format!("{address}/{prefix}"),
            &format!("interface=\"{adapter_alias}\""),
            "metric=1",
            "store=active",
        ])?;
    }

    // DNS.
    match config.dns_mode {
        DnsMode::TunnelProvided => {
            for (index, server) in config.dns_servers.iter().enumerate() {
                let (address, _) = validate_route(server)?;
                if index == 0 {
                    run_netsh(&[
                        "interface", "ip", "set", "dns",
                        &format!("name={adapter_alias}"),
                        "source=static",
                        &format!("addr={address}"),
                        "validate=no",
                    ])?;
                } else {
                    run_netsh(&[
                        "interface", "ip", "add", "dns",
                        &format!("name={adapter_alias}"),
                        &format!("addr={address}"),
                        &format!("index={}", index + 1),
                        "validate=no",
                    ])?;
                }
            }
        }
        DnsMode::System | DnsMode::Disabled => {}
    }
    Ok(())
}

/// Removes routes/DNS. The Wintun adapter itself disappears when the
/// session/adapter handles drop, taking its addresses with it, so the
/// route table is the only state that needs explicit cleanup (defense
/// against leaked routes if adapter teardown is skipped on crash).
pub fn remove(adapter_alias: &str, config: &TunnelConfiguration) -> Result<(), EngineError> {
    let mut first_error = None;
    for route in &config.protected_routes {
        if let Ok((address, prefix)) = validate_route(route) {
            if let Err(error) = run_netsh(&[
                "interface", "ipv4", "delete", "route",
                &format!("{address}/{prefix}"),
                &format!("interface=\"{adapter_alias}\""),
                "store=active",
            ]) {
                tracing::warn!(%error, route, "route cleanup failed");
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_validation_rejects_injection() {
        assert!(validate_route("100.64.0.0/10").is_ok());
        assert!(validate_route("100.64.0.1").is_ok());
        assert!(validate_route("100.64.0.0/40").is_err());
        assert!(validate_route("100.64.0.0 metric=0").is_err());
        assert!(validate_route("evil; rm -rf").is_err());
        assert!(validate_route("::1/128").is_err());
    }
}
