//! Overlay IP, MTU, route, and DNS programming for the Wintun adapter —
//! the Windows replacement for `NEIPv4Settings`/`NEDNSSettings` in
//! `PacketTunnelProvider.swift`.
//!
//! Production uses IP Helper APIs for address, route, and DNS state. A
//! `netsh` manager remains available as an explicit development fallback
//! so beta diagnostics can compare behavior without making shell-adjacent
//! route programming the default.
//!
//! Everything here requires elevation; only the service calls it.

use crate::engine::EngineError;
use quantumlink_proto::models::{DnsMode, TunnelConfiguration};
#[cfg(windows)]
use std::net::Ipv4Addr;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteManagerKind {
    IpHelper,
    NetshDevelopmentFallback,
}

pub trait RouteManager {
    fn apply(&self, adapter_alias: &str, config: &TunnelConfiguration) -> Result<(), EngineError>;
    fn remove(&self, adapter_alias: &str, config: &TunnelConfiguration) -> Result<(), EngineError>;
}

#[derive(Debug, Default)]
pub struct NetshRouteManager;

#[derive(Debug, Default)]
pub struct IpHelperRouteManager;

pub fn default_route_manager_kind() -> RouteManagerKind {
    RouteManagerKind::IpHelper
}

pub fn development_route_manager_diagnostic() -> &'static str {
    "development route manager uses netsh fallback; production validation must use IP Helper"
}

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

impl RouteManager for NetshRouteManager {
    fn apply(&self, adapter_alias: &str, config: &TunnelConfiguration) -> Result<(), EngineError> {
        tracing::warn!(
            diagnostic = development_route_manager_diagnostic(),
            "netsh route manager selected"
        );
        apply_netsh(adapter_alias, config)
    }

    fn remove(&self, adapter_alias: &str, config: &TunnelConfiguration) -> Result<(), EngineError> {
        remove_netsh(adapter_alias, config)
    }
}

impl RouteManager for IpHelperRouteManager {
    fn apply(&self, adapter_alias: &str, config: &TunnelConfiguration) -> Result<(), EngineError> {
        apply_ip_helper(adapter_alias, config)
    }

    fn remove(&self, adapter_alias: &str, config: &TunnelConfiguration) -> Result<(), EngineError> {
        remove_ip_helper(adapter_alias, config)
    }
}

pub fn apply(adapter_alias: &str, config: &TunnelConfiguration) -> Result<(), EngineError> {
    apply_with_manager(&IpHelperRouteManager, adapter_alias, config)
}

pub fn apply_development_fallback(
    adapter_alias: &str,
    config: &TunnelConfiguration,
) -> Result<(), EngineError> {
    apply_with_manager(&NetshRouteManager, adapter_alias, config)
}

pub fn apply_with_manager(
    manager: &dyn RouteManager,
    adapter_alias: &str,
    config: &TunnelConfiguration,
) -> Result<(), EngineError> {
    manager.apply(adapter_alias, config)
}

fn apply_netsh(adapter_alias: &str, config: &TunnelConfiguration) -> Result<(), EngineError> {
    let (overlay_address, _) = validate_route(&config.overlay_ipv4_address)?;

    // Overlay address. /32 host address; reachability of the overlay
    // range comes from the explicit routes below, mirroring how the
    // macOS provider set includedRoutes rather than an interface mask.
    run_netsh(&[
        "interface",
        "ip",
        "set",
        "address",
        &format!("name={adapter_alias}"),
        "source=static",
        &format!("addr={overlay_address}"),
        "mask=255.255.255.255",
    ])?;

    // MTU.
    run_netsh(&[
        "interface",
        "ipv4",
        "set",
        "subinterface",
        &format!("\"{adapter_alias}\""),
        &format!("mtu={}", config.mtu),
        "store=active",
    ])?;

    // Protected routes -> tunnel.
    for route in &config.protected_routes {
        let (address, prefix) = validate_route(route)?;
        run_netsh(&[
            "interface",
            "ipv4",
            "add",
            "route",
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
                        "interface",
                        "ip",
                        "set",
                        "dns",
                        &format!("name={adapter_alias}"),
                        "source=static",
                        &format!("addr={address}"),
                        "validate=no",
                    ])?;
                } else {
                    run_netsh(&[
                        "interface",
                        "ip",
                        "add",
                        "dns",
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
    remove_with_manager(&IpHelperRouteManager, adapter_alias, config)
}

pub fn remove_development_fallback(
    adapter_alias: &str,
    config: &TunnelConfiguration,
) -> Result<(), EngineError> {
    remove_with_manager(&NetshRouteManager, adapter_alias, config)
}

pub fn remove_with_manager(
    manager: &dyn RouteManager,
    adapter_alias: &str,
    config: &TunnelConfiguration,
) -> Result<(), EngineError> {
    manager.remove(adapter_alias, config)
}

fn remove_netsh(adapter_alias: &str, config: &TunnelConfiguration) -> Result<(), EngineError> {
    let mut first_error = None;
    for route in &config.protected_routes {
        if let Ok((address, prefix)) = validate_route(route) {
            if let Err(error) = run_netsh(&[
                "interface",
                "ipv4",
                "delete",
                "route",
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

fn apply_ip_helper(adapter_alias: &str, config: &TunnelConfiguration) -> Result<(), EngineError> {
    #[cfg(not(windows))]
    {
        let _ = (adapter_alias, config);
        return Err(EngineError::Platform(
            "IP Helper route manager requires Windows".into(),
        ));
    }

    #[cfg(windows)]
    {
        let context = IpHelperContext::from_adapter_alias(adapter_alias)?;
        let (overlay_address, _) = validate_route(&config.overlay_ipv4_address)?;
        context.add_unicast_address(overlay_address.parse().map_err(|error| {
            EngineError::Config(format!(
                "overlay IPv4 address {:?} is invalid: {error}",
                config.overlay_ipv4_address
            ))
        })?)?;

        // MTU is not a route/DNS object in IP Helper; keep the old audited
        // primitive only for this adapter setting.
        run_netsh(&[
            "interface",
            "ipv4",
            "set",
            "subinterface",
            &format!("\"{adapter_alias}\""),
            &format!("mtu={}", config.mtu),
            "store=active",
        ])?;

        for route in &config.protected_routes {
            let (address, prefix) = validate_route(route)?;
            context.add_route(
                address.parse().map_err(|error| {
                    EngineError::Config(format!("protected route {route:?} is invalid: {error}"))
                })?,
                prefix,
            )?;
        }

        match config.dns_mode {
            DnsMode::TunnelProvided => context.set_dns_servers(&config.dns_servers)?,
            DnsMode::System | DnsMode::Disabled => {}
        }
        Ok(())
    }
}

fn remove_ip_helper(adapter_alias: &str, config: &TunnelConfiguration) -> Result<(), EngineError> {
    #[cfg(not(windows))]
    {
        let _ = (adapter_alias, config);
        return Err(EngineError::Platform(
            "IP Helper route manager requires Windows".into(),
        ));
    }

    #[cfg(windows)]
    {
        let context = IpHelperContext::from_adapter_alias(adapter_alias)?;
        let mut first_error = None;
        for route in &config.protected_routes {
            if let Ok((address, prefix)) = validate_route(route) {
                if let Err(error) = context.delete_route(
                    address.parse().map_err(|parse_error| {
                        EngineError::Config(format!(
                            "protected route {route:?} is invalid: {parse_error}"
                        ))
                    })?,
                    prefix,
                ) {
                    tracing::warn!(%error, route, "IP Helper route cleanup failed");
                    first_error.get_or_insert(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(windows)]
struct IpHelperContext {
    luid: windows::Win32::NetworkManagement::Ndis::NET_LUID_LH,
    guid: windows::core::GUID,
}

#[cfg(windows)]
impl IpHelperContext {
    fn from_adapter_alias(adapter_alias: &str) -> Result<Self, EngineError> {
        use windows::Win32::NetworkManagement::IpHelper::{
            ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToGuid,
        };

        let alias = windows::core::HSTRING::from(adapter_alias);
        let mut luid = windows::Win32::NetworkManagement::Ndis::NET_LUID_LH::default();
        win32_status("ConvertInterfaceAliasToLuid", unsafe {
            ConvertInterfaceAliasToLuid(&alias, &mut luid)
        })?;

        let mut guid = windows::core::GUID::zeroed();
        win32_status("ConvertInterfaceLuidToGuid", unsafe {
            ConvertInterfaceLuidToGuid(&luid, &mut guid)
        })?;

        Ok(Self { luid, guid })
    }

    fn add_unicast_address(&self, address: Ipv4Addr) -> Result<(), EngineError> {
        use windows::Win32::NetworkManagement::IpHelper::{
            CreateUnicastIpAddressEntry, InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
        };
        use windows::Win32::Networking::WinSock::{
            IpPrefixOriginManual, IpSuffixOriginManual, NldsPreferred,
        };

        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe {
            InitializeUnicastIpAddressEntry(&mut row);
        }
        row.InterfaceLuid = self.luid;
        row.Address = sockaddr_v4(address);
        row.OnLinkPrefixLength = 32;
        row.PrefixOrigin = IpPrefixOriginManual;
        row.SuffixOrigin = IpSuffixOriginManual;
        row.DadState = NldsPreferred;

        win32_status("CreateUnicastIpAddressEntry", unsafe {
            CreateUnicastIpAddressEntry(&row)
        })
    }

    fn add_route(&self, address: Ipv4Addr, prefix: u8) -> Result<(), EngineError> {
        use windows::Win32::NetworkManagement::IpHelper::{
            CreateIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
        };

        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe {
            InitializeIpForwardEntry(&mut row);
        }
        self.populate_route_row(&mut row, address, prefix);
        win32_status("CreateIpForwardEntry2", unsafe {
            CreateIpForwardEntry2(&row)
        })
    }

    fn delete_route(&self, address: Ipv4Addr, prefix: u8) -> Result<(), EngineError> {
        use windows::Win32::NetworkManagement::IpHelper::{
            DeleteIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
        };

        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe {
            InitializeIpForwardEntry(&mut row);
        }
        self.populate_route_row(&mut row, address, prefix);
        win32_status("DeleteIpForwardEntry2", unsafe {
            DeleteIpForwardEntry2(&row)
        })
    }

    fn populate_route_row(
        &self,
        row: &mut windows::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2,
        address: Ipv4Addr,
        prefix: u8,
    ) {
        use windows::Win32::Networking::WinSock::{NlroManual, RouteProtocolNetMgmt};

        row.InterfaceLuid = self.luid;
        row.DestinationPrefix.Prefix = sockaddr_v4(address);
        row.DestinationPrefix.PrefixLength = prefix;
        row.NextHop = sockaddr_v4(Ipv4Addr::UNSPECIFIED);
        row.SitePrefixLength = prefix;
        row.Metric = 1;
        row.Protocol = RouteProtocolNetMgmt;
        row.Origin = NlroManual;
    }

    fn set_dns_servers(&self, dns_servers: &[String]) -> Result<(), EngineError> {
        use windows::core::PWSTR;
        use windows::Win32::NetworkManagement::IpHelper::{
            SetInterfaceDnsSettings, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
            DNS_SETTING_NAMESERVER,
        };

        let mut servers = Vec::with_capacity(dns_servers.len());
        for server in dns_servers {
            let (address, _) = validate_route(server)?;
            servers.push(address);
        }
        let joined_servers = servers.join(" ");
        let mut wide_servers: Vec<u16> = joined_servers
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: DNS_SETTING_NAMESERVER as u64,
            NameServer: PWSTR(wide_servers.as_mut_ptr()),
            ..Default::default()
        };
        win32_status("SetInterfaceDnsSettings", unsafe {
            SetInterfaceDnsSettings(self.guid, &settings)
        })
    }
}

#[cfg(windows)]
fn sockaddr_v4(address: Ipv4Addr) -> windows::Win32::Networking::WinSock::SOCKADDR_INET {
    use windows::Win32::Networking::WinSock::{ADDRESS_FAMILY, AF_INET, IN_ADDR, SOCKADDR_IN};

    windows::Win32::Networking::WinSock::SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: ADDRESS_FAMILY(AF_INET.0),
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: windows::Win32::Networking::WinSock::IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(address.octets()),
                },
            },
            sin_zero: [0; 8],
        },
    }
}

#[cfg(windows)]
fn win32_status(
    operation: &'static str,
    status: windows::Win32::Foundation::WIN32_ERROR,
) -> Result<(), EngineError> {
    if status.0 == 0 {
        Ok(())
    } else {
        Err(EngineError::Platform(format!(
            "{operation} failed: 0x{:08x}",
            status.0
        )))
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

    #[test]
    fn production_route_manager_defaults_to_ip_helper() {
        assert_eq!(default_route_manager_kind(), RouteManagerKind::IpHelper);
    }

    #[test]
    fn development_route_manager_keeps_netsh_fallback_explicit() {
        assert_eq!(
            development_route_manager_diagnostic(),
            "development route manager uses netsh fallback; production validation must use IP Helper"
        );
    }
}
