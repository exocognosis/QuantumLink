//! WFP-based kill switch — the Windows replacement for NetworkExtension
//! route ownership on macOS.
//!
//! Model (mirrors the macOS fail-closed contract):
//! - For every protected prefix, add a **block** filter (low weight) at
//!   `FWPM_LAYER_ALE_AUTH_CONNECT_V4`: nothing may initiate traffic to a
//!   protected destination.
//! - Add a **permit** filter (high weight) for the same prefixes scoped
//!   to the Wintun adapter LUID: protected traffic may flow only through
//!   the tunnel.
//!
//! Result: if the service, adapter, or transport is unhealthy, packets
//! to protected prefixes have no permitted path — they black-hole at the
//! filter layer instead of escaping out the default interface. The
//! tunnel's own encrypted QUIC traffic is unaffected because peer/relay
//! addresses are public IPs outside the protected (CGNAT overlay)
//! prefixes.
//!
//! Lifetime: filters live in a **dynamic** WFP session, so they are
//! removed automatically when the engine handle closes — including on
//! service crash. That is fail-open-after-crash for `failClosed` policy,
//! which matches macOS semantics (tunnel gone => routes gone). A
//! persistent boot-time-filter mode for `strict` deployments is tracked
//! in the beta runbook as follow-up work.

use crate::engine::EngineError;
#[cfg(windows)]
use std::ffi::c_void;
use std::net::Ipv4Addr;
#[cfg(windows)]
use std::sync::OnceLock;
#[cfg(windows)]
use windows::core::GUID;
#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmSubLayerAdd0,
    FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_FILTER0,
    FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_SESSION0,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_ACTION_TYPE, FWP_MATCH_EQUAL, FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK,
    FWP_V4_ADDR_MASK,
};
#[cfg(windows)]
use windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

/// Stable product GUIDs (random, fixed at build time).
#[cfg(windows)]
const SUBLAYER_KEY: GUID = GUID::from_u128(0x7c1a44d0_3f2e_4b8a_9c61_d5a0e84b91f2);

#[cfg(windows)]
const BLOCK_WEIGHT: u8 = 0;
#[cfg(windows)]
const PERMIT_WEIGHT: u8 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpFilterMode {
    FailClosed,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpLayer {
    AleAuthConnectV4,
    OutboundIpPacketV4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpAction {
    Block,
    Permit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedWfpFilter {
    pub layer: WfpLayer,
    pub action: WfpAction,
    pub route: String,
    pub tunnel_interface_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFilterPlan {
    pub mode: WfpFilterMode,
    pub dynamic_session: bool,
    pub persistent_filters: bool,
    pub boot_time_fail_closed: bool,
    pub cleanup_required_on_uninstall: bool,
    pub filters: Vec<PlannedWfpFilter>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpRuntimeInstall {
    DynamicSession,
    PersistentBootTime,
}

pub fn build_filter_plan(
    policy: quantumlink_proto::models::KillSwitchPolicy,
    protected_routes: &[String],
) -> Result<WfpFilterPlan, EngineError> {
    let mut filters = Vec::new();
    for route in protected_routes {
        parse_v4_cidr(route)?;
        filters.push(PlannedWfpFilter {
            layer: WfpLayer::AleAuthConnectV4,
            action: WfpAction::Block,
            route: route.clone(),
            tunnel_interface_required: false,
        });
        filters.push(PlannedWfpFilter {
            layer: WfpLayer::AleAuthConnectV4,
            action: WfpAction::Permit,
            route: route.clone(),
            tunnel_interface_required: true,
        });
        if policy == quantumlink_proto::models::KillSwitchPolicy::Strict {
            filters.push(PlannedWfpFilter {
                layer: WfpLayer::OutboundIpPacketV4,
                action: WfpAction::Block,
                route: route.clone(),
                tunnel_interface_required: false,
            });
            filters.push(PlannedWfpFilter {
                layer: WfpLayer::OutboundIpPacketV4,
                action: WfpAction::Permit,
                route: route.clone(),
                tunnel_interface_required: true,
            });
        }
    }

    Ok(match policy {
        quantumlink_proto::models::KillSwitchPolicy::FailClosed => WfpFilterPlan {
            mode: WfpFilterMode::FailClosed,
            dynamic_session: true,
            persistent_filters: false,
            boot_time_fail_closed: false,
            cleanup_required_on_uninstall: false,
            filters,
        },
        quantumlink_proto::models::KillSwitchPolicy::Strict => WfpFilterPlan {
            mode: WfpFilterMode::Strict,
            dynamic_session: false,
            persistent_filters: true,
            boot_time_fail_closed: true,
            cleanup_required_on_uninstall: true,
            filters,
        },
    })
}

pub fn runtime_install_for_plan(plan: &WfpFilterPlan) -> Result<WfpRuntimeInstall, EngineError> {
    if plan.persistent_filters || plan.boot_time_fail_closed {
        return Err(EngineError::Platform(
            "strict WFP requires persistent boot-time filters; refusing dynamic-session fallback"
                .into(),
        ));
    }
    Ok(WfpRuntimeInstall::DynamicSession)
}

#[cfg(windows)]
pub struct KillSwitchGuard {
    engine: HANDLE,
    protected_routes: Vec<String>,
}

// HANDLE is a raw pointer; the WFP engine handle is safe to close from
// another thread, which is all we do with it after creation.
#[cfg(windows)]
unsafe impl Send for KillSwitchGuard {}
#[cfg(windows)]
unsafe impl Sync for KillSwitchGuard {}

#[cfg(windows)]
impl KillSwitchGuard {
    pub fn engage_with_policy(
        protected_routes: &[String],
        tunnel_luid: u64,
        policy: quantumlink_proto::models::KillSwitchPolicy,
    ) -> Result<Self, EngineError> {
        let plan = build_filter_plan(policy, protected_routes)?;
        match runtime_install_for_plan(&plan)? {
            WfpRuntimeInstall::DynamicSession => {
                Self::engage_dynamic(protected_routes, tunnel_luid)
            }
            WfpRuntimeInstall::PersistentBootTime => Err(EngineError::Platform(
                "persistent WFP install is not implemented".into(),
            )),
        }
    }

    /// Opens a dynamic WFP session and installs block+permit filters for
    /// the supplied protected prefixes. `tunnel_luid` is the Wintun
    /// adapter LUID traffic is permitted through.
    pub fn engage(protected_routes: &[String], tunnel_luid: u64) -> Result<Self, EngineError> {
        Self::engage_with_policy(
            protected_routes,
            tunnel_luid,
            quantumlink_proto::models::KillSwitchPolicy::FailClosed,
        )
    }

    fn engage_dynamic(protected_routes: &[String], tunnel_luid: u64) -> Result<Self, EngineError> {
        let mut engine = HANDLE::default();
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let status = unsafe {
            FwpmEngineOpen0(
                None,
                RPC_C_AUTHN_DEFAULT as u32,
                None,
                Some(&session),
                &mut engine,
            )
        };
        if status != 0 {
            return Err(EngineError::Platform(format!(
                "FwpmEngineOpen0 failed: 0x{status:08x}"
            )));
        }
        let guard = Self {
            engine,
            protected_routes: protected_routes.to_vec(),
        };

        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: display_data("QuantumLink kill switch"),
            weight: u16::MAX,
            ..Default::default()
        };
        let status = unsafe { FwpmSubLayerAdd0(guard.engine, &sublayer, None) };
        if status != 0 {
            return Err(EngineError::Platform(format!(
                "FwpmSubLayerAdd0 failed: 0x{status:08x}"
            )));
        }

        for route in protected_routes {
            let (address, prefix) = parse_v4_cidr(route)?;
            let mask = prefix_to_mask(prefix);
            guard.add_prefix_filters(address, mask, tunnel_luid)?;
        }
        Ok(guard)
    }

    /// Prefixes this guard is protecting — used when the engine
    /// re-engages with the real adapter LUID after Wintun creation.
    pub fn protected_routes(&self) -> &[String] {
        &self.protected_routes
    }

    fn add_prefix_filters(
        &self,
        address: Ipv4Addr,
        mask: u32,
        tunnel_luid: u64,
    ) -> Result<(), EngineError> {
        let addr_and_mask = FWP_V4_ADDR_AND_MASK {
            addr: u32::from(address),
            mask,
        };

        // Block everything to the protected prefix (weight 0).
        let block_conditions = [FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0 {
                r#type: FWP_V4_ADDR_MASK,
                Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                    v4AddrMask: &addr_and_mask as *const _ as *mut _,
                },
            },
        }];
        self.add_filter(
            "QuantumLink block protected prefix",
            FWP_ACTION_BLOCK,
            BLOCK_WEIGHT,
            &block_conditions,
        )?;

        // Permit the same prefix when the local interface is the tunnel
        // (weight 15 > 0, so it wins inside the sublayer).
        let luid = tunnel_luid;
        let permit_conditions = [
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0 {
                    r#type: FWP_V4_ADDR_MASK,
                    Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                        v4AddrMask: &addr_and_mask as *const _ as *mut _,
                    },
                },
            },
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT64,
                    Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                        uint64: &luid as *const u64 as *mut u64,
                    },
                },
            },
        ];
        self.add_filter(
            "QuantumLink permit tunnel interface",
            FWP_ACTION_PERMIT,
            PERMIT_WEIGHT,
            &permit_conditions,
        )?;
        Ok(())
    }

    fn add_filter(
        &self,
        name: &'static str,
        action_type: FWP_ACTION_TYPE,
        weight: u8,
        conditions: &[FWPM_FILTER_CONDITION0],
    ) -> Result<(), EngineError> {
        let weight_value = weight;
        let filter = FWPM_FILTER0 {
            displayData: display_data(name),
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            subLayerKey: SUBLAYER_KEY,
            weight: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous:
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 {
                        uint8: weight_value,
                    },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_ptr() as *mut FWPM_FILTER_CONDITION0,
            action: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTION0 {
                r#type: action_type,
                ..Default::default()
            },
            ..Default::default()
        };
        let status = unsafe { FwpmFilterAdd0(self.engine, &filter, None, None) };
        if status != 0 {
            return Err(EngineError::Platform(format!(
                "FwpmFilterAdd0({name}) failed: 0x{status:08x}"
            )));
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for KillSwitchGuard {
    fn drop(&mut self) {
        // Dynamic session: closing the engine handle removes the
        // sublayer and every filter we added.
        unsafe {
            let _ = FwpmEngineClose0(self.engine);
        }
    }
}

#[cfg(windows)]
fn display_data(
    name: &'static str,
) -> windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
    let wide = display_name_ptr(name);
    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
        name: windows::core::PWSTR(wide),
        description: windows::core::PWSTR::null(),
    }
}

#[cfg(windows)]
fn display_name_ptr(name: &'static str) -> *mut u16 {
    static KILL_SWITCH: OnceLock<Box<[u16]>> = OnceLock::new();
    static BLOCK_PREFIX: OnceLock<Box<[u16]>> = OnceLock::new();
    static PERMIT_TUNNEL: OnceLock<Box<[u16]>> = OnceLock::new();
    static UNKNOWN: OnceLock<Box<[u16]>> = OnceLock::new();

    let cell = match name {
        "QuantumLink kill switch" => &KILL_SWITCH,
        "QuantumLink block protected prefix" => &BLOCK_PREFIX,
        "QuantumLink permit tunnel interface" => &PERMIT_TUNNEL,
        _ => &UNKNOWN,
    };
    cell.get_or_init(|| name.encode_utf16().chain(std::iter::once(0)).collect())
        .as_ptr() as *mut u16
}

fn parse_v4_cidr(route: &str) -> Result<(Ipv4Addr, u8), EngineError> {
    let (address, prefix) = match route.split_once('/') {
        Some((address, prefix)) => (
            address,
            prefix
                .parse::<u8>()
                .map_err(|_| EngineError::Config(format!("bad CIDR prefix: {route:?}")))?,
        ),
        None => (route, 32),
    };
    if prefix > 32 {
        return Err(EngineError::Config(format!("prefix too long: {route:?}")));
    }
    let address: Ipv4Addr = address
        .parse()
        .map_err(|_| EngineError::Config(format!("bad IPv4 address: {route:?}")))?;
    Ok((address, prefix))
}

fn prefix_to_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

pub(crate) fn probe_dynamic_filter_attach() -> Result<(), EngineError> {
    #[cfg(not(windows))]
    {
        return Err(EngineError::Platform(
            "WFP dynamic filter probe requires Windows".into(),
        ));
    }

    #[cfg(windows)]
    {
        let routes = vec!["198.51.100.0/24".to_string()];
        let guard = KillSwitchGuard::engage(&routes, 0)?;
        drop(guard);
        Ok(())
    }
}

pub(crate) fn looks_like_admin_required(error: &EngineError) -> bool {
    match error {
        EngineError::Platform(message) => {
            message.contains("0x00000005")
                || message.contains("0x80070005")
                || message.contains("0x80320005")
                || message.to_ascii_lowercase().contains("access denied")
        }
        _ => false,
    }
}

#[allow(dead_code)]
#[cfg(windows)]
fn _suppress_unused(_: *const c_void) {}

#[cfg(test)]
mod tests {
    use super::*;
    use quantumlink_proto::models::KillSwitchPolicy;

    #[test]
    fn wfp_fail_closed_plan_uses_dynamic_session_filters() {
        let routes = vec!["100.64.0.0/10".to_string()];
        let plan = build_filter_plan(KillSwitchPolicy::FailClosed, &routes).unwrap();

        assert_eq!(plan.mode, WfpFilterMode::FailClosed);
        assert!(plan.dynamic_session);
        assert!(!plan.persistent_filters);
        assert!(!plan.boot_time_fail_closed);
        assert!(plan
            .filters
            .iter()
            .all(|filter| filter.layer == WfpLayer::AleAuthConnectV4));
    }

    #[test]
    fn wfp_strict_plan_is_persistent_boot_time_and_covers_outbound_packets() {
        let routes = vec!["100.64.0.0/10".to_string()];
        let plan = build_filter_plan(KillSwitchPolicy::Strict, &routes).unwrap();

        assert_eq!(plan.mode, WfpFilterMode::Strict);
        assert!(!plan.dynamic_session);
        assert!(plan.persistent_filters);
        assert!(plan.boot_time_fail_closed);
        assert!(plan.cleanup_required_on_uninstall);
        assert!(plan
            .filters
            .iter()
            .any(|filter| filter.layer == WfpLayer::AleAuthConnectV4));
        assert!(plan
            .filters
            .iter()
            .any(|filter| filter.layer == WfpLayer::OutboundIpPacketV4));
    }

    #[test]
    fn wfp_strict_outbound_packet_plan_has_block_and_permit_filters() {
        let routes = vec!["100.64.0.0/10".to_string()];
        let plan = build_filter_plan(KillSwitchPolicy::Strict, &routes).unwrap();

        assert!(plan.filters.iter().any(|filter| {
            filter.layer == WfpLayer::OutboundIpPacketV4 && filter.action == WfpAction::Block
        }));
        assert!(plan.filters.iter().any(|filter| {
            filter.layer == WfpLayer::OutboundIpPacketV4
                && filter.action == WfpAction::Permit
                && filter.tunnel_interface_required
        }));
    }

    #[test]
    fn wfp_strict_runtime_refuses_dynamic_session_fallback() {
        let routes = vec!["100.64.0.0/10".to_string()];
        let plan = build_filter_plan(KillSwitchPolicy::Strict, &routes).unwrap();
        let error = runtime_install_for_plan(&plan).unwrap_err();

        match error {
            EngineError::Platform(message) => {
                assert!(message.contains("refusing dynamic-session fallback"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
