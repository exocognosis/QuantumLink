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
use std::ffi::c_void;
use std::net::Ipv4Addr;
use windows::core::GUID;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmSubLayerAdd0, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0,
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_MATCH_EQUAL, FWP_UINT64, FWP_UINT8,
    FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

/// Stable product GUIDs (random, fixed at build time).
const SUBLAYER_KEY: GUID = GUID::from_u128(0x7c1a44d0_3f2e_4b8a_9c61_d5a0e84b91f2);

const BLOCK_WEIGHT: u8 = 0;
const PERMIT_WEIGHT: u8 = 15;

pub struct KillSwitchGuard {
    engine: HANDLE,
    protected_routes: Vec<String>,
}

// HANDLE is a raw pointer; the WFP engine handle is safe to close from
// another thread, which is all we do with it after creation.
unsafe impl Send for KillSwitchGuard {}
unsafe impl Sync for KillSwitchGuard {}

impl KillSwitchGuard {
    /// Opens a dynamic WFP session and installs block+permit filters for
    /// the supplied protected prefixes. `tunnel_luid` is the Wintun
    /// adapter LUID traffic is permitted through.
    pub fn engage(protected_routes: &[String], tunnel_luid: u64) -> Result<Self, EngineError> {
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
                Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 {
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

impl Drop for KillSwitchGuard {
    fn drop(&mut self) {
        // Dynamic session: closing the engine handle removes the
        // sublayer and every filter we added.
        unsafe {
            let _ = FwpmEngineClose0(self.engine);
        }
    }
}

fn display_data(
    name: &'static str,
) -> windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
    // Leaked once per static name — bounded set, lives for process life.
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let leaked = Box::leak(wide.into_boxed_slice());
    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
        name: windows::core::PWSTR(leaked.as_mut_ptr()),
        description: windows::core::PWSTR::null(),
    }
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

#[allow(dead_code)]
fn _suppress_unused(_: *const c_void) {}
