//! Windows Filtering Platform ownership for the QuantumLink kill switch.
//!
//! `failClosed` uses a dynamic session. `strict` uses provider-owned persistent
//! runtime block filters plus distinct provider-owned boot-time block filters.
//! Tunnel permits always live in a dynamic session and are never installed
//! until a real Wintun LUID is available. Closing the guard therefore removes
//! permits but intentionally leaves strict block coverage in BFE.

use crate::engine::EngineError;
use std::net::Ipv4Addr;

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::ptr::{null_mut, NonNull};
#[cfg(windows)]
use std::sync::OnceLock;
#[cfg(windows)]
use windows::core::GUID;
#[cfg(windows)]
use windows::Win32::Foundation::{
    FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND,
    FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
};
#[cfg(windows)]
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDeleteByKey0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmProviderAdd0, FwpmProviderDeleteByKey0, FwpmProviderGetByKey0, FwpmSubLayerAdd0,
    FwpmSubLayerDeleteByKey0, FwpmSubLayerGetByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0, FWPM_ACTION0, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAGS, FWPM_FILTER_FLAG_BOOTTIME,
    FWPM_FILTER_FLAG_DISABLED, FWPM_FILTER_FLAG_PERSISTENT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_OUTBOUND_IPPACKET_V4, FWPM_PROVIDER0, FWPM_PROVIDER_FLAG_DISABLED,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0,
    FWPM_SUBLAYER_FLAG_PERSISTENT, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB,
    FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME, FWP_MATCH_EQUAL, FWP_UINT64, FWP_UINT8,
    FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
};
#[cfg(windows)]
use windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

pub const PROVIDER_KEY_U128: u128 = 0xe565f2d9_6728_4df3_a578_9de6f6ed725a;
pub const SUBLAYER_KEY_U128: u128 = 0x7c1a44d0_3f2e_4b8a_9c61_d5a0e84b91f2;
pub const PROVIDER_SERVICE_NAME: &str = "QuantumLinkService";

const PROVIDER_DATA: &[u8] = b"QuantumLinkWfpV1";
const OWNED_CONTEXT_PERSISTENT_BLOCK: u64 = 0x514c_4e4b_0000_0001;
const OWNED_CONTEXT_BOOT_TIME_BLOCK: u64 = 0x514c_4e4b_0000_0002;
const OWNED_CONTEXT_TUNNEL_PERMIT: u64 = 0x514c_4e4b_0000_0003;
const OWNED_CONTEXT_DYNAMIC_BLOCK: u64 = 0x514c_4e4b_0000_0004;

#[cfg(windows)]
const PROVIDER_KEY: GUID = GUID::from_u128(PROVIDER_KEY_U128);
#[cfg(windows)]
const SUBLAYER_KEY: GUID = GUID::from_u128(SUBLAYER_KEY_U128);
#[cfg(windows)]
const BLOCK_WEIGHT: u8 = 0;
#[cfg(windows)]
const PERMIT_WEIGHT: u8 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpFilterMode {
    FailClosed,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WfpLayer {
    AleAuthConnectV4,
    OutboundIpPacketV4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WfpAction {
    Block,
    Permit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WfpFilterLifetime {
    Dynamic,
    Persistent,
    BootTime,
}

impl WfpFilterLifetime {
    pub fn persistent_flag(self) -> bool {
        self == Self::Persistent
    }

    pub fn boot_time_flag(self) -> bool {
        self == Self::BootTime
    }

    pub fn management_flags(self) -> u32 {
        match self {
            Self::Dynamic => 0,
            Self::Persistent => 1,
            Self::BootTime => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedWfpFilter {
    pub ownership_key: u128,
    pub provider_key: u128,
    pub sublayer_key: u128,
    pub layer: WfpLayer,
    pub action: WfpAction,
    pub lifetime: WfpFilterLifetime,
    pub route: String,
    pub tunnel_luid: Option<u64>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExistingWfpFilter {
    pub ownership_key: u128,
    pub provider_key: u128,
    pub sublayer_key: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpReconciliationPlan {
    pub delete_keys: Vec<u128>,
    pub add_filters: Vec<PlannedWfpFilter>,
}

pub fn build_filter_plan(
    policy: quantumlink_proto::models::KillSwitchPolicy,
    protected_routes: &[String],
) -> Result<WfpFilterPlan, EngineError> {
    build_filter_plan_for_luid(policy, protected_routes, None)
}

pub fn build_filter_plan_for_luid(
    policy: quantumlink_proto::models::KillSwitchPolicy,
    protected_routes: &[String],
    tunnel_luid: Option<u64>,
) -> Result<WfpFilterPlan, EngineError> {
    let tunnel_luid = tunnel_luid.filter(|luid| *luid != 0);
    let mode = match policy {
        quantumlink_proto::models::KillSwitchPolicy::FailClosed => WfpFilterMode::FailClosed,
        quantumlink_proto::models::KillSwitchPolicy::Strict => WfpFilterMode::Strict,
    };
    let layers: &[WfpLayer] = match mode {
        WfpFilterMode::FailClosed => &[WfpLayer::AleAuthConnectV4],
        WfpFilterMode::Strict => &[WfpLayer::AleAuthConnectV4, WfpLayer::OutboundIpPacketV4],
    };

    let mut filters = Vec::new();
    for route in protected_routes {
        let route = canonical_v4_cidr(route)?;
        for layer in layers {
            match mode {
                WfpFilterMode::FailClosed => filters.push(planned_filter(
                    *layer,
                    WfpAction::Block,
                    WfpFilterLifetime::Dynamic,
                    &route,
                    None,
                )),
                WfpFilterMode::Strict => {
                    filters.push(planned_filter(
                        *layer,
                        WfpAction::Block,
                        WfpFilterLifetime::BootTime,
                        &route,
                        None,
                    ));
                    filters.push(planned_filter(
                        *layer,
                        WfpAction::Block,
                        WfpFilterLifetime::Persistent,
                        &route,
                        None,
                    ));
                }
            }
            if let Some(luid) = tunnel_luid {
                filters.push(planned_filter(
                    *layer,
                    WfpAction::Permit,
                    WfpFilterLifetime::Dynamic,
                    &route,
                    Some(luid),
                ));
            }
        }
    }
    filters.sort_by_key(|filter| filter.ownership_key);
    filters.dedup_by_key(|filter| filter.ownership_key);

    Ok(WfpFilterPlan {
        mode,
        dynamic_session: mode == WfpFilterMode::FailClosed,
        persistent_filters: mode == WfpFilterMode::Strict,
        boot_time_fail_closed: mode == WfpFilterMode::Strict,
        cleanup_required_on_uninstall: mode == WfpFilterMode::Strict,
        filters,
    })
}

fn planned_filter(
    layer: WfpLayer,
    action: WfpAction,
    lifetime: WfpFilterLifetime,
    route: &str,
    tunnel_luid: Option<u64>,
) -> PlannedWfpFilter {
    PlannedWfpFilter {
        ownership_key: stable_filter_key(layer, action, lifetime, route, tunnel_luid),
        provider_key: PROVIDER_KEY_U128,
        sublayer_key: SUBLAYER_KEY_U128,
        layer,
        action,
        lifetime,
        route: route.to_string(),
        tunnel_luid,
    }
}

pub fn runtime_install_for_plan(plan: &WfpFilterPlan) -> Result<WfpRuntimeInstall, EngineError> {
    match plan.mode {
        WfpFilterMode::FailClosed if !plan.persistent_filters && !plan.boot_time_fail_closed => {
            Ok(WfpRuntimeInstall::DynamicSession)
        }
        WfpFilterMode::Strict if plan.persistent_filters && plan.boot_time_fail_closed => {
            let invalid = plan.filters.iter().any(|filter| {
                filter.lifetime.persistent_flag() && filter.lifetime.boot_time_flag()
            });
            if invalid {
                return Err(EngineError::Platform(
                    "strict WFP filter cannot combine persistent and boot-time flags".into(),
                ));
            }
            Ok(WfpRuntimeInstall::PersistentBootTime)
        }
        WfpFilterMode::Strict => Err(EngineError::Platform(
            "strict WFP plan lacks persistent or boot-time coverage; refusing dynamic fallback"
                .into(),
        )),
        WfpFilterMode::FailClosed => Err(EngineError::Platform(
            "failClosed WFP plan unexpectedly requested persistent filters".into(),
        )),
    }
}

pub fn build_reconciliation_plan(
    existing: &[ExistingWfpFilter],
    desired: &[PlannedWfpFilter],
) -> WfpReconciliationPlan {
    let mut delete_keys: Vec<u128> = existing
        .iter()
        .filter(|filter| {
            filter.provider_key == PROVIDER_KEY_U128 && filter.sublayer_key == SUBLAYER_KEY_U128
        })
        .map(|filter| filter.ownership_key)
        .collect();
    delete_keys.sort_unstable();
    delete_keys.dedup();

    let mut add_filters = desired.to_vec();
    add_filters.sort_by_key(|filter| filter.ownership_key);
    add_filters.dedup_by_key(|filter| filter.ownership_key);
    WfpReconciliationPlan {
        delete_keys,
        add_filters,
    }
}

fn stable_filter_key(
    layer: WfpLayer,
    action: WfpAction,
    lifetime: WfpFilterLifetime,
    route: &str,
    tunnel_luid: Option<u64>,
) -> u128 {
    let descriptor = format!(
        "quantumlink-wfp-v1|{layer:?}|{action:?}|{lifetime:?}|{route}|{}",
        tunnel_luid.unwrap_or(0)
    );
    let mut high = 0xcbf2_9ce4_8422_2325u64;
    let mut low = 0x8422_2325_cbf2_9ce4u64;
    for byte in descriptor.bytes() {
        high ^= u64::from(byte);
        high = high.wrapping_mul(0x0000_0100_0000_01b3);
        low ^= u64::from(byte).rotate_left(1);
        low = low.wrapping_mul(0x9e37_79b1_85eb_ca87);
    }
    let mut key = (u128::from(high) << 64) | u128::from(low);
    key &= !(0xfu128 << 76);
    key |= 5u128 << 76;
    key &= !(0x3u128 << 62);
    key |= 0x2u128 << 62;
    key
}

#[cfg(windows)]
pub struct KillSwitchGuard {
    _permit_engine: Option<WfpEngine>,
    mode: WfpFilterMode,
    protected_routes: Vec<String>,
}

#[cfg(windows)]
impl KillSwitchGuard {
    pub fn engage_with_policy(
        protected_routes: &[String],
        tunnel_luid: u64,
        policy: quantumlink_proto::models::KillSwitchPolicy,
    ) -> Result<Self, EngineError> {
        let plan = build_filter_plan_for_luid(policy, protected_routes, Some(tunnel_luid))?;
        match runtime_install_for_plan(&plan)? {
            WfpRuntimeInstall::DynamicSession => Self::engage_dynamic(plan),
            WfpRuntimeInstall::PersistentBootTime => Self::engage_strict(plan),
        }
    }

    pub fn engage(protected_routes: &[String], tunnel_luid: u64) -> Result<Self, EngineError> {
        Self::engage_with_policy(
            protected_routes,
            tunnel_luid,
            quantumlink_proto::models::KillSwitchPolicy::FailClosed,
        )
    }

    fn engage_dynamic(plan: WfpFilterPlan) -> Result<Self, EngineError> {
        let owner_engine = WfpEngine::open(false)?;
        ensure_owner_objects(&owner_engine)?;
        drop(owner_engine);

        let engine = WfpEngine::open(true)?;
        reconcile_filters(&engine, &plan.filters)?;
        Ok(Self {
            _permit_engine: Some(engine),
            mode: WfpFilterMode::FailClosed,
            protected_routes: routes_from_plan(&plan),
        })
    }

    fn engage_strict(plan: WfpFilterPlan) -> Result<Self, EngineError> {
        let engine = WfpEngine::open(false)?;
        ensure_owner_objects(&engine)?;

        let blocks: Vec<_> = plan
            .filters
            .iter()
            .filter(|filter| filter.action == WfpAction::Block)
            .cloned()
            .collect();
        reconcile_filters(&engine, &blocks)?;
        drop(engine);

        let permits: Vec<_> = plan
            .filters
            .iter()
            .filter(|filter| filter.action == WfpAction::Permit)
            .cloned()
            .collect();
        let permit_engine = if permits.is_empty() {
            None
        } else {
            let engine = WfpEngine::open(true)?;
            add_filters_transaction(&engine, &permits)?;
            Some(engine)
        };

        Ok(Self {
            _permit_engine: permit_engine,
            mode: WfpFilterMode::Strict,
            protected_routes: routes_from_plan(&plan),
        })
    }

    pub fn protected_routes(&self) -> &[String] {
        &self.protected_routes
    }

    /// Removes strict tunnel permits before the adapter LUID becomes inactive.
    /// Persistent and boot-time block filters are provider-owned and unaffected.
    pub fn revoke_strict_tunnel_permits(&mut self) {
        if self.mode == WfpFilterMode::Strict {
            self._permit_engine.take();
        }
    }

    pub fn persists_after_drop(&self) -> bool {
        self.mode == WfpFilterMode::Strict
    }
}

#[cfg(windows)]
pub fn reconcile_startup_policy(
    config: &quantumlink_proto::models::TunnelConfiguration,
) -> Result<bool, EngineError> {
    match config.kill_switch {
        quantumlink_proto::models::KillSwitchPolicy::Strict => {
            let plan =
                build_filter_plan_for_luid(config.kill_switch, &config.protected_routes, None)?;
            let engine = WfpEngine::open(false)?;
            ensure_owner_objects(&engine)?;
            reconcile_filters(&engine, &plan.filters)?;
            Ok(true)
        }
        quantumlink_proto::models::KillSwitchPolicy::FailClosed => {
            cleanup_owned_persistent_filters()?;
            Ok(false)
        }
    }
}

#[cfg(windows)]
fn routes_from_plan(plan: &WfpFilterPlan) -> Vec<String> {
    let mut routes: Vec<_> = plan
        .filters
        .iter()
        .map(|filter| filter.route.clone())
        .collect();
    routes.sort();
    routes.dedup();
    routes
}

#[cfg(windows)]
struct WfpEngine(HANDLE);

#[cfg(windows)]
unsafe impl Send for WfpEngine {}
#[cfg(windows)]
unsafe impl Sync for WfpEngine {}

#[cfg(windows)]
impl WfpEngine {
    fn open(dynamic: bool) -> Result<Self, EngineError> {
        let mut engine = HANDLE::default();
        let session = FWPM_SESSION0 {
            flags: if dynamic {
                FWPM_SESSION_FLAG_DYNAMIC
            } else {
                0
            },
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
        status_result("FwpmEngineOpen0", status)?;
        Ok(Self(engine))
    }

    fn handle(&self) -> HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for WfpEngine {
    fn drop(&mut self) {
        unsafe {
            let _ = FwpmEngineClose0(self.0);
        }
    }
}

#[cfg(windows)]
struct WfpTransaction<'a> {
    engine: &'a WfpEngine,
    active: bool,
}

#[cfg(windows)]
impl<'a> WfpTransaction<'a> {
    fn begin(engine: &'a WfpEngine) -> Result<Self, EngineError> {
        let status = unsafe { FwpmTransactionBegin0(engine.handle(), 0) };
        status_result("FwpmTransactionBegin0", status)?;
        Ok(Self {
            engine,
            active: true,
        })
    }

    fn commit(mut self) -> Result<(), EngineError> {
        let status = unsafe { FwpmTransactionCommit0(self.engine.handle()) };
        status_result("FwpmTransactionCommit0", status)?;
        self.active = false;
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WfpTransaction<'_> {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                let _ = FwpmTransactionAbort0(self.engine.handle());
            }
        }
    }
}

#[cfg(windows)]
fn ensure_owner_objects(engine: &WfpEngine) -> Result<(), EngineError> {
    let transaction = WfpTransaction::begin(engine)?;
    ensure_provider(engine)?;
    ensure_sublayer(engine)?;
    transaction.commit()
}

#[cfg(windows)]
fn ensure_provider(engine: &WfpEngine) -> Result<(), EngineError> {
    let mut existing = null_mut();
    let status = unsafe { FwpmProviderGetByKey0(engine.handle(), &PROVIDER_KEY, &mut existing) };
    if status == 0 {
        let existing = NonNull::new(existing).ok_or_else(|| {
            EngineError::Platform("FwpmProviderGetByKey0 returned a null provider".into())
        })?;
        let provider = unsafe { existing.as_ref() };
        let matches = provider.flags & FWPM_PROVIDER_FLAG_PERSISTENT != 0
            && provider.flags & FWPM_PROVIDER_FLAG_DISABLED == 0
            && provider_blob_matches(&provider.providerData, PROVIDER_DATA)
            && !provider.serviceName.is_null()
            && unsafe { provider.serviceName.to_string() }
                .map(|name| name == PROVIDER_SERVICE_NAME)
                .unwrap_or(false);
        free_wfp_memory(existing.as_ptr().cast());
        if !matches {
            return Err(EngineError::Platform(
                "existing QuantumLink WFP provider key has incompatible ownership metadata".into(),
            ));
        }
        return Ok(());
    }
    if status != hresult_code(FWP_E_PROVIDER_NOT_FOUND) {
        return status_result("FwpmProviderGetByKey0", status);
    }

    let mut provider_data = PROVIDER_DATA.to_vec();
    let provider = FWPM_PROVIDER0 {
        providerKey: PROVIDER_KEY,
        displayData: display_data("QuantumLink WFP provider"),
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        providerData: FWP_BYTE_BLOB {
            size: provider_data.len() as u32,
            data: provider_data.as_mut_ptr(),
        },
        serviceName: windows::core::PWSTR(display_name_ptr(PROVIDER_SERVICE_NAME)),
    };
    let status = unsafe { FwpmProviderAdd0(engine.handle(), &provider, None) };
    if status == hresult_code(FWP_E_ALREADY_EXISTS) {
        return Err(EngineError::Platform(
            "QuantumLink WFP provider appeared during reconciliation; retry required".into(),
        ));
    }
    status_result("FwpmProviderAdd0", status)
}

#[cfg(windows)]
fn ensure_sublayer(engine: &WfpEngine) -> Result<(), EngineError> {
    let mut existing = null_mut();
    let status = unsafe { FwpmSubLayerGetByKey0(engine.handle(), &SUBLAYER_KEY, &mut existing) };
    if status == 0 {
        let existing = NonNull::new(existing).ok_or_else(|| {
            EngineError::Platform("FwpmSubLayerGetByKey0 returned a null sublayer".into())
        })?;
        let sublayer = unsafe { existing.as_ref() };
        let matches = sublayer.flags & FWPM_SUBLAYER_FLAG_PERSISTENT != 0
            && !sublayer.providerKey.is_null()
            && unsafe { *sublayer.providerKey == PROVIDER_KEY };
        free_wfp_memory(existing.as_ptr().cast());
        if !matches {
            return Err(EngineError::Platform(
                "existing QuantumLink WFP sublayer key has incompatible ownership metadata".into(),
            ));
        }
        return Ok(());
    }
    if status != hresult_code(FWP_E_SUBLAYER_NOT_FOUND) {
        return status_result("FwpmSubLayerGetByKey0", status);
    }

    let mut provider_key = PROVIDER_KEY;
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_KEY,
        displayData: display_data("QuantumLink kill switch"),
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &mut provider_key,
        weight: u16::MAX,
        ..Default::default()
    };
    let status = unsafe { FwpmSubLayerAdd0(engine.handle(), &sublayer, None) };
    if status == hresult_code(FWP_E_ALREADY_EXISTS) {
        return Err(EngineError::Platform(
            "QuantumLink WFP sublayer appeared during reconciliation; retry required".into(),
        ));
    }
    status_result("FwpmSubLayerAdd0", status)
}

#[cfg(windows)]
fn reconcile_filters(engine: &WfpEngine, desired: &[PlannedWfpFilter]) -> Result<(), EngineError> {
    let existing = enumerate_owned_filter_records(engine)?;
    let plan = build_reconciliation_plan(
        &existing
            .iter()
            .map(|record| record.identity)
            .collect::<Vec<_>>(),
        desired,
    );
    let transaction = WfpTransaction::begin(engine)?;
    for key in plan.delete_keys {
        delete_filter_if_present(engine, GUID::from_u128(key))?;
    }
    for filter in &plan.add_filters {
        add_planned_filter(engine, filter)?;
    }
    transaction.commit()
}

#[cfg(windows)]
fn add_filters_transaction(
    engine: &WfpEngine,
    filters: &[PlannedWfpFilter],
) -> Result<(), EngineError> {
    let transaction = WfpTransaction::begin(engine)?;
    for filter in filters {
        add_planned_filter(engine, filter)?;
    }
    transaction.commit()
}

#[cfg(windows)]
fn add_planned_filter(engine: &WfpEngine, planned: &PlannedWfpFilter) -> Result<(), EngineError> {
    if planned.provider_key != PROVIDER_KEY_U128 || planned.sublayer_key != SUBLAYER_KEY_U128 {
        return Err(EngineError::Platform(
            "refusing to install a WFP filter outside QuantumLink ownership".into(),
        ));
    }
    if planned.lifetime.persistent_flag() && planned.lifetime.boot_time_flag() {
        return Err(EngineError::Platform(
            "WFP persistent and boot-time flags cannot be combined".into(),
        ));
    }

    let (address, prefix) = parse_v4_cidr(&planned.route)?;
    let addr_and_mask = FWP_V4_ADDR_AND_MASK {
        addr: u32::from(address),
        mask: prefix_to_mask(prefix),
    };
    let luid = planned.tunnel_luid.unwrap_or_default();
    if planned.action == WfpAction::Permit && luid == 0 {
        return Err(EngineError::Platform(
            "refusing to install a tunnel permit without an active adapter LUID".into(),
        ));
    }

    let mut conditions = vec![FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0 {
            r#type: FWP_V4_ADDR_MASK,
            Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                v4AddrMask: &addr_and_mask as *const _ as *mut _,
            },
        },
    }];
    if planned.action == WfpAction::Permit {
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                    uint64: &luid as *const u64 as *mut u64,
                },
            },
        });
    }

    let flags = FWPM_FILTER_FLAGS(planned.lifetime.management_flags());
    let (name, action, weight, raw_context) = match (planned.action, planned.lifetime) {
        (WfpAction::Block, WfpFilterLifetime::Persistent) => (
            "QuantumLink persistent block",
            FWP_ACTION_BLOCK,
            BLOCK_WEIGHT,
            OWNED_CONTEXT_PERSISTENT_BLOCK,
        ),
        (WfpAction::Block, WfpFilterLifetime::BootTime) => (
            "QuantumLink boot-time block",
            FWP_ACTION_BLOCK,
            BLOCK_WEIGHT,
            OWNED_CONTEXT_BOOT_TIME_BLOCK,
        ),
        (WfpAction::Block, WfpFilterLifetime::Dynamic) => (
            "QuantumLink dynamic block",
            FWP_ACTION_BLOCK,
            BLOCK_WEIGHT,
            OWNED_CONTEXT_DYNAMIC_BLOCK,
        ),
        (WfpAction::Permit, WfpFilterLifetime::Dynamic) => (
            "QuantumLink tunnel permit",
            FWP_ACTION_PERMIT,
            PERMIT_WEIGHT,
            OWNED_CONTEXT_TUNNEL_PERMIT,
        ),
        (WfpAction::Permit, _) => {
            return Err(EngineError::Platform(
                "tunnel permit filters must be dynamic".into(),
            ));
        }
    };

    let mut provider_key = PROVIDER_KEY;
    let weight_value = weight;
    let filter = FWPM_FILTER0 {
        filterKey: GUID::from_u128(planned.ownership_key),
        displayData: display_data(name),
        flags,
        providerKey: &mut provider_key,
        layerKey: layer_key(planned.layer),
        subLayerKey: SUBLAYER_KEY,
        weight: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 {
                uint8: weight_value,
            },
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: action,
            ..Default::default()
        },
        Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER0_0 {
            rawContext: raw_context,
        },
        ..Default::default()
    };
    let status = unsafe { FwpmFilterAdd0(engine.handle(), &filter, None, None) };
    status_result("FwpmFilterAdd0", status)
}

#[cfg(windows)]
fn layer_key(layer: WfpLayer) -> GUID {
    match layer {
        WfpLayer::AleAuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        WfpLayer::OutboundIpPacketV4 => FWPM_LAYER_OUTBOUND_IPPACKET_V4,
    }
}

#[cfg(windows)]
#[derive(Debug, Clone)]
struct OwnedFilterRecord {
    identity: ExistingWfpFilter,
    flags: u32,
    action: u32,
    raw_context: u64,
}

#[cfg(windows)]
fn enumerate_owned_filter_records(
    engine: &WfpEngine,
) -> Result<Vec<OwnedFilterRecord>, EngineError> {
    let mut records = Vec::new();
    for layer in [WfpLayer::AleAuthConnectV4, WfpLayer::OutboundIpPacketV4] {
        let mut provider_key = PROVIDER_KEY;
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            providerKey: &mut provider_key,
            layerKey: layer_key(layer),
            flags: FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME,
            actionMask: u32::MAX,
            ..Default::default()
        };
        let mut enum_handle = HANDLE::default();
        let status = unsafe {
            FwpmFilterCreateEnumHandle0(engine.handle(), Some(&template), &mut enum_handle)
        };
        if status == hresult_code(FWP_E_PROVIDER_NOT_FOUND) {
            continue;
        }
        status_result("FwpmFilterCreateEnumHandle0", status)?;
        let enum_guard = FilterEnumHandle {
            engine,
            handle: enum_handle,
        };

        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = null_mut();
            let mut count = 0;
            let status = unsafe {
                FwpmFilterEnum0(
                    engine.handle(),
                    enum_guard.handle,
                    64,
                    &mut entries,
                    &mut count,
                )
            };
            status_result("FwpmFilterEnum0", status)?;
            if count == 0 {
                free_wfp_memory(entries.cast());
                break;
            }
            for index in 0..count as usize {
                let filter_ptr = unsafe { *entries.add(index) };
                let Some(filter) = NonNull::new(filter_ptr).map(|ptr| unsafe { ptr.as_ref() })
                else {
                    continue;
                };
                if filter.subLayerKey != SUBLAYER_KEY
                    || filter.providerKey.is_null()
                    || unsafe { *filter.providerKey != PROVIDER_KEY }
                {
                    continue;
                }
                records.push(OwnedFilterRecord {
                    identity: ExistingWfpFilter {
                        ownership_key: filter.filterKey.to_u128(),
                        provider_key: PROVIDER_KEY_U128,
                        sublayer_key: SUBLAYER_KEY_U128,
                    },
                    flags: filter.flags.0,
                    action: filter.action.r#type.0,
                    raw_context: unsafe { filter.Anonymous.rawContext },
                });
            }
            free_wfp_memory(entries.cast());
        }
    }
    records.sort_by_key(|record| record.identity.ownership_key);
    records.dedup_by_key(|record| record.identity.ownership_key);
    Ok(records)
}

#[cfg(windows)]
struct FilterEnumHandle<'a> {
    engine: &'a WfpEngine,
    handle: HANDLE,
}

#[cfg(windows)]
impl Drop for FilterEnumHandle<'_> {
    fn drop(&mut self) {
        unsafe {
            let _ = FwpmFilterDestroyEnumHandle0(self.engine.handle(), self.handle);
        }
    }
}

#[cfg(windows)]
fn delete_filter_if_present(engine: &WfpEngine, key: GUID) -> Result<(), EngineError> {
    let status = unsafe { FwpmFilterDeleteByKey0(engine.handle(), &key) };
    if status == 0 || status == hresult_code(FWP_E_FILTER_NOT_FOUND) {
        Ok(())
    } else {
        status_result("FwpmFilterDeleteByKey0", status)
    }
}

#[cfg(windows)]
pub fn cleanup_owned_persistent_filters() -> Result<(), EngineError> {
    let engine = WfpEngine::open(false)?;
    let provider_state = provider_compatibility(&engine)?;
    let sublayer_state = sublayer_compatibility(&engine)?;
    match (provider_state, sublayer_state) {
        (None, None) => return Ok(()),
        (Some(true), Some(true)) => {}
        _ => {
            return Err(EngineError::Platform(
                "refusing WFP cleanup because provider or sublayer ownership metadata is incompatible"
                    .into(),
            ));
        }
    }
    let existing = enumerate_owned_filter_records(&engine)?;
    let transaction = WfpTransaction::begin(&engine)?;
    for filter in existing {
        delete_filter_if_present(&engine, GUID::from_u128(filter.identity.ownership_key))?;
    }

    let status = unsafe { FwpmSubLayerDeleteByKey0(engine.handle(), &SUBLAYER_KEY) };
    if status != 0 && status != hresult_code(FWP_E_SUBLAYER_NOT_FOUND) {
        return status_result("FwpmSubLayerDeleteByKey0", status);
    }
    let status = unsafe { FwpmProviderDeleteByKey0(engine.handle(), &PROVIDER_KEY) };
    if status != 0 && status != hresult_code(FWP_E_PROVIDER_NOT_FOUND) {
        return status_result("FwpmProviderDeleteByKey0", status);
    }
    transaction.commit()
}

#[cfg(windows)]
#[derive(Debug, serde::Serialize)]
pub struct WfpProbeReport {
    pub passed: bool,
    pub provider_present: bool,
    pub provider_compatible: bool,
    pub sublayer_present: bool,
    pub persistent_sublayer_present: bool,
    pub owned_filter_count: usize,
    pub persistent_block_count: usize,
    pub boot_time_block_count: usize,
    pub dynamic_permit_count: usize,
    pub invalid_filter_count: usize,
}

#[cfg(windows)]
pub fn probe_owned_filter_state() -> Result<WfpProbeReport, EngineError> {
    let engine = WfpEngine::open(false)?;
    let provider_state = provider_compatibility(&engine)?;
    let sublayer_state = sublayer_compatibility(&engine)?;
    let filters = enumerate_owned_filter_records(&engine)?;
    let mut report = WfpProbeReport {
        passed: false,
        provider_present: provider_state.is_some(),
        provider_compatible: provider_state == Some(true),
        sublayer_present: sublayer_state.is_some(),
        persistent_sublayer_present: sublayer_state == Some(true),
        owned_filter_count: filters.len(),
        persistent_block_count: 0,
        boot_time_block_count: 0,
        dynamic_permit_count: 0,
        invalid_filter_count: 0,
    };
    for filter in filters {
        let persistent = filter.flags & FWPM_FILTER_FLAG_PERSISTENT.0 != 0;
        let boot_time = filter.flags & FWPM_FILTER_FLAG_BOOTTIME.0 != 0;
        if filter.flags & FWPM_FILTER_FLAG_DISABLED.0 != 0 {
            report.invalid_filter_count += 1;
            continue;
        }
        let classification = (filter.raw_context, persistent, boot_time, filter.action);
        match classification {
            (OWNED_CONTEXT_PERSISTENT_BLOCK, true, false, action)
                if action == FWP_ACTION_BLOCK.0 =>
            {
                report.persistent_block_count += 1;
            }
            (OWNED_CONTEXT_BOOT_TIME_BLOCK, false, true, action)
                if action == FWP_ACTION_BLOCK.0 =>
            {
                report.boot_time_block_count += 1;
            }
            (OWNED_CONTEXT_TUNNEL_PERMIT, false, false, action)
                if action == FWP_ACTION_PERMIT.0 =>
            {
                report.dynamic_permit_count += 1;
            }
            (OWNED_CONTEXT_DYNAMIC_BLOCK, false, false, action) if action == FWP_ACTION_BLOCK.0 => {
            }
            _ => report.invalid_filter_count += 1,
        }
    }
    let owner_objects_valid = match (report.provider_present, report.sublayer_present) {
        (false, false) => report.owned_filter_count == 0,
        (true, true) => report.provider_compatible && report.persistent_sublayer_present,
        _ => false,
    };
    report.passed = report.invalid_filter_count == 0 && owner_objects_valid;
    Ok(report)
}

#[cfg(windows)]
fn provider_compatibility(engine: &WfpEngine) -> Result<Option<bool>, EngineError> {
    let mut provider = null_mut();
    let status = unsafe { FwpmProviderGetByKey0(engine.handle(), &PROVIDER_KEY, &mut provider) };
    if status == hresult_code(FWP_E_PROVIDER_NOT_FOUND) {
        return Ok(None);
    }
    status_result("FwpmProviderGetByKey0", status)?;
    let provider = NonNull::new(provider)
        .ok_or_else(|| EngineError::Platform("WFP returned a null provider".into()))?;
    let value = unsafe { provider.as_ref() };
    let compatible = value.flags & FWPM_PROVIDER_FLAG_PERSISTENT != 0
        && value.flags & FWPM_PROVIDER_FLAG_DISABLED == 0
        && provider_blob_matches(&value.providerData, PROVIDER_DATA)
        && !value.serviceName.is_null()
        && unsafe { value.serviceName.to_string() }
            .map(|name| name == PROVIDER_SERVICE_NAME)
            .unwrap_or(false);
    free_wfp_memory(provider.as_ptr().cast());
    Ok(Some(compatible))
}

#[cfg(windows)]
fn sublayer_compatibility(engine: &WfpEngine) -> Result<Option<bool>, EngineError> {
    let mut sublayer = null_mut();
    let status = unsafe { FwpmSubLayerGetByKey0(engine.handle(), &SUBLAYER_KEY, &mut sublayer) };
    if status == hresult_code(FWP_E_SUBLAYER_NOT_FOUND) {
        return Ok(None);
    }
    status_result("FwpmSubLayerGetByKey0", status)?;
    let sublayer = NonNull::new(sublayer)
        .ok_or_else(|| EngineError::Platform("WFP returned a null sublayer".into()))?;
    let value = unsafe { sublayer.as_ref() };
    let compatible = value.flags & FWPM_SUBLAYER_FLAG_PERSISTENT != 0
        && !value.providerKey.is_null()
        && unsafe { *value.providerKey == PROVIDER_KEY };
    free_wfp_memory(sublayer.as_ptr().cast());
    Ok(Some(compatible))
}

#[cfg(windows)]
fn provider_blob_matches(blob: &FWP_BYTE_BLOB, expected: &[u8]) -> bool {
    if blob.size as usize != expected.len() || blob.data.is_null() {
        return false;
    }
    unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) == expected }
}

#[cfg(windows)]
fn free_wfp_memory(pointer: *mut c_void) {
    if pointer.is_null() {
        return;
    }
    let mut pointer = pointer;
    unsafe { FwpmFreeMemory0(&mut pointer) };
}

#[cfg(windows)]
fn hresult_code(value: windows::core::HRESULT) -> u32 {
    value.0 as u32
}

#[cfg(windows)]
fn status_result(operation: &str, status: u32) -> Result<(), EngineError> {
    if status == 0 {
        Ok(())
    } else {
        Err(EngineError::Platform(format!(
            "{operation} failed: 0x{status:08x}"
        )))
    }
}

#[cfg(windows)]
fn display_data(name: &'static str) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: windows::core::PWSTR(display_name_ptr(name)),
        description: windows::core::PWSTR::null(),
    }
}

#[cfg(windows)]
fn display_name_ptr(name: &'static str) -> *mut u16 {
    static PROVIDER: OnceLock<Box<[u16]>> = OnceLock::new();
    static SERVICE: OnceLock<Box<[u16]>> = OnceLock::new();
    static SUBLAYER: OnceLock<Box<[u16]>> = OnceLock::new();
    static PERSISTENT_BLOCK: OnceLock<Box<[u16]>> = OnceLock::new();
    static BOOT_BLOCK: OnceLock<Box<[u16]>> = OnceLock::new();
    static DYNAMIC_BLOCK: OnceLock<Box<[u16]>> = OnceLock::new();
    static TUNNEL_PERMIT: OnceLock<Box<[u16]>> = OnceLock::new();
    static UNKNOWN: OnceLock<Box<[u16]>> = OnceLock::new();

    let cell = match name {
        "QuantumLink WFP provider" => &PROVIDER,
        PROVIDER_SERVICE_NAME => &SERVICE,
        "QuantumLink kill switch" => &SUBLAYER,
        "QuantumLink persistent block" => &PERSISTENT_BLOCK,
        "QuantumLink boot-time block" => &BOOT_BLOCK,
        "QuantumLink dynamic block" => &DYNAMIC_BLOCK,
        "QuantumLink tunnel permit" => &TUNNEL_PERMIT,
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

fn canonical_v4_cidr(route: &str) -> Result<String, EngineError> {
    let (address, prefix) = parse_v4_cidr(route)?;
    let network = u32::from(address) & prefix_to_mask(prefix);
    Ok(format!("{}/{prefix}", Ipv4Addr::from(network)))
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
        let guard = KillSwitchGuard::engage(&routes, 1)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use quantumlink_proto::models::KillSwitchPolicy;

    #[test]
    fn fail_closed_plan_is_dynamic_and_has_no_permit_without_live_luid() {
        let routes = vec!["100.64.1.7/10".to_string()];
        let plan = build_filter_plan(KillSwitchPolicy::FailClosed, &routes).unwrap();

        assert_eq!(plan.mode, WfpFilterMode::FailClosed);
        assert!(plan.dynamic_session);
        assert!(!plan.persistent_filters);
        assert!(plan.filters.iter().all(|filter| {
            filter.layer == WfpLayer::AleAuthConnectV4
                && filter.action == WfpAction::Block
                && filter.lifetime == WfpFilterLifetime::Dynamic
                && filter.tunnel_luid.is_none()
                && filter.route == "100.64.0.0/10"
        }));
    }

    #[test]
    fn strict_plan_has_distinct_boot_and_persistent_objects_never_combined() {
        let routes = vec!["100.64.0.0/10".to_string()];
        let plan = build_filter_plan(KillSwitchPolicy::Strict, &routes).unwrap();

        assert_eq!(plan.mode, WfpFilterMode::Strict);
        assert!(!plan.dynamic_session);
        assert!(plan.persistent_filters);
        assert!(plan.boot_time_fail_closed);
        assert!(plan.cleanup_required_on_uninstall);
        for layer in [WfpLayer::AleAuthConnectV4, WfpLayer::OutboundIpPacketV4] {
            let layer_filters: Vec<_> = plan.filters.iter().filter(|f| f.layer == layer).collect();
            assert_eq!(layer_filters.len(), 2);
            assert!(layer_filters.iter().any(|filter| {
                filter.action == WfpAction::Block
                    && filter.lifetime.persistent_flag()
                    && !filter.lifetime.boot_time_flag()
            }));
            assert!(layer_filters.iter().any(|filter| {
                filter.action == WfpAction::Block
                    && filter.lifetime.boot_time_flag()
                    && !filter.lifetime.persistent_flag()
            }));
            assert_ne!(
                layer_filters[0].ownership_key,
                layer_filters[1].ownership_key
            );
            let flags: Vec<_> = layer_filters
                .iter()
                .map(|filter| filter.lifetime.management_flags())
                .collect();
            assert!(flags.contains(&1));
            assert!(flags.contains(&2));
            assert!(flags.iter().all(|flags| flags & 3 != 3));
        }
    }

    #[test]
    fn all_strict_objects_are_provider_and_sublayer_owned() {
        let plan = build_filter_plan(KillSwitchPolicy::Strict, &["100.64.0.0/10".into()]).unwrap();
        assert!(plan.filters.iter().all(|filter| {
            filter.provider_key == PROVIDER_KEY_U128 && filter.sublayer_key == SUBLAYER_KEY_U128
        }));
        assert_eq!(PROVIDER_SERVICE_NAME, "QuantumLinkService");
    }

    #[test]
    fn tunnel_permits_exist_only_for_a_live_luid_and_are_always_dynamic() {
        let routes = vec!["100.64.0.0/10".to_string()];
        let without_luid =
            build_filter_plan_for_luid(KillSwitchPolicy::Strict, &routes, None).unwrap();
        assert!(!without_luid
            .filters
            .iter()
            .any(|filter| filter.action == WfpAction::Permit));

        let with_luid =
            build_filter_plan_for_luid(KillSwitchPolicy::Strict, &routes, Some(42)).unwrap();
        let permits: Vec<_> = with_luid
            .filters
            .iter()
            .filter(|filter| filter.action == WfpAction::Permit)
            .collect();
        assert_eq!(permits.len(), 2);
        assert!(permits.iter().all(|filter| {
            filter.lifetime == WfpFilterLifetime::Dynamic && filter.tunnel_luid == Some(42)
        }));
    }

    #[test]
    fn strict_runtime_selects_persistent_boot_time_without_dynamic_fallback() {
        let plan = build_filter_plan(KillSwitchPolicy::Strict, &["100.64.0.0/10".into()]).unwrap();
        assert_eq!(
            runtime_install_for_plan(&plan).unwrap(),
            WfpRuntimeInstall::PersistentBootTime
        );
    }

    #[test]
    fn reconciliation_replaces_only_product_owned_filters_deterministically() {
        let desired =
            build_filter_plan(KillSwitchPolicy::Strict, &["100.64.0.0/10".into()]).unwrap();
        let owned = ExistingWfpFilter {
            ownership_key: 9,
            provider_key: PROVIDER_KEY_U128,
            sublayer_key: SUBLAYER_KEY_U128,
        };
        let foreign_provider = ExistingWfpFilter {
            ownership_key: 2,
            provider_key: 123,
            sublayer_key: SUBLAYER_KEY_U128,
        };
        let foreign_sublayer = ExistingWfpFilter {
            ownership_key: 3,
            provider_key: PROVIDER_KEY_U128,
            sublayer_key: 456,
        };
        let duplicate = owned;

        let plan = build_reconciliation_plan(
            &[foreign_provider, owned, foreign_sublayer, duplicate],
            &desired.filters,
        );
        assert_eq!(plan.delete_keys, vec![9]);
        assert_eq!(plan.add_filters.len(), desired.filters.len());
        assert!(plan
            .add_filters
            .windows(2)
            .all(|pair| pair[0].ownership_key <= pair[1].ownership_key));
    }

    #[test]
    fn stable_keys_are_canonical_idempotent_and_lifetime_specific() {
        let first = build_filter_plan(KillSwitchPolicy::Strict, &["100.64.1.2/10".into()]).unwrap();
        let second =
            build_filter_plan(KillSwitchPolicy::Strict, &["100.64.0.0/10".into()]).unwrap();
        let first_keys: Vec<_> = first
            .filters
            .iter()
            .map(|filter| filter.ownership_key)
            .collect();
        let second_keys: Vec<_> = second
            .filters
            .iter()
            .map(|filter| filter.ownership_key)
            .collect();
        assert_eq!(first_keys, second_keys);
        assert_eq!(
            first_keys
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            first_keys.len()
        );
    }

    #[test]
    fn canonical_equivalent_routes_do_not_duplicate_filter_objects() {
        let plan = build_filter_plan(
            KillSwitchPolicy::Strict,
            &["100.64.0.0/10".into(), "100.64.1.7/10".into()],
        )
        .unwrap();

        assert_eq!(plan.filters.len(), 4);
        assert!(plan
            .filters
            .iter()
            .all(|filter| filter.route == "100.64.0.0/10"));
    }
}
