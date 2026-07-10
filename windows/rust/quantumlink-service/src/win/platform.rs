//! Production [`PlatformNetwork`] implementation tying together Wintun,
//! route/DNS programming, and the WFP kill switch.

use crate::adapter::TunnelAdapter;
use crate::engine::{EngineError, PlatformNetwork};
use crate::win::{routes, wfp::KillSwitchGuard, wintun_adapter::WintunAdapter};
use quantumlink_proto::models::TunnelConfiguration;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct WindowsPlatform {
    kill_switch: Mutex<Option<KillSwitchGuard>>,
    persistent_strict_engaged: Mutex<bool>,
    /// LUID of the adapter created for the active session; needed when
    /// the kill switch is engaged before/after adapter creation.
    adapter_luid: Mutex<Option<u64>>,
}

impl WindowsPlatform {
    pub fn reconcile_startup(&self, config: &TunnelConfiguration) -> Result<(), EngineError> {
        let engaged = crate::win::wfp::reconcile_startup_policy(config)?;
        *self.persistent_strict_engaged.lock().unwrap() = engaged;
        Ok(())
    }
}

impl PlatformNetwork for WindowsPlatform {
    fn create_adapter(
        &self,
        config: &TunnelConfiguration,
    ) -> Result<Arc<dyn TunnelAdapter>, EngineError> {
        let adapter = WintunAdapter::create()?;
        *self.adapter_luid.lock().unwrap() = Some(adapter.luid());

        // The engine engages the kill switch before the adapter exists
        // (fail closed from the very first packet). Now that the LUID is
        // known, re-engage so the permit filter pins to the right
        // interface.
        let mut guard = self.kill_switch.lock().unwrap();
        if let Some(config_routes) = guard.as_ref().map(|g| g.protected_routes().to_vec()) {
            if let Some(current) = guard.as_mut() {
                current.revoke_strict_tunnel_permits();
            }
            *guard = Some(KillSwitchGuard::engage_with_policy(
                &config_routes,
                adapter.luid(),
                config.kill_switch,
            )?);
        }
        Ok(Arc::new(adapter))
    }

    fn apply_network_config(
        &self,
        adapter: &Arc<dyn TunnelAdapter>,
        config: &TunnelConfiguration,
    ) -> Result<(), EngineError> {
        routes::apply(&adapter.name(), config)
    }

    fn engage_kill_switch(&self, config: &TunnelConfiguration) -> Result<(), EngineError> {
        // LUID 0 = "no interface yet": only the block filters are
        // meaningful until create_adapter re-engages with the real LUID.
        let luid = self.adapter_luid.lock().unwrap().unwrap_or(0);
        let guard = KillSwitchGuard::engage_with_policy(
            &config.protected_routes,
            luid,
            config.kill_switch,
        )?;
        *self.persistent_strict_engaged.lock().unwrap() = guard.persists_after_drop();
        *self.kill_switch.lock().unwrap() = Some(guard);
        Ok(())
    }

    fn disengage_kill_switch(&self) -> Result<(), EngineError> {
        let guard = self.kill_switch.lock().unwrap().take();
        if !guard
            .as_ref()
            .is_some_and(KillSwitchGuard::persists_after_drop)
        {
            *self.persistent_strict_engaged.lock().unwrap() = false;
        }
        Ok(())
    }

    fn kill_switch_engaged(&self) -> bool {
        self.kill_switch.lock().unwrap().is_some()
            || *self.persistent_strict_engaged.lock().unwrap()
    }

    fn teardown(
        &self,
        adapter: &Arc<dyn TunnelAdapter>,
        config: &TunnelConfiguration,
    ) -> Result<(), EngineError> {
        let result = routes::remove(&adapter.name(), config);
        if let Some(guard) = self.kill_switch.lock().unwrap().as_mut() {
            guard.revoke_strict_tunnel_permits();
        }
        adapter.shutdown();
        *self.adapter_luid.lock().unwrap() = None;
        result
    }
}
