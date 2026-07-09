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
    /// LUID of the adapter created for the active session; needed when
    /// the kill switch is engaged before/after adapter creation.
    adapter_luid: Mutex<Option<u64>>,
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
        *self.kill_switch.lock().unwrap() = Some(guard);
        Ok(())
    }

    fn disengage_kill_switch(&self) -> Result<(), EngineError> {
        self.kill_switch.lock().unwrap().take();
        Ok(())
    }

    fn kill_switch_engaged(&self) -> bool {
        self.kill_switch.lock().unwrap().is_some()
    }

    fn teardown(
        &self,
        adapter: &Arc<dyn TunnelAdapter>,
        config: &TunnelConfiguration,
    ) -> Result<(), EngineError> {
        let result = routes::remove(&adapter.name(), config);
        adapter.shutdown();
        *self.adapter_luid.lock().unwrap() = None;
        result
    }
}
