//! Bounded Windows-native runtime probes for security-test evidence.
//!
//! These checks are intentionally non-destructive: they resolve local
//! service assets, round-trip DPAPI with temporary in-memory data, attach
//! WFP filters only in a dynamic session that is immediately dropped, and
//! exercise network-monitor registration lifecycle safety.

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct RuntimeProbeReport {
    pub passed: bool,
    pub checks: Vec<ProbeCheck>,
}

#[derive(Debug, Serialize)]
pub struct ProbeCheck {
    pub name: &'static str,
    pub status: ProbeStatus,
    pub detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Passed,
    Skipped,
    Failed,
}

impl RuntimeProbeReport {
    fn from_checks(checks: Vec<ProbeCheck>) -> Self {
        let passed = checks
            .iter()
            .all(|check| matches!(check.status, ProbeStatus::Passed | ProbeStatus::Skipped));
        Self { passed, checks }
    }
}

pub fn run_runtime_probe() -> RuntimeProbeReport {
    RuntimeProbeReport::from_checks(vec![
        probe_wintun_resolution(),
        probe_dpapi_roundtrip(),
        probe_wfp_dynamic_attach(),
        probe_netmon_restart(),
    ])
}

fn probe_wintun_resolution() -> ProbeCheck {
    match super::wintun_adapter::probe_service_directory_wintun() {
        Ok(path) => ProbeCheck {
            name: "wintun_service_directory_resolution",
            status: ProbeStatus::Passed,
            detail: format!("resolved service-local wintun.dll at {}", path.display()),
        },
        Err(detail) => ProbeCheck {
            name: "wintun_service_directory_resolution",
            status: ProbeStatus::Failed,
            detail,
        },
    }
}

fn probe_dpapi_roundtrip() -> ProbeCheck {
    match super::dpapi::probe_roundtrip() {
        Ok(()) => ProbeCheck {
            name: "dpapi_protect_unprotect_roundtrip",
            status: ProbeStatus::Passed,
            detail: "DPAPI machine-scope protect/unprotect returned the original probe payload"
                .into(),
        },
        Err(error) => ProbeCheck {
            name: "dpapi_protect_unprotect_roundtrip",
            status: ProbeStatus::Failed,
            detail: error.to_string(),
        },
    }
}

fn probe_wfp_dynamic_attach() -> ProbeCheck {
    match super::wfp::probe_dynamic_filter_attach() {
        Ok(()) => ProbeCheck {
            name: "wfp_dynamic_filter_attach_remove",
            status: ProbeStatus::Passed,
            detail:
                "dynamic WFP session accepted test-prefix block/permit filters and closed cleanly"
                    .into(),
        },
        Err(error) if super::wfp::looks_like_admin_required(&error) => ProbeCheck {
            name: "wfp_dynamic_filter_attach_remove",
            status: ProbeStatus::Skipped,
            detail: format!("administrator or LocalSystem rights required: {error}"),
        },
        Err(error) => ProbeCheck {
            name: "wfp_dynamic_filter_attach_remove",
            status: ProbeStatus::Failed,
            detail: error.to_string(),
        },
    }
}

fn probe_netmon_restart() -> ProbeCheck {
    match super::netmon::probe_start_stop_restart() {
        Ok(()) => ProbeCheck {
            name: "netmon_start_stop_restart_callback_safety",
            status: ProbeStatus::Passed,
            detail: "network monitor registered, stopped, restarted, and stopped without panic"
                .into(),
        },
        Err(error) => ProbeCheck {
            name: "netmon_start_stop_restart_callback_safety",
            status: ProbeStatus::Failed,
            detail: error,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_fails_only_failed_checks() {
        let report = RuntimeProbeReport::from_checks(vec![
            ProbeCheck {
                name: "passed",
                status: ProbeStatus::Passed,
                detail: String::new(),
            },
            ProbeCheck {
                name: "skipped",
                status: ProbeStatus::Skipped,
                detail: String::new(),
            },
        ]);
        assert!(report.passed);

        let report = RuntimeProbeReport::from_checks(vec![ProbeCheck {
            name: "failed",
            status: ProbeStatus::Failed,
            detail: String::new(),
        }]);
        assert!(!report.passed);
    }
}
