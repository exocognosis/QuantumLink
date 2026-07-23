//! Deterministic policy enforcement. No model output can bypass this layer.

use qlink_agent_contracts::{Capability, PolicyDecision, PolicyOutcome};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentPolicy {
    pub version: String,
    pub allow_relay_fallback: bool,
    pub allow_raw_diagnostics_export: bool,
    pub preapproved_low_risk_actions: bool,
}

impl Default for AgentPolicy {
    fn default() -> Self {
        Self {
            version: "mvp-v1".into(),
            allow_relay_fallback: true,
            allow_raw_diagnostics_export: false,
            preapproved_low_risk_actions: false,
        }
    }
}

impl AgentPolicy {
    pub fn evaluate(&self, capability: &Capability) -> PolicyDecision {
        let (outcome, code) = match capability {
            Capability::Unknown(_) => (PolicyOutcome::Forbidden, "unknown_action_type"),
            Capability::Inspect | Capability::Diagnose => (PolicyOutcome::Allow, "read_only"),
            Capability::RetryCandidateGathering
            | Capability::RotateStalePeerRecord
            | Capability::ClearExpiredDiagnosticCache
                if self.preapproved_low_risk_actions =>
            {
                (PolicyOutcome::Allow, "preapproved_low_risk")
            }
            Capability::RetryCandidateGathering
            | Capability::RotateStalePeerRecord
            | Capability::ClearExpiredDiagnosticCache => (
                PolicyOutcome::ApprovalRequired,
                "low_risk_requires_approval",
            ),
            Capability::ExportDiagnostics if self.allow_raw_diagnostics_export => {
                (PolicyOutcome::ApprovalRequired, "sensitive_export")
            }
            Capability::ExportDiagnostics => (PolicyOutcome::Forbidden, "raw_export_disabled"),
            Capability::ChangeRelayPolicy if !self.allow_relay_fallback => {
                (PolicyOutcome::Forbidden, "relay_forbidden_by_policy")
            }
            Capability::TrustPeer
            | Capability::ChangeRoutePolicy
            | Capability::ChangeDnsPolicy
            | Capability::ChangeRelayPolicy
            | Capability::ClearQuarantine => (PolicyOutcome::ApprovalRequired, "high_risk_change"),
        };
        PolicyDecision {
            outcome,
            reason_codes: vec![code.into()],
            policy_version: self.version.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_disabled_exports_fail_closed() {
        let policy = AgentPolicy::default();
        assert_eq!(
            policy
                .evaluate(&Capability::Unknown("shell".into()))
                .outcome,
            PolicyOutcome::Forbidden
        );
        assert_eq!(
            policy.evaluate(&Capability::ExportDiagnostics).outcome,
            PolicyOutcome::Forbidden
        );
    }

    #[test]
    fn mutations_are_not_silently_allowed() {
        let policy = AgentPolicy::default();
        assert_eq!(
            policy.evaluate(&Capability::TrustPeer).outcome,
            PolicyOutcome::ApprovalRequired
        );
        assert_eq!(
            policy
                .evaluate(&Capability::RetryCandidateGathering)
                .outcome,
            PolicyOutcome::ApprovalRequired
        );
    }
}
