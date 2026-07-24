//! Stable, serialization-only contracts for QuantumLink Agent.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const CONTRACT_VERSION: &str = "v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRequest {
    pub version: String,
    pub request_id: Uuid,
    pub correlation_id: String,
    pub actor: String,
    pub target_workload: String,
    pub intent: String,
    pub requested_capability: Capability,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Inspect,
    Diagnose,
    RetryCandidateGathering,
    RotateStalePeerRecord,
    ClearExpiredDiagnosticCache,
    TrustPeer,
    ChangeRoutePolicy,
    ChangeDnsPolicy,
    ChangeRelayPolicy,
    ExportDiagnostics,
    ClearQuarantine,
    Unknown(String),
}

impl Capability {
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEnvelope {
    pub version: String,
    pub evidence_id: Uuid,
    pub source: String,
    pub collected_at_unix: u64,
    pub expires_at_unix: u64,
    pub sensitivity: Sensitivity,
    pub facts: BTreeMap<String, String>,
}

impl EvidenceEnvelope {
    pub fn is_fresh(&self, now_unix: u64) -> bool {
        self.collected_at_unix <= now_unix && now_unix < self.expires_at_unix
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Internal,
    Redacted,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Recommendation {
    pub version: String,
    pub diagnosis: FailureCategory,
    pub confidence: f32,
    pub explanation: String,
    pub evidence_ids: Vec<Uuid>,
    pub proposed_capability: Capability,
    pub expected_result: String,
    pub alternatives: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCategory {
    Healthy,
    Identity,
    StalePeerRecord,
    Handshake,
    DirectPath,
    RelayPolicy,
    RouteConflict,
    Dns,
    Platform,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    Allow,
    Deny,
    ApprovalRequired,
    Forbidden,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub outcome: PolicyOutcome,
    pub reason_codes: Vec<String>,
    pub policy_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedAction {
    pub action_id: Uuid,
    pub capability: Capability,
    pub target: String,
    pub parameters: BTreeMap<String, String>,
    pub preconditions: Vec<String>,
    pub expected_state: String,
    pub rollback: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionPlan {
    pub version: String,
    pub plan_id: Uuid,
    pub request_id: Uuid,
    pub policy_version: String,
    pub evidence_ids: Vec<Uuid>,
    pub actions: Vec<PlannedAction>,
}

impl ActionPlan {
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(self)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approval_id: Uuid,
    pub approver: String,
    pub plan_id: Uuid,
    pub plan_digest: String,
    pub policy_version: String,
    pub approved_at_unix: u64,
    pub expires_at_unix: u64,
    pub scope: Vec<Capability>,
}

impl ApprovalRecord {
    pub fn authorizes(&self, plan: &ActionPlan, now_unix: u64) -> bool {
        self.plan_id == plan.plan_id
            && self.policy_version == plan.policy_version
            && self.approved_at_unix <= now_unix
            && now_unix < self.expires_at_unix
            && plan.digest().is_ok_and(|digest| digest == self.plan_digest)
            && plan
                .actions
                .iter()
                .all(|action| self.scope.contains(&action.capability))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionResult {
    pub action_id: Uuid,
    pub success: bool,
    pub actual_state: String,
    pub failure: Option<FailureCategory>,
    pub rollback_status: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: Uuid,
    pub timestamp_unix: u64,
    pub actor: String,
    pub request_id: Uuid,
    pub evidence_ids: Vec<Uuid>,
    pub decision: PolicyDecision,
    pub plan_digest: Option<String>,
    pub before_state: String,
    pub after_state: String,
    pub previous_event_hash: Option<String>,
    pub event_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_plan_invalidates_approval() {
        let mut plan = ActionPlan {
            version: CONTRACT_VERSION.into(),
            plan_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            policy_version: "p1".into(),
            evidence_ids: vec![],
            actions: vec![PlannedAction {
                action_id: Uuid::new_v4(),
                capability: Capability::RetryCandidateGathering,
                target: "agent-a".into(),
                parameters: BTreeMap::new(),
                preconditions: vec![],
                expected_state: "connected".into(),
                rollback: "none".into(),
            }],
        };
        let approval = ApprovalRecord {
            approval_id: Uuid::new_v4(),
            approver: "admin".into(),
            plan_id: plan.plan_id,
            plan_digest: plan.digest().unwrap(),
            policy_version: "p1".into(),
            approved_at_unix: 10,
            expires_at_unix: 20,
            scope: vec![Capability::RetryCandidateGathering],
        };
        assert!(approval.authorizes(&plan, 15));
        plan.actions[0].target = "agent-b".into();
        assert!(!approval.authorizes(&plan, 15));
        assert!(!approval.authorizes(&plan, 20));
    }
}
