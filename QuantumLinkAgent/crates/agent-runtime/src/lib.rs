//! QuantumLink Agent orchestration. Every mutation is re-authorized at execution time.

use qlink_agent_actions::ActionExecutor;
use qlink_agent_audit::AuditLog;
use qlink_agent_contracts::{
    ActionPlan, ActionResult, AgentRequest, ApprovalRecord, AuditEvent, EvidenceEnvelope,
    PlannedAction, PolicyDecision, PolicyOutcome, Recommendation, CONTRACT_VERSION,
};
use qlink_agent_evidence::validate_safe;
use qlink_agent_policy::AgentPolicy;
use qlink_agent_reasoning::ReasoningProvider;
use std::collections::BTreeMap;
use uuid::Uuid;

pub struct AgentRuntime<R, A> {
    policy: AgentPolicy,
    reasoning: R,
    executor: A,
    audit: AuditLog,
}

impl<R: ReasoningProvider, A: ActionExecutor> AgentRuntime<R, A> {
    pub fn new(policy: AgentPolicy, reasoning: R, executor: A, audit: AuditLog) -> Self {
        Self {
            policy,
            reasoning,
            executor,
            audit,
        }
    }

    pub fn diagnose(
        &self,
        request: &AgentRequest,
        evidence: &[EvidenceEnvelope],
        now_unix: u64,
    ) -> Result<Recommendation, String> {
        ensure_version(&request.version)?;
        if evidence.is_empty() {
            return Err("diagnosis requires evidence".into());
        }
        for item in evidence {
            ensure_version(&item.version)?;
            if !item.is_fresh(now_unix) {
                return Err(format!("stale evidence: {}", item.evidence_id));
            }
            validate_safe(item)?;
        }
        self.reasoning.recommend(request, evidence)
    }

    pub fn plan(
        &self,
        request: &AgentRequest,
        recommendation: &Recommendation,
    ) -> Result<(ActionPlan, PolicyDecision), String> {
        ensure_version(&request.version)?;
        ensure_version(&recommendation.version)?;
        if !recommendation.proposed_capability.is_known() {
            return Err("unknown action type".into());
        }
        let decision = self.policy.evaluate(&recommendation.proposed_capability);
        let action = PlannedAction {
            action_id: Uuid::new_v4(),
            capability: recommendation.proposed_capability.clone(),
            target: request.target_workload.clone(),
            parameters: BTreeMap::new(),
            preconditions: vec![
                "evidence remains fresh".into(),
                "policy version remains unchanged".into(),
            ],
            expected_state: recommendation.expected_result.clone(),
            rollback: "Restore the captured pre-action state".into(),
        };
        Ok((
            ActionPlan {
                version: CONTRACT_VERSION.into(),
                plan_id: Uuid::new_v4(),
                request_id: request.request_id,
                policy_version: self.policy.version.clone(),
                evidence_ids: recommendation.evidence_ids.clone(),
                actions: vec![action],
            },
            decision,
        ))
    }

    pub fn apply(
        &mut self,
        request: &AgentRequest,
        plan: &ActionPlan,
        approval: Option<&ApprovalRecord>,
        now_unix: u64,
    ) -> Result<Vec<ActionResult>, String> {
        ensure_version(&plan.version)?;
        if plan.request_id != request.request_id {
            return Err("plan request mismatch".into());
        }
        if plan.policy_version != self.policy.version {
            return Err("policy version mismatch".into());
        }

        let decisions: Vec<_> = plan
            .actions
            .iter()
            .map(|action| self.policy.evaluate(&action.capability))
            .collect();
        if decisions.iter().any(|decision| {
            matches!(
                decision.outcome,
                PolicyOutcome::Deny | PolicyOutcome::Forbidden
            )
        }) {
            return Err("policy denied action plan".into());
        }
        if decisions
            .iter()
            .any(|decision| decision.outcome == PolicyOutcome::ApprovalRequired)
            && !approval.is_some_and(|record| record.authorizes(plan, now_unix))
        {
            return Err("valid approval required".into());
        }

        let mut results = Vec::with_capacity(plan.actions.len());
        for (action, decision) in plan.actions.iter().zip(decisions) {
            let before = "captured-before-state".to_string();
            let result = self.executor.apply(action);
            self.audit.append(AuditEvent {
                event_id: Uuid::new_v4(),
                timestamp_unix: now_unix,
                actor: request.actor.clone(),
                request_id: request.request_id,
                evidence_ids: plan.evidence_ids.clone(),
                decision,
                plan_digest: Some(plan.digest().map_err(|error| error.to_string())?),
                before_state: before,
                after_state: result.actual_state.clone(),
                previous_event_hash: None,
                event_hash: String::new(),
            })?;
            results.push(result);
        }
        Ok(results)
    }

    pub fn rollback(
        &mut self,
        request: &AgentRequest,
        plan: &ActionPlan,
        now_unix: u64,
    ) -> Result<Vec<ActionResult>, String> {
        let mut results = Vec::with_capacity(plan.actions.len());
        for action in plan.actions.iter().rev() {
            let result = self.executor.rollback(action);
            self.audit.append(AuditEvent {
                event_id: Uuid::new_v4(),
                timestamp_unix: now_unix,
                actor: request.actor.clone(),
                request_id: request.request_id,
                evidence_ids: plan.evidence_ids.clone(),
                decision: self.policy.evaluate(&action.capability),
                plan_digest: Some(plan.digest().map_err(|error| error.to_string())?),
                before_state: "applied".into(),
                after_state: result.actual_state.clone(),
                previous_event_hash: None,
                event_hash: String::new(),
            })?;
            results.push(result);
        }
        Ok(results)
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }
}

fn ensure_version(version: &str) -> Result<(), String> {
    if version == CONTRACT_VERSION {
        Ok(())
    } else {
        Err(format!("unsupported contract version: {version}"))
    }
}

pub fn approval_for(
    plan: &ActionPlan,
    approver: impl Into<String>,
    now_unix: u64,
    ttl_seconds: u64,
) -> Result<ApprovalRecord, String> {
    Ok(ApprovalRecord {
        approval_id: Uuid::new_v4(),
        approver: approver.into(),
        plan_id: plan.plan_id,
        plan_digest: plan.digest().map_err(|error| error.to_string())?,
        policy_version: plan.policy_version.clone(),
        approved_at_unix: now_unix,
        expires_at_unix: now_unix.saturating_add(ttl_seconds),
        scope: plan
            .actions
            .iter()
            .map(|action| action.capability.clone())
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlink_agent_actions::MvpActionExecutor;
    use qlink_agent_contracts::{Capability, FailureCategory, Sensitivity};
    use qlink_agent_reasoning::DeterministicReasoning;
    use tempfile::tempdir;

    fn fixture() -> (AgentRequest, EvidenceEnvelope) {
        let request = AgentRequest {
            version: CONTRACT_VERSION.into(),
            request_id: Uuid::new_v4(),
            correlation_id: "c1".into(),
            actor: "operator".into(),
            target_workload: "agent-a".into(),
            intent: "repair connectivity".into(),
            requested_capability: Capability::Diagnose,
        };
        let evidence = EvidenceEnvelope {
            version: CONTRACT_VERSION.into(),
            evidence_id: Uuid::new_v4(),
            source: "qlink-core".into(),
            collected_at_unix: 10,
            expires_at_unix: 20,
            sensitivity: Sensitivity::Redacted,
            facts: [("peer_record_status".into(), "stale".into())].into(),
        };
        (request, evidence)
    }

    #[test]
    fn model_free_workflow_requires_bound_approval_and_audits_rollback() {
        let dir = tempdir().unwrap();
        let mut runtime = AgentRuntime::new(
            AgentPolicy::default(),
            DeterministicReasoning,
            MvpActionExecutor::default(),
            AuditLog::new(dir.path().join("audit.jsonl")),
        );
        let (request, evidence) = fixture();
        let recommendation = runtime.diagnose(&request, &[evidence], 15).unwrap();
        assert_eq!(recommendation.diagnosis, FailureCategory::StalePeerRecord);
        let (plan, decision) = runtime.plan(&request, &recommendation).unwrap();
        assert_eq!(decision.outcome, PolicyOutcome::ApprovalRequired);
        assert!(runtime.apply(&request, &plan, None, 15).is_err());
        let approval = approval_for(&plan, "admin", 15, 10).unwrap();
        assert!(runtime.apply(&request, &plan, Some(&approval), 16).unwrap()[0].success);
        assert!(runtime.rollback(&request, &plan, 17).unwrap()[0].success);
        assert!(runtime.audit().verify().unwrap());
        assert_eq!(runtime.audit().read_all().unwrap().len(), 2);
    }

    #[test]
    fn stale_evidence_and_expired_approval_fail_closed() {
        let dir = tempdir().unwrap();
        let mut runtime = AgentRuntime::new(
            AgentPolicy::default(),
            DeterministicReasoning,
            MvpActionExecutor::default(),
            AuditLog::new(dir.path().join("audit.jsonl")),
        );
        let (request, evidence) = fixture();
        assert!(runtime.diagnose(&request, &[evidence.clone()], 20).is_err());
        let recommendation = runtime.diagnose(&request, &[evidence], 15).unwrap();
        let (plan, _) = runtime.plan(&request, &recommendation).unwrap();
        let approval = approval_for(&plan, "admin", 15, 1).unwrap();
        assert!(runtime.apply(&request, &plan, Some(&approval), 16).is_err());
    }
}
