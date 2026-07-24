//! Allowlisted, reversible action execution.

use qlink_agent_contracts::{ActionResult, Capability, FailureCategory, PlannedAction};
use std::collections::BTreeMap;

pub trait ActionExecutor {
    fn apply(&mut self, action: &PlannedAction) -> ActionResult;
    fn rollback(&mut self, action: &PlannedAction) -> ActionResult;
}

#[derive(Default)]
pub struct MvpActionExecutor {
    states: BTreeMap<String, String>,
    previous: BTreeMap<String, String>,
}

impl MvpActionExecutor {
    pub fn state(&self, target: &str) -> Option<&str> {
        self.states.get(target).map(String::as_str)
    }
}

impl ActionExecutor for MvpActionExecutor {
    fn apply(&mut self, action: &PlannedAction) -> ActionResult {
        let supported = matches!(
            action.capability,
            Capability::RetryCandidateGathering
                | Capability::RotateStalePeerRecord
                | Capability::ClearExpiredDiagnosticCache
        );
        if !supported {
            return ActionResult {
                action_id: action.action_id,
                success: false,
                actual_state: "unchanged".into(),
                failure: Some(FailureCategory::Unknown),
                rollback_status: None,
            };
        }
        let old = self
            .states
            .insert(action.target.clone(), action.expected_state.clone())
            .unwrap_or_else(|| "initial".into());
        self.previous.insert(action.target.clone(), old);
        ActionResult {
            action_id: action.action_id,
            success: true,
            actual_state: action.expected_state.clone(),
            failure: None,
            rollback_status: Some("available".into()),
        }
    }

    fn rollback(&mut self, action: &PlannedAction) -> ActionResult {
        match self.previous.remove(&action.target) {
            Some(old) => {
                self.states.insert(action.target.clone(), old.clone());
                ActionResult {
                    action_id: action.action_id,
                    success: true,
                    actual_state: old,
                    failure: None,
                    rollback_status: Some("completed".into()),
                }
            }
            None => ActionResult {
                action_id: action.action_id,
                success: false,
                actual_state: "unchanged".into(),
                failure: Some(FailureCategory::Unknown),
                rollback_status: Some("not_available".into()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    #[test]
    fn only_allowlisted_actions_apply_and_rollback() {
        let mut executor = MvpActionExecutor::default();
        let mut action = PlannedAction {
            action_id: Uuid::new_v4(),
            capability: Capability::RetryCandidateGathering,
            target: "a".into(),
            parameters: BTreeMap::new(),
            preconditions: vec![],
            expected_state: "retried".into(),
            rollback: "restore".into(),
        };
        assert!(executor.apply(&action).success);
        assert!(executor.rollback(&action).success);
        action.capability = Capability::TrustPeer;
        assert!(!executor.apply(&action).success);
    }
}
