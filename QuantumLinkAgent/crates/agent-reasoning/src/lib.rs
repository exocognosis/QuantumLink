//! Optional reasoning providers. Policy never trusts provider output directly.

use qlink_agent_contracts::{
    AgentRequest, Capability, EvidenceEnvelope, FailureCategory, Recommendation, CONTRACT_VERSION,
};
use qlink_agent_evidence::{classify, redact_text, validate_safe};

pub trait ReasoningProvider: Send + Sync {
    fn recommend(
        &self,
        request: &AgentRequest,
        evidence: &[EvidenceEnvelope],
    ) -> Result<Recommendation, String>;
}

#[derive(Default)]
pub struct DeterministicReasoning;

impl ReasoningProvider for DeterministicReasoning {
    fn recommend(
        &self,
        _request: &AgentRequest,
        evidence: &[EvidenceEnvelope],
    ) -> Result<Recommendation, String> {
        for item in evidence {
            validate_safe(item)?;
        }
        let diagnosis = evidence
            .first()
            .map(classify)
            .unwrap_or(FailureCategory::Unknown);
        let capability = match diagnosis {
            FailureCategory::StalePeerRecord => Capability::RotateStalePeerRecord,
            FailureCategory::DirectPath => Capability::RetryCandidateGathering,
            FailureCategory::Healthy | FailureCategory::Unknown => Capability::Inspect,
            _ => Capability::Diagnose,
        };
        Ok(Recommendation {
            version: CONTRACT_VERSION.into(),
            diagnosis: diagnosis.clone(),
            confidence: if diagnosis == FailureCategory::Unknown {
                0.25
            } else {
                1.0
            },
            explanation: redact_text(&format!("Deterministic diagnosis: {diagnosis:?}")),
            evidence_ids: evidence.iter().map(|item| item.evidence_id).collect(),
            proposed_capability: capability,
            expected_result: "Restore the workload's policy-compliant private path".into(),
            alternatives: vec!["Escalate to an operator without changing policy".into()],
        })
    }
}

/// Boundary for a local model or enterprise-approved API. Implementations must
/// accept only validated, redacted envelopes and return the same typed schema.
pub struct ProviderAdapter<F>(pub F);

impl<F> ReasoningProvider for ProviderAdapter<F>
where
    F: Fn(&AgentRequest, &[EvidenceEnvelope]) -> Result<Recommendation, String> + Send + Sync,
{
    fn recommend(
        &self,
        request: &AgentRequest,
        evidence: &[EvidenceEnvelope],
    ) -> Result<Recommendation, String> {
        for item in evidence {
            validate_safe(item)?;
        }
        (self.0)(request, evidence)
    }
}
