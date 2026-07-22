# QuantumLink Agent Policy and Permissions

## Policy principle

QuantumLink Agent can assist operators, but it cannot become a hidden authority that weakens mesh security. Every action must be classified, explainable, reversible where possible, and audited.

## Trust-mode floor

The active mesh trust mode sets the minimum allowed identity behavior.

`public-required`: on-chain identity verification is mandatory. Missing, revoked, or expired records fail closed.

`private-preferred`: verified identity is preferred, but explicit private allowlist exceptions can be used.

`development-optional`: identity checks can be bypassed for development, with visible warnings.

The Agent may recommend stronger trust. It may not silently weaken trust.

## Risk tiers

`read_only`: inspect redacted state and produce an explanation.

`recommendation_only`: propose a change but do not apply it.

`low_risk_apply`: apply a reversible cleanup under pre-approved policy.

`approval_required`: require explicit user or admin approval.

`forbidden`: reject the action.

## Approval-required actions

- Trusting a new peer.
- Weakening identity verification.
- Disabling fail-closed routing.
- Allowing relay fallback where relay is policy-blocked.
- Exporting raw diagnostics.
- Revealing unredacted endpoint metadata.
- Changing DNS behavior.
- Switching full-tunnel or split-tunnel defaults.
- Clearing quarantine or revocation state.

## Forbidden actions

- Export private keys.
- Export session keys.
- Publish traffic metadata on-chain.
- Publish DNS contents on-chain.
- Publish private routes on-chain.
- Suppress audit logging.
- Hide a policy downgrade.
- Accept a public-mesh peer with missing required identity.

## Audit event shape

Every applied Agent action should record:

- Timestamp.
- Actor.
- Request source.
- Risk tier.
- Policy before state.
- Policy after state.
- Evidence IDs.
- Approval record, if required.
- Rollback guidance.
