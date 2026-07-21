# Policy Engine

The policy engine evaluates whether an Agent recommendation can be applied.

Initial responsibilities:

- Enforce trust-mode floors.
- Classify action risk.
- Require approval for high-risk changes.
- Reject forbidden actions.
- Generate reversible policy patches.

Policy enforcement should be deterministic and testable without invoking a language model.
