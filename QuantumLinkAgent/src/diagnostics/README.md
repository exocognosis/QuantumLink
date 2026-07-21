# Diagnostics

Diagnostics models provide redacted evidence to the Agent runtime.

Initial responsibilities:

- Redact sensitive fields by default.
- Preserve source and freshness labels.
- Represent route, relay, identity, DNS, platform, and cryptographic failure categories.
- Support safe support-bundle export.

Raw packet payloads, private keys, session keys, and raw DNS logs are out of scope.
