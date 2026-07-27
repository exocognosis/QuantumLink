# Public Beta Hardening Gates

Do not broadly expose public rendezvous or relay services until these gates are
satisfied. Bearer-token admission, per-client IP rate limits, loopback
OpenMetrics service counters, bounded request lines, connection ceilings, idle
timeouts, and relay payload/registration caps are implemented; TLS
control-plane support is implemented behind the explicit `public-edge-tls`
feature. Per-peer relay datagram saturation quotas, starter alert rules, and
journald retention templates are implemented and gated by smoke evidence. Hot
service-token file rotation and digest-file service-token revocation are
implemented. Fresh deployed revocation, rollback, alerting, and retention
evidence remain release gates.

## Rendezvous

- Require non-placeholder admission tokens for publication and lookup paths.
- Keep revoked service-token digest files configured and prove rejected
  revoked-token counters in every public evidence run.
- Enforce per-source and per-mesh rate limits beyond the current per-client IP
  window.
- Extend record-specific bounds for endpoint count and per-mesh publication
  volume beyond the current request-line and connection ceilings.
- Add structured audit logs with redacted peer identifiers.
- Add expiry-pruning counters and connect the service metrics to the operator
  alerting pipeline.
- Run malformed-input, connection-churn, and record-flood stress after every change.

## Relay

- Require non-placeholder admission tokens for peer registration.
- Keep revoked service-token digest files configured and prove revoked-token
  registration/traffic rejection counters in every public evidence run.
- Keep per-peer send-rate saturation quotas enabled and prove
  `relay_peer_rate_limited_total` in every public evidence run.
- Protect against peer ID squatting and duplicate registration abuse.
- Extend backpressure metrics if the relay moves from synchronous delivery to
  queued datagram delivery.
- Run relay-fallback stress with intentionally unreachable direct candidates.

## Release Gate

- Private LAN harness passes at 10, 25, and 50 peers.
- Resource sampling shows no unbounded CPU, memory, file descriptor, or socket growth.
- Expired peer records and stale certificate rotation tests pass.
- Public services run behind firewall rules that expose only intended ports.
- Off-host `scripts/public-edge-live-evidence.sh` produces a passing
  `manifest.json` with both app-relay and resident TURN relay proofs plus
  metrics-scrape proof for auth, revoked-token rejection, bounds, payload, and
  peer-saturation counters.
- `scripts/verify-public-infra-evidence.rb --require-public` rejects local,
  placeholder, stale, unauthenticated, non-TLS, no-rate-limit, no-revocation,
  and no-rollback evidence.
- Public-edge alert rules and `journald@quantumlink` retention are installed on
  the deployed host or replaced with an equivalent operator-controlled path.
- Incident rollback path is documented and tested.
