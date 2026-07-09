# Windows Rendezvous And Relay Production Controls

This is the production gate for QuantumLink Windows rendezvous and relay
services. Windows remains blocked until active endpoint evidence is linked from
`windows/docs/production-release-readiness.md` and the sidecar manifest passes
`windows/scripts/verify-rendezvous-relay-production-evidence.rb`.

## Required Controls

- TLS is mandatory for every publish, lookup, relay allocation, control,
  health, and revocation endpoint. Production rendezvous endpoints must use
  HTTPS. Production relay endpoints must use `turns:` or HTTPS.
- Publish and lookup calls require authenticated Dytallix identity, device
  binding, entitlement status, and caller policy context before any record is
  accepted or returned.
- Peer records must be signed by the publishing device, include an issued-at
  time, expire quickly, and be rejected when expired, malformed, replayed, or
  signed by a revoked key.
- Rate limits apply by identity, source address, endpoint, and entitlement
  class using independent burst and sustained limits.
- Abuse logs record identity class, source prefix, endpoint, decision, reason
  code, request id, and timing. Logs must not capture packet payloads, game
  payloads, private keys, wallet stores, entitlement tokens, or raw secret
  material.
- Revocation changes must propagate to publish, lookup, and relay allocation
  decisions in under 60 seconds, including cached records.
- Relay allocation is denied when entitlement checks fail, policy checks fail,
  identity is revoked, the peer record is expired, or the caller exceeds rate
  limits.
- Retention policy stores operational metadata only. Raw packet payloads and
  game payloads are never retained by rendezvous or relay services.
- Operators must be able to rotate service keys, rotate endpoint DNS, drain
  endpoints, revoke signing keys, and shut down publish, lookup, and relay
  allocation during an incident.

## Production Evidence Gate

Before a Windows production release can proceed, the release readiness ledger
must link evidence for the controls below. Endpoint evidence must also be
summarized in `windows/validation/rendezvous-relay-production-evidence.json`
and pass:

```sh
ruby windows/scripts/verify-rendezvous-relay-production-evidence.rb \
  --require-ready \
  windows/validation/rendezvous-relay-production-evidence.json
```

The verifier accepts a blocked manifest as structurally valid when
`--require-ready` is omitted, but production-release mode uses
`--require-ready`, so blocked or missing evidence fails the release gate.

- Active rendezvous and relay endpoint hostnames.
- TLS configuration and certificate rotation procedure.
- Authenticated publish and lookup acceptance/rejection matrix.
- Signed expiring record validation with expiry, replay, malformed signature,
  and revoked-key rejection.
- Token-bucket rate-limit proof by identity, source address, endpoint, and
  entitlement class.
- Abuse log samples showing decision metadata without packet payload capture.
- Revocation propagation evidence showing publish, lookup, and relay decisions
  updated in under 60 seconds.
- Relay allocation denial matrix for entitlement and policy failures.
- Retention configuration showing metadata-only retention and no raw payload
  capture.
- Operator drill evidence for key rotation, endpoint rotation, endpoint drain,
  and incident shutdown.

## Operator Runbook

Key rotation:

1. Publish the new rendezvous/relay verification key to the production trust
   bundle.
2. Deploy services accepting both old and new keys.
3. Move signing to the new key.
4. Wait for the maximum record TTL plus cache TTL.
5. Remove the old key from the trust bundle.
6. Verify old-key records are rejected and new-key records are accepted.

Endpoint rotation:

1. Add the replacement endpoint behind TLS with the same authentication and
   policy gates.
2. Publish endpoint metadata to Windows clients through the signed
   release/update channel.
3. Drain the old endpoint by rejecting new relay allocations while allowing
   existing allocations to expire.
4. Remove DNS for the old endpoint after allocation TTL expiry.
5. Link endpoint rotation evidence from
   `windows/docs/production-release-readiness.md`.

Incident shutdown:

1. Disable publish first to stop new record creation.
2. Disable relay allocation for affected identities, regions, or endpoint
   classes.
3. Push revocations for known compromised identities or service keys.
4. Keep lookup read-only only when it does not expose revoked or stale records.
5. Preserve metadata-only abuse logs for incident review.
6. Re-enable endpoints only after policy, key, and retention checks pass.
