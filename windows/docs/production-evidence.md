# Windows Rendezvous And Relay Production Evidence

This is the machine-readable evidence contract for the Windows production
rendezvous and relay gate. It does not make Windows production-ready by itself;
it only proves the control-plane sidecar evidence required by
`windows/docs/production-release-readiness.md`.

The release workflow reads this manifest from the repo-relative path supplied
by `rendezvous_relay_production_evidence_manifest`, defaulting to:

- `windows/validation/rendezvous-relay-production-evidence.json`

## Required Top-Level Fields

```json
{
  "schemaVersion": 2,
  "evidenceKind": "windowsRendezvousRelayProductionEvidence",
  "product": "QuantumLink Windows",
  "platform": "windows",
  "releaseScope": "windows-x64-production-release",
  "generatedAt": "2026-07-09T00:00:00Z",
  "status": "pass",
  "release": {
    "commitSha": "<40-or-64-character-release-commit>",
    "ref": "refs/tags/v1.0.0"
  },
  "deploymentId": "<immutable-control-plane-deployment-id>"
}
```

`status` may be `pass`, `blocked`, or `fail`. A well-formed manifest with a
blocked gate remains structurally valid, but production-release verification
still fails because the workflow runs the verifier with `--require-ready`.
The manifest and every control proof must be no more than seven days old and
no more than five minutes in the future. Production verification binds
`release.commitSha` and `release.ref` to `GITHUB_SHA` and `GITHUB_REF`.

## Rendezvous And Relay Gate

The `rendezvousRelay` section proves hardened endpoint controls. It must
include non-empty secure rendezvous and relay endpoint lists, redaction
booleans, and these passing controls:

- `tls`
- `authentication`
- `signed_expiring_records`
- `rate_limits`
- `abuse_logs`
- `revocation_propagation`
- `relay_denial`
- `retention`
- `key_rotation`
- `endpoint_rotation`
- `incident_shutdown`

Each control must include a distinct repo-relative JSON evidence path, the
file's SHA-256 digest, and `redacted: true`. The referenced file must exist in
the checked-out repository;
phantom paths keep the release blocked. Duplicate controls, unknown controls,
Windows absolute paths, UNC paths, and parent-directory traversal are rejected.
Evidence files must resolve inside the repository and are limited to 1 MiB each.
Rendezvous endpoints must be HTTPS URLs without embedded credentials, query
strings, fragments, or reserved placeholder domains. Relay endpoints must use
`turns:` or HTTPS. `endpointSetSha256` is computed over the sorted endpoint
lists and binds every control proof to the exact deployment endpoint set.

Each control evidence file uses `schemaVersion: 1`,
`evidenceKind: windowsRendezvousRelayControlEvidence`, and repeats the matching
control name, deployment id, release commit/ref, endpoint-set digest,
generation time, passing status, and redaction flag. Its `assertions` array
must contain passing control-specific results:

- TLS: enabled, valid certificate, and tested rotation.
- Authentication: authorized acceptance and unauthorized rejection.
- Signed records: valid acceptance plus expiry, replay, malformed-signature,
  and revoked-key rejection.
- Rate limits: identity, source, endpoint, and entitlement enforcement.
- Abuse logs: decisions recorded with payloads and secrets excluded.
- Revocation: publish, lookup, and relay propagation under 60 seconds.
- Relay denial: entitlement, policy, revocation, expiry, and rate-limit denial.
- Retention: metadata only with packet and game payloads excluded.
- Operations: key rotation, endpoint replacement/drain, and incident shutdown.

## Secret Boundary

The manifest must not contain private keys, wallet seeds, keystore paths,
entitlement tokens, production endpoint secrets, raw packet payloads, raw game
payloads, packet captures, or raw support-bundle archives. Abuse logs must be
redacted, and `rawPacketPayloadsCommitted` plus `rawGamePayloadsCommitted` must
both be false.

## Verification

Run structural validation:

```sh
ruby windows/scripts/verify-rendezvous-relay-production-evidence.rb \
  windows/validation/rendezvous-relay-production-evidence.json
```

Run the production-release gate:

```sh
ruby windows/scripts/verify-rendezvous-relay-production-evidence.rb \
  --require-ready \
  --expected-sha "$(git rev-parse HEAD)" \
  --expected-ref refs/tags/v1.0.0 \
  --report windows/build/validation/rendezvous-relay-production-evidence-verification.json \
  windows/validation/rendezvous-relay-production-evidence.json
```

The verifier emits JSON with `valid`, `productionEvidenceReady`,
`rendezvousRelayReady`, `failures`, and `blockers`. Invalid schema or forbidden
secret findings are reported as failures. Missing or explicitly blocked
production evidence is reported as blockers. For production runs the workflow
copies the verification report, manifest, and each digest-bound control proof
into the checksummed release artifact set.
