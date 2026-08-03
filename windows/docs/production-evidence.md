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
must contain control-specific results. Every passing assertion must set
`measured: true` and reference a distinct source file with `source` and
`sourceSha256`. `source` must be a safe repo-relative JSON path, and the digest
must match the file's bytes. The verifier resolves and validates source files
independently; a digest string without a source file is not evidence.

Passing source files use this schema:

```json
{
  "schemaVersion": 1,
  "evidenceKind": "windowsRendezvousRelayAssertionSourceEvidence",
  "control": "tls",
  "assertion": "certificate_valid",
  "status": "pass",
  "measured": true,
  "generatedAt": "2026-07-09T00:00:00Z",
  "deploymentId": "<immutable-control-plane-deployment-id>",
  "releaseCommitSha": "<40-or-64-character-release-commit>",
  "releaseRef": "refs/tags/v1.0.0",
  "endpointSetSha256": "<digest-of-the-declared-endpoint-set>",
  "redacted": true
}
```

Each source proof must bind the matching control and assertion plus the exact
deployment, release, and endpoint set. It must be a measured pass, redacted,
no more than seven days old or five minutes in the future, contained in the
repository, and at most 1 MiB. Reusing one source file for multiple assertions
is rejected. Blocked and failed control proofs remain structurally valid with
`measured: false` assertions and do not claim source files.

The required control-specific assertions are:

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

## Evidence Generation

Start from the intentionally blocked deployment contract:

- `windows/deployment/rendezvous-relay-production.template.json`

After deployment, run public-edge evidence from an off-host tester and collect
the Windows measurement bundle:

```sh
scripts/public-edge-live-evidence.sh --env-file ./edge.env --build

ruby windows/scripts/collect-rendezvous-relay-production-measurements.rb \
  --contract windows/deployment/rendezvous-relay-production.json \
  --public-edge-manifest build/public-edge-live-evidence/<run>/manifest.json \
  --output windows/build/validation/rendezvous-relay-production-measurements.json

ruby windows/scripts/plan-rendezvous-relay-operator-sources.rb \
  --contract windows/deployment/rendezvous-relay-production.json \
  --measurements windows/build/validation/rendezvous-relay-production-measurements.json \
  --output windows/build/validation/rendezvous-relay-operator-source-plan.json
```

The collector intentionally maps only assertions directly proved by the
public-edge smoke and verifier fields:

- TLS enabled.
- Authorized traffic accepted.
- Unauthorized rendezvous and relay authentication rejected.
- Rendezvous and relay endpoint request/payload limits enforced.
- Over-quota relay datagrams denied.

It leaves certificate validation and rotation, valid/expired/replayed/malformed
signed-record behavior, revoked peer-record signing keys, identity, source, and
entitlement limits, abuse-log redaction, revocation propagation timing,
entitlement/policy/revoked/expired relay denial, retention, key rotation,
endpoint rotation, and incident shutdown blocked unless separate operator source
files are supplied. Each `--operator-source` must already be a redacted
`windowsRendezvousRelayAssertionSourceEvidence` JSON file bound to the same
deployment id, release commit/ref, and endpoint-set digest.

The operator-source planner writes a blocked plan plus non-production templates
under `windows/build/validation/`. Templates use
`windowsRendezvousRelayOperatorSourceTemplate`, `status: blocked`, and
`measured: false`; they are not accepted by the collector or verifier as
passing evidence. They identify the exact `windows/validation/operator-sources`
path and proof requirement for each remaining assertion. After the operator
replaces the relevant templates with measured, redacted
`windowsRendezvousRelayAssertionSourceEvidence` files, rerun the collector with
one `--operator-source` argument per completed source file.

TLS certificate/rotation, signed-record lifecycle, rate-limit, and relay-denial
source files are generated from a single redacted operator drill report, not by
editing source JSON by hand:

```sh
ruby windows/scripts/generate-rendezvous-relay-operator-sources.rb \
  --contract windows/deployment/rendezvous-relay-production.json \
  --drill-report windows/build/operator-drills/tls-signed-records-limits-denial.json \
  --output-directory windows/validation/operator-sources
```

The drill report must use
`evidenceKind: windowsRendezvousRelayOperatorDrillReport`, `status: pass`,
`redacted: true`, a fresh `generatedAt`, and the same deployment id, release
commit/ref, and endpoint-set digest as the deployment contract. The generator
currently promotes these fourteen assertions only when the report proves each
required field: `tls/certificate_valid`, `tls/rotation_tested`,
`signed_expiring_records/valid_record_accepted`,
`signed_expiring_records/expired_rejected`,
`signed_expiring_records/replay_rejected`,
`signed_expiring_records/malformed_signature_rejected`, and
`signed_expiring_records/revoked_key_rejected`,
`rate_limits/identity_limit_enforced`,
`rate_limits/source_limit_enforced`,
`rate_limits/entitlement_limit_enforced`,
`relay_denial/entitlement_denied`, `relay_denial/policy_denied`,
`relay_denial/revoked_denied`, and `relay_denial/expired_denied`. It rejects
unredacted reports, raw capture/private-key markers, stale reports, endpoint
mismatches, incomplete certificate validation, incomplete rotation proof,
incomplete signed-record negative tests, incomplete rate-limit proofs, and
incomplete relay-denial proofs.

After collecting measurements, run
`windows/scripts/generate-rendezvous-relay-production-evidence.rb`. The
generator writes the manifest, distinct control proofs, digest manifest, and
SHA-256 checksum list, including each source proof used by a passing assertion.
It computes source digests from the referenced files and emits `pass` only when
the deployment and every prerequisite are passing and each required assertion
has schema-valid, release-bound source evidence. User-supplied digest strings
are never sufficient. Missing measurements remain `blocked`; measured failures
remain `fail`.

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
