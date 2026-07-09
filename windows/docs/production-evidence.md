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
  "schemaVersion": 1,
  "evidenceKind": "windowsRendezvousRelayProductionEvidence",
  "product": "QuantumLink Windows",
  "platform": "windows",
  "releaseScope": "windows-x64-production-release",
  "generatedAt": "2026-07-09T00:00:00Z",
  "status": "pass"
}
```

`status` may be `pass`, `blocked`, or `fail`. A well-formed manifest with a
blocked gate remains structurally valid, but production-release verification
still fails because the workflow runs the verifier with `--require-ready`.

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

Each control must include a repo-relative, redacted evidence path and
`redacted: true`. The referenced file must exist in the checked-out repository;
phantom paths keep the release blocked. Duplicate controls, unknown controls,
Windows absolute paths, UNC paths, and parent-directory traversal are rejected.
Evidence files must resolve inside the repository and are limited to 1 MiB each.
Rendezvous endpoints must be HTTPS URLs without embedded credentials, query
strings, or fragments. Relay endpoints must use `turns:` or HTTPS.

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
  windows/validation/rendezvous-relay-production-evidence.json
```

The verifier emits JSON with `valid`, `productionEvidenceReady`,
`rendezvousRelayReady`, `failures`, and `blockers`. Invalid schema or forbidden
secret findings are reported as failures. Missing or explicitly blocked
production evidence is reported as blockers.
