# SteamOS Non-Hardware Production Evidence

This is the machine-readable evidence contract for SteamOS production gates
that do not require physical Steam Deck hardware.

The release verifier reads this manifest from either:

- `QLINK_STEAMOS_PRODUCTION_EVIDENCE_MANIFEST=/path/to/production-evidence-manifest.json`
- `dist/steamos/quantumlink-steamos-<version>/production-evidence-manifest.json`

This manifest can make `nonHardwareProductionReady` true in
`verify-report.json`. It must not make full `productionReady` true by itself;
real Steam Deck validation remains a separate production gate.

## Required Top-Level Fields

```json
{
  "schemaVersion": 1,
  "evidenceKind": "steamosNonHardwareProductionEvidence",
  "product": "QuantumLink SteamOS",
  "platform": "steamos",
  "releaseScope": "steamos-direct-installer",
  "generatedAt": "2026-07-02T00:00:00Z",
  "status": "pass",
  "host": {
    "hardwareClaimed": false,
    "physicalSteamHardwareRequired": false
  }
}
```

`status` may be `pass`, `blocked`, or `fail`. A well-formed manifest with a
blocked gate remains structurally valid, but production-ready verification
still fails when `QLINK_STEAMOS_REQUIRE_PRODUCTION_READY=1`.

## Dytallix Gate

The `dytallix` section proves the public mesh policy without publishing wallet
secrets or raw endpoint material. It must include an HTTPS registry endpoint,
network and contract identifiers, redaction booleans, and these public
`publicDytallixRequired` cases:

| Case | Expected observed decision |
|---|---|
| `active` | `accepted` |
| `missing` | `rejected` |
| `revoked` | `rejected` |
| `suspended` | `rejected` |
| `mismatched` | `rejected` |
| `stale` | `rejected` |
| `unavailable` | `rejected` |

Each case must include a relative redacted evidence path.

## Rendezvous And Relay Gate

The `rendezvousRelay` section proves hardened staging or production endpoint
controls. It must include non-empty secure rendezvous and relay endpoint lists,
redaction booleans, and these passing controls:

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

Each control must include a relative redacted evidence path.

## Secret Boundary

The manifest must not contain private keys, wallet seeds, keystore paths,
entitlement tokens, production endpoint secrets, raw packet payloads, raw game
payloads, raw packet captures, or raw support-bundle archives.

## Verification

Run:

```sh
bash steam/steamos/scripts/verify-production-evidence.sh \
  steam/steamos/validation/production-evidence-manifest.json
```

The standalone verifier emits JSON with `valid`, `productionEvidenceReady`,
`dytallixReady`, `rendezvousRelayReady`, `failures`, and `blockers`. The
release verifier folds that result into `verify-report.json` as
`nonHardwareProductionEvidenceValidated` and `nonHardwareProductionReady`.
