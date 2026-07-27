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

The preferred operator flow is to collect redacted case evidence under one
bundle directory and generate the manifest:

```sh
bash steam/steamos/scripts/collect-production-evidence.sh \
  --evidence-root steam/steamos/validation/non-hardware/<timestamp> \
  --output steam/steamos/validation/non-hardware/<timestamp>/production-evidence-manifest.json
```

The bundle root must contain `metadata.json`; referenced evidence files stay
inside the bundle and are hashed into each case as `sha256`. The collector
rejects missing files, parent-directory traversal, private-key markers, wallet
seed markers, entitlement-token markers, raw packet captures, and raw support
bundle archives.

When a shared public-edge live-evidence run already exists, bridge it into the
SteamOS contract instead of copying its claims manually:

```sh
python3 steam/steamos/scripts/bridge-public-edge-evidence.py \
  --public-edge-manifest validation/public-edge/<timestamp>/manifest.json \
  --dytallix-evidence-root validation/dytallix/<timestamp> \
  --output-root steam/steamos/validation/non-hardware/<timestamp>
```

This command documents an operator capability; it does not establish that a
live run exists. The bridge first runs the shared public-edge verifier,
confines referenced files to their evidence roots, rejects secret-like content,
and records source hashes. It can pass TLS, authentication, rate limits,
revocation propagation, and relay denial from the verified relay runs.

The bridge can additionally pass `signed_expiring_records` only when the
public-edge manifest references
`proofs.signedExpiringRecords.evidence`. That versioned, redacted verifier
report must attest ML-DSA-65 verification with the same source revision and
identity, contain record/signature/key hashes rather than raw records, prove a
published record was returned by lookup, prove an older record was absent after
expiry, and prove a higher-sequence replacement was published and returned
before the prior record expired. Missing, malformed, inconsistent, stale, or
privacy-unsafe proof leaves the control blocked or rejects the bridge.

The other controls, including abuse-log samples, retention, key rotation,
endpoint rotation, and incident shutdown, remain blocked until their own live
evidence is provided. Omit the Dytallix root or add `--allow-blocked` only when
intentionally creating a valid but incomplete evidence bundle.
`--allow-blocked` is for gap analysis and must not feed production packaging.

Minimum signed-record lifecycle reference:

```json
{
  "proofs": {
    "signedExpiringRecords": {
      "evidence": "signed-records/lifecycle-verification.json",
      "sha256": "<lowercase SHA-256 of the verifier report>"
    }
  }
}
```

The referenced schema-v1 report uses
`evidenceKind=quantumLinkSignedRecordLifecycleVerification`. It includes a
`qlink-core-peer-record-verifier` section, `publication`, `expiryProbe`, and
`refresh` observations, plus explicit booleans confirming that raw records,
private keys, ICE credentials, and endpoint addresses were not committed.
Every referenced path must remain inside the public-edge run root and must not
traverse a symlink. The bridged sidecar contains only whitelisted assertions
and the source report SHA-256.

Minimum `metadata.json` shape:

```json
{
  "generatedAt": "2026-07-10T00:00:00Z",
  "status": "pass",
  "dytallix": {
    "status": "pass",
    "registryEndpoint": "https://registry.example.invalid",
    "networkId": "dytallix-mainnet-or-staging",
    "contract": "quantumlink-node-registry",
    "walletAddressesRedacted": true,
    "rawWalletMaterialCommitted": false,
    "cases": {
      "active": {"observedDecision": "accepted", "evidence": "dytallix/active.json"},
      "missing": {"observedDecision": "rejected", "evidence": "dytallix/missing.json"},
      "revoked": {"observedDecision": "rejected", "evidence": "dytallix/revoked.json"},
      "suspended": {"observedDecision": "rejected", "evidence": "dytallix/suspended.json"},
      "mismatched": {"observedDecision": "rejected", "evidence": "dytallix/mismatched.json"},
      "stale": {"observedDecision": "rejected", "evidence": "dytallix/stale.json"},
      "unavailable": {"observedDecision": "rejected", "evidence": "dytallix/unavailable.json"}
    }
  },
  "rendezvousRelay": {
    "status": "pass",
    "rendezvousEndpoints": ["https://rv.example.invalid"],
    "relayEndpoints": ["turns:relay.example.invalid:5349"],
    "abuseLogsRedacted": true,
    "rawPacketPayloadsCommitted": false,
    "rawGamePayloadsCommitted": false,
    "controls": {
      "tls": {"status": "pass", "evidence": "rendezvous-relay/tls.txt"},
      "authentication": {"status": "pass", "evidence": "rendezvous-relay/authentication.txt"},
      "signed_expiring_records": {"status": "pass", "evidence": "rendezvous-relay/signed_expiring_records.txt"},
      "rate_limits": {"status": "pass", "evidence": "rendezvous-relay/rate_limits.txt"},
      "abuse_logs": {"status": "pass", "evidence": "rendezvous-relay/abuse_logs.txt"},
      "revocation_propagation": {"status": "pass", "evidence": "rendezvous-relay/revocation_propagation.txt"},
      "relay_denial": {"status": "pass", "evidence": "rendezvous-relay/relay_denial.txt"},
      "retention": {"status": "pass", "evidence": "rendezvous-relay/retention.txt"},
      "key_rotation": {"status": "pass", "evidence": "rendezvous-relay/key_rotation.txt"},
      "endpoint_rotation": {"status": "pass", "evidence": "rendezvous-relay/endpoint_rotation.txt"},
      "incident_shutdown": {"status": "pass", "evidence": "rendezvous-relay/incident_shutdown.txt"}
    }
  }
}
```
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
Collector-generated manifests also include each evidence file SHA-256 digest.

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

For a signed non-hardware RC dry run:

```sh
QLINK_STEAMOS_RELEASE_PRIVATE_KEY=/secure/path/steamos-release-private.pem \
QLINK_STEAMOS_RELEASE_PUBLIC_KEY=/secure/path/steamos-release-public.pem \
bash steam/steamos/scripts/steamos-rc-dry-run.sh \
  --evidence-root steam/steamos/validation/non-hardware/<timestamp>
```

With complete evidence, the dry run must produce a valid signed package with
`nonHardwareProductionReady=true` while still leaving `productionReady=false`
until Steam Deck evidence is linked. A fixture or incomplete bridged bundle
instead remains structurally valid with `productionEvidenceReady=false` and
`nonHardwareProductionReady=false`.

CI runs the same positive path on compatible Linux with ephemeral Ed25519 keys
through `steam/steamos/tests/compatible-linux-signed-rc-proof-test.sh`. That
proof validates release mechanics only; it is not production signing evidence.
