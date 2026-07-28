# SteamOS Non-Hardware Production Evidence

This is the machine-readable evidence contract for SteamOS production gates
that do not require physical Steam Deck hardware.

The release verifier reads this manifest from either:

- `QLINK_STEAMOS_PRODUCTION_EVIDENCE_MANIFEST=/path/to/production-evidence-manifest.json`
- `dist/steamos/quantumlink-steamos-<version>/production-evidence-manifest.json`

Only a schema-v2 manifest that satisfies every requirement in this document is
eligible to make `nonHardwareProductionReady` true in `verify-report.json`. It
must not make full `productionReady` true by itself; real Steam Deck validation
remains a separate production gate.

## Schema Compatibility And Readiness

- Schema v1 is historical. Collectors and verifiers may continue to parse it so
  prior evidence can be inspected, but it is always production-blocked.
- A schema-v1 manifest must produce `productionEvidenceReady=false` and
  `nonHardwareProductionReady=false`, regardless of its recorded `status`.
- Schema v1 must not be automatically promoted, inferred, or relabeled as
  schema v2.
- Schema v2 is the only production-eligible evidence contract.
- Fixture, synthetic, loopback, or local-only evidence remains useful for
  contract testing but cannot satisfy a schema-v2 `liveChain` gate.

The collector, bridge, and verifier enforce this schema-v2 contract. SteamOS
remains No-Go until qualifying live evidence is linked and independently
verified.

## Required Top-Level Fields

```json
{
  "schemaVersion": 2,
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
still fails when `QLINK_STEAMOS_REQUIRE_PRODUCTION_READY=1`. Top-level `pass`
is valid only when both the Dytallix and rendezvous/relay gates pass.

## Dytallix Gate

The `dytallix` section proves the public mesh policy without publishing wallet
secrets or raw endpoint material. Schema v2 requires:

- `bindingVersion` exactly `stableIdentityV2`.
- `contractSchemaVersion` exactly `2`.
- `evidenceClass` exactly `liveChain`.
- An HTTPS registry endpoint.
- Non-empty network ID and chain ID pins.
- A non-empty deployed contract address.
- The deployed contract code SHA-256 pin.
- Independently verified finalized-chain inclusion for every lifecycle
  transaction and the associated exact contract readback.

The independently finalized checkpoint height must be at or above every
lifecycle and TTL-refresh transaction height. The finality sidecar must
inventory those transaction IDs, heights, and finalized block hashes.
That report must be signed with ECDSA P-256/SHA-256 by the independent
finality verifier. Verification uses the trusted public key configured outside
the evidence bundle through
`QLINK_DYTALLIX_FINALITY_VERIFIER_PUBLIC_KEY`; a key supplied only by the
bundle is not a trust anchor.
For each finalized transaction, the signed report binds the transaction ID and
block to its lifecycle case, observed outcome, stable identity revision, exact
readback status, and readback digest. TTL refresh entries bind both revisions.

An SDK mutation receipt, transaction confirmation, or exact readback proves
submission and convergence only. It is not finalized-chain evidence. In
particular, the current pinned SDK's receipt/readback result and finalized-block
metadata must not be used to assert finality. Finality must be captured and
verified independently against the pinned chain and transaction.

### Required Lifecycle Matrix

All lifecycle observations must use the same pinned network, chain, deployed
contract, stable peer identity, and authorized wallet/device relationship.

| Case | Required result |
|---|---|
| `register` | Finalized transaction; exact active v2 binding readback |
| `update` | Finalized transaction; monotonic identity revision and exact readback |
| `suspend` | Finalized transaction; exact suspended readback and trust rejection |
| `reactivate` | Finalized transaction; exact active readback and restored trust |
| `revoke` | Finalized transaction; exact terminal revoked readback and trust rejection |
| `post_revocation_reactivation` | Reactivation transaction rejected; revoked state unchanged |
| `ttlRefresh` | Refreshed reachability record accepted while stable identity revision is unchanged |

The TTL refresh may advance the signed reachability-record sequence, but it
must preserve the stable Dytallix identity revision. A refresh implemented as
an identity mutation fails this control.

### Required Negative Policy Matrix

Each negative case must record the expected rejection, the observed rejection,
the pinned policy inputs, and a mandatory sidecar reference:

| Case | Required result |
|---|---|
| `legacy_v1_downgrade` | Reject any attempt to use or silently fall back to v1 |
| `expired_authorization` | Reject an expired wallet/device authorization |
| `device_mismatch` | Reject a binding for a different device |
| `signing_key_mismatch` | Reject a peer record signed by an unbound key |
| `wrong_mesh_scope` | Reject a binding outside the authorized mesh scope |
| `ttl_excess` | Reject a peer-record TTL above the binding policy |
| `non_monotonic_revision` | Reject an equal or lower identity revision |
| `missing` | Reject a peer absent from the registry |
| `suspended` | Reject a suspended identity |
| `revoked` | Reject a terminally revoked identity |
| `registry_outage` | Fail closed when the pinned registry is unavailable |

Aliases or collapsed cases are not sufficient. Every matrix row must have its
own observation and evidence sidecar.

The preferred operator flow is to collect redacted case evidence under one
bundle directory and generate the manifest:

```sh
bash steam/steamos/scripts/collect-production-evidence.sh \
  --evidence-root steam/steamos/validation/non-hardware/<timestamp> \
  --output steam/steamos/validation/non-hardware/<timestamp>/production-evidence-manifest.json
```

The bundle root must contain `metadata.json`. Every lifecycle case, negative
case, finality proof, readback, and rendezvous/relay control must reference a
mandatory redacted sidecar using a normalized relative path and lowercase
SHA-256 digest.

The collector stages referenced files beside the generated manifest under
`production-evidence/`. The verifier resolves each path relative to the
manifest directory, rejects absolute paths, parent-directory traversal,
symlinks, and any resolved path outside that root, requires the sidecar to
exist as a regular file, calculates
its SHA-256, and require an exact digest match. A recorded digest without a
contained file is not evidence. Missing, substituted, escaped, symlinked, or
digest-mismatched sidecars fail the manifest.

Dytallix sidecars are JSON evidence records, not opaque attachments. Their
chain and contract pins, transaction IDs, finalized heights, lifecycle
outcomes, readback states, identity revisions, and policy decisions must match
the corresponding manifest assertions. A matching digest over unrelated
content does not satisfy the gate.

Collectors and verifiers must also reject private-key markers, wallet seed
markers, entitlement-token markers, raw packet captures, and raw support bundle
archives.

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

Minimum schema-v2 `metadata.json` shape:

```json
{
  "schemaVersion": 2,
  "generatedAt": "2026-07-10T00:00:00Z",
  "status": "pass",
  "dytallix": {
    "status": "pass",
    "bindingVersion": "stableIdentityV2",
    "contractSchemaVersion": 2,
    "evidenceClass": "liveChain",
    "registryEndpoint": "https://registry.example.invalid",
    "networkId": "dytallix-production",
    "chainId": "<pinned chain ID>",
    "contractAddress": "<20-byte hexadecimal deployed address>",
    "contractCodeHash": "<lowercase deployed-code hash>",
    "walletAddressesRedacted": true,
    "rawWalletMaterialCommitted": false,
    "finality": {
      "independentlyVerified": true,
      "verificationMethod": "independentFinalizedBlock",
      "finalizedBlockHeight": 12345,
      "finalizedBlockHash": "<64-character lowercase block hash>",
      "sdkReceiptOnly": false,
      "evidence": "dytallix/finality.json",
      "verifierSignature": {
        "algorithm": "ecdsa-p256-sha256",
        "publicKey": "dytallix/finality-verifier-public.pem",
        "signature": "dytallix/finality.sig"
      }
    },
    "lifecycle": {
      "register": {"observedOutcome": "accepted", "transactionId": "<tx>", "finalized": true, "finalizedBlockHeight": 12346, "stableIdentityRevision": 1, "evidence": "dytallix/lifecycle/register.json"},
      "update": {"observedOutcome": "accepted", "transactionId": "<tx>", "finalized": true, "finalizedBlockHeight": 12347, "stableIdentityRevision": 2, "evidence": "dytallix/lifecycle/update.json"},
      "suspend": {"observedOutcome": "accepted", "transactionId": "<tx>", "finalized": true, "finalizedBlockHeight": 12348, "stableIdentityRevision": 3, "evidence": "dytallix/lifecycle/suspend.json"},
      "reactivate": {"observedOutcome": "accepted", "transactionId": "<tx>", "finalized": true, "finalizedBlockHeight": 12349, "stableIdentityRevision": 4, "evidence": "dytallix/lifecycle/reactivate.json"},
      "revoke": {"observedOutcome": "accepted", "transactionId": "<tx>", "finalized": true, "finalizedBlockHeight": 12350, "stableIdentityRevision": 5, "evidence": "dytallix/lifecycle/revoke.json"},
      "post_revocation_reactivation": {"observedOutcome": "rejected", "transactionId": "<tx>", "finalized": true, "finalizedBlockHeight": 12351, "stableIdentityRevision": 5, "evidence": "dytallix/lifecycle/post-revocation-reactivation.json"}
    },
    "negativePolicies": {
      "legacy_v1_downgrade": {"observedDecision": "rejected", "evidence": "dytallix/negative/legacy-v1-downgrade.json"},
      "expired_authorization": {"observedDecision": "rejected", "evidence": "dytallix/negative/expired-authorization.json"},
      "device_mismatch": {"observedDecision": "rejected", "evidence": "dytallix/negative/device-mismatch.json"},
      "signing_key_mismatch": {"observedDecision": "rejected", "evidence": "dytallix/negative/signing-key-mismatch.json"},
      "wrong_mesh_scope": {"observedDecision": "rejected", "evidence": "dytallix/negative/wrong-mesh-scope.json"},
      "ttl_excess": {"observedDecision": "rejected", "evidence": "dytallix/negative/ttl-excess.json"},
      "non_monotonic_revision": {"observedDecision": "rejected", "evidence": "dytallix/negative/non-monotonic-revision.json"},
      "missing": {"observedDecision": "rejected", "evidence": "dytallix/negative/missing.json"},
      "suspended": {"observedDecision": "rejected", "evidence": "dytallix/negative/suspended.json"},
      "revoked": {"observedDecision": "rejected", "evidence": "dytallix/negative/revoked.json"},
      "registry_outage": {"observedDecision": "rejected", "evidence": "dytallix/negative/registry-outage.json"}
    },
    "ttlRefresh": {
      "observedOutcome": "accepted",
      "transactionId": "<tx>",
      "finalized": true,
      "finalizedBlockHeight": 12352,
      "stableIdentityRevisionBefore": 5,
      "stableIdentityRevisionAfter": 5,
      "evidence": "dytallix/ttl-refresh.json"
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

Each control must include a relative redacted evidence path and matching
lowercase SHA-256 digest. The mandatory containment and digest rules apply to
these sidecars exactly as they apply to Dytallix evidence.

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
The verifier enforces schema v2, independently verified finality, the complete
lifecycle and negative-policy matrices, and contained sidecar digest matching.
Schema-v1 output remains parseable but is never production-eligible.

For a signed non-hardware RC dry run:

```sh
QLINK_STEAMOS_RELEASE_PRIVATE_KEY=/secure/path/steamos-release-private.pem \
QLINK_STEAMOS_RELEASE_PUBLIC_KEY=/secure/path/steamos-release-public.pem \
bash steam/steamos/scripts/steamos-rc-dry-run.sh \
  --evidence-root steam/steamos/validation/non-hardware/<timestamp>
```

With complete schema-v2 live evidence, the dry run must produce a valid signed package with
`nonHardwareProductionReady=true` while still leaving `productionReady=false`
until Steam Deck evidence is linked. A schema-v1, fixture, synthetic,
non-finalized, or incomplete bridged bundle instead remains production-blocked
with `productionEvidenceReady=false` and
`nonHardwareProductionReady=false`.

CI runs the same positive path on compatible Linux with ephemeral Ed25519 keys
through `steam/steamos/tests/compatible-linux-signed-rc-proof-test.sh`. That
proof validates release mechanics only; it is not production signing evidence.
