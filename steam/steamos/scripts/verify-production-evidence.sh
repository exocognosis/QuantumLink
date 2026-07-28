#!/usr/bin/env bash
set -euo pipefail

MANIFEST="${1:-}"

if [ -z "$MANIFEST" ]; then
    echo "usage: $0 steam/steamos/validation/production-evidence.json" >&2
    exit 2
fi

python3 - "$MANIFEST" <<'PY'
import json
import hashlib
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

manifest_path = Path(sys.argv[1])
failures: list[str] = []
warnings: list[str] = []
blockers: list[str] = []


def fail(message: str) -> None:
    failures.append(message)


def block(message: str) -> None:
    blockers.append(message)


def is_nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def is_relative_evidence_path(value: object) -> bool:
    if not is_nonempty_string(value):
        return False
    path = Path(str(value))
    return not path.is_absolute() and ".." not in path.parts


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def verify_evidence_file(
    entry: dict,
    label: str,
    *,
    required_digest: bool,
    require_json: bool = False,
) -> dict | None:
    evidence = entry.get("evidence")
    if not is_relative_evidence_path(evidence):
        fail(f"{label} evidence must be a relative path")
        return None
    digest = entry.get("sha256")
    if required_digest and not is_sha256(digest):
        fail(f"{label} sha256 is required and must be a 64-character lowercase hex digest")
        return None
    if digest is not None and not is_sha256(digest):
        fail(f"{label} sha256 must be a 64-character lowercase hex digest")
        return None
    rel = Path(str(evidence))
    root = manifest_path.parent.resolve()
    cursor = manifest_path.parent
    for part in rel.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            fail(f"{label} evidence must not traverse symbolic links")
            return None
    path = (manifest_path.parent / rel).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        fail(f"{label} evidence escapes the manifest directory")
        return None
    if not path.is_file():
        fail(f"{label} evidence file is missing: {evidence}")
        return None
    raw = path.read_bytes()
    if forbidden.search(str(rel)) or forbidden.search(raw.decode("utf-8", errors="ignore")):
        fail(f"{label} evidence contains a forbidden secret or raw-artifact marker")
    if is_sha256(digest) and hashlib.sha256(raw).hexdigest() != digest:
        fail(f"{label} sha256 does not match evidence file: {evidence}")
        return None
    if not require_json:
        return None
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        fail(f"{label} evidence must be valid JSON: {error}")
        return None
    if not isinstance(document, dict):
        fail(f"{label} evidence must be a JSON object")
        return None
    return document


def verify_auxiliary_file(
    entry: dict,
    path_field: str,
    digest_field: str,
    label: str,
) -> Path | None:
    reference = entry.get(path_field)
    digest = entry.get(digest_field)
    if not is_relative_evidence_path(reference):
        fail(f"{label} must be a relative path")
        return None
    if not is_sha256(digest):
        fail(f"{label} sha256 is required and must be a lowercase SHA-256 digest")
        return None
    rel = Path(str(reference))
    root = manifest_path.parent.resolve()
    cursor = manifest_path.parent
    for part in rel.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            fail(f"{label} must not traverse symbolic links")
            return None
    path = (manifest_path.parent / rel).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        fail(f"{label} escapes the manifest directory")
        return None
    if not path.is_file():
        fail(f"{label} file is missing: {reference}")
        return None
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        fail(f"{label} sha256 does not match: {reference}")
        return None
    return path


def endpoint_has_secure_scheme(value: str, allowed: set[str]) -> bool:
    parsed = urlparse(value)
    if parsed.scheme not in allowed:
        return False
    if parsed.scheme == "turns":
        return bool(parsed.netloc or parsed.path)
    return bool(parsed.netloc)


raw_text = ""
manifest: object = {}
if not manifest_path.is_file():
    fail(f"production evidence manifest is missing: {manifest_path}")
else:
    raw_text = manifest_path.read_text(encoding="utf-8", errors="ignore")
    forbidden = re.compile(
        r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|"
        r"WALLET_SEED|ENTITLEMENT_TOKEN|DYTALLIX_WALLET_SECRET|"
        r"QLINK_PRODUCTION_ENDPOINT_SECRET|STEAMOS_RELEASE_PRIVATE_KEY|"
        r"\.pcapng?\b|support-bundle.*\.(?:tar|tar\.gz|tgz|zst|zip)\b",
        re.IGNORECASE,
    )
    if forbidden.search(raw_text):
        fail("forbidden secret marker found in production evidence manifest")
    try:
        manifest = json.loads(raw_text)
    except json.JSONDecodeError as error:
        fail(f"production evidence manifest is invalid JSON: {error}")
        manifest = {}

if not isinstance(manifest, dict):
    fail("production evidence manifest must be a JSON object")
    manifest = {}

schema_version = manifest.get("schemaVersion")
if schema_version not in {1, 2}:
    fail("schemaVersion must be 1 or 2")
elif schema_version == 1:
    block("schemaVersion 1 is historical evidence and is not production-ready")
if manifest.get("evidenceKind") != "steamosNonHardwareProductionEvidence":
    fail("evidenceKind must be steamosNonHardwareProductionEvidence")
if manifest.get("product") != "QuantumLink SteamOS":
    fail("product must be QuantumLink SteamOS")
if manifest.get("platform") != "steamos":
    fail("platform must be steamos")
if manifest.get("releaseScope") != "steamos-direct-installer":
    fail("releaseScope must be steamos-direct-installer")
generated_at = manifest.get("generatedAt")
if not is_nonempty_string(generated_at):
    fail("generatedAt is required")
elif not str(generated_at).endswith("Z"):
    fail("generatedAt must be a UTC RFC3339 timestamp ending in Z")
else:
    try:
        datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
    except ValueError:
        fail("generatedAt must be a valid RFC3339 timestamp")
if manifest.get("status") not in {"pass", "blocked", "fail"}:
    fail("status must be pass, blocked, or fail")
elif manifest.get("status") != "pass":
    block(f"production evidence status is {manifest.get('status')}")

host = manifest.get("host")
if not isinstance(host, dict):
    fail("host section is required")
else:
    if host.get("hardwareClaimed") is not False:
        fail("host.hardwareClaimed must be false for non-hardware production evidence")
    if host.get("physicalSteamHardwareRequired") is not False:
        fail("host.physicalSteamHardwareRequired must be false")

dytallix = manifest.get("dytallix")
dytallix_failures_at_start = len(failures)
dytallix_blockers_at_start = len(blockers)
required_dytallix_cases_v1 = {
    "active": "accepted",
    "missing": "rejected",
    "revoked": "rejected",
    "suspended": "rejected",
    "mismatched": "rejected",
    "stale": "rejected",
    "unavailable": "rejected",
}
required_lifecycle_cases = {
    "register": "accepted",
    "update": "accepted",
    "suspend": "accepted",
    "reactivate": "accepted",
    "revoke": "accepted",
    "post_revocation_reactivation": "rejected",
}
required_negative_cases = {
    "legacy_v1_downgrade",
    "expired_authorization",
    "device_mismatch",
    "signing_key_mismatch",
    "wrong_mesh_scope",
    "ttl_excess",
    "non_monotonic_revision",
    "missing",
    "suspended",
    "revoked",
    "registry_outage",
}
if not isinstance(dytallix, dict):
    fail("dytallix section is required")
    dytallix = {}
else:
    if dytallix.get("status") != "pass":
        if dytallix.get("status") in {"blocked", "fail"}:
            block(f"dytallix.status is {dytallix.get('status')}")
        else:
            fail("dytallix.status must be pass, blocked, or fail")
    endpoint = dytallix.get("registryEndpoint")
    if not is_nonempty_string(endpoint) or not endpoint_has_secure_scheme(str(endpoint), {"https"}):
        fail("dytallix.registryEndpoint must be an https URL")
    if schema_version == 1:
        for field in ("networkId", "contract"):
            if not is_nonempty_string(dytallix.get(field)):
                fail(f"dytallix.{field} is required")
    else:
        if dytallix.get("bindingVersion") != "stableIdentityV2":
            fail("dytallix.bindingVersion must be stableIdentityV2")
        if dytallix.get("contractSchemaVersion") != 2:
            fail("dytallix.contractSchemaVersion must be 2")
        if dytallix.get("evidenceClass") != "liveChain":
            block("dytallix.evidenceClass must be liveChain")
        for field in ("networkId", "chainId", "contractAddress"):
            if not is_nonempty_string(dytallix.get(field)):
                fail(f"dytallix.{field} is required")
        if not is_sha256(dytallix.get("contractCodeHash")):
            fail("dytallix.contractCodeHash must be a 64-character lowercase hex digest")
    if dytallix.get("walletAddressesRedacted") is not True:
        fail("dytallix.walletAddressesRedacted must be true")
    if dytallix.get("rawWalletMaterialCommitted") is not False:
        fail("dytallix.rawWalletMaterialCommitted must be false")

    if schema_version == 1:
        case_matrix = dytallix.get("caseMatrix")
        if not isinstance(case_matrix, list):
            fail("dytallix.caseMatrix must be an array")
            case_matrix = []
        cases_by_name = {}
        for entry in case_matrix:
            if not isinstance(entry, dict):
                fail("dytallix.caseMatrix entries must be objects")
                continue
            case_name = entry.get("case")
            if not is_nonempty_string(case_name):
                fail("dytallix.caseMatrix entry is missing case")
                continue
            cases_by_name[str(case_name)] = entry
        for case_name, expected_decision in required_dytallix_cases_v1.items():
            entry = cases_by_name.get(case_name)
            if entry is None:
                fail(f"missing Dytallix case: {case_name}")
                continue
            if entry.get("trustMode") != "publicDytallixRequired":
                fail(f"Dytallix case {case_name} must use publicDytallixRequired trustMode")
            if entry.get("expectedDecision") != expected_decision:
                fail(f"Dytallix case {case_name} expectedDecision must be {expected_decision}")
            if entry.get("observedDecision") != expected_decision:
                block(f"Dytallix case {case_name} observedDecision is {entry.get('observedDecision')}")
            if entry.get("redacted") is not True:
                fail(f"Dytallix case {case_name} must be redacted")
            if not is_relative_evidence_path(entry.get("evidence")):
                fail(f"Dytallix case {case_name} evidence must be a relative path")
            if "sha256" in entry and not is_sha256(entry.get("sha256")):
                fail(f"Dytallix case {case_name} sha256 must be a 64-character lowercase hex digest")
    else:
        finality = dytallix.get("finality")
        if not isinstance(finality, dict):
            fail("dytallix.finality section is required")
            finality = {}
        if finality.get("independentlyVerified") is not True:
            block("dytallix.finality.independentlyVerified must be true")
        if finality.get("verificationMethod") != "independentFinalizedBlock":
            block("dytallix.finality.verificationMethod must be independentFinalizedBlock")
        if not isinstance(finality.get("finalizedBlockHeight"), int) or finality.get("finalizedBlockHeight") < 0:
            fail("dytallix.finality.finalizedBlockHeight must be a non-negative integer")
        if not is_sha256(finality.get("finalizedBlockHash")):
            fail("dytallix.finality.finalizedBlockHash must be a 64-character lowercase hex digest")
        if finality.get("sdkReceiptOnly") is not False:
            block("dytallix.finality.sdkReceiptOnly must be false")
        finality_document = verify_evidence_file(
            finality,
            "Dytallix finality",
            required_digest=True,
            require_json=True,
        )
        finalized_transactions: dict[str, dict] = {}
        if finality_document is not None:
            if finality_document.get("evidenceKind") != "dytallixIndependentFinalityVerification":
                fail("Dytallix finality evidenceKind must be dytallixIndependentFinalityVerification")
            if finality_document.get("independentFromMutationSdk") != (finality.get("sdkReceiptOnly") is False):
                fail("Dytallix finality evidence SDK-independence claim does not match manifest")
            for field in (
                "networkId",
                "chainId",
                "contractAddress",
                "contractCodeHash",
                "finalizedBlockHeight",
                "finalizedBlockHash",
            ):
                expected = finality.get(field) if field.startswith("finalized") else dytallix.get(field)
                if finality_document.get(field) != expected:
                    fail(f"Dytallix finality evidence {field} does not match manifest")
            transactions = finality_document.get("finalizedTransactions")
            if not isinstance(transactions, list):
                fail("Dytallix finality evidence finalizedTransactions must be an array")
                transactions = []
            for transaction in transactions:
                if not isinstance(transaction, dict):
                    fail("Dytallix finality evidence transaction entries must be objects")
                    continue
                transaction_id = transaction.get("transactionId")
                if not is_nonempty_string(transaction_id):
                    fail("Dytallix finality evidence transactionId is required")
                    continue
                if str(transaction_id) in finalized_transactions:
                    fail(f"Dytallix finality evidence contains duplicate transaction: {transaction_id}")
                if not isinstance(transaction.get("finalizedBlockHeight"), int):
                    fail(f"Dytallix finality transaction {transaction_id} finalizedBlockHeight must be an integer")
                if not is_sha256(transaction.get("finalizedBlockHash")):
                    fail(f"Dytallix finality transaction {transaction_id} finalizedBlockHash must be a SHA-256 digest")
                finalized_transactions[str(transaction_id)] = transaction
        verifier_signature = finality.get("verifierSignature")
        if not isinstance(verifier_signature, dict):
            fail("dytallix.finality.verifierSignature section is required")
            verifier_signature = {}
        if verifier_signature.get("algorithm") != "ecdsa-p256-sha256":
            fail("dytallix.finality.verifierSignature.algorithm must be ecdsa-p256-sha256")
        bundled_public_key = verify_auxiliary_file(
            verifier_signature,
            "publicKey",
            "publicKeySha256",
            "Dytallix finality verifier public key",
        )
        signature_path = verify_auxiliary_file(
            verifier_signature,
            "signature",
            "signatureSha256",
            "Dytallix finality verifier signature",
        )
        trusted_public_key_value = os.environ.get("QLINK_DYTALLIX_FINALITY_VERIFIER_PUBLIC_KEY", "")
        trusted_public_key = Path(trusted_public_key_value).expanduser() if trusted_public_key_value else None
        if trusted_public_key is None:
            block("trusted Dytallix finality verifier public key is not configured")
        elif trusted_public_key.is_symlink() or not trusted_public_key.is_file():
            fail("QLINK_DYTALLIX_FINALITY_VERIFIER_PUBLIC_KEY must be a regular non-symlink file")
        elif bundled_public_key is not None and bundled_public_key.read_bytes() != trusted_public_key.read_bytes():
            fail("Dytallix finality verifier public key does not match the trusted key")
        elif finality_document is not None and signature_path is not None and bundled_public_key is not None:
            try:
                key_details = subprocess.run(
                    ["openssl", "pkey", "-pubin", "-in", str(trusted_public_key), "-text", "-noout"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                verification = subprocess.run(
                    [
                        "openssl",
                        "dgst",
                        "-sha256",
                        "-verify",
                        str(trusted_public_key),
                        "-signature",
                        str(signature_path),
                        str((manifest_path.parent / Path(str(finality.get("evidence")))).resolve()),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except FileNotFoundError:
                fail("openssl is required to verify the Dytallix finality signature")
            else:
                key_description = key_details.stdout + key_details.stderr
                if (
                    key_details.returncode != 0
                    or "ASN1 OID: prime256v1" not in key_description
                ):
                    fail("Dytallix finality verifier key must be ECDSA P-256 (prime256v1)")
                elif verification.returncode != 0:
                    fail("Dytallix independent finality verifier signature is invalid")

        def matrix_by_name(field: str) -> dict[str, dict]:
            matrix = dytallix.get(field)
            if not isinstance(matrix, list):
                fail(f"dytallix.{field} must be an array")
                return {}
            result: dict[str, dict] = {}
            for entry in matrix:
                if not isinstance(entry, dict):
                    fail(f"dytallix.{field} entries must be objects")
                    continue
                name = entry.get("case")
                if not is_nonempty_string(name):
                    fail(f"dytallix.{field} entry is missing case")
                    continue
                if str(name) in result:
                    fail(f"dytallix.{field} contains duplicate case: {name}")
                result[str(name)] = entry
            return result

        lifecycle = matrix_by_name("lifecycleMatrix")
        lifecycle_revisions: list[int] = []
        for case_name, expected in required_lifecycle_cases.items():
            entry = lifecycle.get(case_name)
            if entry is None:
                fail(f"missing Dytallix lifecycle case: {case_name}")
                continue
            if entry.get("expectedOutcome") != expected:
                fail(f"Dytallix lifecycle case {case_name} expectedOutcome must be {expected}")
            if entry.get("observedOutcome") != expected:
                block(f"Dytallix lifecycle case {case_name} observedOutcome is {entry.get('observedOutcome')}")
            if entry.get("finalized") is not True:
                block(f"Dytallix lifecycle case {case_name} must be independently finalized")
            if not isinstance(entry.get("finalizedBlockHeight"), int) or entry.get("finalizedBlockHeight") < 0:
                fail(f"Dytallix lifecycle case {case_name} finalizedBlockHeight must be a non-negative integer")
            if not is_nonempty_string(entry.get("transactionId")):
                fail(f"Dytallix lifecycle case {case_name} transactionId is required")
            revision = entry.get("stableIdentityRevision")
            if not isinstance(revision, int) or revision < 1:
                fail(f"Dytallix lifecycle case {case_name} stableIdentityRevision must be a positive integer")
            else:
                lifecycle_revisions.append(revision)
            if entry.get("redacted") is not True:
                fail(f"Dytallix lifecycle case {case_name} must be redacted")
            document = verify_evidence_file(
                entry,
                f"Dytallix lifecycle case {case_name}",
                required_digest=True,
                require_json=True,
            )
            if document is not None:
                expected_readback = {
                    "register": "active",
                    "update": "active",
                    "suspend": "suspended",
                    "reactivate": "active",
                    "revoke": "revoked",
                    "post_revocation_reactivation": "revoked",
                }[case_name]
                expected_fields = {
                    "evidenceKind": "dytallixLifecycleObservation",
                    "case": case_name,
                    "observedOutcome": entry.get("observedOutcome"),
                    "transactionId": entry.get("transactionId"),
                    "finalizedBlockHeight": entry.get("finalizedBlockHeight"),
                    "stableIdentityRevision": entry.get("stableIdentityRevision"),
                    "readbackStatus": expected_readback,
                    "networkId": dytallix.get("networkId"),
                    "chainId": dytallix.get("chainId"),
                    "contractAddress": dytallix.get("contractAddress"),
                    "contractCodeHash": dytallix.get("contractCodeHash"),
                }
                for field, expected_value in expected_fields.items():
                    if document.get(field) != expected_value:
                        fail(f"Dytallix lifecycle case {case_name} evidence {field} does not match manifest")
            transaction_id = entry.get("transactionId")
            transaction = finalized_transactions.get(str(transaction_id))
            if transaction is None and entry.get("finalized") is True:
                fail(f"Dytallix lifecycle case {case_name} transaction is absent from independent finality evidence")
            elif transaction is not None and transaction.get("finalizedBlockHeight") != entry.get("finalizedBlockHeight"):
                fail(f"Dytallix lifecycle case {case_name} finality height does not match independent evidence")
            elif transaction is not None and document is not None:
                signed_fields = {
                    "case": case_name,
                    "observedOutcome": entry.get("observedOutcome"),
                    "stableIdentityRevision": entry.get("stableIdentityRevision"),
                    "readbackStatus": document.get("readbackStatus"),
                    "readbackDigest": document.get("readbackDigest"),
                }
                if not is_sha256(document.get("readbackDigest")):
                    fail(f"Dytallix lifecycle case {case_name} readbackDigest must be a SHA-256 digest")
                for field, expected_value in signed_fields.items():
                    if transaction.get(field) != expected_value:
                        fail(f"Dytallix lifecycle case {case_name} {field} is not bound by independent finality evidence")
            if (
                isinstance(entry.get("finalizedBlockHeight"), int)
                and isinstance(finality.get("finalizedBlockHeight"), int)
                and entry["finalizedBlockHeight"] > finality["finalizedBlockHeight"]
            ):
                fail(f"Dytallix lifecycle case {case_name} occurs after the independently finalized checkpoint")
        if lifecycle_revisions and lifecycle_revisions != sorted(lifecycle_revisions):
            fail("Dytallix lifecycle stableIdentityRevision values must be monotonic")

        negative = matrix_by_name("negativePolicyMatrix")
        for case_name in sorted(required_negative_cases):
            entry = negative.get(case_name)
            if entry is None:
                fail(f"missing Dytallix negative policy case: {case_name}")
                continue
            if entry.get("expectedDecision") != "rejected":
                fail(f"Dytallix negative policy case {case_name} expectedDecision must be rejected")
            if entry.get("observedDecision") != "rejected":
                block(f"Dytallix negative policy case {case_name} observedDecision is {entry.get('observedDecision')}")
            if entry.get("redacted") is not True:
                fail(f"Dytallix negative policy case {case_name} must be redacted")
            document = verify_evidence_file(
                entry,
                f"Dytallix negative policy case {case_name}",
                required_digest=True,
                require_json=True,
            )
            if document is not None:
                expected_fields = {
                    "evidenceKind": "dytallixNegativePolicyObservation",
                    "case": case_name,
                    "observedDecision": entry.get("observedDecision"),
                    "policyInputsRedacted": True,
                    "networkId": dytallix.get("networkId"),
                    "chainId": dytallix.get("chainId"),
                    "contractAddress": dytallix.get("contractAddress"),
                    "contractCodeHash": dytallix.get("contractCodeHash"),
                }
                for field, expected_value in expected_fields.items():
                    if document.get(field) != expected_value:
                        fail(f"Dytallix negative policy case {case_name} evidence {field} does not match manifest")

        ttl_refresh = dytallix.get("ttlRefresh")
        if not isinstance(ttl_refresh, dict):
            fail("dytallix.ttlRefresh section is required")
        else:
            if ttl_refresh.get("observedOutcome") != "accepted":
                block("dytallix.ttlRefresh.observedOutcome must be accepted")
            before = ttl_refresh.get("stableIdentityRevisionBefore")
            after = ttl_refresh.get("stableIdentityRevisionAfter")
            if not isinstance(before, int) or before < 1 or after != before:
                fail("dytallix.ttlRefresh must preserve a positive stable identity revision")
            if ttl_refresh.get("finalized") is not True:
                block("dytallix.ttlRefresh must be independently finalized")
            if not isinstance(ttl_refresh.get("finalizedBlockHeight"), int) or ttl_refresh.get("finalizedBlockHeight") < 0:
                fail("dytallix.ttlRefresh.finalizedBlockHeight must be a non-negative integer")
            if not is_nonempty_string(ttl_refresh.get("transactionId")):
                fail("dytallix.ttlRefresh.transactionId is required")
            document = verify_evidence_file(
                ttl_refresh,
                "Dytallix TTL refresh",
                required_digest=True,
                require_json=True,
            )
            if document is not None:
                expected_fields = {
                    "evidenceKind": "dytallixTtlRefreshObservation",
                    "observedOutcome": ttl_refresh.get("observedOutcome"),
                    "transactionId": ttl_refresh.get("transactionId"),
                    "finalizedBlockHeight": ttl_refresh.get("finalizedBlockHeight"),
                    "stableIdentityRevisionBefore": ttl_refresh.get("stableIdentityRevisionBefore"),
                    "stableIdentityRevisionAfter": ttl_refresh.get("stableIdentityRevisionAfter"),
                    "networkId": dytallix.get("networkId"),
                    "chainId": dytallix.get("chainId"),
                    "contractAddress": dytallix.get("contractAddress"),
                    "contractCodeHash": dytallix.get("contractCodeHash"),
                }
                for field, expected_value in expected_fields.items():
                    if document.get(field) != expected_value:
                        fail(f"Dytallix TTL refresh evidence {field} does not match manifest")
            ttl_transaction = finalized_transactions.get(str(ttl_refresh.get("transactionId")))
            if ttl_transaction is None and ttl_refresh.get("finalized") is True:
                fail("Dytallix TTL refresh transaction is absent from independent finality evidence")
            elif ttl_transaction is not None and ttl_transaction.get("finalizedBlockHeight") != ttl_refresh.get("finalizedBlockHeight"):
                fail("Dytallix TTL refresh finality height does not match independent evidence")
            elif ttl_transaction is not None and document is not None:
                signed_fields = {
                    "case": "ttl_refresh",
                    "observedOutcome": ttl_refresh.get("observedOutcome"),
                    "stableIdentityRevisionBefore": ttl_refresh.get("stableIdentityRevisionBefore"),
                    "stableIdentityRevisionAfter": ttl_refresh.get("stableIdentityRevisionAfter"),
                    "readbackStatus": document.get("readbackStatus"),
                    "readbackDigest": document.get("readbackDigest"),
                }
                if not is_sha256(document.get("readbackDigest")):
                    fail("Dytallix TTL refresh readbackDigest must be a SHA-256 digest")
                for field, expected_value in signed_fields.items():
                    if ttl_transaction.get(field) != expected_value:
                        fail(f"Dytallix TTL refresh {field} is not bound by independent finality evidence")
            if (
                isinstance(ttl_refresh.get("finalizedBlockHeight"), int)
                and isinstance(finality.get("finalizedBlockHeight"), int)
                and ttl_refresh["finalizedBlockHeight"] > finality["finalizedBlockHeight"]
            ):
                fail("Dytallix TTL refresh occurs after the independently finalized checkpoint")

dytallix_ready = schema_version == 2 and len(failures) == dytallix_failures_at_start and len(blockers) == dytallix_blockers_at_start

rendezvous = manifest.get("rendezvousRelay")
rendezvous_failures_at_start = len(failures)
rendezvous_blockers_at_start = len(blockers)
required_controls = {
    "tls",
    "authentication",
    "signed_expiring_records",
    "rate_limits",
    "abuse_logs",
    "revocation_propagation",
    "relay_denial",
    "retention",
    "key_rotation",
    "endpoint_rotation",
    "incident_shutdown",
}
if not isinstance(rendezvous, dict):
    fail("rendezvousRelay section is required")
    rendezvous = {}
else:
    if rendezvous.get("status") != "pass":
        if rendezvous.get("status") in {"blocked", "fail"}:
            block(f"rendezvousRelay.status is {rendezvous.get('status')}")
        else:
            fail("rendezvousRelay.status must be pass, blocked, or fail")
    rendezvous_endpoints = rendezvous.get("rendezvousEndpoints")
    if not isinstance(rendezvous_endpoints, list) or not rendezvous_endpoints:
        fail("rendezvousRelay.rendezvousEndpoints must be a non-empty array")
        rendezvous_endpoints = []
    for endpoint in rendezvous_endpoints:
        if not is_nonempty_string(endpoint) or not endpoint_has_secure_scheme(str(endpoint), {"https", "tls"}):
            fail("rendezvous endpoint must use https or tls")

    relay_endpoints = rendezvous.get("relayEndpoints")
    if not isinstance(relay_endpoints, list) or not relay_endpoints:
        fail("rendezvousRelay.relayEndpoints must be a non-empty array")
        relay_endpoints = []
    for endpoint in relay_endpoints:
        if not is_nonempty_string(endpoint) or not endpoint_has_secure_scheme(str(endpoint), {"turns", "https", "tls"}):
            fail("relay endpoint must use turns, https, or tls")

    if rendezvous.get("abuseLogsRedacted") is not True:
        fail("rendezvousRelay.abuseLogsRedacted must be true")
    for field in ("rawPacketPayloadsCommitted", "rawGamePayloadsCommitted"):
        if rendezvous.get(field) is not False:
            fail(f"rendezvousRelay.{field} must be false")

    controls = rendezvous.get("controls")
    if not isinstance(controls, list):
        fail("rendezvousRelay.controls must be an array")
        controls = []
    controls_by_name = {}
    for entry in controls:
        if not isinstance(entry, dict):
            fail("rendezvousRelay.controls entries must be objects")
            continue
        control_name = entry.get("control")
        if not is_nonempty_string(control_name):
            fail("rendezvousRelay.controls entry is missing control")
            continue
        controls_by_name[str(control_name)] = entry

    for control_name in sorted(required_controls):
        entry = controls_by_name.get(control_name)
        if entry is None:
            fail(f"missing rendezvous/relay control: {control_name}")
            continue
        if entry.get("status") != "pass":
            if entry.get("status") in {"blocked", "fail"}:
                block(f"rendezvous/relay control {control_name} status is {entry.get('status')}")
            else:
                fail(f"rendezvous/relay control {control_name} status must be pass, blocked, or fail")
        if schema_version == 1:
            if not is_relative_evidence_path(entry.get("evidence")):
                fail(f"rendezvous/relay control {control_name} evidence must be a relative path")
            if "sha256" in entry and not is_sha256(entry.get("sha256")):
                fail(f"rendezvous/relay control {control_name} sha256 must be a 64-character lowercase hex digest")
        else:
            verify_evidence_file(
                entry,
                f"rendezvous/relay control {control_name}",
                required_digest=True,
            )

rendezvous_ready = schema_version == 2 and len(failures) == rendezvous_failures_at_start and len(blockers) == rendezvous_blockers_at_start
ready = not failures and not blockers
report = {
    "valid": not failures,
    "productionEvidenceReady": ready,
    "dytallixReady": dytallix_ready,
    "rendezvousRelayReady": rendezvous_ready,
    "manifest": str(manifest_path),
    "blockers": blockers,
    "failures": failures,
    "warnings": warnings,
}
print(json.dumps(report, separators=(",", ":"), sort_keys=True))
raise SystemExit(0 if not failures else 1)
PY
