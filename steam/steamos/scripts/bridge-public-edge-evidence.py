#!/usr/bin/env python3
"""Bridge shared public-edge live evidence into the SteamOS evidence contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]
PUBLIC_VERIFIER = REPO_ROOT / "scripts" / "verify-public-infra-evidence.rb"
STEAMOS_COLLECTOR = SCRIPT_DIR / "collect-production-evidence.sh"

REQUIRED_DYTALLIX_LIFECYCLE = {
    "register": "accepted",
    "update": "accepted",
    "suspend": "accepted",
    "reactivate": "accepted",
    "revoke": "accepted",
    "post_revocation_reactivation": "rejected",
}
REQUIRED_DYTALLIX_NEGATIVE_POLICIES = (
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
)
REQUIRED_CONTROLS = (
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
)
FORBIDDEN = re.compile(
    r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|"
    r"WALLET_SEED|ENTITLEMENT_TOKEN|DYTALLIX_WALLET_SECRET|"
    r"QLINK_PRODUCTION_ENDPOINT_SECRET|STEAMOS_RELEASE_PRIVATE_KEY|"
    r"local-edge-secret|replace-with-|"
    r"\.pcapng?\b|support-bundle.*\.(?:tar|tar\.gz|tgz|zst|zip)\b",
    re.IGNORECASE,
)
SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
SHA256_RE = re.compile(r"[0-9a-f]{64}")

CONTROL_FIELDS: dict[str, tuple[str, ...]] = {
    "tls": (
        "control_tls_ca_configured",
        "rendezvous_tls_enabled",
        "relay_tls_enabled",
    ),
    "authentication": (
        "rendezvous_auth_required",
        "relay_auth_required",
        "rendezvous_auth_verified",
        "relay_auth_verified",
    ),
    "rate_limits": (
        "rendezvous_rate_limit_per_window",
        "relay_rate_limit_per_window",
        "admission_rate_limit_window_seconds",
        "bounds_verified",
        "relay_payload_limit_verified",
        "relay_saturation_limit_verified",
        "rendezvous_request_too_large_total",
        "relay_request_too_large_total",
        "relay_payload_too_large_total",
        "relay_peer_rate_limited_total",
    ),
    "revocation_propagation": (
        "revoked_token_digest_file_configured",
        "service_token_revocation_verified",
        "rendezvous_revoked_token_rejected",
        "relay_revoked_token_rejected",
        "rendezvous_replacement_token_accepted",
        "relay_replacement_token_accepted",
        "rendezvous_auth_revocations_total",
        "relay_auth_revocations_total",
        "revocation_list_sha256",
    ),
    "relay_denial": (
        "selected_path",
        "frames_sent",
        "relay_payload_limit_verified",
        "relay_saturation_limit_verified",
        "relay_payload_too_large_total",
        "relay_peer_rate_limited_total",
    ),
}

UNSUPPORTED_PROOFS = {
    "signed_expiring_records": (
        "shared live evidence does not include complete signed publication, "
        "expiry-rejection, and refresh proof"
    ),
    "abuse_logs": "shared live evidence exposes counters, not redacted abuse-log samples",
    "retention": "shared live evidence does not attest deployed log retention",
    "key_rotation": "service-token replacement is not cryptographic key-rotation proof",
    "endpoint_rotation": "release rollback is not endpoint-rotation proof",
    "incident_shutdown": "release rollback is not an incident shutdown drill",
}


class BridgeError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Convert a quantumLinkPublicEdgeLiveEvidence run into the existing "
            "SteamOS non-hardware production evidence bundle and manifest."
        )
    )
    parser.add_argument("--public-edge-manifest", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--output-manifest", type=Path)
    parser.add_argument(
        "--dytallix-evidence-root",
        type=Path,
        help="Existing redacted operator bundle containing metadata.json.dytallix",
    )
    parser.add_argument(
        "--allow-blocked",
        action="store_true",
        help="Keep a valid blocked manifest when proof is incomplete",
    )
    parser.add_argument("--max-age-seconds", type=int, default=7 * 24 * 60 * 60)
    return parser.parse_args()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_checked(path: Path, label: str) -> bytes:
    if not path.is_file():
        raise BridgeError(f"{label} is missing: {path}")
    raw = path.read_bytes()
    if FORBIDDEN.search(str(path)) or FORBIDDEN.search(raw.decode("utf-8", errors="ignore")):
        raise BridgeError(f"{label} contains a forbidden secret or raw-artifact marker")
    return raw


def load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = read_checked(path, label)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise BridgeError(f"{label} is invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise BridgeError(f"{label} must be a JSON object")
    return value, raw


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BridgeError(message)


def parse_timestamp(value: object, max_age_seconds: int) -> None:
    require(isinstance(value, str) and value.endswith("Z"), "public-edge generatedAt must be a UTC RFC3339 timestamp ending in Z")
    try:
        generated = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise BridgeError("public-edge generatedAt must be valid RFC3339") from error
    now = datetime.now(timezone.utc)
    require((generated - now).total_seconds() <= 300, "public-edge generatedAt is too far in the future")
    require((now - generated).total_seconds() <= max_age_seconds, "public-edge generatedAt is stale")


def timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def resolve_source_path(reference: object, run_root: Path, label: str) -> Path:
    require(isinstance(reference, str) and bool(reference.strip()), f"{label} path is required")
    rel = Path(reference)
    candidates = [rel] if rel.is_absolute() else [run_root / rel, REPO_ROOT / rel]
    for candidate in candidates:
        if candidate.is_symlink():
            raise BridgeError(f"{label} must not be a symbolic link")
        try:
            lexical_relative = candidate.absolute().relative_to(run_root)
        except ValueError:
            lexical_relative = None
        if lexical_relative is not None:
            cursor = run_root
            if any((cursor := cursor / part).is_symlink() for part in lexical_relative.parts):
                raise BridgeError(f"{label} must not traverse symbolic links")
        resolved = candidate.resolve()
        try:
            resolved.relative_to(run_root)
        except ValueError:
            continue
        if resolved.is_file():
            return resolved
    raise BridgeError(f"{label} must resolve to a regular file inside the public-edge run root")


def run_public_verifier(evidence: Path, git_sha: str, turn: bool, max_age_seconds: int) -> dict[str, Any]:
    command = [
        "ruby",
        str(PUBLIC_VERIFIER),
        "--require-public",
    ]
    if turn:
        command.append("--require-turn-relay")
    command.extend(
        [
            "--expected-sha",
            git_sha,
            "--max-age-seconds",
            str(max_age_seconds),
            str(evidence),
        ]
    )
    try:
        result = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    except FileNotFoundError as error:
        raise BridgeError("ruby is required to run the shared public-edge verifier") from error
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise BridgeError(f"shared public-edge verifier returned invalid JSON for {evidence}") from error
    require(isinstance(report, dict), "shared public-edge verifier report must be an object")
    if result.returncode != 0 or report.get("valid") is not True or report.get("publicInfraReady") is not True:
        details = report.get("failures", []) + report.get("blockers", [])
        raise BridgeError(f"shared public-edge verification failed for {evidence}: {details}")
    return report


def all_true(items: tuple[dict[str, Any], ...], fields: tuple[str, ...]) -> bool:
    return all(item.get(field) is True for item in items for field in fields)


def all_positive(items: tuple[dict[str, Any], ...], fields: tuple[str, ...]) -> bool:
    return all(isinstance(item.get(field), int) and item[field] > 0 for item in items for field in fields)


def control_status(control: str, app: dict[str, Any], turn: dict[str, Any]) -> str:
    items = (app, turn)
    if control == "tls":
        return "pass" if all_true(items, CONTROL_FIELDS[control]) else "blocked"
    if control == "authentication":
        return "pass" if all_true(items, CONTROL_FIELDS[control]) else "blocked"
    if control == "rate_limits":
        booleans = ("bounds_verified", "relay_payload_limit_verified", "relay_saturation_limit_verified")
        positives = tuple(field for field in CONTROL_FIELDS[control] if field not in booleans)
        return "pass" if all_true(items, booleans) and all_positive(items, positives) else "blocked"
    if control == "revocation_propagation":
        booleans = (
            "revoked_token_digest_file_configured",
            "service_token_revocation_verified",
            "rendezvous_revoked_token_rejected",
            "relay_revoked_token_rejected",
            "rendezvous_replacement_token_accepted",
            "relay_replacement_token_accepted",
        )
        counters = ("rendezvous_auth_revocations_total", "relay_auth_revocations_total")
        digests = all(
            isinstance(item.get("revocation_list_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}:[0-9a-f]{64}", item["revocation_list_sha256"]) is not None
            for item in items
        )
        return "pass" if all_true(items, booleans) and all_positive(items, counters) and digests else "blocked"
    if control == "relay_denial":
        booleans = ("relay_payload_limit_verified", "relay_saturation_limit_verified")
        counters = ("frames_sent", "relay_payload_too_large_total", "relay_peer_rate_limited_total")
        paths_ok = app.get("selected_path") == "relay" and turn.get("selected_path") == "turn-relay"
        return "pass" if paths_ok and all_true(items, booleans) and all_positive(items, counters) else "blocked"
    return "blocked"


def signed_record_lifecycle_proof(
    proofs: dict[str, Any],
    run_root: Path,
    manifest: dict[str, Any],
) -> tuple[str, str | None, dict[str, Any], str | None]:
    reference = proofs.get("signedExpiringRecords")
    if not isinstance(reference, dict) or not reference.get("evidence"):
        return (
            "blocked",
            UNSUPPORTED_PROOFS["signed_expiring_records"],
            {},
            None,
        )

    proof_path = resolve_source_path(
        reference.get("evidence"),
        run_root,
        "signed expiring record lifecycle evidence",
    )
    proof, proof_raw = load_json(proof_path, "signed expiring record lifecycle evidence")
    proof_sha = sha256(proof_raw)
    expected_sha = reference.get("sha256")
    require(
        isinstance(expected_sha, str)
        and re.fullmatch(r"[0-9a-f]{64}", expected_sha) is not None,
        "signed expiring record lifecycle evidence reference requires sha256",
    )
    require(
        expected_sha == proof_sha,
        "signed expiring record lifecycle evidence sha256 does not match",
    )
    publication = proof.get("publication")
    expiry = proof.get("expiryProbe")
    refresh = proof.get("refresh")
    verifier = proof.get("verifier")
    redaction = proof.get("redaction")

    assertions = {
        "schemaVersion": proof.get("schemaVersion"),
        "evidenceKind": proof.get("evidenceKind"),
        "status": proof.get("status"),
        "generatedAt": proof.get("generatedAt"),
        "gitSha": proof.get("gitSha"),
        "rendezvousEndpointSha256": proof.get("rendezvousEndpointSha256"),
        "verifier": {
            field: verifier.get(field)
            for field in ("kind", "gitSha", "cryptographicVerificationPerformed")
        }
        if isinstance(verifier, dict)
        else {},
        "publication": {
            field: publication.get(field)
            for field in (
                "recordSha256",
                "peerIdSha256",
                "meshIdSha256",
                "keyFingerprintSha256",
                "signatureSha256",
                "signatureAlgorithm",
                "signatureValid",
                "peerIdBindingValid",
                "meshIdBindingValid",
                "sequence",
                "publishedAtUnix",
                "expiresAtUnix",
                "lookupAtUnix",
                "lookupRecordSha256",
            )
        }
        if isinstance(publication, dict)
        else {},
        "expiryProbe": {
            field: expiry.get(field)
            for field in (
                "recordSha256",
                "peerIdSha256",
                "meshIdSha256",
                "keyFingerprintSha256",
                "signatureSha256",
                "signatureAlgorithm",
                "signatureValidBeforeExpiry",
                "sequence",
                "expiresAtUnix",
                "lookupAtUnix",
                "lookupResult",
            )
        }
        if isinstance(expiry, dict)
        else {},
        "refresh": {
            field: refresh.get(field)
            for field in (
                "recordSha256",
                "peerIdSha256",
                "meshIdSha256",
                "keyFingerprintSha256",
                "signatureSha256",
                "signatureAlgorithm",
                "signatureValid",
                "peerIdBindingValid",
                "meshIdBindingValid",
                "sequence",
                "publishedAtUnix",
                "expiresAtUnix",
                "lookupAtUnix",
                "lookupRecordSha256",
            )
        }
        if isinstance(refresh, dict)
        else {},
        "redaction": {
            field: redaction.get(field)
            for field in (
                "rawRecordsCommitted",
                "privateKeysCommitted",
                "iceCredentialsCommitted",
                "endpointAddressesCommitted",
            )
        }
        if isinstance(redaction, dict)
        else {},
    }

    if not all(
        isinstance(section, dict)
        for section in (publication, expiry, refresh, verifier, redaction)
    ):
        return (
            "blocked",
            "signed record lifecycle proof requires verifier, publication, expiryProbe, refresh, and redaction sections",
            assertions,
            proof_sha,
        )

    digest_fields = (
        publication.get("recordSha256"),
        publication.get("peerIdSha256"),
        publication.get("meshIdSha256"),
        publication.get("keyFingerprintSha256"),
        publication.get("signatureSha256"),
        expiry.get("recordSha256"),
        expiry.get("peerIdSha256"),
        expiry.get("meshIdSha256"),
        expiry.get("keyFingerprintSha256"),
        expiry.get("signatureSha256"),
        refresh.get("recordSha256"),
        refresh.get("peerIdSha256"),
        refresh.get("meshIdSha256"),
        refresh.get("keyFingerprintSha256"),
        refresh.get("signatureSha256"),
        publication.get("lookupRecordSha256"),
        refresh.get("lookupRecordSha256"),
        proof.get("rendezvousEndpointSha256"),
    )
    digests_valid = all(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
        for value in digest_fields
    )
    sequence_values = (
        expiry.get("sequence"),
        publication.get("sequence"),
        refresh.get("sequence"),
    )
    sequences_valid = all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in sequence_values
    )
    if sequences_valid:
        sequences_valid = (
            expiry["sequence"] < publication["sequence"]
            and refresh["sequence"] > publication["sequence"]
        )

    identity_stable = (
        publication.get("peerIdSha256")
        == expiry.get("peerIdSha256")
        == refresh.get("peerIdSha256")
        and publication.get("meshIdSha256")
        == expiry.get("meshIdSha256")
        == refresh.get("meshIdSha256")
        and publication.get("keyFingerprintSha256")
        == expiry.get("keyFingerprintSha256")
        == refresh.get("keyFingerprintSha256")
    )
    algorithms_valid = all(
        section.get("signatureAlgorithm") == "ML-DSA-65"
        for section in (publication, expiry, refresh)
    )
    signature_results_valid = (
        publication.get("signatureValid") is True
        and expiry.get("signatureValidBeforeExpiry") is True
        and refresh.get("signatureValid") is True
    )
    bindings_valid = all(
        section.get("peerIdBindingValid") is True
        and section.get("meshIdBindingValid") is True
        for section in (publication, refresh)
    )
    lookup_results_valid = (
        publication.get("lookupRecordSha256") == publication.get("recordSha256")
        and refresh.get("lookupRecordSha256") == refresh.get("recordSha256")
        and expiry.get("lookupResult") == "not_found"
    )
    records_distinct = (
        refresh.get("recordSha256") != publication.get("recordSha256")
        and expiry.get("recordSha256") != publication.get("recordSha256")
    )
    unix_fields = (
        publication.get("publishedAtUnix"),
        publication.get("expiresAtUnix"),
        publication.get("lookupAtUnix"),
        expiry.get("expiresAtUnix"),
        expiry.get("lookupAtUnix"),
        refresh.get("publishedAtUnix"),
        refresh.get("expiresAtUnix"),
        refresh.get("lookupAtUnix"),
    )
    timestamps_valid = all(
        isinstance(value, int) and not isinstance(value, bool) and value > 0
        for value in unix_fields
    )
    generated_at = timestamp(proof.get("generatedAt"))
    if timestamps_valid and generated_at is not None:
        generated_unix = int(generated_at.timestamp())
        timestamps_valid = (
            publication["publishedAtUnix"]
            <= publication["lookupAtUnix"]
            <= generated_unix
            and publication["publishedAtUnix"]
            < refresh["publishedAtUnix"]
            < publication["expiresAtUnix"]
            and refresh["publishedAtUnix"]
            <= refresh["lookupAtUnix"]
            <= generated_unix
            and refresh["expiresAtUnix"] > publication["expiresAtUnix"]
            and expiry["expiresAtUnix"] < expiry["lookupAtUnix"] <= generated_unix
        )
    else:
        timestamps_valid = False
    verifier_valid = (
        verifier.get("kind") == "qlink-core-peer-record-verifier"
        and verifier.get("gitSha") == manifest.get("gitSha")
        and verifier.get("cryptographicVerificationPerformed") is True
    )
    redaction_valid = all(
        redaction.get(field) is False
        for field in (
            "rawRecordsCommitted",
            "privateKeysCommitted",
            "iceCredentialsCommitted",
            "endpointAddressesCommitted",
        )
    )
    expected_keys = {
        "schemaVersion",
        "evidenceKind",
        "status",
        "generatedAt",
        "gitSha",
        "rendezvousEndpointSha256",
        "verifier",
        "publication",
        "expiryProbe",
        "refresh",
        "redaction",
    }
    publication_keys = {
        "recordSha256",
        "peerIdSha256",
        "meshIdSha256",
        "keyFingerprintSha256",
        "signatureSha256",
        "signatureAlgorithm",
        "signatureValid",
        "peerIdBindingValid",
        "meshIdBindingValid",
        "sequence",
        "publishedAtUnix",
        "expiresAtUnix",
        "lookupAtUnix",
        "lookupRecordSha256",
    }
    expiry_keys = {
        "recordSha256",
        "peerIdSha256",
        "meshIdSha256",
        "keyFingerprintSha256",
        "signatureSha256",
        "signatureAlgorithm",
        "signatureValidBeforeExpiry",
        "sequence",
        "expiresAtUnix",
        "lookupAtUnix",
        "lookupResult",
    }
    verifier_keys = {"kind", "gitSha", "cryptographicVerificationPerformed"}
    redaction_keys = {
        "rawRecordsCommitted",
        "privateKeysCommitted",
        "iceCredentialsCommitted",
        "endpointAddressesCommitted",
    }
    unexpected_fields_valid = (
        set(proof) == expected_keys
        and set(verifier) == verifier_keys
        and set(publication) == publication_keys
        and set(expiry) == expiry_keys
        and set(refresh) == publication_keys
        and set(redaction) == redaction_keys
    )
    envelope_valid = (
        proof.get("schemaVersion") == 1
        and proof.get("evidenceKind") == "quantumLinkSignedRecordLifecycleVerification"
        and proof.get("status") == "pass"
        and proof.get("generatedAt") == manifest.get("generatedAt")
        and proof.get("gitSha") == manifest.get("gitSha")
        and proof.get("rendezvousEndpointSha256")
        == sha256(manifest["endpoints"]["rendezvous"].encode("utf-8"))
    )

    valid = all(
        (
            envelope_valid,
            verifier_valid,
            redaction_valid,
            unexpected_fields_valid,
            digests_valid,
            sequences_valid,
            identity_stable,
            algorithms_valid,
            signature_results_valid,
            bindings_valid,
            lookup_results_valid,
            records_distinct,
            timestamps_valid,
        )
    )
    if valid:
        return "pass", None, assertions, proof_sha
    return (
        "blocked",
        "signed record lifecycle proof is incomplete or internally inconsistent",
        assertions,
        proof_sha,
    )


def public_control_documents(
    manifest: dict[str, Any],
    manifest_raw: bytes,
    proofs: dict[str, Any],
    run_root: Path,
    app: dict[str, Any],
    app_raw: bytes,
    turn: dict[str, Any],
    turn_raw: bytes,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    controls: dict[str, dict[str, Any]] = {}
    documents: dict[str, dict[str, Any]] = {}
    source = {
        "gitSha": manifest["gitSha"],
        "publicEdgeManifestSha256": sha256(manifest_raw),
        "appRelayEvidenceSha256": sha256(app_raw),
        "turnRelayEvidenceSha256": sha256(turn_raw),
    }
    signed_status, signed_reason, signed_assertions, signed_source_sha = (
        signed_record_lifecycle_proof(proofs, run_root, manifest)
    )
    if signed_source_sha is not None:
        source["signedExpiringRecordsEvidenceSha256"] = signed_source_sha
    for control in REQUIRED_CONTROLS:
        status = (
            signed_status
            if control == "signed_expiring_records"
            else control_status(control, app, turn)
        )
        fields = CONTROL_FIELDS.get(control, ())
        document: dict[str, Any] = {
            "schemaVersion": 2,
            "evidenceKind": "steamosPublicEdgeControlEvidence",
            "control": control,
            "status": status,
            "generatedAt": manifest["generatedAt"],
            "source": source,
            "assertions": {
                "appRelay": {field: app.get(field) for field in fields},
                "turnRelay": {field: turn.get(field) for field in fields},
            },
            "redaction": {
                "credentialsCommitted": False,
                "rawPacketPayloadsCommitted": False,
                "rawGamePayloadsCommitted": False,
            },
        }
        if control == "signed_expiring_records":
            document["assertions"] = signed_assertions
        if status != "pass":
            document["blockedReason"] = (
                signed_reason
                if control == "signed_expiring_records"
                else UNSUPPORTED_PROOFS.get(control, "required shared proof did not pass")
            )
        relative = f"rendezvous-relay/{control}.json"
        controls[control] = {"status": status, "evidence": relative}
        documents[control] = document
    return controls, documents


def encoded_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def unresolved_dytallix() -> tuple[dict[str, Any], dict[str, bytes]]:
    documents: dict[str, bytes] = {}

    def blocked_reference(relative: str, case: str) -> dict[str, Any]:
        raw = encoded_json(
            {
                "schemaVersion": 2,
                "evidenceKind": "steamosDytallixDependency",
                "case": case,
                "status": "blocked",
                "blockedReason": "live Dytallix evidence bundle was not supplied",
                "redacted": True,
            }
        )
        documents[relative] = raw
        return {"evidence": relative, "sha256": sha256(raw), "redacted": True}

    def replace_document(relative: str, entry: dict[str, Any], document: dict[str, Any]) -> None:
        raw = encoded_json(document)
        documents[relative] = raw
        entry["sha256"] = sha256(raw)

    finality = blocked_reference("dytallix/finality.json", "finality")
    finality.update(
        {
            "independentlyVerified": False,
            "verificationMethod": "unavailable",
            "finalizedBlockHeight": 0,
            "finalizedBlockHash": "0" * 64,
            "sdkReceiptOnly": True,
        }
    )
    verifier_public_key_raw = b"unconfigured Dytallix finality verifier public key\n"
    verifier_signature_raw = b"unconfigured Dytallix finality verifier signature\n"
    documents["dytallix/finality-verifier-public.pem"] = verifier_public_key_raw
    documents["dytallix/finality.sig"] = verifier_signature_raw
    finality["verifierSignature"] = {
        "algorithm": "ecdsa-p256-sha256",
        "publicKey": "dytallix/finality-verifier-public.pem",
        "publicKeySha256": sha256(verifier_public_key_raw),
        "signature": "dytallix/finality.sig",
        "signatureSha256": sha256(verifier_signature_raw),
    }
    lifecycle: dict[str, dict[str, Any]] = {}
    for revision, case_name in enumerate(REQUIRED_DYTALLIX_LIFECYCLE, start=1):
        relative = f"dytallix/lifecycle/{case_name}.json"
        lifecycle[case_name] = blocked_reference(relative, case_name)
        lifecycle[case_name].update(
            {
                "observedOutcome": "unavailable",
                "transactionId": "unavailable",
                "finalized": False,
                "finalizedBlockHeight": 0,
                "stableIdentityRevision": revision,
            }
        )
    negative: dict[str, dict[str, Any]] = {}
    for case_name in REQUIRED_DYTALLIX_NEGATIVE_POLICIES:
        relative = f"dytallix/negative/{case_name}.json"
        negative[case_name] = blocked_reference(relative, case_name)
        negative[case_name]["observedDecision"] = "unavailable"
    ttl_refresh = blocked_reference("dytallix/ttl-refresh.json", "ttl_refresh")
    ttl_refresh.update(
        {
            "observedOutcome": "unavailable",
            "transactionId": "unavailable",
            "finalized": False,
            "finalizedBlockHeight": 0,
            "stableIdentityRevisionBefore": 1,
            "stableIdentityRevisionAfter": 1,
        }
    )
    metadata = {
        "status": "blocked",
        "evidenceClass": "liveChain",
        "bindingVersion": "stableIdentityV2",
        "contractSchemaVersion": 2,
        "registryEndpoint": "https://live-evidence-required.invalid",
        "networkId": "unresolved",
        "chainId": "unresolved",
        "contractAddress": "unresolved",
        "contractCodeHash": "0" * 64,
        "walletAddressesRedacted": True,
        "rawWalletMaterialCommitted": False,
        "finality": finality,
        "lifecycle": lifecycle,
        "negativePolicies": negative,
        "ttlRefresh": ttl_refresh,
    }
    pins = {
        "networkId": metadata["networkId"],
        "chainId": metadata["chainId"],
        "contractAddress": metadata["contractAddress"],
        "contractCodeHash": metadata["contractCodeHash"],
    }
    replace_document(
        "dytallix/finality.json",
        finality,
        {
            "evidenceKind": "dytallixIndependentFinalityVerification",
            "independentFromMutationSdk": False,
            **pins,
            "finalizedBlockHeight": finality["finalizedBlockHeight"],
            "finalizedBlockHash": finality["finalizedBlockHash"],
            "finalizedTransactions": [],
        },
    )
    readback_status = {
        "register": "active",
        "update": "active",
        "suspend": "suspended",
        "reactivate": "active",
        "revoke": "revoked",
        "post_revocation_reactivation": "revoked",
    }
    for case_name, entry in lifecycle.items():
        replace_document(
            f"dytallix/lifecycle/{case_name}.json",
            entry,
            {
                "evidenceKind": "dytallixLifecycleObservation",
                "case": case_name,
                "observedOutcome": entry["observedOutcome"],
                "transactionId": entry["transactionId"],
                "finalizedBlockHeight": entry["finalizedBlockHeight"],
                "stableIdentityRevision": entry["stableIdentityRevision"],
                "readbackStatus": readback_status[case_name],
                **pins,
            },
        )
    for case_name, entry in negative.items():
        replace_document(
            f"dytallix/negative/{case_name}.json",
            entry,
            {
                "evidenceKind": "dytallixNegativePolicyObservation",
                "case": case_name,
                "observedDecision": entry["observedDecision"],
                "policyInputsRedacted": True,
                **pins,
            },
        )
    replace_document(
        "dytallix/ttl-refresh.json",
        ttl_refresh,
        {
            "evidenceKind": "dytallixTtlRefreshObservation",
            "observedOutcome": ttl_refresh["observedOutcome"],
            "transactionId": ttl_refresh["transactionId"],
            "finalizedBlockHeight": ttl_refresh["finalizedBlockHeight"],
            "stableIdentityRevisionBefore": ttl_refresh["stableIdentityRevisionBefore"],
            "stableIdentityRevisionAfter": ttl_refresh["stableIdentityRevisionAfter"],
            **pins,
        },
    )
    return metadata, documents


def load_dytallix(root: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    resolved_root = root.resolve()
    metadata, _ = load_json(resolved_root / "metadata.json", "Dytallix bundle metadata")
    section = metadata.get("dytallix")
    require(isinstance(section, dict), "Dytallix bundle metadata.dytallix section is required")
    require(
        metadata.get("schemaVersion") == 2 or section.get("schemaVersion") == 2,
        "Dytallix evidence schemaVersion must be 2",
    )
    require(
        section.get("evidenceClass") == "liveChain",
        "Dytallix evidenceClass must be liveChain; fixture or synthetic evidence is not production evidence",
    )
    require(
        section.get("bindingVersion") == "stableIdentityV2",
        "Dytallix bindingVersion must be stableIdentityV2",
    )
    require(
        section.get("contractSchemaVersion") == 2,
        "Dytallix contractSchemaVersion must be 2",
    )
    require(section.get("status") == "pass", "Dytallix live-chain evidence status must be pass")
    for field in (
        "registryEndpoint",
        "networkId",
        "chainId",
        "contractAddress",
    ):
        require(
            isinstance(section.get(field), str) and bool(section[field].strip()),
            f"Dytallix {field} is required",
        )
    require(
        isinstance(section.get("contractCodeHash"), str)
        and SHA256_RE.fullmatch(section["contractCodeHash"]) is not None,
        "Dytallix contractCodeHash must be a 64-character lowercase hex digest",
    )
    require(section.get("walletAddressesRedacted") is True, "Dytallix wallet addresses must be redacted")
    require(section.get("rawWalletMaterialCommitted") is False, "Dytallix raw wallet material must not be committed")
    documents: dict[str, bytes] = {}

    def checked_reference(entry: object, label: str) -> tuple[dict[str, Any], str]:
        require(isinstance(entry, dict), f"{label} is required")
        assert isinstance(entry, dict)
        expected_sha = entry.get("sha256")
        require(
            isinstance(expected_sha, str)
            and SHA256_RE.fullmatch(expected_sha) is not None,
            f"{label} evidence requires sha256",
        )
        source = resolve_source_path(entry.get("evidence"), resolved_root, f"{label} evidence")
        _, source_raw = load_json(source, f"{label} evidence")
        source_sha = sha256(source_raw)
        require(expected_sha == source_sha, f"{label} evidence sha256 does not match")
        relative = source.relative_to(resolved_root).as_posix()
        documents[relative] = source_raw
        copied = dict(entry)
        copied.update({"evidence": relative, "sha256": source_sha})
        return copied, relative

    def checked_binary_reference(
        reference: object,
        expected_sha: object,
        label: str,
    ) -> tuple[str, str]:
        require(
            isinstance(expected_sha, str) and SHA256_RE.fullmatch(expected_sha) is not None,
            f"{label} requires sha256",
        )
        source = resolve_source_path(reference, resolved_root, label)
        source_raw = read_checked(source, label)
        source_sha = sha256(source_raw)
        require(expected_sha == source_sha, f"{label} sha256 does not match")
        relative = source.relative_to(resolved_root).as_posix()
        documents[relative] = source_raw
        return relative, source_sha

    finality, _ = checked_reference(section.get("finality"), "Dytallix finality")
    require(finality.get("independentlyVerified") is True, "Dytallix finality must be independently verified")
    require(
        finality.get("verificationMethod") == "independentFinalizedBlock",
        "Dytallix finality verificationMethod must be independentFinalizedBlock",
    )
    require(finality.get("sdkReceiptOnly") is False, "Dytallix finality cannot rely on an SDK receipt")
    verifier_signature = finality.get("verifierSignature")
    require(isinstance(verifier_signature, dict), "Dytallix finality verifierSignature is required")
    assert isinstance(verifier_signature, dict)
    require(
        verifier_signature.get("algorithm") == "ecdsa-p256-sha256",
        "Dytallix finality verifier signature algorithm must be ecdsa-p256-sha256",
    )
    public_key, public_key_sha = checked_binary_reference(
        verifier_signature.get("publicKey"),
        verifier_signature.get("publicKeySha256"),
        "Dytallix finality verifier public key",
    )
    signature, signature_sha = checked_binary_reference(
        verifier_signature.get("signature"),
        verifier_signature.get("signatureSha256"),
        "Dytallix finality verifier signature",
    )
    finality["verifierSignature"] = {
        "algorithm": "ecdsa-p256-sha256",
        "publicKey": public_key,
        "publicKeySha256": public_key_sha,
        "signature": signature,
        "signatureSha256": signature_sha,
    }

    source_lifecycle = section.get("lifecycle")
    require(isinstance(source_lifecycle, dict), "Dytallix lifecycle must be an object")
    lifecycle: dict[str, dict[str, Any]] = {}
    for case_name, expected_outcome in REQUIRED_DYTALLIX_LIFECYCLE.items():
        entry, _ = checked_reference(source_lifecycle.get(case_name), f"Dytallix lifecycle case {case_name}")
        require(
            entry.get("observedOutcome") == expected_outcome,
            f"Dytallix lifecycle case {case_name} observedOutcome must be {expected_outcome}",
        )
        require(entry.get("finalized") is True, f"Dytallix lifecycle case {case_name} must be finalized")
        lifecycle[case_name] = entry

    source_negative = section.get("negativePolicies")
    require(isinstance(source_negative, dict), "Dytallix negativePolicies must be an object")
    negative: dict[str, dict[str, Any]] = {}
    for case_name in REQUIRED_DYTALLIX_NEGATIVE_POLICIES:
        entry, _ = checked_reference(
            source_negative.get(case_name),
            f"Dytallix negative policy case {case_name}",
        )
        require(
            entry.get("observedDecision") == "rejected",
            f"Dytallix negative policy case {case_name} observedDecision must be rejected",
        )
        negative[case_name] = entry

    ttl_refresh, _ = checked_reference(section.get("ttlRefresh"), "Dytallix TTL refresh")
    require(ttl_refresh.get("observedOutcome") == "accepted", "Dytallix TTL refresh must be accepted")
    require(ttl_refresh.get("finalized") is True, "Dytallix TTL refresh must be finalized")
    require(
        ttl_refresh.get("stableIdentityRevisionBefore")
        == ttl_refresh.get("stableIdentityRevisionAfter"),
        "Dytallix TTL refresh must preserve stable identity revision",
    )

    copied_section = {
        field: section[field]
        for field in (
            "status",
            "evidenceClass",
            "bindingVersion",
            "contractSchemaVersion",
            "registryEndpoint",
            "networkId",
            "chainId",
            "contractAddress",
            "contractCodeHash",
        )
    }
    copied_section.update({
        "walletAddressesRedacted": True,
        "rawWalletMaterialCommitted": False,
        "finality": finality,
        "lifecycle": lifecycle,
        "negativePolicies": negative,
        "ttlRefresh": ttl_refresh,
    })
    return copied_section, documents


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    require(args.max_age_seconds > 0, "--max-age-seconds must be positive")

    public_manifest_path = args.public_edge_manifest.resolve()
    run_root = public_manifest_path.parent
    require(not args.output_root.expanduser().is_symlink(), "output root must not be a symbolic link")
    output_root = args.output_root.resolve()
    output_manifest = (args.output_manifest or (output_root / "production-evidence.json")).resolve()
    require(not output_root.exists() or not any(output_root.iterdir()), "output root must be absent or empty")
    try:
        output_root.relative_to(run_root)
    except ValueError:
        pass
    else:
        raise BridgeError("output root must be outside the public-edge run root")

    manifest, manifest_raw = load_json(public_manifest_path, "public-edge live evidence manifest")
    require(manifest.get("schemaVersion") == 1, "public-edge schemaVersion must be 1")
    require(manifest.get("evidenceKind") == "quantumLinkPublicEdgeLiveEvidence", "unexpected public-edge evidenceKind")
    require(manifest.get("mode") == "public", "public-edge evidence mode must be public")
    require(manifest.get("status") == "pass", "public-edge evidence status must be pass")
    parse_timestamp(manifest.get("generatedAt"), args.max_age_seconds)
    git_sha = manifest.get("gitSha")
    require(isinstance(git_sha, str) and SHA_RE.fullmatch(git_sha) is not None, "public-edge gitSha must be a lowercase commit digest")

    endpoints = manifest.get("endpoints")
    proofs = manifest.get("proofs")
    require(isinstance(endpoints, dict), "public-edge endpoints section is required")
    require(isinstance(proofs, dict), "public-edge proofs section is required")
    app_proof = proofs.get("appRelay")
    turn_proof = proofs.get("turnRelay")
    require(isinstance(app_proof, dict), "public-edge appRelay proof is required")
    require(isinstance(turn_proof, dict), "public-edge turnRelay proof is required")

    app_path = resolve_source_path(app_proof.get("evidence"), run_root, "app-relay evidence")
    turn_path = resolve_source_path(turn_proof.get("evidence"), run_root, "TURN-relay evidence")
    app_report = run_public_verifier(app_path, git_sha, False, args.max_age_seconds)
    turn_report = run_public_verifier(turn_path, git_sha, True, args.max_age_seconds)
    require(app_report.get("selectedPath") == "relay", "app-relay verifier must select relay")
    require(turn_report.get("selectedPath") == "turn-relay", "TURN verifier must select turn-relay")

    app, app_raw = load_json(app_path, "app-relay evidence")
    turn, turn_raw = load_json(turn_path, "TURN-relay evidence")
    for field in ("rendezvous", "relay", "stun", "turn"):
        require(app.get(field) == endpoints.get(field), f"public-edge endpoint {field} does not match app-relay evidence")
        require(turn.get(field) == endpoints.get(field), f"public-edge endpoint {field} does not match TURN-relay evidence")

    controls, control_documents = public_control_documents(
        manifest,
        manifest_raw,
        proofs,
        run_root,
        app,
        app_raw,
        turn,
        turn_raw,
    )
    if args.dytallix_evidence_root:
        dytallix, dytallix_documents = load_dytallix(args.dytallix_evidence_root)
    else:
        dytallix, dytallix_documents = unresolved_dytallix()

    rendezvous_status = "pass" if all(entry["status"] == "pass" for entry in controls.values()) else "blocked"
    dytallix_status = dytallix.get("status", "blocked")
    if "fail" in {rendezvous_status, dytallix_status}:
        overall_status = "fail"
    elif rendezvous_status == "pass" and dytallix_status == "pass":
        overall_status = "pass"
    else:
        overall_status = "blocked"
    metadata = {
        "schemaVersion": 2,
        "generatedAt": manifest["generatedAt"],
        "status": overall_status,
        "dytallix": dytallix,
        "rendezvousRelay": {
            "status": rendezvous_status,
            "rendezvousEndpoints": [endpoints["rendezvous"]],
            "relayEndpoints": [endpoints["relay"]],
            "abuseLogsRedacted": True,
            "rawPacketPayloadsCommitted": False,
            "rawGamePayloadsCommitted": False,
            "controls": controls,
        },
    }

    output_root.mkdir(parents=True, exist_ok=True)
    write_json(output_root / "metadata.json", metadata)
    for relative, raw in dytallix_documents.items():
        destination = output_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    for control, document in control_documents.items():
        write_json(output_root / "rendezvous-relay" / f"{control}.json", document)

    command = [
        "bash",
        str(STEAMOS_COLLECTOR),
        "--evidence-root",
        str(output_root),
        "--output",
        str(output_manifest),
        "--allow-blocked",
    ]
    result = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout, end="", file=sys.stderr)
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        raise BridgeError("SteamOS production evidence collector rejected the bridged bundle")

    report = json.loads(result.stdout)
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    if report.get("productionEvidenceReady") is not True and not args.allow_blocked:
        raise BridgeError("bridged SteamOS evidence is valid but blocked; rerun with --allow-blocked to retain incomplete proof")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BridgeError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
