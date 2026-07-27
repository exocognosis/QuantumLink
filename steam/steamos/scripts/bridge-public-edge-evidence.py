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

REQUIRED_DYTALLIX_CASES = (
    "active",
    "missing",
    "revoked",
    "suspended",
    "mismatched",
    "stale",
    "unavailable",
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
    "signed_expiring_records": "shared live evidence does not attest signed record expiry",
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


def resolve_source_path(reference: object, run_root: Path, label: str) -> Path:
    require(isinstance(reference, str) and bool(reference.strip()), f"{label} path is required")
    rel = Path(reference)
    candidates = [rel] if rel.is_absolute() else [run_root / rel, REPO_ROOT / rel]
    for candidate in candidates:
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


def public_control_documents(
    manifest: dict[str, Any],
    manifest_raw: bytes,
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
    for control in REQUIRED_CONTROLS:
        status = control_status(control, app, turn)
        fields = CONTROL_FIELDS.get(control, ())
        document: dict[str, Any] = {
            "schemaVersion": 1,
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
        if status != "pass":
            document["blockedReason"] = UNSUPPORTED_PROOFS.get(control, "required shared proof did not pass")
        relative = f"rendezvous-relay/{control}.json"
        controls[control] = {"status": status, "evidence": relative}
        documents[control] = document
    return controls, documents


def unresolved_dytallix() -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    cases: dict[str, dict[str, Any]] = {}
    documents: dict[str, dict[str, Any]] = {}
    for case_name in REQUIRED_DYTALLIX_CASES:
        relative = f"dytallix/{case_name}.json"
        cases[case_name] = {
            "observedDecision": "unavailable",
            "evidence": relative,
            "redacted": True,
        }
        documents[case_name] = {
            "schemaVersion": 1,
            "evidenceKind": "steamosDytallixDependency",
            "case": case_name,
            "status": "blocked",
            "observedDecision": "unavailable",
            "redacted": True,
            "blockedReason": "live Dytallix evidence bundle was not supplied",
        }
    metadata = {
        "status": "blocked",
        "registryEndpoint": "https://live-evidence-required.invalid",
        "networkId": "unresolved",
        "contract": "unresolved",
        "walletAddressesRedacted": True,
        "rawWalletMaterialCommitted": False,
        "cases": cases,
    }
    return metadata, documents


def load_dytallix(root: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    resolved_root = root.resolve()
    metadata, _ = load_json(resolved_root / "metadata.json", "Dytallix bundle metadata")
    section = metadata.get("dytallix")
    require(isinstance(section, dict), "Dytallix bundle metadata.dytallix section is required")
    require(section.get("walletAddressesRedacted") is True, "Dytallix wallet addresses must be redacted")
    require(section.get("rawWalletMaterialCommitted") is False, "Dytallix raw wallet material must not be committed")
    cases = section.get("cases")
    require(isinstance(cases, dict), "Dytallix bundle metadata.dytallix.cases must be an object")

    copied_cases: dict[str, dict[str, Any]] = {}
    documents: dict[str, dict[str, Any]] = {}
    expected_decisions = {
        "active": "accepted",
        "missing": "rejected",
        "revoked": "rejected",
        "suspended": "rejected",
        "mismatched": "rejected",
        "stale": "rejected",
        "unavailable": "rejected",
    }
    for case_name in REQUIRED_DYTALLIX_CASES:
        entry = cases.get(case_name)
        require(isinstance(entry, dict), f"Dytallix case {case_name} is required")
        require(entry.get("redacted", True) is True, f"Dytallix case {case_name} must be redacted")
        source = resolve_source_path(entry.get("evidence"), resolved_root, f"Dytallix case {case_name} evidence")
        source_document, source_raw = load_json(source, f"Dytallix case {case_name} evidence")
        observed = entry.get("observedDecision")
        require(
            observed == expected_decisions[case_name],
            f"Dytallix case {case_name} observedDecision must be {expected_decisions[case_name]}",
        )
        require(
            source_document.get("observedDecision") == observed,
            f"Dytallix case {case_name} evidence decision does not match metadata",
        )
        require(
            source_document.get("redacted") is True,
            f"Dytallix case {case_name} evidence must assert redacted=true",
        )
        relative = f"dytallix/{case_name}.json"
        copied_cases[case_name] = {
            "observedDecision": observed,
            "evidence": relative,
            "redacted": True,
        }
        documents[case_name] = {
            "schemaVersion": 1,
            "evidenceKind": "steamosDytallixCaseEvidence",
            "case": case_name,
            "status": "pass",
            "observedDecision": observed,
            "redacted": True,
            "sourceSha256": sha256(source_raw),
        }
    copied_section = {
        "status": section.get("status"),
        "registryEndpoint": section.get("registryEndpoint"),
        "networkId": section.get("networkId"),
        "contract": section.get("contract"),
        "walletAddressesRedacted": True,
        "rawWalletMaterialCommitted": False,
        "cases": copied_cases,
    }
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

    controls, control_documents = public_control_documents(manifest, manifest_raw, app, app_raw, turn, turn_raw)
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
    for case_name, document in dytallix_documents.items():
        write_json(output_root / "dytallix" / f"{case_name}.json", document)
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
