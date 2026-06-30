#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STEAMOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER="$STEAMOS_ROOT/scripts/install-steamos.sh"
VALIDATION_ROOT="$STEAMOS_ROOT/validation/deck"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_DIR="${QLINK_DECK_EVIDENCE_DIR:-$VALIDATION_ROOT/$TIMESTAMP}"
MODE="${1:-}"

STATUS_BEFORE="$EVIDENCE_DIR/status-before.json"
STATUS_AFTER="$EVIDENCE_DIR/status-after.json"
DOCTOR_TXT="$EVIDENCE_DIR/doctor.txt"
ROUTE_LEAK_TXT="$EVIDENCE_DIR/route-leak-check.txt"
JOURNAL_TXT="$EVIDENCE_DIR/journal-qlinkd.txt"
NFTABLES_TXT="$EVIDENCE_DIR/nftables.txt"
IP_ROUTE_TXT="$EVIDENCE_DIR/ip-route.txt"
SUPPORT_REDACTION_TXT="$EVIDENCE_DIR/support-bundle-redaction.txt"
REPORT_JSON="$EVIDENCE_DIR/validation-report.json"

mkdir -p "$EVIDENCE_DIR"

usage() {
    cat >&2 <<'EOF'
usage: deck-validation.sh <mode>

modes:
  preflight
  install
  activate
  route-leak-check
  support-bundle-check
  uninstall

Set QLINK_DECK_EVIDENCE_DIR to reuse a single evidence directory across modes.
EOF
}

fail() {
    echo "FAIL: $*" >&2
    write_report "fail" "$*"
    exit 1
}

json_escape() {
    local input="${1:-}"
    input="${input//\\/\\\\}"
    input="${input//\"/\\\"}"
    input="${input//$'\n'/\\n}"
    input="${input//$'\r'/\\r}"
    input="${input//$'\t'/\\t}"
    printf '%s' "$input"
}

write_report() {
    local status="$1"
    local detail="${2:-}"
    cat > "$REPORT_JSON" <<EOF
{
  "mode": "$(json_escape "$MODE")",
  "status": "$(json_escape "$status")",
  "detail": "$(json_escape "$detail")",
  "timestampUtc": "$(json_escape "$TIMESTAMP")",
  "evidenceDir": "$(json_escape "$EVIDENCE_DIR")",
  "hardwareClaimed": false,
  "rawPcapCommitted": false,
  "rawSupportBundleCommitted": false,
  "privateMaterialCommitted": false,
  "requiredEvidence": [
    "status-before.json",
    "status-after.json",
    "doctor.txt",
    "route-leak-check.txt",
    "journal-qlinkd.txt",
    "nftables.txt",
    "ip-route.txt",
    "support-bundle-redaction.txt",
    "validation-report.json"
  ]
}
EOF
}

redact_stream() {
    sed -E \
        -e 's/[0-9a-fA-F]{64,}/<redacted-hex>/g' \
        -e 's/[A-Za-z0-9_\/+=-]{40,}/<redacted-token>/g' \
        -e 's/([0-9]{1,3}\.){3}[0-9]{1,3}/<redacted-ipv4>/g' \
        -e 's/([[:xdigit:]]{0,4}:){2,}[[:xdigit:]]{0,4}/<redacted-ipv6>/g' \
        -e 's#(/[A-Za-z0-9._-]+){3,}#<redacted-path>#g' \
        -e 's/(wallet|seed|secret|token|private[_ -]?key|endpoint)[^[:space:]]*/\1=<redacted>/Ig'
}

run_redacted() {
    local output="$1"
    local tmp_output="$EVIDENCE_DIR/.command-output.$$"
    local rc=0
    shift
    "$@" > "$tmp_output" 2>&1 || rc=$?
    {
        printf '$'
        printf ' %q' "$@"
        printf '\n'
        cat "$tmp_output"
        if [ "$rc" -ne 0 ]; then
            printf 'command_exit=%s\n' "$rc"
        fi
    } | redact_stream > "$output"
    rm -f "$tmp_output"
    return "$rc"
}

capture_status() {
    local output="$1"
    if command -v qlinkctl >/dev/null 2>&1; then
        if qlinkctl status 2>/tmp/qlink-deck-status.err | redact_stream > "$output"; then
            return 0
        fi
        local error
        error="$(redact_stream < /tmp/qlink-deck-status.err | tr '\n' ' ')"
        cat > "$output" <<EOF
{
  "status": "unavailable",
  "error": "$(json_escape "$error")"
}
EOF
        rm -f /tmp/qlink-deck-status.err
        return 0
    fi

    cat > "$output" <<'EOF'
{
  "status": "unavailable",
  "error": "qlinkctl not found on PATH"
}
EOF
}

capture_doctor() {
    if command -v qlinkctl >/dev/null 2>&1; then
        run_redacted "$DOCTOR_TXT" qlinkctl doctor || true
    else
        printf 'qlinkctl not found on PATH\n' > "$DOCTOR_TXT"
    fi
}

capture_routes() {
    if command -v ip >/dev/null 2>&1; then
        run_redacted "$IP_ROUTE_TXT" ip route show table all || true
    else
        printf 'ip command not found\n' > "$IP_ROUTE_TXT"
    fi
}

capture_nftables() {
    if command -v nft >/dev/null 2>&1; then
        run_redacted "$NFTABLES_TXT" nft list ruleset || true
    else
        printf 'nft command not found\n' > "$NFTABLES_TXT"
    fi
}

capture_journal() {
    if command -v journalctl >/dev/null 2>&1; then
        run_redacted "$JOURNAL_TXT" journalctl -u qlinkd --no-pager --since -30min || true
    else
        printf 'journalctl not found\n' > "$JOURNAL_TXT"
    fi
}

write_route_leak_check() {
    {
        echo "SteamOS route leak checklist"
        echo
        echo "Required assertions:"
        echo "- Default route is not replaced by QuantumLink in split-tunnel game mode."
        echo "- Protected QuantumLink overlay route is limited to game/party traffic, normally 100.64.0.0/10."
        echo "- Steam account, store, wallet, checkout, inventory, marketplace, launcher, and embedded browser categories bypass QuantumLink."
        echo "- Game profiles under steam/steamos/config/games remain split-tunnel by default."
        echo "- No raw pcaps are written by this script."
        echo
        echo "Current route snapshot is in ip-route.txt."
        echo "Current nftables snapshot is in nftables.txt."
    } > "$ROUTE_LEAK_TXT"
}

write_support_redaction_check() {
    {
        echo "Support bundle redaction checklist"
        echo
        echo "Required assertions:"
        echo "- Do not commit raw support bundle archives."
        echo "- Do not commit private endpoints, wallet material, device keys, peer IDs, DNS data, or packet captures."
        echo "- Commit only this redacted text summary and validation-report.json."
        echo "- Use ephemeral peer labels such as peer_1 and peer_2 in human notes."
    } > "$SUPPORT_REDACTION_TXT"
}

capture_common() {
    capture_status "$STATUS_BEFORE"
    capture_doctor
    capture_routes
    capture_nftables
    capture_journal
    write_route_leak_check
    write_support_redaction_check
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

mode_preflight() {
    capture_common
    capture_status "$STATUS_AFTER"
    write_report "blocked" "preflight evidence captured; hardware gate still requires two-Deck run"
}

mode_install() {
    require_command bash
    capture_status "$STATUS_BEFORE"
    local install_status="blocked"
    local install_detail="install evidence captured; inspect journal-qlinkd.txt for installer output"
    if ! run_redacted "$JOURNAL_TXT" bash "$INSTALLER"; then
        install_status="fail"
        install_detail="installer command failed; inspect journal-qlinkd.txt"
    fi
    capture_status "$STATUS_AFTER"
    capture_doctor
    capture_routes
    capture_nftables
    write_route_leak_check
    write_support_redaction_check
    write_report "$install_status" "$install_detail"
}

mode_activate() {
    capture_status "$STATUS_BEFORE"
    local activate_status="blocked"
    local activate_detail="activation evidence captured; real Deck peer traffic still required"
    if command -v systemctl >/dev/null 2>&1; then
        if ! run_redacted "$JOURNAL_TXT" systemctl restart qlinkd; then
            activate_status="fail"
            activate_detail="systemctl restart qlinkd failed; inspect journal-qlinkd.txt"
        fi
    else
        printf 'systemctl not found\n' > "$JOURNAL_TXT"
        activate_status="fail"
        activate_detail="systemctl not found"
    fi
    capture_status "$STATUS_AFTER"
    capture_doctor
    capture_routes
    capture_nftables
    write_route_leak_check
    write_support_redaction_check
    write_report "$activate_status" "$activate_detail"
}

mode_route_leak_check() {
    capture_status "$STATUS_BEFORE"
    capture_routes
    capture_nftables
    write_route_leak_check
    capture_status "$STATUS_AFTER"
    capture_doctor
    capture_journal
    write_support_redaction_check
    write_report "blocked" "route leak checklist captured; manual Steam category verification still required"
}

mode_support_bundle_check() {
    capture_status "$STATUS_BEFORE"
    write_support_redaction_check
    capture_status "$STATUS_AFTER"
    capture_doctor
    capture_routes
    capture_nftables
    capture_journal
    write_route_leak_check
    write_report "blocked" "support redaction checklist captured; no raw support bundle written"
}

mode_uninstall() {
    capture_status "$STATUS_BEFORE"
    local uninstall_status="blocked"
    local uninstall_detail="uninstall/rollback evidence captured; inspect residual route and nftables state"
    if command -v systemctl >/dev/null 2>&1; then
        if ! run_redacted "$JOURNAL_TXT" systemctl stop qlinkd; then
            uninstall_status="fail"
            uninstall_detail="systemctl stop qlinkd failed; inspect journal-qlinkd.txt"
        fi
    else
        printf 'systemctl not found\n' > "$JOURNAL_TXT"
        uninstall_status="fail"
        uninstall_detail="systemctl not found"
    fi
    if command -v qlinkd >/dev/null 2>&1; then
        run_redacted "$EVIDENCE_DIR/deactivate-network.txt" qlinkd --deactivate-network || true
    fi
    capture_status "$STATUS_AFTER"
    capture_doctor
    capture_routes
    capture_nftables
    write_route_leak_check
    write_support_redaction_check
    write_report "$uninstall_status" "$uninstall_detail"
}

case "$MODE" in
    preflight) mode_preflight ;;
    install) mode_install ;;
    activate) mode_activate ;;
    route-leak-check) mode_route_leak_check ;;
    support-bundle-check) mode_support_bundle_check ;;
    uninstall) mode_uninstall ;;
    ""|-h|--help) usage; exit 2 ;;
    *) usage; fail "unknown mode: $MODE" ;;
esac

printf 'Deck validation evidence: %s\n' "$EVIDENCE_DIR"
