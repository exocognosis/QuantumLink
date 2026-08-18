#!/bin/sh
set -eu

fail() {
    echo "linux desktop-control integration failed: $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

wait_for_path() {
    path="$1"
    attempts="$2"
    while [ "$attempts" -gt 0 ]; do
        [ -e "$path" ] && return 0
        attempts=$((attempts - 1))
        sleep 1
    done
    return 1
}

[ "${QLINK_INTEGRATION_ISOLATED:-}" = "1" ] || \
    fail "set QLINK_INTEGRATION_ISOLATED=1 on a disposable Linux host"
[ "$(uname -s)" = "Linux" ] || fail "Linux is required"
[ "$(id -u)" -eq 0 ] || fail "root is required"
[ -d /run/systemd/system ] || fail "systemd is not PID 1"

require_command cargo
require_command groupadd
require_command pkexec
require_command python3
require_command systemctl

REPO_ROOT="${QLINK_REPO_ROOT:-$(CDPATH='' cd -- "$(dirname "$0")/../../.." && pwd)}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/quantumlink-desktop-control-target}"
REPORT="${QLINK_INTEGRATION_REPORT:-/tmp/quantumlink-steamos-desktop-control-linux.json}"
SERVICE_DIR=/etc/systemd/system/qlinkd.service.d
STATE_DIR=/var/lib/quantumlink
CONFIG_DIR=/etc/quantumlink
PEER_ID=peer-linux-integration

cleanup() {
    systemctl stop qlinkd.service >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

cd "$REPO_ROOT"
CARGO_TARGET_DIR="$TARGET_DIR" cargo build --locked -p qlinkd -p qlinkctl

getent group quantumlink >/dev/null 2>&1 || groupadd --system quantumlink
install -d -m 0750 -o root -g quantumlink "$STATE_DIR" "$CONFIG_DIR" "$CONFIG_DIR/games"
install -m 0755 "$TARGET_DIR/debug/qlinkd" /usr/local/bin/qlinkd
install -m 0755 "$TARGET_DIR/debug/qlinkctl" /usr/local/bin/qlinkctl
install -d -m 0755 /usr/local/libexec /etc/polkit-1/rules.d
install -m 0755 \
    steam/steamos/packaging/libexec/quantumlink-service-control \
    /usr/local/libexec/quantumlink-service-control
install -m 0644 \
    steam/steamos/packaging/polkit/49-quantumlink-service-control.rules \
    /etc/polkit-1/rules.d/49-quantumlink-service-control.rules
install -m 0644 steam/steamos/config/games/*.toml "$CONFIG_DIR/games/"
install -m 0644 steam/steamos/config/steam-bypass.toml "$CONFIG_DIR/steam-bypass.toml"
install -m 0644 steam/steamos/packaging/systemd/qlinkd.service \
    /etc/systemd/system/qlinkd.service
install -d -m 0755 "$SERVICE_DIR"
install -m 0644 \
    steam/steamos/packaging/systemd/qlinkd.service.d/planning-only.conf.sample \
    "$SERVICE_DIR/10-planning-only.conf"

systemctl daemon-reload
systemctl start dbus.service
systemctl restart polkit.service

/usr/local/bin/qlinkctl service start
wait_for_path /run/quantumlink/qlinkd.sock 20 || {
    systemctl status qlinkd.service --no-pager >&2 || true
    journalctl -u qlinkd.service --no-pager >&2 || true
    fail "qlinkd control socket did not start"
}

/usr/local/bin/qlinkctl status > /tmp/qlink-status.json
/usr/local/bin/qlinkctl doctor > /tmp/qlink-doctor.txt
/usr/local/bin/qlinkctl profile list > /tmp/qlink-profiles.json
/usr/local/bin/qlinkctl profile select factorio > /tmp/qlink-profile-selected.json
/usr/local/bin/qlinkctl profile clear > /tmp/qlink-profile-cleared.json

INVITE_CODE="$(python3 - <<'PY'
import base64
import json
import time

invite = {
    "meshId": "mesh-linux-integration",
    "partyId": "party-linux-integration",
    "rendezvous": ["rv.integration.invalid:9471"],
    "relay": ["relay.integration.invalid:9472"],
    "hostPeerId": "peer-linux-integration",
    "hostAlias": "Linux Integration Peer",
    "trustMode": "privateFriends",
    "trustSource": "integration-test",
    "expiresAtUnix": int(time.time()) + 3600,
}
raw = json.dumps(invite, separators=(",", ":")).encode()
print(base64.urlsafe_b64encode(raw).decode().rstrip("="))
PY
)"

/usr/local/bin/qlinkctl invite import "$INVITE_CODE" > /tmp/qlink-invite-import.txt
/usr/local/bin/qlinkctl peer select "$PEER_ID" > /tmp/qlink-peer-select.txt
/usr/local/bin/qlinkctl peer state > /tmp/qlink-peer-selected.json
/usr/local/bin/qlinkctl peer trust "$PEER_ID" > /tmp/qlink-peer-trust.txt
/usr/local/bin/qlinkctl peer clear > /tmp/qlink-peer-clear.txt
/usr/local/bin/qlinkctl peer revoke "$PEER_ID" > /tmp/qlink-peer-revoke.txt
/usr/local/bin/qlinkctl peer state > /tmp/qlink-peer-revoked.json
/usr/local/bin/qlinkctl peer remove "$PEER_ID" > /tmp/qlink-peer-remove.txt
/usr/local/bin/qlinkctl peer state > /tmp/qlink-peer-removed.json

/usr/local/bin/qlinkctl service restart
wait_for_path /run/quantumlink/qlinkd.sock 20 || fail "qlinkd socket did not return after restart"
/usr/local/bin/qlinkctl status > /tmp/qlink-status-after-restart.json
/usr/local/bin/qlinkctl service stop
[ ! -S /run/quantumlink/qlinkd.sock ] || fail "control socket remained after service stop"

REPORT="$REPORT" python3 - <<'PY'
import json
import os
import pathlib
import platform
import subprocess

def load_json(path):
    return json.loads(pathlib.Path(path).read_text())

status = load_json("/tmp/qlink-status.json")
profiles = load_json("/tmp/qlink-profiles.json")
selected_profile = load_json("/tmp/qlink-profile-selected.json")
cleared_profile = load_json("/tmp/qlink-profile-cleared.json")
selected_peer = load_json("/tmp/qlink-peer-selected.json")
revoked_peer = load_json("/tmp/qlink-peer-revoked.json")
removed_peer = load_json("/tmp/qlink-peer-removed.json")
status_after_restart = load_json("/tmp/qlink-status-after-restart.json")

assert status["network"]["dryRun"] is True
assert any(profile["id"] == "factorio" for profile in profiles)
assert selected_profile["selectedProfile"]["id"] == "factorio"
assert cleared_profile["selectedProfile"] is None
assert selected_peer["selectedPeerId"] == "peer-linux-integration"
assert any(peer["peerId"] == "peer-linux-integration" for peer in selected_peer["peers"])
assert any(
    peer["peerId"] == "peer-linux-integration" and peer["revoked"] is True
    for peer in revoked_peer["peers"]
)
assert not any(peer["peerId"] == "peer-linux-integration" for peer in removed_peer["peers"])
assert status_after_restart["network"]["dryRun"] is True

report = {
    "schemaVersion": 1,
    "hostClass": "privileged-linux-container",
    "kernel": platform.release(),
    "systemd": subprocess.check_output(
        ["systemctl", "--version"], text=True
    ).splitlines()[0],
    "cgroupVersion": "v2" if pathlib.Path("/sys/fs/cgroup/cgroup.controllers").exists() else "v1",
    "checks": {
        "systemdPlanningService": "passed",
        "pkexecServiceStartRestartStop": "passed",
        "daemonStatus": "passed",
        "doctor": "passed",
        "profileListSelectClear": "passed",
        "inviteImport": "passed",
        "peerSelectClearRevokeRemove": "passed",
        "peerTrustReadOnly": "passed",
        "socketRemovedAfterStop": "passed",
    },
    "productionReady": False,
    "notProductionReady": True,
    "limitations": [
        "Docker Desktop Linux VM is not Steam Deck hardware",
        "planning-only service does not apply TUN, route, or nftables state",
        "root pkexec execution does not prove an interactive SteamOS PolicyKit prompt",
        "desktop rendering and Steam Input are outside this Linux harness",
    ],
}
path = pathlib.Path(os.environ["REPORT"])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(report, indent=2) + "\n")
print(path)
PY

echo "Linux desktop-control integration passed: $REPORT"
