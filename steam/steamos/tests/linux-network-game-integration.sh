#!/bin/sh
set -eu

fail() {
    echo "linux network-game integration failed: $*" >&2
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

run_authorized_service_action() {
    runuser -u deck -- /usr/local/bin/qlinkctl service "$1"
}

assert_status() {
    status_file="$1"
    phase="$2"
    profile="$3"
    executable="$4"
    python3 - "$status_file" "$phase" "$profile" "$executable" <<'PY'
import json
import sys

status = json.load(open(sys.argv[1], encoding="utf-8"))
expected_state, expected_profile, expected_executable = sys.argv[2:]
network = status["network"]
process = status["gameProfile"]["processClassification"]
assert network["state"] == "applied"
assert network["dryRun"] is False
assert network["ownershipRecordPresent"] is True
assert status["dataPlane"]["state"] == "ready"
assert status["dataPlane"]["packetIoAvailable"] is True
assert process["state"] == expected_state
assert process["profileId"] == expected_profile
if expected_executable:
    assert process["executable"] == expected_executable
PY
}

nft_cgroup_v2_supported() {
    probe_table=qlink_cgroup_probe
    probe_cgroup=qlink-nft-probe
    mkdir "/sys/fs/cgroup/$probe_cgroup"
    supported=1
    if "$NFT_COMMAND" add table inet "$probe_table" \
        && "$NFT_COMMAND" add chain inet "$probe_table" output \
            '{' type route hook output priority 0 ';' policy accept ';' '}' \
        && "$NFT_COMMAND" add rule inet "$probe_table" output \
            socket cgroupv2 level 1 "\"$probe_cgroup\"" counter \
            2>/tmp/qlink-nft-cgroup-probe.err; then
        supported=0
    fi
    "$NFT_COMMAND" delete table inet "$probe_table" >/dev/null 2>&1 || true
    rmdir "/sys/fs/cgroup/$probe_cgroup"
    return "$supported"
}

[ "${QLINK_INTEGRATION_ISOLATED:-}" = "1" ] || \
    fail "set QLINK_INTEGRATION_ISOLATED=1 on a disposable Linux host"
[ "$(uname -s)" = "Linux" ] || fail "Linux is required"
[ "$(id -u)" -eq 0 ] || fail "root is required"
[ -d /run/systemd/system ] || fail "systemd is not PID 1"

for command in ip nft pkexec python3 runuser systemctl useradd usermod; do
    require_command "$command"
done

REPORT="${QLINK_INTEGRATION_REPORT:-/tmp/quantumlink-steamos-network-game-linux.json}"
SERVICE_DIR=/etc/systemd/system/qlinkd.service.d
DECK_UID=1000
IP_COMMAND="$(command -v ip)"
NFT_COMMAND="$(command -v nft)"

cleanup() {
    systemctl stop qlinkd.service >/dev/null 2>&1 || true
    "$NFT_COMMAND" delete table inet qlink >/dev/null 2>&1 || true
    "$IP_COMMAND" rule del fwmark 0x514c table 51820 >/dev/null 2>&1 || true
    "$IP_COMMAND" link delete dev qlink0 >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

[ -x /usr/local/bin/qlinkd ] || fail "qlinkd is not installed"
[ -x /usr/local/bin/qlinkctl ] || fail "qlinkctl is not installed"
[ -x /usr/local/libexec/quantumlink-service-control ] || \
    fail "service helper is not installed"
[ -f /etc/polkit-1/rules.d/49-quantumlink-service-control.rules ] || \
    fail "PolicyKit rule is not installed"

if /usr/local/libexec/quantumlink-service-control start unexpected >/dev/null 2>&1; then
    fail "service helper accepted extra arguments"
fi
if /usr/local/libexec/quantumlink-service-control enable >/dev/null 2>&1; then
    fail "service helper accepted an unsupported action"
fi

id deck >/dev/null 2>&1 || useradd --create-home --uid "$DECK_UID" --shell /bin/sh deck
id qlinkguest >/dev/null 2>&1 || useradd --create-home --shell /bin/sh qlinkguest
usermod -a -G quantumlink deck
install -m 0644 \
    /workspace/steam/steamos/tests/fixtures/40-quantumlink-service-control-integration.rules \
    /etc/polkit-1/rules.d/40-quantumlink-service-control-integration.rules

systemctl restart polkit.service
systemctl stop qlinkd.service >/dev/null 2>&1 || true

if runuser -u qlinkguest -- /usr/local/bin/qlinkctl service start \
    </dev/null >/tmp/qlink-guest-service.out 2>/tmp/qlink-guest-service.err; then
    fail "non-member user controlled qlinkd"
fi

run_authorized_service_action start
wait_for_path /run/quantumlink/qlinkd.sock 20 || fail "authenticated start did not create socket"
run_authorized_service_action restart
wait_for_path /run/quantumlink/qlinkd.sock 20 || fail "authenticated restart did not restore socket"
run_authorized_service_action stop
[ ! -S /run/quantumlink/qlinkd.sock ] || fail "authenticated stop left the socket active"

cat > /etc/quantumlink/games/proton-integration.toml <<'EOF'
id = "proton-integration"
display_name = "Proton Integration"
executables = ["proton"]
udp_ports = [27015]
lan_discovery = false
voice_chat_safe = true
low_latency = true
EOF

install -m 0755 /dev/stdin /usr/local/bin/factorio <<'EOF'
#!/bin/sh
cat "/proc/$$/cgroup" > /tmp/qlink-native-cgroup.txt
sleep 6
EOF
install -m 0755 /dev/stdin /usr/local/bin/game.exe <<'EOF'
#!/bin/sh
cat "/proc/$$/cgroup" > /tmp/qlink-proton-child-cgroup.txt
sleep 6
EOF
install -m 0755 /dev/stdin /usr/local/bin/proton <<'EOF'
#!/bin/sh
cat "/proc/$$/cgroup" > /tmp/qlink-proton-parent-cgroup.txt
/usr/local/bin/game.exe &
child=$!
wait "$child"
EOF

systemctl start qlinkd.service
wait_for_path /run/quantumlink/qlinkd.sock 20 || {
    systemctl status qlinkd.service --no-pager >&2 || true
    journalctl -u qlinkd.service --no-pager >&2 || true
    fail "planning service did not create socket"
}
/usr/local/bin/qlinkctl profile select factorio >/tmp/qlink-factorio-selected.json
systemctl stop qlinkd.service

rm -f "$SERVICE_DIR/10-planning-only.conf"
systemctl daemon-reload

[ -c /dev/net/tun ] || {
    install -d -m 0755 /dev/net
    mknod /dev/net/tun c 10 200
    chmod 0666 /dev/net/tun
}

run_authorized_service_action start
wait_for_path /run/quantumlink/qlinkd.sock 20 || {
    systemctl status qlinkd.service --no-pager >&2 || true
    journalctl -u qlinkd.service --no-pager >&2 || true
    fail "active service did not create socket"
}
wait_for_path /sys/class/net/qlink0 20 || {
    systemctl status qlinkd.service --no-pager >&2 || true
    journalctl -u qlinkd.service --no-pager >&2 || true
    fail "active service did not create qlink0"
}

"$IP_COMMAND" -details link show dev qlink0 > /tmp/qlink-active-link.txt
"$IP_COMMAND" -4 address show dev qlink0 > /tmp/qlink-active-address.txt
"$IP_COMMAND" rule show > /tmp/qlink-active-rules.txt
"$IP_COMMAND" route show table 51820 > /tmp/qlink-active-routes.txt
"$NFT_COMMAND" -a list table inet qlink > /tmp/qlink-active-nftables.txt
/usr/local/bin/qlinkctl status > /tmp/qlink-active-status.json

grep -Fq "100.64.10.2/32" /tmp/qlink-active-address.txt || fail "qlink0 address is missing"
grep -Eq "fwmark 0x0*514c.*lookup 51820" /tmp/qlink-active-rules.txt || \
    fail "QuantumLink policy rule is missing"
grep -Fq "100.64.0.0/10 dev qlink0" /tmp/qlink-active-routes.txt || \
    fail "QuantumLink route is missing"
grep -Fq "table inet qlink" /tmp/qlink-active-nftables.txt || \
    fail "QuantumLink nftables table is missing"
grep -Fq "meta mark != 0x0000514c drop" /tmp/qlink-active-nftables.txt || \
    fail "fail-closed nftables rule is missing"
assert_status /tmp/qlink-active-status.json armed factorio ""

NFT_CGROUP_STATUS=passed
NATIVE_GAME_STATUS=passed
PROTON_GAME_STATUS=passed
if nft_cgroup_v2_supported; then
    loginctl enable-linger deck
    systemctl start "user@$DECK_UID.service"
    wait_for_path "/run/user/$DECK_UID/bus" 20 || {
        systemctl status "user@$DECK_UID.service" --no-pager >&2 || true
        fail "deck user systemd manager did not start"
    }

    runuser -u deck -- env \
        XDG_RUNTIME_DIR="/run/user/$DECK_UID" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$DECK_UID/bus" \
        /usr/local/bin/qlinkctl game launch -- /usr/local/bin/factorio \
        >/tmp/qlink-native-launch.out 2>/tmp/qlink-native-launch.err &
    native_launch_pid=$!
    wait_for_path /tmp/qlink-native-cgroup.txt 20 || {
        cat /tmp/qlink-native-launch.err >&2 || true
        fail "native game did not enter the classified scope"
    }
    /usr/local/bin/qlinkctl status > /tmp/qlink-native-active-status.json
    "$NFT_COMMAND" -a list table inet qlink > /tmp/qlink-native-active-nftables.txt
    assert_status /tmp/qlink-native-active-status.json active factorio factorio
    grep -Fq "quantumlink-game-" /tmp/qlink-native-cgroup.txt || \
        fail "native game cgroup is not a QuantumLink scope"
    grep -Fq "socket cgroupv2" /tmp/qlink-native-active-nftables.txt || \
        fail "native cgroup nftables rules are missing"
    wait "$native_launch_pid" || {
        cat /tmp/qlink-native-launch.err >&2 || true
        fail "native game launch failed"
    }
    /usr/local/bin/qlinkctl status > /tmp/qlink-native-clean-status.json
    "$NFT_COMMAND" -a list table inet qlink > /tmp/qlink-native-clean-nftables.txt
    assert_status /tmp/qlink-native-clean-status.json armed factorio ""
    if grep -Fq "qlink-game-" /tmp/qlink-native-clean-nftables.txt; then
        fail "native game nftables rules remained after exit"
    fi

    /usr/local/bin/qlinkctl profile select proton-integration \
        > /tmp/qlink-proton-selected.json
    python3 - /tmp/qlink-proton-selected.json <<'PY'
import json
import sys

status = json.load(open(sys.argv[1], encoding="utf-8"))
assert status["portEnforcement"]["restartRequired"] is True
PY
    run_authorized_service_action restart
    wait_for_path /run/quantumlink/qlinkd.sock 20 || \
        fail "profile restart did not restore socket"

    runuser -u deck -- env \
        XDG_RUNTIME_DIR="/run/user/$DECK_UID" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$DECK_UID/bus" \
        /usr/local/bin/qlinkctl game launch -- /usr/local/bin/proton \
        >/tmp/qlink-proton-launch.out 2>/tmp/qlink-proton-launch.err &
    proton_launch_pid=$!
    wait_for_path /tmp/qlink-proton-child-cgroup.txt 20 || {
        cat /tmp/qlink-proton-launch.err >&2 || true
        fail "Proton-shaped child did not enter the classified scope"
    }
    /usr/local/bin/qlinkctl status > /tmp/qlink-proton-active-status.json
    "$NFT_COMMAND" -a list table inet qlink > /tmp/qlink-proton-active-nftables.txt
    assert_status /tmp/qlink-proton-active-status.json active proton-integration proton
    cmp -s /tmp/qlink-proton-parent-cgroup.txt /tmp/qlink-proton-child-cgroup.txt || \
        fail "Proton-shaped child left the classified cgroup"
    grep -Fq "quantumlink-game-" /tmp/qlink-proton-child-cgroup.txt || \
        fail "Proton-shaped child cgroup is not a QuantumLink scope"
    grep -Fq "udp dport 27015" /tmp/qlink-proton-active-nftables.txt || \
        fail "Proton-shaped destination-port rule is missing"
    grep -Fq "udp sport 27015" /tmp/qlink-proton-active-nftables.txt || \
        fail "Proton-shaped source-port rule is missing"
    wait "$proton_launch_pid" || {
        cat /tmp/qlink-proton-launch.err >&2 || true
        fail "Proton-shaped game launch failed"
    }
    /usr/local/bin/qlinkctl status > /tmp/qlink-proton-clean-status.json
    "$NFT_COMMAND" -a list table inet qlink > /tmp/qlink-proton-clean-nftables.txt
    assert_status /tmp/qlink-proton-clean-status.json armed proton-integration ""
    if grep -Fq "qlink-game-" /tmp/qlink-proton-clean-nftables.txt; then
        fail "Proton-shaped nftables rules remained after exit"
    fi
else
    NFT_CGROUP_STATUS=blocked
    NATIVE_GAME_STATUS=blocked
    PROTON_GAME_STATUS=blocked
fi

run_authorized_service_action stop
[ ! -e /sys/class/net/qlink0 ] || fail "qlink0 remained after service stop"
if "$NFT_COMMAND" list table inet qlink >/dev/null 2>&1; then
    fail "QuantumLink nftables table remained after service stop"
fi
if "$IP_COMMAND" rule show | grep -Eq "fwmark 0x0*514c.*lookup 51820"; then
    fail "QuantumLink policy rule remained after service stop"
fi
[ ! -e /var/lib/quantumlink/network-ownership.json ] || \
    fail "network ownership record remained after service stop"

REPORT="$REPORT" \
NFT_CGROUP_STATUS="$NFT_CGROUP_STATUS" \
NATIVE_GAME_STATUS="$NATIVE_GAME_STATUS" \
PROTON_GAME_STATUS="$PROTON_GAME_STATUS" \
python3 - <<'PY'
import json
import os
import pathlib
import platform
import subprocess

report = {
    "schemaVersion": 1,
    "hostClass": "privileged-linux-container",
    "kernel": platform.release(),
    "systemd": subprocess.check_output(
        ["systemctl", "--version"], text=True
    ).splitlines()[0],
    "cgroupVersion": "v2",
    "checks": {
        "scopedServiceHelper": "passed",
        "policyKitGroupAuthorization": "passed",
        "policyKitInteractiveAuthentication": "blocked",
        "policyKitNonMemberDenied": "passed",
        "activeTunAddress": "passed",
        "activePolicyRoute": "passed",
        "activeNftablesFailClosed": "passed",
        "nftCgroupV2KernelSupport": os.environ["NFT_CGROUP_STATUS"],
        "nativeGameCgroupClassification": os.environ["NATIVE_GAME_STATUS"],
        "nativeGameRuleCleanup": os.environ["NATIVE_GAME_STATUS"],
        "protonDescendantCgroupClassification": os.environ["PROTON_GAME_STATUS"],
        "protonGameRuleCleanup": os.environ["PROTON_GAME_STATUS"],
        "ownedNetworkTeardown": "passed",
    },
    "productionReady": False,
    "notProductionReady": True,
    "limitations": [
        "Docker Desktop Linux VM is not Steam Deck hardware",
        "Docker has no logind session, so the production AUTH_ADMIN_KEEP prompt remains unproved",
        "A test-only PolicyKit rule granted the same helper and group boundary without a prompt",
        "Proton behavior used shell fixtures, not Valve Proton or a Windows game",
        "No two-Deck packet, suspend, voice, anti-cheat, or compatibility proof was run",
    ],
}
if os.environ["NFT_CGROUP_STATUS"] == "blocked":
    report["limitations"].append(
        "Docker Desktop kernel lacks nftables socket cgroupv2 support, so native and Proton classification remain blocked"
    )
path = pathlib.Path(os.environ["REPORT"])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(report, indent=2) + "\n")
print(path)
PY

echo "Linux network-game integration completed: $REPORT"
