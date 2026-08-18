#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STEAMOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER="$STEAMOS_ROOT/scripts/install-steamos.sh"
PACKAGER="$STEAMOS_ROOT/scripts/package-steamos.sh"
VERIFIER="$STEAMOS_ROOT/scripts/verify-steamos-release.sh"

TMP_ROOT="$(mktemp -d)"
TMP_ROOT="$(cd "$TMP_ROOT" && pwd -P)"
cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_file() {
    [ -f "$1" ] || fail "expected file: $1"
}

assert_dir() {
    [ -d "$1" ] || fail "expected directory: $1"
}

assert_executable() {
    [ -x "$1" ] || fail "expected executable: $1"
}

assert_contains() {
    file="$1"
    needle="$2"
    grep -F "$needle" "$file" >/dev/null || fail "expected '$needle' in $file"
}

assert_not_contains() {
    file="$1"
    needle="$2"
    if grep -F "$needle" "$file" >/dev/null; then
        fail "did not expect '$needle' in $file"
    fi
}

assert_path_absent() {
    [ ! -e "$1" ] || fail "expected path to be absent: $1"
}

PREFIX="$TMP_ROOT/prefix"
DESTDIR="$TMP_ROOT/destdir"
FAKEBIN="$TMP_ROOT/fakebin"
NO_INSTALL_BIN="$TMP_ROOT/no-install-bin"
MUTATING_INSTALL_BIN="$TMP_ROOT/mutating-install-bin"
REAL_INSTALL="$(command -v install)"
mkdir -p "$PREFIX/bin" "$FAKEBIN" "$NO_INSTALL_BIN" "$MUTATING_INSTALL_BIN"

cat > "$PREFIX/bin/qlinkd" <<'EOF'
#!/usr/bin/env sh
echo fake qlinkd "$@"
EOF
cat > "$PREFIX/bin/qlinkctl" <<'EOF'
#!/usr/bin/env sh
echo fake qlinkctl "$@"
EOF
cat > "$PREFIX/bin/qlink-desktop" <<'EOF'
#!/usr/bin/env sh
echo fake qlink-desktop "$@"
EOF
chmod 0755 "$PREFIX/bin/qlinkd" "$PREFIX/bin/qlinkctl" "$PREFIX/bin/qlink-desktop"

cat > "$FAKEBIN/id" <<'EOF'
#!/usr/bin/env sh
if [ "$1" = "-u" ]; then
    echo 1000
else
    /usr/bin/id "$@"
fi
EOF
chmod 0755 "$FAKEBIN/id"

cat > "$NO_INSTALL_BIN/install" <<'EOF'
#!/usr/bin/env sh
echo "install should not be called before DESTDIR root rejection" >&2
exit 97
EOF
chmod 0755 "$NO_INSTALL_BIN/install"

cat > "$MUTATING_INSTALL_BIN/install" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

"$REAL_INSTALL" "$@"

if [ "${MUTATE_MARKER:-}" ] && [ ! -e "$MUTATE_MARKER" ] && [ "$#" -ge 4 ]; then
    last_arg="${@: -1}"
    if [ "$1" = "-d" ] && [ "$last_arg" = "${MUTATE_AFTER_DIR:-}" ]; then
        mkdir -p "$(dirname "$MUTATE_MARKER")" "$MUTATE_TARGET"
        rm -rf "$MUTATE_LINK"
        ln -s "$MUTATE_TARGET" "$MUTATE_LINK"
        : > "$MUTATE_MARKER"
    fi
fi
EOF
chmod 0755 "$MUTATING_INSTALL_BIN/install"

BINDIR="/opt/quantumlink/bin"
SYSD_UNIT_DIR="/usr/lib/systemd/system"
CONFIG_DIR="/etc/quantumlink"
STATE_DIR="/var/lib/quantumlink"
APPLICATIONS_DIR="/usr/share/applications"
ICON_DIR="/usr/share/icons/hicolor/256x256/apps"

PATH="$FAKEBIN:$PATH" \
PREFIX="$PREFIX" \
DESTDIR="$DESTDIR" \
BINDIR="$BINDIR" \
SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
CONFIG_DIR="$CONFIG_DIR" \
STATE_DIR="$STATE_DIR" \
APPLICATIONS_DIR="$APPLICATIONS_DIR" \
ICON_DIR="$ICON_DIR" \
bash "$INSTALLER" >"$TMP_ROOT/install.out"

UNIT="$DESTDIR$SYSD_UNIT_DIR/qlinkd.service"
SAMPLE="$DESTDIR$SYSD_UNIT_DIR/qlinkd.service.d/planning-only.conf.sample"
LIVE_DROPIN="$DESTDIR$SYSD_UNIT_DIR/qlinkd.service.d/10-planning-only.conf"

assert_executable "$DESTDIR$BINDIR/qlinkd"
assert_executable "$DESTDIR$BINDIR/qlinkctl"
assert_executable "$DESTDIR$BINDIR/qlink-desktop"
assert_file "$DESTDIR$APPLICATIONS_DIR/quantumlink-steamos.desktop"
assert_file "$DESTDIR$APPLICATIONS_DIR/quantumlink-steamos-game-mode.desktop"
assert_file "$DESTDIR$ICON_DIR/quantumlink-steamos.png"
assert_executable "$DESTDIR/usr/local/libexec/quantumlink-service-control"
assert_file "$DESTDIR/etc/polkit-1/rules.d/49-quantumlink-service-control.rules"
assert_contains "$DESTDIR$APPLICATIONS_DIR/quantumlink-steamos.desktop" "Exec=$BINDIR/qlink-desktop"
assert_contains "$DESTDIR$APPLICATIONS_DIR/quantumlink-steamos-game-mode.desktop" "Exec=$BINDIR/qlink-desktop --game-mode"
assert_contains "$DESTDIR$APPLICATIONS_DIR/quantumlink-steamos.desktop" "Icon=quantumlink-steamos"
assert_file "$UNIT"
assert_file "$SAMPLE"
[ ! -e "$LIVE_DROPIN" ] || fail "default install must not enable planning-only drop-in"
assert_dir "$DESTDIR$CONFIG_DIR"
assert_dir "$DESTDIR$CONFIG_DIR/secrets"
assert_dir "$DESTDIR$STATE_DIR"
assert_file "$DESTDIR$CONFIG_DIR/steam-bypass.toml"
assert_dir "$DESTDIR$CONFIG_DIR/games"
assert_file "$DESTDIR$CONFIG_DIR/games/factorio.toml"
assert_contains "$DESTDIR$CONFIG_DIR/steam-bypass.toml" "bypass_categories"
assert_contains "$DESTDIR/usr/local/libexec/quantumlink-service-control" \
    'exec /usr/bin/systemctl "$1" qlinkd.service'
assert_contains "$DESTDIR/etc/polkit-1/rules.d/49-quantumlink-service-control.rules" \
    'polkit.Result.AUTH_ADMIN_KEEP'

assert_contains "$UNIT" "ExecStart=$BINDIR/qlinkd --activate-network"
assert_contains "$UNIT" "ExecStop=$BINDIR/qlinkd --deactivate-network"
assert_contains "$UNIT" "ExecStopPost=$BINDIR/qlinkd --deactivate-network"
assert_contains "$UNIT" "RuntimeDirectoryMode=0750"
assert_contains "$UNIT" "StateDirectoryMode=0750"
assert_contains "$UNIT" "ConfigurationDirectoryMode=0750"
assert_contains "$SAMPLE" "ExecStart="
assert_contains "$SAMPLE" "ExecStart=$BINDIR/qlinkd"

BROKEN_ROOT="$TMP_ROOT/broken-steamos"
BROKEN_DESTDIR="$TMP_ROOT/broken-destdir"
mkdir -p "$BROKEN_ROOT/scripts" "$BROKEN_ROOT/packaging/systemd/qlinkd.service.d" \
    "$BROKEN_ROOT/packaging/desktop/icons" "$BROKEN_ROOT/packaging/libexec" \
    "$BROKEN_ROOT/packaging/polkit"
cp "$INSTALLER" "$BROKEN_ROOT/scripts/install-steamos.sh"
cp "$STEAMOS_ROOT/packaging/systemd/qlinkd.service" "$BROKEN_ROOT/packaging/systemd/qlinkd.service"
cp "$STEAMOS_ROOT/packaging/systemd/qlinkd.service.d/planning-only.conf.sample" \
    "$BROKEN_ROOT/packaging/systemd/qlinkd.service.d/planning-only.conf.sample"
cp "$STEAMOS_ROOT/packaging/desktop/quantumlink-steamos.desktop" \
    "$BROKEN_ROOT/packaging/desktop/quantumlink-steamos.desktop"
cp "$STEAMOS_ROOT/packaging/desktop/quantumlink-steamos-game-mode.desktop" \
    "$BROKEN_ROOT/packaging/desktop/quantumlink-steamos-game-mode.desktop"
cp "$STEAMOS_ROOT/packaging/desktop/icons/quantumlink-steamos.png" \
    "$BROKEN_ROOT/packaging/desktop/icons/quantumlink-steamos.png"
cp "$STEAMOS_ROOT/packaging/libexec/quantumlink-service-control" \
    "$BROKEN_ROOT/packaging/libexec/quantumlink-service-control"
cp "$STEAMOS_ROOT/packaging/polkit/49-quantumlink-service-control.rules" \
    "$BROKEN_ROOT/packaging/polkit/49-quantumlink-service-control.rules"
sed -i.bak "s#ExecStart=/usr/local/bin/qlinkd --activate-network#ExecStart=/usr/local/bin/qlinkd#" \
    "$BROKEN_ROOT/packaging/systemd/qlinkd.service"
if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$BROKEN_DESTDIR" \
    BINDIR="$BINDIR" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR="$STATE_DIR" \
    bash "$BROKEN_ROOT/scripts/install-steamos.sh" >"$TMP_ROOT/broken.out" 2>"$TMP_ROOT/broken.err"; then
    fail "expected planning-only base ExecStart to fail installer validation"
fi
assert_contains "$TMP_ROOT/broken.err" "validation failed"

if PATH="$NO_INSTALL_BIN:$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="/" \
    BINDIR="$TMP_ROOT/slash-destdir-bin" \
    SYSD_UNIT_DIR="$TMP_ROOT/slash-destdir-systemd" \
    CONFIG_DIR="$TMP_ROOT/slash-destdir-config" \
    STATE_DIR="$TMP_ROOT/slash-destdir-state" \
    bash "$INSTALLER" >"$TMP_ROOT/slash-destdir.out" 2>"$TMP_ROOT/slash-destdir.err"; then
    fail "expected DESTDIR=/ install to be rejected"
fi
assert_contains "$TMP_ROOT/slash-destdir.err" "DESTDIR resolves to the live root"
assert_not_contains "$TMP_ROOT/slash-destdir.err" "install should not be called"

if PATH="$NO_INSTALL_BIN:$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="/./" \
    BINDIR="$TMP_ROOT/slash-dot-destdir-bin" \
    SYSD_UNIT_DIR="$TMP_ROOT/slash-dot-destdir-systemd" \
    CONFIG_DIR="$TMP_ROOT/slash-dot-destdir-config" \
    STATE_DIR="$TMP_ROOT/slash-dot-destdir-state" \
    bash "$INSTALLER" >"$TMP_ROOT/slash-dot-destdir.out" 2>"$TMP_ROOT/slash-dot-destdir.err"; then
    fail "expected DESTDIR=/./ install to be rejected"
fi
assert_contains "$TMP_ROOT/slash-dot-destdir.err" "DESTDIR resolves to the live root"
assert_not_contains "$TMP_ROOT/slash-dot-destdir.err" "install should not be called"

if PATH="$NO_INSTALL_BIN:$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="//" \
    BINDIR="$TMP_ROOT/double-slash-destdir-bin" \
    SYSD_UNIT_DIR="$TMP_ROOT/double-slash-destdir-systemd" \
    CONFIG_DIR="$TMP_ROOT/double-slash-destdir-config" \
    STATE_DIR="$TMP_ROOT/double-slash-destdir-state" \
    bash "$INSTALLER" >"$TMP_ROOT/double-slash-destdir.out" 2>"$TMP_ROOT/double-slash-destdir.err"; then
    fail "expected DESTDIR=// install to be rejected"
fi
assert_contains "$TMP_ROOT/double-slash-destdir.err" "DESTDIR resolves to the live root"
assert_not_contains "$TMP_ROOT/double-slash-destdir.err" "install should not be called"

ROOT_SYMLINK_DESTDIR="$TMP_ROOT/root-symlink-destdir"
ln -s / "$ROOT_SYMLINK_DESTDIR"
if PATH="$NO_INSTALL_BIN:$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$ROOT_SYMLINK_DESTDIR" \
    BINDIR="$TMP_ROOT/root-symlink-destdir-bin" \
    SYSD_UNIT_DIR="$TMP_ROOT/root-symlink-destdir-systemd" \
    CONFIG_DIR="$TMP_ROOT/root-symlink-destdir-config" \
    STATE_DIR="$TMP_ROOT/root-symlink-destdir-state" \
    bash "$INSTALLER" >"$TMP_ROOT/root-symlink-destdir.out" 2>"$TMP_ROOT/root-symlink-destdir.err"; then
    fail "expected DESTDIR symlink to / install to be rejected"
fi
assert_contains "$TMP_ROOT/root-symlink-destdir.err" "DESTDIR resolves to the live root"
assert_not_contains "$TMP_ROOT/root-symlink-destdir.err" "install should not be called"

SYMLINK_PARENT_OUTSIDE="$TMP_ROOT/symlink-parent-outside"
SYMLINK_PARENT_LINK="$TMP_ROOT/symlink-parent"
mkdir -p "$SYMLINK_PARENT_OUTSIDE"
ln -s "$SYMLINK_PARENT_OUTSIDE" "$SYMLINK_PARENT_LINK"
if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$SYMLINK_PARENT_LINK/new-stage" \
    BINDIR="$BINDIR" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR="$STATE_DIR" \
    bash "$INSTALLER" >"$TMP_ROOT/symlink-parent-destdir.out" 2>"$TMP_ROOT/symlink-parent-destdir.err"; then
    if [ -e "$SYMLINK_PARENT_OUTSIDE/new-stage" ]; then
        fail "symlinked parent DESTDIR escaped staging root: $SYMLINK_PARENT_OUTSIDE/new-stage"
    fi
    fail "expected symlinked parent DESTDIR to be rejected"
fi
assert_contains "$TMP_ROOT/symlink-parent-destdir.err" "DESTDIR contains symlink component"
assert_path_absent "$SYMLINK_PARENT_OUTSIDE/new-stage"

SYMLINK_INTERMEDIATE_ROOT="$TMP_ROOT/symlink-intermediate-root"
SYMLINK_INTERMEDIATE_OUTSIDE="$TMP_ROOT/symlink-intermediate-outside"
mkdir -p "$SYMLINK_INTERMEDIATE_ROOT" "$SYMLINK_INTERMEDIATE_OUTSIDE"
ln -s "$SYMLINK_INTERMEDIATE_OUTSIDE" "$SYMLINK_INTERMEDIATE_ROOT/link"
if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$SYMLINK_INTERMEDIATE_ROOT/link/new-stage" \
    BINDIR="$BINDIR" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR="$STATE_DIR" \
    bash "$INSTALLER" >"$TMP_ROOT/symlink-intermediate-destdir.out" 2>"$TMP_ROOT/symlink-intermediate-destdir.err"; then
    if [ -e "$SYMLINK_INTERMEDIATE_OUTSIDE/new-stage" ]; then
        fail "symlinked intermediate DESTDIR escaped staging root: $SYMLINK_INTERMEDIATE_OUTSIDE/new-stage"
    fi
    fail "expected symlinked intermediate DESTDIR to be rejected"
fi
assert_contains "$TMP_ROOT/symlink-intermediate-destdir.err" "DESTDIR contains symlink component"
assert_path_absent "$SYMLINK_INTERMEDIATE_OUTSIDE/new-stage"

TARGET_SYMLINK_ROOT="$TMP_ROOT/target-symlink"
mkdir -p "$TARGET_SYMLINK_ROOT"

TARGET_SYMLINK_BINDIR_STAGE="$TARGET_SYMLINK_ROOT/bindir-stage"
TARGET_SYMLINK_BINDIR_OUTSIDE="$TARGET_SYMLINK_ROOT/bindir-outside"
mkdir -p "$TARGET_SYMLINK_BINDIR_STAGE" "$TARGET_SYMLINK_BINDIR_OUTSIDE"
ln -s "$TARGET_SYMLINK_BINDIR_OUTSIDE" "$TARGET_SYMLINK_BINDIR_STAGE/opt"
if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$TARGET_SYMLINK_BINDIR_STAGE" \
    BINDIR="$BINDIR" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR="$STATE_DIR" \
    bash "$INSTALLER" >"$TMP_ROOT/target-symlink-bindir.out" 2>"$TMP_ROOT/target-symlink-bindir.err"; then
    if [ -e "$TARGET_SYMLINK_BINDIR_OUTSIDE/quantumlink" ]; then
        fail "inside DESTDIR BINDIR symlink escaped staging root: $TARGET_SYMLINK_BINDIR_OUTSIDE/quantumlink"
    fi
    fail "expected inside DESTDIR BINDIR symlink to be rejected"
fi
assert_contains "$TMP_ROOT/target-symlink-bindir.err" "BINDIR target contains symlink component"
assert_path_absent "$TARGET_SYMLINK_BINDIR_OUTSIDE/quantumlink"

TARGET_SYMLINK_SYSTEMD_STAGE="$TARGET_SYMLINK_ROOT/systemd-stage"
TARGET_SYMLINK_SYSTEMD_OUTSIDE="$TARGET_SYMLINK_ROOT/systemd-outside"
mkdir -p "$TARGET_SYMLINK_SYSTEMD_STAGE" "$TARGET_SYMLINK_SYSTEMD_OUTSIDE"
ln -s "$TARGET_SYMLINK_SYSTEMD_OUTSIDE" "$TARGET_SYMLINK_SYSTEMD_STAGE/usr"
if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$TARGET_SYMLINK_SYSTEMD_STAGE" \
    BINDIR="$BINDIR" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR="$STATE_DIR" \
    bash "$INSTALLER" >"$TMP_ROOT/target-symlink-systemd.out" 2>"$TMP_ROOT/target-symlink-systemd.err"; then
    if [ -e "$TARGET_SYMLINK_SYSTEMD_OUTSIDE/lib" ]; then
        fail "inside DESTDIR SYSD_UNIT_DIR symlink escaped staging root: $TARGET_SYMLINK_SYSTEMD_OUTSIDE/lib"
    fi
    fail "expected inside DESTDIR SYSD_UNIT_DIR symlink to be rejected"
fi
assert_contains "$TMP_ROOT/target-symlink-systemd.err" "SYSD_UNIT_DIR target contains symlink component"
assert_path_absent "$TARGET_SYMLINK_SYSTEMD_OUTSIDE/lib"

TARGET_SYMLINK_CONFIG_STAGE="$TARGET_SYMLINK_ROOT/config-stage"
TARGET_SYMLINK_CONFIG_OUTSIDE="$TARGET_SYMLINK_ROOT/config-outside"
mkdir -p "$TARGET_SYMLINK_CONFIG_STAGE" "$TARGET_SYMLINK_CONFIG_OUTSIDE"
ln -s "$TARGET_SYMLINK_CONFIG_OUTSIDE" "$TARGET_SYMLINK_CONFIG_STAGE/etc"
if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$TARGET_SYMLINK_CONFIG_STAGE" \
    BINDIR="$BINDIR" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR="$STATE_DIR" \
    bash "$INSTALLER" >"$TMP_ROOT/target-symlink-config.out" 2>"$TMP_ROOT/target-symlink-config.err"; then
    if [ -e "$TARGET_SYMLINK_CONFIG_OUTSIDE/quantumlink" ]; then
        fail "inside DESTDIR CONFIG_DIR symlink escaped staging root: $TARGET_SYMLINK_CONFIG_OUTSIDE/quantumlink"
    fi
    fail "expected inside DESTDIR CONFIG_DIR symlink to be rejected"
fi
assert_contains "$TMP_ROOT/target-symlink-config.err" "CONFIG_DIR target contains symlink component"
assert_path_absent "$TARGET_SYMLINK_CONFIG_OUTSIDE/quantumlink"

TARGET_SYMLINK_STATE_STAGE="$TARGET_SYMLINK_ROOT/state-stage"
TARGET_SYMLINK_STATE_OUTSIDE="$TARGET_SYMLINK_ROOT/state-outside"
mkdir -p "$TARGET_SYMLINK_STATE_STAGE" "$TARGET_SYMLINK_STATE_OUTSIDE"
ln -s "$TARGET_SYMLINK_STATE_OUTSIDE" "$TARGET_SYMLINK_STATE_STAGE/var"
if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$TARGET_SYMLINK_STATE_STAGE" \
    BINDIR="$BINDIR" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR="$STATE_DIR" \
    bash "$INSTALLER" >"$TMP_ROOT/target-symlink-state.out" 2>"$TMP_ROOT/target-symlink-state.err"; then
    if [ -e "$TARGET_SYMLINK_STATE_OUTSIDE/lib" ]; then
        fail "inside DESTDIR STATE_DIR symlink escaped staging root: $TARGET_SYMLINK_STATE_OUTSIDE/lib"
    fi
    fail "expected inside DESTDIR STATE_DIR symlink to be rejected"
fi
assert_contains "$TMP_ROOT/target-symlink-state.err" "STATE_DIR target contains symlink component"
assert_path_absent "$TARGET_SYMLINK_STATE_OUTSIDE/lib"

STALE_SYMLINK_ROOT="$TMP_ROOT/stale-symlink"
mkdir -p "$STALE_SYMLINK_ROOT"

STALE_DESTDIR_STAGE="$STALE_SYMLINK_ROOT/destdir-stage"
STALE_DESTDIR_OUTSIDE="$STALE_SYMLINK_ROOT/destdir-outside"
if PATH="$MUTATING_INSTALL_BIN:$FAKEBIN:$PATH" \
    REAL_INSTALL="$REAL_INSTALL" \
    MUTATE_MARKER="$TMP_ROOT/stale-destdir.marker" \
    MUTATE_AFTER_DIR="$STALE_DESTDIR_STAGE" \
    MUTATE_LINK="$STALE_DESTDIR_STAGE" \
    MUTATE_TARGET="$STALE_DESTDIR_OUTSIDE" \
    PREFIX="$PREFIX" \
    DESTDIR="$STALE_DESTDIR_STAGE" \
    BINDIR="$BINDIR" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR="$STATE_DIR" \
    bash "$INSTALLER" >"$TMP_ROOT/stale-destdir.out" 2>"$TMP_ROOT/stale-destdir.err"; then
    if [ -e "$STALE_DESTDIR_OUTSIDE/opt" ]; then
        fail "post-validation DESTDIR symlink escaped staging root: $STALE_DESTDIR_OUTSIDE/opt"
    fi
    fail "expected post-validation DESTDIR symlink to be rejected"
fi
assert_contains "$TMP_ROOT/stale-destdir.err" "DESTDIR contains symlink component"
assert_path_absent "$STALE_DESTDIR_OUTSIDE/opt"

STALE_BINDIR_STAGE="$STALE_SYMLINK_ROOT/bindir-stage"
STALE_BINDIR_OUTSIDE="$STALE_SYMLINK_ROOT/bindir-outside"
mkdir -p "$STALE_BINDIR_STAGE"
if PATH="$MUTATING_INSTALL_BIN:$FAKEBIN:$PATH" \
    REAL_INSTALL="$REAL_INSTALL" \
    MUTATE_MARKER="$TMP_ROOT/stale-bindir.marker" \
    MUTATE_AFTER_DIR="$STALE_BINDIR_STAGE$BINDIR" \
    MUTATE_LINK="$STALE_BINDIR_STAGE/opt" \
    MUTATE_TARGET="$STALE_BINDIR_OUTSIDE" \
    PREFIX="$PREFIX" \
    DESTDIR="$STALE_BINDIR_STAGE" \
    BINDIR="$BINDIR" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR="$STATE_DIR" \
    bash "$INSTALLER" >"$TMP_ROOT/stale-bindir.out" 2>"$TMP_ROOT/stale-bindir.err"; then
    if [ -e "$STALE_BINDIR_OUTSIDE/quantumlink/bin/qlinkd" ]; then
        fail "post-validation BINDIR symlink escaped staging root: $STALE_BINDIR_OUTSIDE/quantumlink/bin/qlinkd"
    fi
    fail "expected post-validation BINDIR symlink to be rejected"
fi
assert_contains "$TMP_ROOT/stale-bindir.err" "BINDIR target contains symlink component"
assert_path_absent "$STALE_BINDIR_OUTSIDE/quantumlink/bin/qlinkd"

if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$TMP_ROOT/bad-bindir-destdir" \
    BINDIR="/opt/quantum link/bin" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR="$STATE_DIR" \
    bash "$INSTALLER" >"$TMP_ROOT/bad-bindir-space.out" 2>"$TMP_ROOT/bad-bindir-space.err"; then
    fail "expected whitespace BINDIR to be rejected"
fi
assert_contains "$TMP_ROOT/bad-bindir-space.err" "BINDIR contains characters"

if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$TMP_ROOT/bad-bindir-percent-destdir" \
    BINDIR="/opt/quantum%link/bin" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR="$STATE_DIR" \
    bash "$INSTALLER" >"$TMP_ROOT/bad-bindir-percent.out" 2>"$TMP_ROOT/bad-bindir-percent.err"; then
    fail "expected percent BINDIR to be rejected"
fi
assert_contains "$TMP_ROOT/bad-bindir-percent.err" "BINDIR contains characters"

TRAVERSAL_ROOT="$TMP_ROOT/traversal"
mkdir -p "$TRAVERSAL_ROOT"

if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$TRAVERSAL_ROOT/bindir-stage" \
    BINDIR="/../escape/bin" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR="$STATE_DIR" \
    bash "$INSTALLER" >"$TMP_ROOT/traversal-bindir.out" 2>"$TMP_ROOT/traversal-bindir.err"; then
    fail "expected traversal BINDIR to be rejected"
fi
assert_contains "$TMP_ROOT/traversal-bindir.err" "BINDIR contains invalid path component"
assert_path_absent "$TRAVERSAL_ROOT/escape"

if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$TRAVERSAL_ROOT/systemd-stage" \
    BINDIR="$BINDIR" \
    SYSD_UNIT_DIR="/../escape-systemd" \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR="$STATE_DIR" \
    bash "$INSTALLER" >"$TMP_ROOT/traversal-systemd.out" 2>"$TMP_ROOT/traversal-systemd.err"; then
    fail "expected traversal SYSD_UNIT_DIR to be rejected"
fi
assert_contains "$TMP_ROOT/traversal-systemd.err" "SYSD_UNIT_DIR contains invalid path component"
assert_path_absent "$TRAVERSAL_ROOT/escape-systemd"

if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$TRAVERSAL_ROOT/config-stage" \
    BINDIR="$BINDIR" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR="/../escape-config" \
    STATE_DIR="$STATE_DIR" \
    bash "$INSTALLER" >"$TMP_ROOT/traversal-config.out" 2>"$TMP_ROOT/traversal-config.err"; then
    fail "expected traversal CONFIG_DIR to be rejected"
fi
assert_contains "$TMP_ROOT/traversal-config.err" "CONFIG_DIR contains invalid path component"
assert_path_absent "$TRAVERSAL_ROOT/escape-config"

if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$TRAVERSAL_ROOT/state-stage" \
    BINDIR="$BINDIR" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR="/../escape-state" \
    bash "$INSTALLER" >"$TMP_ROOT/traversal-state.out" 2>"$TMP_ROOT/traversal-state.err"; then
    fail "expected traversal STATE_DIR to be rejected"
fi
assert_contains "$TMP_ROOT/traversal-state.err" "STATE_DIR contains invalid path component"
assert_path_absent "$TRAVERSAL_ROOT/escape-state"

NEWLINE_TRAVERSAL_ROOT="$TMP_ROOT/newline-traversal"
mkdir -p "$NEWLINE_TRAVERSAL_ROOT"

if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$NEWLINE_TRAVERSAL_ROOT/systemd-stage" \
    BINDIR="$BINDIR" \
    SYSD_UNIT_DIR=$'/safe\n/../../escape-systemd' \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR="$STATE_DIR" \
    bash "$INSTALLER" >"$TMP_ROOT/newline-traversal-systemd.out" 2>"$TMP_ROOT/newline-traversal-systemd.err"; then
    fail "expected newline traversal SYSD_UNIT_DIR to be rejected"
fi
assert_contains "$TMP_ROOT/newline-traversal-systemd.err" "SYSD_UNIT_DIR contains invalid path component"
assert_path_absent "$NEWLINE_TRAVERSAL_ROOT/escape-systemd"

if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$NEWLINE_TRAVERSAL_ROOT/config-stage" \
    BINDIR="$BINDIR" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR=$'/safe\n/../../escape-config' \
    STATE_DIR="$STATE_DIR" \
    bash "$INSTALLER" >"$TMP_ROOT/newline-traversal-config.out" 2>"$TMP_ROOT/newline-traversal-config.err"; then
    fail "expected newline traversal CONFIG_DIR to be rejected"
fi
assert_contains "$TMP_ROOT/newline-traversal-config.err" "CONFIG_DIR contains invalid path component"
assert_path_absent "$NEWLINE_TRAVERSAL_ROOT/escape-config"

if PATH="$FAKEBIN:$PATH" \
    PREFIX="$PREFIX" \
    DESTDIR="$NEWLINE_TRAVERSAL_ROOT/state-stage" \
    BINDIR="$BINDIR" \
    SYSD_UNIT_DIR="$SYSD_UNIT_DIR" \
    CONFIG_DIR="$CONFIG_DIR" \
    STATE_DIR=$'/safe\n/../../escape-state' \
    bash "$INSTALLER" >"$TMP_ROOT/newline-traversal-state.out" 2>"$TMP_ROOT/newline-traversal-state.err"; then
    fail "expected newline traversal STATE_DIR to be rejected"
fi
assert_contains "$TMP_ROOT/newline-traversal-state.err" "STATE_DIR contains invalid path component"
assert_path_absent "$NEWLINE_TRAVERSAL_ROOT/escape-state"

if PATH="$FAKEBIN:$PATH" PREFIX="$PREFIX" BINDIR="$BINDIR" bash "$INSTALLER" >"$TMP_ROOT/live.out" 2>"$TMP_ROOT/live.err"; then
    fail "expected live non-root install without DESTDIR to be rejected"
fi
assert_contains "$TMP_ROOT/live.err" "must run as root"

PACKAGE_DIST="$TMP_ROOT/package-dist"
QLINK_STEAMOS_VERSION="9.9.9-test" \
QLINK_STEAMOS_OUTPUT_DIR="$PACKAGE_DIST" \
QLINK_STEAMOS_BIN_DIR="$PREFIX/bin" \
QLINK_STEAMOS_SKIP_BUILD=1 \
    bash "$PACKAGER" >"$TMP_ROOT/package.out" 2>"$TMP_ROOT/package.err"

PACKAGE_ROOT="$PACKAGE_DIST/quantumlink-steamos-9.9.9-test"
PACKAGE_ARCHIVE="$PACKAGE_DIST/quantumlink-steamos-9.9.9-test.tar.zst"
assert_file "$PACKAGE_ARCHIVE"
assert_file "$PACKAGE_ROOT/SHA256SUMS.txt"
assert_file "$PACKAGE_ROOT/SBOM.spdx.json"
assert_file "$PACKAGE_ROOT/release-manifest.json"
assert_file "$PACKAGE_ROOT/verify-report.json"

assert_contains "$PACKAGE_ROOT/SHA256SUMS.txt" "quantumlink-steamos-9.9.9-test.tar.zst"
assert_contains "$PACKAGE_ROOT/release-manifest.json" '"product":"QuantumLink SteamOS"'
assert_contains "$PACKAGE_ROOT/release-manifest.json" '"platform":"steamos"'
assert_contains "$PACKAGE_ROOT/release-manifest.json" '"mode":"dev-classical"'
assert_contains "$PACKAGE_ROOT/release-manifest.json" '"productionMode":false'
assert_not_contains "$PACKAGE_ROOT/release-manifest.json" '"productionReady"'
assert_contains "$PACKAGE_ROOT/verify-report.json" '"notProductionReady":true'
assert_contains "$PACKAGE_ROOT/verify-report.json" '"requireProductionReady":false'
assert_contains "$PACKAGE_ROOT/verify-report.json" '"signatureMode":"dev-classical"'
assert_contains "$PACKAGE_ROOT/verify-report.json" '"signatureValidated":false'

VERIFY_REPORT="$TMP_ROOT/standalone-verify-report.json" \
    bash "$VERIFIER" "$PACKAGE_ARCHIVE" >"$TMP_ROOT/verify.out" 2>"$TMP_ROOT/verify.err"
assert_file "$TMP_ROOT/standalone-verify-report.json"
assert_contains "$TMP_ROOT/standalone-verify-report.json" '"notProductionReady":true'

echo "install-steamos-test: ok"
