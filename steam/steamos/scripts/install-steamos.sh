#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STEAMOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PREFIX="${PREFIX:-}"
DESTDIR="${DESTDIR:-}"
BINDIR="${BINDIR:-/usr/local/bin}"
SYSD_UNIT_DIR="${SYSD_UNIT_DIR:-/etc/systemd/system}"
CONFIG_DIR="${CONFIG_DIR:-/etc/quantumlink}"
STATE_DIR="${STATE_DIR:-/var/lib/quantumlink}"
UNIT_NAME="qlinkd.service"
ACTIVATED_SAMPLE_NAME="activate-network.conf.sample"
CONTROL_GROUP_NAME="quantumlink"
UNIT_TMP=""
ACTIVATED_SAMPLE_TMP=""

cleanup() {
    if [ -n "$UNIT_TMP" ]; then
        rm -f "$UNIT_TMP"
    fi
    if [ -n "$ACTIVATED_SAMPLE_TMP" ]; then
        rm -f "$ACTIVATED_SAMPLE_TMP"
    fi
}
trap cleanup EXIT

if [ -z "$DESTDIR" ] && [ "$(id -u)" -ne 0 ]; then
    echo "install-steamos.sh must run as root; try: sudo $0" >&2
    exit 1
fi

validate_paths() {
    if [ -n "$DESTDIR" ]; then
        validate_destdir
    fi

    case "$BINDIR" in
        *'&'*|*'#'*|*'\'*|*'%'*|*[[:space:]]*)
            echo "BINDIR contains characters that cannot be safely rewritten into systemd units: $BINDIR" >&2
            exit 1
            ;;
    esac

    validate_install_path BINDIR "$BINDIR"
    validate_install_path SYSD_UNIT_DIR "$SYSD_UNIT_DIR"
    validate_install_path CONFIG_DIR "$CONFIG_DIR"
    validate_install_path STATE_DIR "$STATE_DIR"

    if [ -n "$DESTDIR" ]; then
        reject_symlink_components "BINDIR target" "$DESTDIR$BINDIR"
        reject_symlink_components "SYSD_UNIT_DIR target" "$DESTDIR$SYSD_UNIT_DIR"
        reject_symlink_components "CONFIG_DIR target" "$DESTDIR$CONFIG_DIR"
        reject_symlink_components "STATE_DIR target" "$DESTDIR$STATE_DIR"
        guarded_mkdir DESTDIR "$DESTDIR" 0755
    fi
}

validate_destdir() {
    if [ -e "$DESTDIR" ]; then
        if ! destdir_real="$(cd "$DESTDIR" && pwd -P)"; then
            echo "DESTDIR must be a directory: $DESTDIR" >&2
            exit 1
        fi
        if [ -z "${destdir_real//\//}" ]; then
            echo "DESTDIR resolves to the live root; unset DESTDIR for a live install or use a staging directory" >&2
            exit 1
        fi
    fi

    validate_install_path DESTDIR "$DESTDIR"
    reject_symlink_components DESTDIR "$DESTDIR"
}

reject_symlink_components() {
    path_name="$1"
    checked_path="$2"
    path_component="$checked_path"

    while [ "$path_component" != "/" ] && [ -n "$path_component" ]; do
        while [ "$path_component" != "/" ] && [ "${path_component%/}" != "$path_component" ]; do
            path_component="${path_component%/}"
        done

        if [ -L "$path_component" ]; then
            echo "$path_name contains symlink component: $path_component" >&2
            exit 1
        fi

        path_parent="$(dirname "$path_component")"
        if [ "$path_parent" = "$path_component" ]; then
            break
        fi
        path_component="$path_parent"
    done
}

guarded_mkdir() {
    path_name="$1"
    dir_path="$2"
    mode="$3"

    if [ -n "$DESTDIR" ]; then
        reject_symlink_components "$path_name" "$dir_path"
    fi
    install -d -m "$mode" "$dir_path"
    if [ -n "$DESTDIR" ]; then
        reject_symlink_components "$path_name" "$dir_path"
    fi
}

validate_install_path() {
    path_name="$1"
    install_path="$2"

    case "$install_path" in
        /*) ;;
        *)
            echo "$path_name must be an absolute path: $install_path" >&2
            exit 1
            ;;
    esac

    case "$install_path" in
        *[[:space:]]*|*/./*|*/../*|*/.|*/..)
            echo "$path_name contains invalid path component: $install_path" >&2
            exit 1
            ;;
    esac
}

find_binary() {
    name="$1"

    if [ -n "$PREFIX" ] && [ -x "$PREFIX/bin/$name" ]; then
        printf '%s\n' "$PREFIX/bin/$name"
        return 0
    fi

    if [ -x "$REPO_ROOT/target/release/$name" ]; then
        printf '%s\n' "$REPO_ROOT/target/release/$name"
        return 0
    fi

    echo "missing $name: build $REPO_ROOT/target/release/$name or set PREFIX to a staged install prefix" >&2
    return 1
}

install_file() {
    src="$1"
    dst="$2"
    mode="$3"

    install -d -m 0755 "$(dirname "$dst")"
    install -m "$mode" "$src" "$dst"
}

guarded_install_file() {
    path_name="$1"
    src="$2"
    dst="$3"
    mode="$4"

    if [ -z "$DESTDIR" ]; then
        install_file "$src" "$dst" "$mode"
        return
    fi

    reject_symlink_components "$path_name" "$dst"
    guarded_mkdir "$path_name" "$(dirname "$dst")" 0755
    reject_symlink_components "$path_name" "$dst"
    install -m "$mode" "$src" "$dst"
    reject_symlink_components "$path_name" "$dst"
}

rewrite_unit_paths() {
    src="$1"
    dst="$2"

    sed "s#/usr/local/bin/qlinkd#$BINDIR/qlinkd#g" "$src" > "$dst"
}

validate_contains() {
    file="$1"
    expected="$2"

    if ! grep -F "$expected" "$file" >/dev/null; then
        echo "validation failed: expected '$expected' in $file" >&2
        exit 1
    fi
}

validate_exact_line() {
    file="$1"
    expected="$2"

    if ! grep -Fx "$expected" "$file" >/dev/null; then
        echo "validation failed: expected exact line '$expected' in $file" >&2
        exit 1
    fi
}

validate_installation() {
    installed_unit="$DESTDIR$SYSD_UNIT_DIR/$UNIT_NAME"
    installed_sample="$DESTDIR$SYSD_UNIT_DIR/$UNIT_NAME.d/$ACTIVATED_SAMPLE_NAME"

    if [ ! -x "$DESTDIR$BINDIR/qlinkd" ]; then
        echo "validation failed: installed qlinkd is missing or not executable: $DESTDIR$BINDIR/qlinkd" >&2
        exit 1
    fi
    if [ ! -x "$DESTDIR$BINDIR/qlinkctl" ]; then
        echo "validation failed: installed qlinkctl is missing or not executable: $DESTDIR$BINDIR/qlinkctl" >&2
        exit 1
    fi
    if [ ! -f "$installed_unit" ]; then
        echo "validation failed: systemd unit is missing: $installed_unit" >&2
        exit 1
    fi
    validate_exact_line "$installed_unit" "ExecStart=$BINDIR/qlinkd"
    validate_exact_line "$installed_unit" "ExecStop=$BINDIR/qlinkd --deactivate-network"
    validate_exact_line "$installed_unit" "ExecStopPost=$BINDIR/qlinkd --deactivate-network"
    validate_exact_line "$installed_unit" "Group=$CONTROL_GROUP_NAME"
    validate_exact_line "$installed_unit" "UMask=0007"
    if [ ! -f "$installed_sample" ]; then
        echo "validation failed: activated-mode sample is missing: $installed_sample" >&2
        exit 1
    fi
    validate_exact_line "$installed_sample" "ExecStart="
    validate_exact_line "$installed_sample" "ExecStart=$BINDIR/qlinkd --activate-network"
}

ensure_live_control_group() {
    if [ -n "$DESTDIR" ]; then
        return
    fi

    if getent group "$CONTROL_GROUP_NAME" >/dev/null 2>&1; then
        return
    fi

    if ! command -v groupadd >/dev/null 2>&1; then
        echo "missing groupadd; create system group '$CONTROL_GROUP_NAME' before live install" >&2
        exit 1
    fi

    groupadd --system "$CONTROL_GROUP_NAME"
}

validate_paths

QLINKD_SRC="$(find_binary qlinkd)"
QLINKCTL_SRC="$(find_binary qlinkctl)"
UNIT_SRC="$STEAMOS_ROOT/packaging/systemd/$UNIT_NAME"
ACTIVATED_SAMPLE_SRC="$STEAMOS_ROOT/packaging/systemd/$UNIT_NAME.d/$ACTIVATED_SAMPLE_NAME"

if [ ! -f "$UNIT_SRC" ]; then
    echo "missing systemd unit: $UNIT_SRC" >&2
    exit 1
fi
if [ ! -f "$ACTIVATED_SAMPLE_SRC" ]; then
    echo "missing activated-mode sample: $ACTIVATED_SAMPLE_SRC" >&2
    exit 1
fi

echo "Installing QuantumLink SteamOS assets"
echo "  qlinkd:   $QLINKD_SRC"
echo "  qlinkctl: $QLINKCTL_SRC"
echo "  bindir:   $DESTDIR$BINDIR"

ensure_live_control_group

guarded_mkdir "BINDIR target" "$DESTDIR$BINDIR" 0755
guarded_install_file "BINDIR target" "$QLINKD_SRC" "$DESTDIR$BINDIR/qlinkd" 0755
guarded_install_file "BINDIR target" "$QLINKCTL_SRC" "$DESTDIR$BINDIR/qlinkctl" 0755

guarded_mkdir "CONFIG_DIR target" "$DESTDIR$CONFIG_DIR" 0750
guarded_mkdir "STATE_DIR target" "$DESTDIR$STATE_DIR" 0750
UNIT_TMP="$(mktemp)"
rewrite_unit_paths "$UNIT_SRC" "$UNIT_TMP"
guarded_install_file "SYSD_UNIT_DIR target" "$UNIT_TMP" "$DESTDIR$SYSD_UNIT_DIR/$UNIT_NAME" 0644
ACTIVATED_SAMPLE_TMP="$(mktemp)"
rewrite_unit_paths "$ACTIVATED_SAMPLE_SRC" "$ACTIVATED_SAMPLE_TMP"
guarded_install_file "SYSD_UNIT_DIR target" "$ACTIVATED_SAMPLE_TMP" "$DESTDIR$SYSD_UNIT_DIR/$UNIT_NAME.d/$ACTIVATED_SAMPLE_NAME" 0644

validate_installation

if command -v systemctl >/dev/null 2>&1 && [ -z "$DESTDIR" ]; then
    systemctl daemon-reload
else
    echo "Skipping systemctl daemon-reload because systemctl is unavailable or DESTDIR is set"
fi

cat <<EOF

QuantumLink SteamOS install complete.

Add SteamOS users who may run qlinkctl status/doctor to the quantumlink group.

Next commands:
  sudoedit $CONFIG_DIR/config.json
  sudo systemctl enable --now qlinkd
  systemctl status qlinkd
  sudo qlinkctl status

Default service behavior:
  qlinkd.service runs dry-run planning only and does not apply TUN, route, or
  nftables changes.

Activated mode sample:
  sample: $SYSD_UNIT_DIR/$UNIT_NAME.d/$ACTIVATED_SAMPLE_NAME
  enable: sudo cp $SYSD_UNIT_DIR/$UNIT_NAME.d/$ACTIVATED_SAMPLE_NAME $SYSD_UNIT_DIR/$UNIT_NAME.d/10-activate-network.conf
          sudo systemctl daemon-reload
          sudo systemctl restart qlinkd
  revert: sudo rm -f $SYSD_UNIT_DIR/$UNIT_NAME.d/10-activate-network.conf
          sudo systemctl daemon-reload
          sudo systemctl restart qlinkd

  The activated sample overrides ExecStart with:
    $BINDIR/qlinkd --activate-network
  The installed unit runs ExecStop and ExecStopPost with:
    $BINDIR/qlinkd --deactivate-network
  Those teardown commands are no-ops for dry-run service starts and remove only
  qlink-owned network state recorded by successful activated starts. Do not
  combine --check with --activate-network or --deactivate-network.

If this SteamOS image update removes files under /usr/local or custom systemd
units, re-run this installer after the update.
EOF
