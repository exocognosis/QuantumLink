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
SECRETS_DIR="$CONFIG_DIR/secrets"
STATE_DIR="${STATE_DIR:-/var/lib/quantumlink}"
APPLICATIONS_DIR="${APPLICATIONS_DIR:-/usr/share/applications}"
ICON_DIR="${ICON_DIR:-/usr/share/icons/hicolor/256x256/apps}"
LIBEXEC_DIR="/usr/local/libexec"
POLKIT_RULES_DIR="/etc/polkit-1/rules.d"
UNIT_NAME="qlinkd.service"
PLANNING_SAMPLE_NAME="planning-only.conf.sample"
CONTROL_GROUP_NAME="quantumlink"
UNIT_TMP=""
PLANNING_SAMPLE_TMP=""
DESKTOP_ENTRY_TMP=""
GAME_MODE_ENTRY_TMP=""

cleanup() {
    if [ -n "$UNIT_TMP" ]; then
        rm -f "$UNIT_TMP"
    fi
    if [ -n "$PLANNING_SAMPLE_TMP" ]; then
        rm -f "$PLANNING_SAMPLE_TMP"
    fi
    if [ -n "$DESKTOP_ENTRY_TMP" ]; then
        rm -f "$DESKTOP_ENTRY_TMP"
    fi
    if [ -n "$GAME_MODE_ENTRY_TMP" ]; then
        rm -f "$GAME_MODE_ENTRY_TMP"
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
    validate_install_path APPLICATIONS_DIR "$APPLICATIONS_DIR"
    validate_install_path ICON_DIR "$ICON_DIR"
    validate_install_path LIBEXEC_DIR "$LIBEXEC_DIR"
    validate_install_path POLKIT_RULES_DIR "$POLKIT_RULES_DIR"

    if [ -n "$DESTDIR" ]; then
        reject_symlink_components "BINDIR target" "$DESTDIR$BINDIR"
        reject_symlink_components "SYSD_UNIT_DIR target" "$DESTDIR$SYSD_UNIT_DIR"
        reject_symlink_components "CONFIG_DIR target" "$DESTDIR$CONFIG_DIR"
        reject_symlink_components "SECRETS_DIR target" "$DESTDIR$SECRETS_DIR"
        reject_symlink_components "STATE_DIR target" "$DESTDIR$STATE_DIR"
        reject_symlink_components "APPLICATIONS_DIR target" "$DESTDIR$APPLICATIONS_DIR"
        reject_symlink_components "ICON_DIR target" "$DESTDIR$ICON_DIR"
        reject_symlink_components "LIBEXEC_DIR target" "$DESTDIR$LIBEXEC_DIR"
        reject_symlink_components "POLKIT_RULES_DIR target" "$DESTDIR$POLKIT_RULES_DIR"
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

rewrite_desktop_paths() {
    src="$1"
    dst="$2"

    sed "s#/usr/local/bin/qlink-desktop#$BINDIR/qlink-desktop#g" "$src" > "$dst"
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
    installed_sample="$DESTDIR$SYSD_UNIT_DIR/$UNIT_NAME.d/$PLANNING_SAMPLE_NAME"

    if [ ! -x "$DESTDIR$BINDIR/qlinkd" ]; then
        echo "validation failed: installed qlinkd is missing or not executable: $DESTDIR$BINDIR/qlinkd" >&2
        exit 1
    fi
    if [ ! -x "$DESTDIR$BINDIR/qlinkctl" ]; then
        echo "validation failed: installed qlinkctl is missing or not executable: $DESTDIR$BINDIR/qlinkctl" >&2
        exit 1
    fi
    if [ ! -x "$DESTDIR$BINDIR/qlink-desktop" ]; then
        echo "validation failed: installed qlink-desktop is missing or not executable: $DESTDIR$BINDIR/qlink-desktop" >&2
        exit 1
    fi
    installed_desktop="$DESTDIR$APPLICATIONS_DIR/quantumlink-steamos.desktop"
    installed_game_mode="$DESTDIR$APPLICATIONS_DIR/quantumlink-steamos-game-mode.desktop"
    installed_icon="$DESTDIR$ICON_DIR/quantumlink-steamos.png"
    installed_helper="$DESTDIR$LIBEXEC_DIR/quantumlink-service-control"
    installed_polkit_rule="$DESTDIR$POLKIT_RULES_DIR/49-quantumlink-service-control.rules"
    if [ ! -f "$installed_desktop" ] || [ ! -f "$installed_game_mode" ] || [ ! -f "$installed_icon" ]; then
        echo "validation failed: SteamOS desktop launcher assets are missing" >&2
        exit 1
    fi
    validate_exact_line "$installed_desktop" "Exec=$BINDIR/qlink-desktop"
    validate_exact_line "$installed_game_mode" "Exec=$BINDIR/qlink-desktop --game-mode"
    validate_exact_line "$installed_desktop" "Icon=quantumlink-steamos"
    if [ ! -x "$installed_helper" ]; then
        echo "validation failed: service helper is missing or not executable: $installed_helper" >&2
        exit 1
    fi
    if [ ! -f "$installed_polkit_rule" ]; then
        echo "validation failed: PolicyKit rule is missing: $installed_polkit_rule" >&2
        exit 1
    fi
    validate_contains "$installed_helper" "exec /usr/bin/systemctl \"\$1\" qlinkd.service"
    validate_contains "$installed_polkit_rule" \
        'action.lookup("program") !== "/usr/local/libexec/quantumlink-service-control"'
    validate_contains "$installed_polkit_rule" 'subject.isInGroup("quantumlink")'
    validate_contains "$installed_polkit_rule" 'polkit.Result.AUTH_ADMIN_KEEP'
    if [ ! -f "$installed_unit" ]; then
        echo "validation failed: systemd unit is missing: $installed_unit" >&2
        exit 1
    fi
    validate_exact_line "$installed_unit" "ExecStart=$BINDIR/qlinkd --activate-network"
    validate_exact_line "$installed_unit" "ExecStop=$BINDIR/qlinkd --deactivate-network"
    validate_exact_line "$installed_unit" "ExecStopPost=$BINDIR/qlinkd --deactivate-network"
    validate_exact_line "$installed_unit" "Group=$CONTROL_GROUP_NAME"
    validate_exact_line "$installed_unit" "UMask=0007"
    if [ ! -f "$installed_sample" ]; then
        echo "validation failed: planning-only sample is missing: $installed_sample" >&2
        exit 1
    fi
    validate_exact_line "$installed_sample" "ExecStart="
    validate_exact_line "$installed_sample" "ExecStart=$BINDIR/qlinkd"
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

ensure_live_desktop_user() {
    if [ -n "$DESTDIR" ]; then
        return
    fi

    desktop_user="${QLINK_DESKTOP_USER:-${SUDO_USER:-}}"
    if [ -z "$desktop_user" ] || [ "$desktop_user" = "root" ]; then
        return
    fi
    if ! getent passwd "$desktop_user" >/dev/null 2>&1; then
        echo "QLINK_DESKTOP_USER does not identify a local user: $desktop_user" >&2
        exit 1
    fi
    if id -nG "$desktop_user" | tr ' ' '\n' | grep -Fx "$CONTROL_GROUP_NAME" >/dev/null; then
        return
    fi
    if ! command -v usermod >/dev/null 2>&1; then
        echo "missing usermod; add '$desktop_user' to '$CONTROL_GROUP_NAME' before launch" >&2
        exit 1
    fi

    usermod -a -G "$CONTROL_GROUP_NAME" "$desktop_user"
}

validate_paths

QLINKD_SRC="$(find_binary qlinkd)"
QLINKCTL_SRC="$(find_binary qlinkctl)"
QLINK_DESKTOP_SRC="$(find_binary qlink-desktop)"
UNIT_SRC="$STEAMOS_ROOT/packaging/systemd/$UNIT_NAME"
PLANNING_SAMPLE_SRC="$STEAMOS_ROOT/packaging/systemd/$UNIT_NAME.d/$PLANNING_SAMPLE_NAME"
DESKTOP_ENTRY_SRC="$STEAMOS_ROOT/packaging/desktop/quantumlink-steamos.desktop"
GAME_MODE_ENTRY_SRC="$STEAMOS_ROOT/packaging/desktop/quantumlink-steamos-game-mode.desktop"
DESKTOP_ICON_SRC="$STEAMOS_ROOT/packaging/desktop/icons/quantumlink-steamos.png"
SERVICE_HELPER_SRC="$STEAMOS_ROOT/packaging/libexec/quantumlink-service-control"
POLKIT_RULE_SRC="$STEAMOS_ROOT/packaging/polkit/49-quantumlink-service-control.rules"

if [ ! -f "$UNIT_SRC" ]; then
    echo "missing systemd unit: $UNIT_SRC" >&2
    exit 1
fi
if [ ! -f "$PLANNING_SAMPLE_SRC" ]; then
    echo "missing planning-only sample: $PLANNING_SAMPLE_SRC" >&2
    exit 1
fi
if [ ! -f "$DESKTOP_ENTRY_SRC" ] || [ ! -f "$GAME_MODE_ENTRY_SRC" ] || [ ! -f "$DESKTOP_ICON_SRC" ]; then
    echo "missing SteamOS desktop launcher assets" >&2
    exit 1
fi
if [ ! -f "$SERVICE_HELPER_SRC" ] || [ ! -f "$POLKIT_RULE_SRC" ]; then
    echo "missing SteamOS service authorization assets" >&2
    exit 1
fi

echo "Installing QuantumLink SteamOS assets"
echo "  qlinkd:   $QLINKD_SRC"
echo "  qlinkctl: $QLINKCTL_SRC"
echo "  desktop:  $QLINK_DESKTOP_SRC"
echo "  bindir:   $DESTDIR$BINDIR"

ensure_live_control_group
ensure_live_desktop_user

guarded_mkdir "BINDIR target" "$DESTDIR$BINDIR" 0755
guarded_install_file "BINDIR target" "$QLINKD_SRC" "$DESTDIR$BINDIR/qlinkd" 0755
guarded_install_file "BINDIR target" "$QLINKCTL_SRC" "$DESTDIR$BINDIR/qlinkctl" 0755
guarded_install_file "BINDIR target" "$QLINK_DESKTOP_SRC" "$DESTDIR$BINDIR/qlink-desktop" 0755
DESKTOP_ENTRY_TMP="$(mktemp)"
rewrite_desktop_paths "$DESKTOP_ENTRY_SRC" "$DESKTOP_ENTRY_TMP"
guarded_install_file "APPLICATIONS_DIR target" "$DESKTOP_ENTRY_TMP" \
    "$DESTDIR$APPLICATIONS_DIR/quantumlink-steamos.desktop" 0644
GAME_MODE_ENTRY_TMP="$(mktemp)"
rewrite_desktop_paths "$GAME_MODE_ENTRY_SRC" "$GAME_MODE_ENTRY_TMP"
guarded_install_file "APPLICATIONS_DIR target" "$GAME_MODE_ENTRY_TMP" \
    "$DESTDIR$APPLICATIONS_DIR/quantumlink-steamos-game-mode.desktop" 0644
guarded_install_file "ICON_DIR target" "$DESKTOP_ICON_SRC" \
    "$DESTDIR$ICON_DIR/quantumlink-steamos.png" 0644
guarded_install_file "LIBEXEC_DIR target" "$SERVICE_HELPER_SRC" \
    "$DESTDIR$LIBEXEC_DIR/quantumlink-service-control" 0755
guarded_install_file "POLKIT_RULES_DIR target" "$POLKIT_RULE_SRC" \
    "$DESTDIR$POLKIT_RULES_DIR/49-quantumlink-service-control.rules" 0644

guarded_mkdir "CONFIG_DIR target" "$DESTDIR$CONFIG_DIR" 0750
guarded_mkdir "SECRETS_DIR target" "$DESTDIR$SECRETS_DIR" 0700
guarded_mkdir "STATE_DIR target" "$DESTDIR$STATE_DIR" 0750

# Steam-safe bypass policy and per-game routing profiles. qlinkd loads these
# from CONFIG_DIR at startup to enforce and disclose which traffic bypasses the
# tunnel. They are optional: when the source tree ships them they are installed,
# and when absent the daemon falls back to built-in production-safe defaults.
if [ -e "$STEAMOS_ROOT/config/steam-bypass.toml" ]; then
    guarded_mkdir "GAMES_DIR target" "$DESTDIR$CONFIG_DIR/games" 0750
    guarded_install_file "steam-safe bypass policy" \
        "$STEAMOS_ROOT/config/steam-bypass.toml" \
        "$DESTDIR$CONFIG_DIR/steam-bypass.toml" 0644
    for profile in "$STEAMOS_ROOT"/config/games/*.toml; do
        [ -e "$profile" ] || continue
        guarded_install_file "game profile" \
            "$profile" \
            "$DESTDIR$CONFIG_DIR/games/$(basename "$profile")" 0644
    done
fi
UNIT_TMP="$(mktemp)"
rewrite_unit_paths "$UNIT_SRC" "$UNIT_TMP"
guarded_install_file "SYSD_UNIT_DIR target" "$UNIT_TMP" "$DESTDIR$SYSD_UNIT_DIR/$UNIT_NAME" 0644
PLANNING_SAMPLE_TMP="$(mktemp)"
rewrite_unit_paths "$PLANNING_SAMPLE_SRC" "$PLANNING_SAMPLE_TMP"
guarded_install_file "SYSD_UNIT_DIR target" "$PLANNING_SAMPLE_TMP" "$DESTDIR$SYSD_UNIT_DIR/$UNIT_NAME.d/$PLANNING_SAMPLE_NAME" 0644

validate_installation

if command -v systemctl >/dev/null 2>&1 && [ -z "$DESTDIR" ]; then
    systemctl daemon-reload
else
    echo "Skipping systemctl daemon-reload because systemctl is unavailable or DESTDIR is set"
fi

cat <<EOF

QuantumLink SteamOS install complete.

The installer adds QLINK_DESKTOP_USER or SUDO_USER to the quantumlink group.
Log out and back in before you open the desktop application.

Next commands:
  sudoedit $CONFIG_DIR/config.json
  sudo systemctl enable --now qlinkd
  systemctl status qlinkd
  sudo qlinkctl status
  Open QuantumLink from the SteamOS application menu.

Default service behavior:
  qlinkd.service applies the owned TUN, route, and nftables plan. Invalid or
  unsafe network configuration stops startup before protected traffic flows.

Planning-only recovery sample:
  sample: $SYSD_UNIT_DIR/$UNIT_NAME.d/$PLANNING_SAMPLE_NAME
  enable: sudo cp $SYSD_UNIT_DIR/$UNIT_NAME.d/$PLANNING_SAMPLE_NAME $SYSD_UNIT_DIR/$UNIT_NAME.d/10-planning-only.conf
          sudo systemctl daemon-reload
          sudo systemctl restart qlinkd
  revert: sudo rm -f $SYSD_UNIT_DIR/$UNIT_NAME.d/10-planning-only.conf
          sudo systemctl daemon-reload
          sudo systemctl restart qlinkd

  The planning-only sample overrides ExecStart with:
    $BINDIR/qlinkd
  The installed unit runs ExecStop and ExecStopPost with:
    $BINDIR/qlinkd --deactivate-network
  Those teardown commands are no-ops for planning-only starts and remove only
  qlink-owned network state recorded by successful activated starts. Do not
  combine --check with --activate-network or --deactivate-network.

If this SteamOS image update removes files under /usr/local or custom systemd
units, re-run this installer after the update.
EOF
