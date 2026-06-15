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
UNIT_TMP=""

cleanup() {
    if [ -n "$UNIT_TMP" ]; then
        rm -f "$UNIT_TMP"
    fi
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
    echo "install-steamos.sh must run as root; try: sudo $0" >&2
    exit 1
fi

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

    install -D -m "$mode" "$src" "$dst"
}

QLINKD_SRC="$(find_binary qlinkd)"
QLINKCTL_SRC="$(find_binary qlinkctl)"
UNIT_SRC="$STEAMOS_ROOT/packaging/systemd/$UNIT_NAME"

if [ ! -f "$UNIT_SRC" ]; then
    echo "missing systemd unit: $UNIT_SRC" >&2
    exit 1
fi

echo "Installing QuantumLink SteamOS assets"
echo "  qlinkd:   $QLINKD_SRC"
echo "  qlinkctl: $QLINKCTL_SRC"
echo "  bindir:   $DESTDIR$BINDIR"

install -d -m 0755 "$DESTDIR$BINDIR"
install_file "$QLINKD_SRC" "$DESTDIR$BINDIR/qlinkd" 0755
install_file "$QLINKCTL_SRC" "$DESTDIR$BINDIR/qlinkctl" 0755

install -d -m 0750 "$DESTDIR$CONFIG_DIR"
install -d -m 0750 "$DESTDIR$STATE_DIR"
UNIT_TMP="$(mktemp)"
sed "s#/usr/local/bin/qlinkd#$BINDIR/qlinkd#g" "$UNIT_SRC" > "$UNIT_TMP"
install_file "$UNIT_TMP" "$DESTDIR$SYSD_UNIT_DIR/$UNIT_NAME" 0644

if command -v systemctl >/dev/null 2>&1 && [ -z "$DESTDIR" ]; then
    systemctl daemon-reload
else
    echo "Skipping systemctl daemon-reload because systemctl is unavailable or DESTDIR is set"
fi

cat <<EOF

QuantumLink SteamOS install complete.

Next commands:
  sudoedit $CONFIG_DIR/config.json
  sudo systemctl enable --now qlinkd
  systemctl status qlinkd
  sudo qlinkctl status

If this SteamOS image update removes files under /usr/local or custom systemd
units, re-run this installer after the update.
EOF
