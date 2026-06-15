#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
PRODUCT_NAME="QuantumLinkApp"
APP_NAME="QuantumLink"
PROCESS_NAME="QuantumLinkApp"
BUNDLE_ID="com.quantumlink.macos"
MIN_SYSTEM_VERSION="14.0"
RESOURCE_BUNDLE="QuantumLink_QuantumLinkApp.bundle"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_RESOURCES="$APP_CONTENTS/Resources"
APP_BINARY="$APP_MACOS/$PROCESS_NAME"
INFO_PLIST="$APP_CONTENTS/Info.plist"

cd "$ROOT_DIR"

stop_app() {
  pkill -x "$PROCESS_NAME" >/dev/null 2>&1 || true

  for _ in {1..20}; do
    if ! pgrep -x "$PROCESS_NAME" >/dev/null 2>&1; then
      return 0
    fi

    sleep 0.1
  done

  pkill -9 -x "$PROCESS_NAME" >/dev/null 2>&1 || true
}

stop_app

swift build --product "$PRODUCT_NAME"
BUILD_DIR="$(swift build --show-bin-path)"
BUILD_BINARY="$BUILD_DIR/$PRODUCT_NAME"

rm -rf "$APP_BUNDLE"
mkdir -p "$APP_MACOS" "$APP_RESOURCES"
cp "$BUILD_BINARY" "$APP_BINARY"
chmod +x "$APP_BINARY"

if [[ -d "$BUILD_DIR/$RESOURCE_BUNDLE" ]]; then
  cp -R "$BUILD_DIR/$RESOURCE_BUNDLE" "$APP_BUNDLE/$RESOURCE_BUNDLE"
  cp -R "$BUILD_DIR/$RESOURCE_BUNDLE" "$APP_RESOURCES/$RESOURCE_BUNDLE"
fi

cat >"$INFO_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>$PROCESS_NAME</string>
  <key>CFBundleIdentifier</key>
  <string>$BUNDLE_ID</string>
  <key>CFBundleName</key>
  <string>$APP_NAME</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>LSMinimumSystemVersion</key>
  <string>$MIN_SYSTEM_VERSION</string>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
PLIST

open_app() {
  /usr/bin/open -n "$APP_BUNDLE"
}

case "$MODE" in
  run)
    open_app
    ;;
  --debug|debug)
    lldb -- "$APP_BINARY"
    ;;
  --logs|logs)
    open_app
    /usr/bin/log stream --info --style compact --predicate "process == \"$PROCESS_NAME\""
    ;;
  --telemetry|telemetry)
    open_app
    /usr/bin/log stream --info --style compact --predicate "subsystem == \"$BUNDLE_ID\""
    ;;
  --verify|verify)
    open_app
    sleep 1
    if pgrep -f "$BUILD_BINARY" >/dev/null 2>&1; then
      echo "unexpected raw SwiftPM process still running: $BUILD_BINARY" >&2
      exit 1
    fi

    pgrep -f "$APP_BINARY" >/dev/null
    ;;
  *)
    echo "usage: $0 [run|--debug|--logs|--telemetry|--verify]" >&2
    exit 2
    ;;
esac
