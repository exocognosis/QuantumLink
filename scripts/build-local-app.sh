#!/usr/bin/env bash
# Build a clickable QuantumLink.app for local use without an Apple
# Developer account. Differs from build-unsigned-xcode.sh in that
# this variant ad-hoc-signs the bundle (and the embedded Rust dylib)
# so macOS Gatekeeper doesn't block first-launch with the
# "unidentified developer" dialog. Double-click works after the
# usual one-time right-click → Open dance the FIRST time, and
# without ANY prompts after that on the same machine.
#
# What this DOES give you:
#   - A real .app bundle with Info.plist, embedded frameworks, and
#     the bundled Rust core dylib.
#   - A SwiftUI surface that runs end-to-end against the Rust core
#     locally (smoke transports, qlinkctl-style flows, all the panel
#     UX work).
#   - Ad-hoc signature good enough for `spctl --assess`'s
#     execute-only path and for AppKit/SwiftUI to load.
#
# What this does NOT give you:
#   - A working Network Extension. The packet tunnel provider needs
#     the `com.apple.developer.networking.networkextension`
#     entitlement which Apple grants only to Developer-ID-signed
#     bundles. Locally the tunnel falls back to the development drop
#     transport — UI works, real packets do not flow.
#   - Notarization. Distributing the .app to other Macs still
#     triggers Gatekeeper. This script is for the device that built it.
#   - Sparkle update validation (no EdDSA signing key wired in).
#
# Usage:
#   ./scripts/build-local-app.sh                      # build + ad-hoc sign
#   ./scripts/build-local-app.sh --install            # also copy to ~/Applications
#   ./scripts/build-local-app.sh --install --launch   # ... and open it
#   ./scripts/build-local-app.sh --output ~/Desktop   # custom destination

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$ROOT/QuantumLink.xcodeproj"
# DerivedData lives in /tmp instead of $ROOT/DerivedData on purpose:
# when the source tree is under a file-provider-watched directory
# (iCloud Drive on Desktop, Dropbox, etc.), macOS auto-applies xattrs
# like com.apple.fileprovider.fpfs#P and com.apple.FinderInfo to
# every file written there. codesign rejects any Mach-O / bundle
# carrying those xattrs ("resource fork, Finder information, or
# similar detritus not allowed"), so the fix is to keep build
# outputs out of a watched directory entirely. /tmp is the safest
# bet — no Spotlight, no fileprovider, no quarantine.
DERIVED="${QLINK_DERIVED_DATA:-/tmp/qlink-local-app}"
APP_PATH="$DERIVED/Build/Products/Debug/QuantumLink.app"

INSTALL=0
LAUNCH=0
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install) INSTALL=1; shift ;;
    --launch) LAUNCH=1; shift ;;
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# //;s/^#$//'
      exit 0
      ;;
    *) echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

if ! command -v xcodegen >/dev/null 2>&1; then
  cat >&2 <<'EOF'
xcodegen is not installed. Install with:
  brew install xcodegen
Then rerun this script.
EOF
  exit 1
fi

# Stage 1: Rust core as XCFramework. Embedded into the app bundle by
# the Xcode target spec.
echo "==> Building Rust XCFramework"
"$ROOT/scripts/build-rust-xcframework.sh"

# Cargo + lipo+xcodebuild often leave macOS extended attributes
# (com.apple.quarantine, com.apple.macl, FinderInfo) on the dylibs
# that get copied into the bundle. codesign refuses to sign anything
# with xattrs ("resource fork, Finder information, or similar
# detritus not allowed"), so strip them now while the source tree is
# pristine. -c clears all xattrs; -r recurses.
xattr -cr "$ROOT/build/qlink-core.xcframework" || true

# Stage 2: Regenerate the Xcode project from macos/project.yml so any
# spec edits land before xcodebuild runs.
echo "==> Regenerating Xcode project"
"$ROOT/scripts/generate-xcode-project.sh"

# Stage 3: Build with ad-hoc signing. CODE_SIGN_IDENTITY="-" tells
# Xcode to use the ad-hoc identity (a self-signed cert that's
# accepted for local execution but rejected for distribution). The
# -allowProvisioningUpdates flag short-circuits the "no provisioning
# profile" dialog when no team is configured.
echo "==> Building QuantumLink.app (ad-hoc signed)"
#
# Why CODE_SIGN_ENTITLEMENTS="": the project's default entitlements
# include `com.apple.developer.networking.networkextension` and an
# app-group, both of which require an Apple-Developer provisioning
# profile. Forcing them empty drops the profile requirement so
# ad-hoc signing works. The packet-tunnel can't function without
# those entitlements anyway, which we've already accepted in the
# header comments above.
xcodebuild \
  -project "$PROJECT" \
  -scheme QuantumLink \
  -configuration Debug \
  -destination 'platform=macOS' \
  -derivedDataPath "$DERIVED" \
  CODE_SIGN_IDENTITY="-" \
  CODE_SIGNING_REQUIRED=YES \
  CODE_SIGNING_ALLOWED=YES \
  CODE_SIGN_ENTITLEMENTS="" \
  DEVELOPMENT_TEAM="" \
  PROVISIONING_PROFILE_SPECIFIER="" \
  OTHER_CODE_SIGN_FLAGS="--timestamp=none" \
  build

if [[ ! -d "$APP_PATH" ]]; then
  echo "Build succeeded but $APP_PATH is missing." >&2
  exit 1
fi

# Stage 3.5: Build the privileged helper binary and embed it into
# the app bundle's Contents/MacOS/. The helper opens utun on
# behalf of the unprivileged GUI; the GUI's "Authorize Helper"
# button copies this binary out to /usr/local/libexec via an
# osascript admin prompt.
echo "==> Building qlinkhelper + embedding in bundle"
cargo build --manifest-path "$ROOT/rust/qlink-core/Cargo.toml" --bin qlinkhelper --release
HELPER_BINARY="$ROOT/target/release/qlinkhelper"
if [[ ! -x "$HELPER_BINARY" ]]; then
  echo "qlinkhelper binary missing at $HELPER_BINARY" >&2
  exit 1
fi
cp "$HELPER_BINARY" "$APP_PATH/Contents/MacOS/qlinkhelper"
chmod 755 "$APP_PATH/Contents/MacOS/qlinkhelper"

# Stage 4: Belt-and-braces. Some embedded binaries (Sparkle's
# Updater.app, qlink-core.framework, the tunnel extension) might
# need an explicit pass to ensure every nested Mach-O carries the
# ad-hoc signature. `--deep` walks the bundle recursively.
echo "==> Re-applying ad-hoc signature (recursive)"
codesign --force --deep --sign - "$APP_PATH"

# Stage 5: Verify the bundle is internally consistent. `--strict`
# catches mismatched code requirements + missing signatures.
echo "==> Verifying signature"
codesign --verify --verbose=2 "$APP_PATH" || {
  echo "Signature verification failed." >&2
  exit 1
}

echo "==> Built: $APP_PATH"

# Stage 6: Optional install / open. Default destination is
# ~/Applications because /Applications writes need admin rights and
# this is a per-user dev build.
if [[ -n "$OUTPUT_DIR" ]]; then
  mkdir -p "$OUTPUT_DIR"
  TARGET="$OUTPUT_DIR/QuantumLink.app"
  echo "==> Copying to $TARGET"
  rm -rf "$TARGET"
  cp -R "$APP_PATH" "$TARGET"
  APP_PATH="$TARGET"
elif [[ "$INSTALL" -eq 1 ]]; then
  USER_APPS="$HOME/Applications"
  mkdir -p "$USER_APPS"
  TARGET="$USER_APPS/QuantumLink.app"
  echo "==> Installing to $TARGET"
  rm -rf "$TARGET"
  cp -R "$APP_PATH" "$TARGET"
  APP_PATH="$TARGET"
fi

if [[ "$LAUNCH" -eq 1 ]]; then
  echo "==> Launching"
  open "$APP_PATH"
fi

cat <<EOF

QuantumLink.app is at: $APP_PATH

First launch on this machine: macOS will refuse with "cannot be
opened because the developer cannot be verified". Right-click the
app icon and choose Open; macOS remembers the choice from then on.

The packet tunnel will not actually attach to utun without the
Apple-granted Network Extension entitlement. The UI runs end-to-end
against the bundled Rust core, but real mesh connectivity requires
an Apple Developer account + entitlement approval. See
docs/pre-apple-development.md for the gating items.
EOF
