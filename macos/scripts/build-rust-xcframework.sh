#!/usr/bin/env bash
set -euo pipefail

# ROOT = macOS silo (macos/); REPO_ROOT = monorepo root (holds the shared
# qlink-core crate and the Cargo workspace target/ dir).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
HOST_TARGET="$(rustc -vV | awk '/^host:/ { print $2 }')"
if [[ -n "${QLINK_RUST_TARGETS:-}" ]]; then
  TARGETS="$QLINK_RUST_TARGETS"
elif [[ "$HOST_TARGET" == *-apple-darwin ]]; then
  TARGETS="aarch64-apple-darwin x86_64-apple-darwin"
else
  TARGETS="$HOST_TARGET"
fi
BUILD_DIR="$ROOT/build"
HEADER_DIR="$BUILD_DIR/qlink-core-headers"
UNIVERSAL_DIR="$BUILD_DIR/qlink-core-universal"
XCFRAMEWORK="$BUILD_DIR/qlink-core.xcframework"

mkdir -p "$BUILD_DIR"
find "$BUILD_DIR" -maxdepth 1 \( -name 'qlink-core*.xcframework' -o -name 'qlink-core-headers*' -o -name 'qlink-core-universal*' \) -exec rm -rf {} +
mkdir -p "$HEADER_DIR"
cp "$REPO_ROOT/qlink-core/include/qlink_core.h" "$HEADER_DIR/qlink_core.h"

ARGS=()
DARWIN_LIBS=()
for target in $TARGETS; do
  if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -qx "$target"; then
    cat >&2 <<EOF
Missing Rust target: $target

Install it with:
  rustup target add $target

Or override the build targets explicitly:
  QLINK_RUST_TARGETS="$HOST_TARGET" ./scripts/build-rust-xcframework.sh
EOF
    exit 1
  fi

  (cd "$REPO_ROOT" && cargo build -p qlink-core --release --target "$target")
  LIB="$REPO_ROOT/target/$target/release/libqlink_core.a"
  if [[ ! -f "$LIB" ]]; then
    echo "Missing Rust static library: $LIB" >&2
    exit 1
  fi

  if [[ "$target" == *-apple-darwin ]]; then
    DARWIN_LIBS+=("$LIB")
  else
    ARGS+=("-library" "$LIB" "-headers" "$HEADER_DIR")
  fi
done

if [[ "${#DARWIN_LIBS[@]}" -gt 1 ]]; then
  mkdir -p "$UNIVERSAL_DIR"
  UNIVERSAL_LIB="$UNIVERSAL_DIR/libqlink_core.a"
  lipo -create "${DARWIN_LIBS[@]}" -output "$UNIVERSAL_LIB"
  ARGS+=("-library" "$UNIVERSAL_LIB" "-headers" "$HEADER_DIR")
elif [[ "${#DARWIN_LIBS[@]}" -eq 1 ]]; then
  ARGS+=("-library" "${DARWIN_LIBS[0]}" "-headers" "$HEADER_DIR")
fi

xcodebuild -create-xcframework "${ARGS[@]}" -output "$XCFRAMEWORK"
echo "Created $XCFRAMEWORK"
