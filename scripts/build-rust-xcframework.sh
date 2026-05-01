#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_TARGET="$(rustc -vV | awk '/^host:/ { print $2 }')"
TARGETS="${QLINK_RUST_TARGETS:-$HOST_TARGET}"
BUILD_DIR="$ROOT/build"
HEADER_DIR="$BUILD_DIR/qlink-core-headers"
XCFRAMEWORK="$BUILD_DIR/qlink-core.xcframework"

mkdir -p "$BUILD_DIR"
find "$BUILD_DIR" -maxdepth 1 \( -name 'qlink-core*.xcframework' -o -name 'qlink-core-headers*' \) -exec rm -rf {} +
mkdir -p "$HEADER_DIR"
cp "$ROOT/rust/qlink-core/include/qlink_core.h" "$HEADER_DIR/qlink_core.h"

ARGS=()
for target in $TARGETS; do
  cargo build -p qlink-core --release --target "$target"
  LIB="$ROOT/target/$target/release/libqlink_core.a"
  if [[ ! -f "$LIB" ]]; then
    echo "Missing Rust static library: $LIB" >&2
    exit 1
  fi
  ARGS+=("-library" "$LIB" "-headers" "$HEADER_DIR")
done

xcodebuild -create-xcframework "${ARGS[@]}" -output "$XCFRAMEWORK"
echo "Created $XCFRAMEWORK"
