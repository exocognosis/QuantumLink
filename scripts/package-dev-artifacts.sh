#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT/build/dist"
STAGE="$DIST_DIR/QuantumLink-dev"
ARCHIVE="$DIST_DIR/QuantumLink-dev.tar.gz"

cd "$ROOT"

cargo build --workspace --release
swift build -c release --product QuantumLinkSmoke
SWIFT_RELEASE_BIN="$(swift build -c release --show-bin-path)"

rm -rf "$STAGE" "$ARCHIVE"
mkdir -p "$STAGE/bin" "$STAGE/lib" "$STAGE/config" "$STAGE/docs"

cp "$ROOT/target/release/qlinkctl" "$STAGE/bin/qlinkctl"
cp "$SWIFT_RELEASE_BIN/QuantumLinkSmoke" "$STAGE/bin/QuantumLinkSmoke"
cp "$ROOT/target/release/libqlink_core.dylib" "$STAGE/lib/libqlink_core.dylib"
cp "$ROOT/config/mesh.example.json" "$STAGE/config/mesh.example.json"
cp "$ROOT/README.md" "$STAGE/README.md"
cp "$ROOT/docs/architecture.md" "$STAGE/docs/architecture.md"
cp "$ROOT/docs/security.md" "$STAGE/docs/security.md"

cat > "$STAGE/RUNBOOK.md" <<'EOF'
# QuantumLink Development Artifact Runbook

These artifacts are unsigned local development tools. They are not notarized and do not install a packet tunnel extension.

Run the Swift-to-Rust local QUIC transport smoke:

```sh
QLINK_CORE_DYLIB="$PWD/lib/libqlink_core.dylib" \
./bin/QuantumLinkSmoke transport-loopback \
  --mode dev-quic-loopback \
  --dylib "$PWD/lib/libqlink_core.dylib"
```

Run Rust control/data-plane smoke commands:

```sh
./bin/qlinkctl simulate-handshake
./bin/qlinkctl quic-loopback
./bin/qlinkctl mesh-loopback
./bin/qlinkctl relay-loopback
```
EOF

tar -C "$DIST_DIR" -czf "$ARCHIVE" QuantumLink-dev
echo "Created $ARCHIVE"
