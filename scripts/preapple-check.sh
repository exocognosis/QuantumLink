#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log() {
  printf '\n==> %s\n' "$*"
}

run() {
  log "$*"
  "$@"
}

log "Toolchain"
swift --version
rustc --version
cargo --version
xcodebuild -version || true
if command -v xcodegen >/dev/null 2>&1; then
  xcodegen --version
else
  echo "xcodegen=missing (unsigned Xcode project build will be skipped)"
fi

run swift test
run cargo fmt --all -- --check
run cargo test --workspace
run cargo build --workspace --release

DYLIB="$ROOT/target/release/libqlink_core.dylib"

log "Swift dylib-backed integration tests"
QLINK_CORE_DYLIB="$DYLIB" swift test --filter RustCoreBridgeTests
QLINK_CORE_DYLIB="$DYLIB" swift test --filter TunnelTransportTests/testRustDevQuicLoopbackTransportWhenDylibIsConfigured
QLINK_CORE_DYLIB="$DYLIB" swift test --filter TunnelTransportTests/testTransportSmokeRunnerWhenDylibIsConfigured

run swift run QuantumLinkSmoke validate-config --config "$ROOT/config/mesh.example.json"
run swift run QuantumLinkSmoke preflight \
  --config "$ROOT/config/mesh.example.json" \
  --transport \
  --mode dev-quic-loopback \
  --dylib "$DYLIB"

run "$ROOT/target/release/qlinkctl" simulate-handshake
run "$ROOT/target/release/qlinkctl" quic-loopback
run "$ROOT/target/release/qlinkctl" mesh-loopback
run "$ROOT/target/release/qlinkctl" relay-loopback

run "$ROOT/scripts/build-rust-xcframework.sh"
run "$ROOT/scripts/package-dev-artifacts.sh"

if command -v xcodegen >/dev/null 2>&1; then
  run "$ROOT/scripts/build-unsigned-xcode.sh"
else
  log "Skipping unsigned Xcode project build because xcodegen is not installed"
fi

cat <<'EOF'

Pre-Apple local validation complete.

Still blocked on Apple Developer account or Apple-granted capabilities:
- Packet Tunnel Provider provisioning and real tunnel installation
- Developer ID signing
- Notarization and stapling
- MDM pre-approval payload validation on managed fleets
EOF
