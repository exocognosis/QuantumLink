#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
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
  echo "xcodegen=missing"
fi

run swift test
run "$ROOT/scripts/macos-release-readiness.sh"
run cargo fmt --all -- --check
run cargo test --workspace
run cargo build --workspace --release

DYLIB="$REPO_ROOT/target/release/libqlink_core.dylib"

log "Swift dylib-backed integration tests"
QLINK_CORE_DYLIB="$DYLIB" swift test --filter RustCoreBridgeTests
QLINK_CORE_DYLIB="$DYLIB" swift test --filter TunnelTransportTests/testRustDevQuicLoopbackTransportWhenDylibIsConfigured
QLINK_CORE_DYLIB="$DYLIB" swift test --filter TunnelTransportTests/testTransportSmokeRunnerWhenDylibIsConfigured

run swift run QuantumLinkSmoke validate-config --config "$REPO_ROOT/config/mesh.example.json"
run swift run QuantumLinkSmoke preflight \
  --config "$REPO_ROOT/config/mesh.example.json" \
  --transport \
  --mode dev-quic-loopback \
  --dylib "$DYLIB"

run "$REPO_ROOT/target/release/qlinkctl" simulate-handshake
run "$REPO_ROOT/target/release/qlinkctl" quic-loopback
run "$REPO_ROOT/target/release/qlinkctl" mesh-loopback
run "$REPO_ROOT/target/release/qlinkctl" relay-loopback

run "$ROOT/scripts/build-rust-xcframework.sh"
run "$ROOT/scripts/package-dev-artifacts.sh"

if command -v xcodegen >/dev/null 2>&1; then
  run "$ROOT/scripts/package-macos.sh" --skip-sign --pkg
elif [[ "${QLINK_ALLOW_SKIP_XCODEGEN:-false}" == "true" ]]; then
  log "Skipping unsigned release package dry run because xcodegen is not installed and QLINK_ALLOW_SKIP_XCODEGEN=true"
else
  echo "xcodegen is required for unsigned release package dry run." >&2
  echo "Install it with: brew install xcodegen" >&2
  echo "Set QLINK_ALLOW_SKIP_XCODEGEN=true only for non-packaging CI lanes." >&2
  exit 1
fi

cat <<'EOF'

Pre-Apple local validation complete.

Still blocked on Apple Developer account or Apple-granted capabilities:
- Packet Tunnel Provider provisioning and real tunnel installation
- Developer ID signing
- Notarization and stapling
- MDM pre-approval payload validation on managed fleets

Unsigned local release artifacts, when XcodeGen is installed:
- build/release/QuantumLink.dmg
- build/release/QuantumLink.pkg
EOF
