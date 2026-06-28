#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
DIST_DIR="$ROOT/build/dist"
STAGE="$DIST_DIR/QuantumLink-dev"
ARCHIVE="$DIST_DIR/QuantumLink-dev.tar.gz"
CHECKSUM="$ARCHIVE.sha256"

cd "$ROOT"

cargo build -p qlink-core --release
swift build -c release --product QuantumLinkSmoke
SWIFT_RELEASE_BIN="$(swift build -c release --show-bin-path)"

rm -rf "$STAGE" "$ARCHIVE" "$CHECKSUM"
mkdir -p "$STAGE/bin" "$STAGE/lib" "$STAGE/config" "$STAGE/docs"

cp "$REPO_ROOT/target/release/qlinkctl" "$STAGE/bin/qlinkctl"
cp "$SWIFT_RELEASE_BIN/QuantumLinkSmoke" "$STAGE/bin/QuantumLinkSmoke"
cp "$REPO_ROOT/target/release/libqlink_core.dylib" "$STAGE/lib/libqlink_core.dylib"
cp "$REPO_ROOT/config/mesh.example.json" "$STAGE/config/mesh.example.json"
cp "$REPO_ROOT/README.md" "$STAGE/README.md"
cp "$REPO_ROOT/docs/architecture.md" "$STAGE/docs/architecture.md"
cp "$REPO_ROOT/docs/security.md" "$STAGE/docs/security.md"

cat > "$STAGE/RUNBOOK.md" <<'EOF'
# QuantumLink Development Artifact Runbook

These artifacts are unsigned local development tools. They are not notarized and do not install a packet tunnel extension.

Validate the bundled example config:

```sh
./bin/QuantumLinkSmoke validate-config --config config/mesh.example.json
```

Verify the retired Swift-to-Rust local QUIC loopback fails closed:

```sh
QLINK_CORE_DYLIB="$PWD/lib/libqlink_core.dylib" \
! ./bin/QuantumLinkSmoke transport-loopback \
  --mode dev-quic-loopback \
  --dylib "$PWD/lib/libqlink_core.dylib"
```

Run Rust control/data-plane checks:

```sh
./bin/qlinkctl simulate-handshake
! ./bin/qlinkctl quic-loopback
! ./bin/qlinkctl mesh-loopback
! ./bin/qlinkctl relay-loopback
! ./bin/qlinkctl relay-smoke
```
EOF

{
  echo "# QuantumLink Development Artifact Manifest"
  echo
  echo "generated_at_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "git_sha=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "swift_version=$(swift --version | head -n 1)"
  echo "rustc_version=$(rustc --version)"
  echo "cargo_version=$(cargo --version)"
  if command -v xcodebuild >/dev/null 2>&1; then
    echo "xcodebuild_version=$(xcodebuild -version | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
  else
    echo "xcodebuild_version=missing"
  fi
  echo
  echo "## SHA256"
  (
    cd "$STAGE"
    find . -type f ! -name MANIFEST.txt | LC_ALL=C sort | while IFS= read -r artifact; do
      shasum -a 256 "$artifact"
    done
  )
} > "$STAGE/MANIFEST.txt"

tar -C "$DIST_DIR" -czf "$ARCHIVE" QuantumLink-dev
shasum -a 256 "$ARCHIVE" > "$CHECKSUM"
echo "Created $ARCHIVE"
echo "Created $CHECKSUM"
