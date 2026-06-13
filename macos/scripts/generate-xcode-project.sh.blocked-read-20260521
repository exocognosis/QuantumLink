#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v xcodegen >/dev/null 2>&1; then
  cat >&2 <<'EOF'
xcodegen is not installed.

Install it with one of:
  brew install xcodegen
  mint install yonaskolb/XcodeGen

Then rerun:
  ./scripts/generate-xcode-project.sh
EOF
  exit 127
fi

"$ROOT/scripts/build-rust-xcframework.sh"
xcodegen generate --spec "$ROOT/macos/project.yml" --project "$ROOT"
echo "Generated $ROOT/QuantumLink.xcodeproj"
