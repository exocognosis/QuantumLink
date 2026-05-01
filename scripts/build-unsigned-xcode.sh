#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$ROOT/QuantumLink.xcodeproj"

if ! command -v xcodegen >/dev/null 2>&1; then
  cat >&2 <<'EOF'
xcodegen is not installed; skipping unsigned Xcode build.

Install it with:
  brew install xcodegen

Then rerun:
  ./scripts/build-unsigned-xcode.sh
EOF
  exit 0
fi

"$ROOT/scripts/generate-xcode-project.sh"

xcodebuild \
  -project "$PROJECT" \
  -scheme QuantumLink \
  -configuration Debug \
  -destination 'platform=macOS' \
  -derivedDataPath "$ROOT/DerivedData/UnsignedXcodeBuild" \
  CODE_SIGNING_ALLOWED=NO \
  build

echo "Built unsigned QuantumLink Xcode target"
