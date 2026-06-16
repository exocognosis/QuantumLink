#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v xcodegen >/dev/null 2>&1; then
  cat >&2 <<'EOF'
xcodegen is not installed.

Install it with:
  brew install xcodegen

Then rerun:
  ./scripts/generate-xcode-project.sh
EOF
  exit 127
fi

xcodegen generate \
  --spec "$ROOT/project.yml" \
  --project "$ROOT"
