#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

xcodegen generate \
  --spec "$ROOT/project.yml" \
  --project "$ROOT/QuantumLink.xcodeproj"
