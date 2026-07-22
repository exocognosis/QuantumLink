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

spec_path="$ROOT/project.yml"
generated_spec=""
if [[ "${QLINK_DISABLE_SPARKLE_PACKAGE:-false}" == "true" ]]; then
  generated_spec="$ROOT/project.generated.no-sparkle.yml"
  ruby -ryaml -e '
    spec = YAML.load_file(ARGV[0])
    spec.delete("packages")
    deps = spec.dig("targets", "QuantumLink", "dependencies")
    deps.reject! { |dep| dep.is_a?(Hash) && dep["package"] == "Sparkle" } if deps
    File.write(ARGV[1], YAML.dump(spec))
  ' "$ROOT/project.yml" "$generated_spec"
  spec_path="$generated_spec"
fi

xcodegen generate --spec "$spec_path" --project "$ROOT"
if [[ -n "$generated_spec" ]]; then
  rm -f "$generated_spec"
fi
echo "Generated $ROOT/QuantumLink.xcodeproj"
