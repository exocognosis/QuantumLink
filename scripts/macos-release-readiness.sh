#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

require_signing_env=false
require_pkg_signing_env=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-signing-env)
      require_signing_env=true
      shift
      ;;
    --require-pkg-signing-env)
      require_signing_env=true
      require_pkg_signing_env=true
      shift
      ;;
    *)
      echo "Unknown flag: $1" >&2
      exit 64
      ;;
  esac
done

failures=0

log() {
  printf '\n==> %s\n' "$*"
}

pass() {
  printf 'ok - %s\n' "$*"
}

fail() {
  printf 'FAIL - %s\n' "$*" >&2
  failures=$((failures + 1))
}

require_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    pass "found $path"
  else
    fail "missing $path"
  fi
}

require_env() {
  local name="$1"
  if [[ -n "${!name:-}" ]]; then
    pass "env $name is set"
  else
    fail "env $name is required for signed release packaging"
  fi
}

reject_env_value() {
  local name="$1"
  local rejected="$2"
  local label="$3"
  if [[ "${!name:-}" == "$rejected" ]]; then
    fail "$label must not use placeholder value $rejected"
  else
    pass "$label is not using placeholder value"
  fi
}

require_contains() {
  local path="$1"
  local pattern="$2"
  local label="$3"
  if grep -Fq "$pattern" "$path"; then
    pass "$label"
  else
    fail "$label"
  fi
}

xcconfig_value() {
  local key="$1"
  awk -F '=' -v key="$key" '
    $1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
      value=$2
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)
      print value
      exit
    }
  ' macos/config/QuantumLink.common.xcconfig
}

log "Required macOS project files"
require_file macos/project.yml
require_file macos/config/QuantumLink.common.xcconfig
require_file macos/config/QuantumLink.unsigned.xcconfig
require_file macos/config/QuantumLink.developer-id.template.xcconfig
require_file macos/Info/QuantumLink.Info.plist
require_file macos/Info/QuantumLinkTunnel.Info.plist
require_file macos/entitlements/QuantumLink.entitlements
require_file macos/entitlements/QuantumLinkTunnel.entitlements
require_file scripts/package-macos.sh
require_file scripts/generate-xcode-project.sh

log "Plist syntax"
for plist in \
  macos/Info/QuantumLink.Info.plist \
  macos/Info/QuantumLinkTunnel.Info.plist \
  macos/entitlements/QuantumLink.entitlements \
  macos/entitlements/QuantumLinkTunnel.entitlements
do
  if plutil -lint "$plist" >/dev/null; then
    pass "valid plist $plist"
  else
    fail "invalid plist $plist"
  fi
done

log "Bundle identifiers and app group"
app_bundle_id="$(xcconfig_value QLINK_APP_BUNDLE_ID)"
tunnel_bundle_id="$(xcconfig_value QLINK_TUNNEL_BUNDLE_ID)"
app_group="$(xcconfig_value QLINK_APP_GROUP)"

[[ -n "$app_bundle_id" ]] || fail "QLINK_APP_BUNDLE_ID must be set in common xcconfig"
[[ -n "$tunnel_bundle_id" ]] || fail "QLINK_TUNNEL_BUNDLE_ID must be set in common xcconfig"
[[ -n "$app_group" ]] || fail "QLINK_APP_GROUP must be set in common xcconfig"

if [[ "$tunnel_bundle_id" == "$app_bundle_id".* ]]; then
  pass "tunnel bundle id is namespaced under app bundle id"
else
  fail "tunnel bundle id should be namespaced under app bundle id"
fi

if [[ "$app_group" == group.* ]]; then
  pass "app group uses group.* prefix"
else
  fail "app group must use group.* prefix"
fi

log "Entitlement templates"
for entitlements in macos/entitlements/QuantumLink.entitlements macos/entitlements/QuantumLinkTunnel.entitlements; do
  require_contains "$entitlements" "com.apple.security.app-sandbox" "$entitlements declares app sandbox"
  require_contains "$entitlements" "com.apple.security.network.client" "$entitlements declares network client access"
  require_contains "$entitlements" "com.apple.security.application-groups" "$entitlements declares application group"
  require_contains "$entitlements" '$(QLINK_APP_GROUP)' "$entitlements uses QLINK_APP_GROUP substitution"
  require_contains "$entitlements" "com.apple.developer.networking.networkextension" "$entitlements declares Network Extension entitlement"
  require_contains "$entitlements" "packet-tunnel-provider" "$entitlements declares packet tunnel provider capability"
done

log "XcodeGen target wiring"
require_contains macos/project.yml "CODE_SIGN_ENTITLEMENTS: macos/entitlements/QuantumLink.entitlements" "app target uses app entitlements"
require_contains macos/project.yml "CODE_SIGN_ENTITLEMENTS: macos/entitlements/QuantumLinkTunnel.entitlements" "tunnel target uses tunnel entitlements"
require_contains macos/project.yml "INFOPLIST_FILE: macos/Info/QuantumLink.Info.plist" "app target uses app Info.plist"
require_contains macos/project.yml "INFOPLIST_FILE: macos/Info/QuantumLinkTunnel.Info.plist" "tunnel target uses tunnel Info.plist"
require_contains macos/project.yml "PRODUCT_BUNDLE_IDENTIFIER: \$(QLINK_APP_BUNDLE_ID)" "app target uses QLINK_APP_BUNDLE_ID"
require_contains macos/project.yml "PRODUCT_BUNDLE_IDENTIFIER: \$(QLINK_TUNNEL_BUNDLE_ID)" "tunnel target uses QLINK_TUNNEL_BUNDLE_ID"
require_contains macos/project.yml "PROVISIONING_PROFILE_SPECIFIER: \$(QLINK_APP_PROVISIONING_PROFILE_SPECIFIER)" "app target uses app provisioning profile specifier"
require_contains macos/project.yml "PROVISIONING_PROFILE_SPECIFIER: \$(QLINK_TUNNEL_PROVISIONING_PROFILE_SPECIFIER)" "tunnel target uses tunnel provisioning profile specifier"
require_contains macos/Info/QuantumLinkTunnel.Info.plist "com.apple.networkextension.packet-tunnel" "tunnel Info.plist declares packet tunnel extension point"

log "Packaging workflow"
require_contains scripts/package-macos.sh "codesign --force --options runtime --timestamp" "package script signs with hardened runtime and timestamp"
require_contains scripts/package-macos.sh "xcrun notarytool submit" "package script submits artifacts to notarytool"
require_contains scripts/package-macos.sh "xcrun stapler staple" "package script staples notarization tickets"
require_contains scripts/package-macos.sh "hdiutil create" "package script creates DMG"
require_contains scripts/package-macos.sh "productbuild" "package script can create PKG"
require_contains scripts/package-macos.sh "codesign --verify --deep --strict" "package script verifies app signature"

if [[ "$require_signing_env" == "true" ]]; then
  log "Signed release environment"
  require_env APPLE_DEVELOPER_ID_APPLICATION
  require_env APPLE_NOTARY_PROFILE
  require_env QLINK_DEVELOPMENT_TEAM
  require_env QLINK_APP_BUNDLE_ID
  require_env QLINK_TUNNEL_BUNDLE_ID
  require_env QLINK_APP_GROUP
  require_env QLINK_APP_PROVISIONING_PROFILE_SPECIFIER
  require_env QLINK_TUNNEL_PROVISIONING_PROFILE_SPECIFIER
  require_env QLINK_SPARKLE_FEED_URL
  require_env QLINK_SPARKLE_PUBLIC_ED_KEY
  reject_env_value QLINK_APP_BUNDLE_ID "com.quantumlink.macos" "app bundle id"
  reject_env_value QLINK_TUNNEL_BUNDLE_ID "com.quantumlink.macos.PacketTunnel" "tunnel bundle id"
  reject_env_value QLINK_APP_GROUP "group.com.quantumlink.macos" "app group"
  if [[ "$require_pkg_signing_env" == "true" ]]; then
    require_env APPLE_DEVELOPER_ID_INSTALLER
  fi
fi

if (( failures > 0 )); then
  printf '\nmacOS release readiness check failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

cat <<'EOF'

macOS release readiness static checks passed.

This confirms project settings, entitlement templates, Info.plist files, and
packaging workflow wiring. A real installable packet tunnel still requires
Apple-granted Network Extension capability, matching provisioning profiles,
Developer ID signing, notarization, and stapling.
EOF
