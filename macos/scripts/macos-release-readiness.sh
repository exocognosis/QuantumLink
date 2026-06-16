#!/usr/bin/env bash
# Validate the environment needed for a signed macOS release before
# invoking the heavier archive/sign/notarize packaging path.

set -euo pipefail

require_pkg_signing_env=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-pkg-signing-env) require_pkg_signing_env=true; shift ;;
    *) echo "Unknown flag: $1" >&2; exit 64 ;;
  esac
done

missing=()

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    missing+=("$name")
  fi
}

require_env APPLE_DEVELOPER_ID_APPLICATION
require_env APPLE_NOTARY_PROFILE
require_env QLINK_APP_BUNDLE_ID
require_env QLINK_TUNNEL_BUNDLE_ID
require_env QLINK_DEVELOPMENT_TEAM
require_env QLINK_APP_PROVISIONING_PROFILE_SPECIFIER
require_env QLINK_TUNNEL_PROVISIONING_PROFILE_SPECIFIER

if [[ "$require_pkg_signing_env" == "true" ]]; then
  require_env APPLE_DEVELOPER_ID_INSTALLER
fi

if [[ ${#missing[@]} -gt 0 ]]; then
  printf 'Missing signed macOS release environment:\n' >&2
  printf '  %s\n' "${missing[@]}" >&2
  exit 1
fi

echo "Signed macOS release environment is present"
