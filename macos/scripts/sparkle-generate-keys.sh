#!/usr/bin/env bash
# Generate or print the Sparkle 2 EdDSA key pair used to sign QuantumLink updates.
#
# Sparkle ships a `generate_keys` binary inside its Swift Package artifact bundle.
# After at least one Xcode build of the QuantumLink target (which resolves the
# Sparkle package), the binary is available under the SPM package cache.
#
# Usage:
#   ./scripts/sparkle-generate-keys.sh                # creates the key pair if it does not yet exist
#   ./scripts/sparkle-generate-keys.sh --print-public # prints the existing public key
#
# The private key is stored in the macOS Keychain by Sparkle's own tooling
# (it never lands on disk in plaintext). The public key is written to
# build/sparkle/eddsa.pub for inclusion in CI as `QLINK_SPARKLE_PUBLIC_ED_KEY`.

set -euo pipefail

mode="${1:-generate}"
out_dir="build/sparkle"
mkdir -p "$out_dir"

generate_keys_bin="$(find "${HOME}/Library/Developer/Xcode/DerivedData" \
    -type f \
    -name generate_keys \
    -path '*Sparkle*' \
    2>/dev/null | head -n 1 || true)"

if [[ -z "${generate_keys_bin}" ]]; then
    cat >&2 <<'EOF'
Could not locate Sparkle's `generate_keys` binary. Build the QuantumLink Xcode
project at least once so SPM resolves the Sparkle package, then re-run this
script. If you build outside Xcode (`swift build`), pass --xcode to the build
script or run `xcodebuild -resolvePackageDependencies`.
EOF
    exit 1
fi

case "${mode}" in
    generate)
        echo "Using generate_keys at: ${generate_keys_bin}"
        "${generate_keys_bin}" --account QuantumLink --print-public-key > "${out_dir}/eddsa.pub.tmp" || true
        if [[ -s "${out_dir}/eddsa.pub.tmp" ]]; then
            mv "${out_dir}/eddsa.pub.tmp" "${out_dir}/eddsa.pub"
            echo "Public key written to ${out_dir}/eddsa.pub"
        else
            rm -f "${out_dir}/eddsa.pub.tmp"
            "${generate_keys_bin}" --account QuantumLink
            "${generate_keys_bin}" --account QuantumLink --print-public-key > "${out_dir}/eddsa.pub"
            echo "Generated key pair; public key written to ${out_dir}/eddsa.pub"
        fi
        ;;
    --print-public)
        "${generate_keys_bin}" --account QuantumLink --print-public-key
        ;;
    *)
        echo "Unknown mode: ${mode}" >&2
        exit 64
        ;;
esac
