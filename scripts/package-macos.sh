#!/usr/bin/env bash
# Build, sign, notarize, and staple a Developer ID release of QuantumLink.macOS.
#
# Required environment for a real release:
#   APPLE_DEVELOPER_ID_APPLICATION   - codesign identity, e.g.
#                                      "Developer ID Application: Acme Inc (TEAMID)"
#   APPLE_DEVELOPER_ID_INSTALLER     - PKG codesign identity (only if --pkg)
#   APPLE_NOTARY_PROFILE             - notarytool keychain profile name created via
#                                      `xcrun notarytool store-credentials`
#   QLINK_APP_BUNDLE_ID              - app bundle id, e.g. com.acme.QuantumLink
#   QLINK_TUNNEL_BUNDLE_ID           - tunnel bundle id, e.g. com.acme.QuantumLink.PacketTunnel
#   QLINK_SPARKLE_FEED_URL           - public appcast URL
#   QLINK_SPARKLE_PUBLIC_ED_KEY      - Sparkle EdDSA public key (base64)
#
# Usage:
#   ./scripts/package-macos.sh                # produces signed .app + .dmg
#   ./scripts/package-macos.sh --pkg          # also produces signed .pkg
#   ./scripts/package-macos.sh --skip-sign    # local unsigned build (CI without secrets)

set -euo pipefail

skip_sign=false
build_pkg=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-sign) skip_sign=true; shift ;;
        --pkg)       build_pkg=true; shift ;;
        *) echo "Unknown flag: $1" >&2; exit 64 ;;
    esac
done

require_env() {
    local var="$1"
    if [[ -z "${!var:-}" ]]; then
        echo "Missing required env var: ${var}" >&2
        exit 1
    fi
}

if [[ "${skip_sign}" == "false" ]]; then
    require_env APPLE_DEVELOPER_ID_APPLICATION
    require_env APPLE_NOTARY_PROFILE
    require_env QLINK_APP_BUNDLE_ID
    require_env QLINK_TUNNEL_BUNDLE_ID
    if [[ "${build_pkg}" == "true" ]]; then
        require_env APPLE_DEVELOPER_ID_INSTALLER
    fi
fi

work_dir="$(pwd)"
out_dir="${work_dir}/build/release"
mkdir -p "${out_dir}"

echo "==> Building Rust XCFramework"
./scripts/build-rust-xcframework.sh

echo "==> Generating Xcode project"
./scripts/generate-xcode-project.sh

archive_path="${out_dir}/QuantumLink.xcarchive"
export_path="${out_dir}/export"
rm -rf "${archive_path}" "${export_path}"
mkdir -p "${export_path}"

echo "==> Archiving QuantumLink.app"
if [[ "${skip_sign}" == "true" ]]; then
    xcodebuild \
        -project QuantumLink.xcodeproj \
        -scheme QuantumLink \
        -configuration Release \
        -archivePath "${archive_path}" \
        CODE_SIGNING_ALLOWED=NO \
        archive
else
    xcodebuild \
        -project QuantumLink.xcodeproj \
        -scheme QuantumLink \
        -configuration Release \
        -archivePath "${archive_path}" \
        CODE_SIGN_STYLE=Manual \
        "CODE_SIGN_IDENTITY=${APPLE_DEVELOPER_ID_APPLICATION}" \
        archive
fi

app_path="${archive_path}/Products/Applications/QuantumLink.app"
if [[ ! -d "${app_path}" ]]; then
    echo "Archive missing QuantumLink.app at ${app_path}" >&2
    exit 1
fi

cp -R "${app_path}" "${export_path}/QuantumLink.app"
app_path="${export_path}/QuantumLink.app"

if [[ "${skip_sign}" == "true" ]]; then
    echo "==> Skipping codesign / notarization (--skip-sign)"
else
    echo "==> Re-signing nested binaries (extension, frameworks)"
    while IFS= read -r -d '' nested; do
        codesign --force --options runtime --timestamp \
            --sign "${APPLE_DEVELOPER_ID_APPLICATION}" \
            "${nested}"
    done < <(find "${app_path}/Contents" \
        \( -name '*.appex' -o -name '*.framework' -o -name '*.dylib' \) \
        -print0)

    echo "==> Codesigning QuantumLink.app"
    codesign --force --options runtime --timestamp \
        --sign "${APPLE_DEVELOPER_ID_APPLICATION}" \
        "${app_path}"

    echo "==> Verifying codesign"
    codesign --verify --deep --strict --verbose=2 "${app_path}"

    echo "==> Submitting to Apple notary service"
    zip_for_notary="${out_dir}/QuantumLink-notary.zip"
    rm -f "${zip_for_notary}"
    /usr/bin/ditto -c -k --keepParent "${app_path}" "${zip_for_notary}"
    xcrun notarytool submit "${zip_for_notary}" \
        --keychain-profile "${APPLE_NOTARY_PROFILE}" \
        --wait

    echo "==> Stapling notary ticket"
    xcrun stapler staple "${app_path}"
    xcrun stapler validate "${app_path}"
fi

dmg_path="${out_dir}/QuantumLink.dmg"
echo "==> Building DMG at ${dmg_path}"
rm -f "${dmg_path}"
hdiutil create \
    -volname "QuantumLink" \
    -srcfolder "${app_path}" \
    -ov \
    -format UDZO \
    "${dmg_path}"

if [[ "${skip_sign}" == "false" ]]; then
    echo "==> Codesigning DMG"
    codesign --force --sign "${APPLE_DEVELOPER_ID_APPLICATION}" "${dmg_path}"
    echo "==> Notarizing DMG"
    xcrun notarytool submit "${dmg_path}" \
        --keychain-profile "${APPLE_NOTARY_PROFILE}" \
        --wait
    xcrun stapler staple "${dmg_path}"
fi

if [[ "${build_pkg}" == "true" ]]; then
    pkg_path="${out_dir}/QuantumLink.pkg"
    echo "==> Building PKG at ${pkg_path}"
    rm -f "${pkg_path}"
    productbuild \
        --component "${app_path}" /Applications \
        "${pkg_path}"

    if [[ "${skip_sign}" == "false" ]]; then
        signed_pkg="${out_dir}/QuantumLink-signed.pkg"
        productsign --sign "${APPLE_DEVELOPER_ID_INSTALLER}" \
            "${pkg_path}" "${signed_pkg}"
        mv "${signed_pkg}" "${pkg_path}"
        xcrun notarytool submit "${pkg_path}" \
            --keychain-profile "${APPLE_NOTARY_PROFILE}" \
            --wait
        xcrun stapler staple "${pkg_path}"
    fi
fi

echo "==> Release artifacts under ${out_dir}:"
ls -lh "${out_dir}"
