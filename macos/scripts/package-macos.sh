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
#   QLINK_DEVELOPMENT_TEAM           - Apple Team ID for signed archive builds
#   QLINK_APP_PROVISIONING_PROFILE_SPECIFIER
#                                      app provisioning profile specifier for manual signing
#   QLINK_TUNNEL_PROVISIONING_PROFILE_SPECIFIER
#                                      packet tunnel provisioning profile specifier for manual signing
#   QLINK_SPARKLE_FEED_URL           - public appcast URL
#   QLINK_SPARKLE_PUBLIC_ED_KEY      - Sparkle EdDSA public key (base64)
# Optional environment:
#   QLINK_CARGO_TARGET_DIR           - external Cargo target dir for release packaging
#   QLINKCTL_SOURCE_PATH             - prebuilt universal qlinkctl helper
#
# Usage:
#   ./scripts/package-macos.sh                # produces signed .app + .dmg
#   ./scripts/package-macos.sh --pkg          # also produces signed .pkg
#   ./scripts/package-macos.sh --skip-sign    # local unsigned build (CI without secrets)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${ROOT}/.." && pwd)"
cd "${ROOT}"

skip_sign=false
build_pkg=false
original_args=("$@")

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

reject_placeholder_release_ids() {
    local failed=false
    if [[ "${QLINK_APP_BUNDLE_ID:-}" == "com.quantumlink.macos" ]]; then
        echo "QLINK_APP_BUNDLE_ID must not use the placeholder com.quantumlink.macos for signed releases" >&2
        failed=true
    fi
    if [[ "${QLINK_TUNNEL_BUNDLE_ID:-}" == "com.quantumlink.macos.PacketTunnel" ]]; then
        echo "QLINK_TUNNEL_BUNDLE_ID must not use the placeholder com.quantumlink.macos.PacketTunnel for signed releases" >&2
        failed=true
    fi
    if [[ "${QLINK_APP_GROUP:-}" == "group.com.quantumlink.macos" ]]; then
        echo "QLINK_APP_GROUP must not use the placeholder group.com.quantumlink.macos for signed releases" >&2
        failed=true
    fi
    if [[ "${failed}" == "true" ]]; then
        exit 1
    fi
}

if [[ "${skip_sign}" == "false" ]]; then
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
    reject_placeholder_release_ids
    if [[ "${build_pkg}" == "true" ]]; then
        require_env APPLE_DEVELOPER_ID_INSTALLER
    fi
fi

work_dir="${ROOT}"
out_dir="${work_dir}/build/release"
mkdir -p "${out_dir}"

cargo_target_root="${QLINK_CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/quantumlink-cargo-target}"

if [[ -z "${QLINK_PACKAGE_STAGED:-}" && "${QLINK_DISABLE_PACKAGE_STAGING:-false}" != "true" ]]; then
    stage_dir="$(mktemp -d "${TMPDIR:-/tmp}/quantumlink-package.XXXXXX")"
    stage_root="${stage_dir}/QuantumLinkOS"
    cleanup_stage() {
        rm -rf "${stage_dir}"
    }
    trap cleanup_stage EXIT

    echo "==> Staging release build under ${stage_root}"
    mkdir -p "${stage_root}"
    rsync -a --delete \
        --exclude '.git' \
        --exclude '.worktrees' \
        --exclude 'macos/.build' \
        --exclude 'macos/QuantumLink.xcodeproj' \
        --exclude 'macos/build' \
        --exclude 'target' \
        "${REPO_ROOT}/" "${stage_root}/"

    QLINK_PACKAGE_STAGED=1 \
    QLINK_CARGO_TARGET_DIR="${cargo_target_root}" \
        "${stage_root}/macos/scripts/package-macos.sh" "${original_args[@]}"

    rm -rf "${out_dir}"
    mkdir -p "${out_dir}"
    rsync -a "${stage_root}/macos/build/release/" "${out_dir}/"
    echo "==> Copied staged release artifacts to ${out_dir}"
    ls -lh "${out_dir}"
    exit 0
fi

build_universal_qlinkctl() {
    if [[ -n "${QLINKCTL_SOURCE_PATH:-}" ]]; then
        if [[ -x "${QLINKCTL_SOURCE_PATH}" ]]; then
            echo "==> Using prebuilt qlinkctl at ${QLINKCTL_SOURCE_PATH}"
            return
        fi
        echo "QLINKCTL_SOURCE_PATH is set but not executable: ${QLINKCTL_SOURCE_PATH}" >&2
        exit 1
    fi

    local host_target targets helper_dir helper_output
    host_target="$(rustc -vV | awk '/^host:/ { print $2 }')"
    if [[ -n "${QLINK_RUST_TARGETS:-}" ]]; then
        targets="${QLINK_RUST_TARGETS}"
    elif [[ "${host_target}" == *-apple-darwin ]]; then
        targets="aarch64-apple-darwin x86_64-apple-darwin"
    else
        targets="${host_target}"
    fi

    helper_dir="${out_dir}/helpers"
    helper_output="${helper_dir}/qlinkctl"
    rm -rf "${helper_dir}"
    mkdir -p "${helper_dir}" "${cargo_target_root}"

    local helpers=()
    for target in ${targets}; do
        if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -qx "${target}"; then
            echo "Missing Rust target: ${target}" >&2
            echo "Install it with: rustup target add ${target}" >&2
            exit 1
        fi
        CARGO_TARGET_DIR="${cargo_target_root}" cargo build -p qlink-core --bin qlinkctl --release --target "${target}"
        helpers+=("${cargo_target_root}/${target}/release/qlinkctl")
    done

    if [[ "${#helpers[@]}" -gt 1 ]]; then
        lipo -create "${helpers[@]}" -output "${helper_output}"
    else
        cp "${helpers[0]}" "${helper_output}"
    fi
    chmod 755 "${helper_output}"
    export QLINKCTL_SOURCE_PATH="${helper_output}"
    echo "==> Built qlinkctl helper at ${QLINKCTL_SOURCE_PATH}"
}

sanitize_app_bundle() {
    local bundle_path="$1"
    find "${bundle_path}" -name '._*' -delete
    xattr -cr "${bundle_path}" 2>/dev/null || true
}

write_release_checksums() {
    local checksum_path="${out_dir}/SHA256SUMS.txt"
    local artifacts=("${dmg_path}")
    if [[ "${build_pkg}" == "true" ]]; then
        artifacts+=("${pkg_path}")
    fi

    echo "==> Writing release checksums to ${checksum_path}"
    shasum -a 256 "${artifacts[@]}" > "${checksum_path}"
}

xcode_settings=(
    "QLINK_APP_BUNDLE_ID=${QLINK_APP_BUNDLE_ID:-com.quantumlink.macos}"
    "QLINK_TUNNEL_BUNDLE_ID=${QLINK_TUNNEL_BUNDLE_ID:-com.quantumlink.macos.PacketTunnel}"
    "QLINK_APP_GROUP=${QLINK_APP_GROUP:-group.com.quantumlink.macos}"
    "QLINK_SPARKLE_FEED_URL=${QLINK_SPARKLE_FEED_URL:-}"
    "QLINK_SPARKLE_PUBLIC_ED_KEY=${QLINK_SPARKLE_PUBLIC_ED_KEY:-}"
    "QLINK_APP_PROVISIONING_PROFILE_SPECIFIER=${QLINK_APP_PROVISIONING_PROFILE_SPECIFIER:-}"
    "QLINK_TUNNEL_PROVISIONING_PROFILE_SPECIFIER=${QLINK_TUNNEL_PROVISIONING_PROFILE_SPECIFIER:-}"
)

if [[ -n "${QLINK_DEVELOPMENT_TEAM:-}" ]]; then
    xcode_settings+=("DEVELOPMENT_TEAM=${QLINK_DEVELOPMENT_TEAM}")
fi

if [[ "${skip_sign}" == "true" ]]; then
    export QLINK_DISABLE_SPARKLE_PACKAGE="${QLINK_DISABLE_SPARKLE_PACKAGE:-true}"
fi

echo "==> Building Rust XCFramework"
./scripts/build-rust-xcframework.sh

echo "==> Building qlinkctl helper"
build_universal_qlinkctl

echo "==> Generating Xcode project"
./scripts/generate-xcode-project.sh

archive_path="${out_dir}/QuantumLink.xcarchive"
export_path="${out_dir}/export"
derived_data_path="${out_dir}/DerivedData"
source_packages_path="${out_dir}/SourcePackages"
rm -rf "${archive_path}" "${export_path}"
mkdir -p "${export_path}" "${derived_data_path}" "${source_packages_path}"

echo "==> Archiving QuantumLink.app"
if [[ "${skip_sign}" == "true" ]]; then
    xcodebuild \
        -project QuantumLink.xcodeproj \
        -scheme QuantumLink \
        -configuration Release \
        -archivePath "${archive_path}" \
        -derivedDataPath "${derived_data_path}" \
        -clonedSourcePackagesDirPath "${source_packages_path}" \
        CODE_SIGNING_ALLOWED=NO \
        "${xcode_settings[@]}" \
        archive
else
    xcodebuild \
        -project QuantumLink.xcodeproj \
        -scheme QuantumLink \
        -configuration Release \
        -archivePath "${archive_path}" \
        -derivedDataPath "${derived_data_path}" \
        -clonedSourcePackagesDirPath "${source_packages_path}" \
        CODE_SIGN_STYLE=Manual \
        CODE_SIGNING_ALLOWED=YES \
        CODE_SIGNING_REQUIRED=YES \
        "CODE_SIGN_IDENTITY=${APPLE_DEVELOPER_ID_APPLICATION}" \
        "${xcode_settings[@]}" \
        archive
fi

app_path="${archive_path}/Products/Applications/QuantumLink.app"
if [[ ! -d "${app_path}" ]]; then
    echo "Archive missing QuantumLink.app at ${app_path}" >&2
    exit 1
fi

cp -R "${app_path}" "${export_path}/QuantumLink.app"
app_path="${export_path}/QuantumLink.app"
sanitize_app_bundle "${app_path}"

helper_path="${app_path}/Contents/MacOS/qlinkctl"
echo "==> Bundling qlinkctl helper at ${helper_path}"
install -m 755 "${QLINKCTL_SOURCE_PATH}" "${helper_path}"
if [[ ! -x "${helper_path}" ]]; then
    echo "Missing bundled qlinkctl helper at ${helper_path}" >&2
    exit 1
fi

if [[ "${skip_sign}" == "true" ]]; then
    echo "==> Skipping codesign / notarization (--skip-sign)"
else
    resolved_app_entitlements="${out_dir}/QuantumLink.resolved.entitlements"
    resolved_tunnel_entitlements="${out_dir}/QuantumLinkTunnel.resolved.entitlements"
    sed 's|$(QLINK_APP_GROUP)|'"${QLINK_APP_GROUP}"'|g' \
        entitlements/QuantumLink.entitlements > "${resolved_app_entitlements}"
    sed 's|$(QLINK_APP_GROUP)|'"${QLINK_APP_GROUP}"'|g' \
        entitlements/QuantumLinkTunnel.entitlements > "${resolved_tunnel_entitlements}"

    echo "==> Codesigning qlinkctl helper"
    codesign --force --options runtime --timestamp \
        --sign "${APPLE_DEVELOPER_ID_APPLICATION}" \
        "${helper_path}"

    echo "==> Re-signing nested frameworks and dylibs"
    while IFS= read -r -d '' nested; do
        codesign --force --options runtime --timestamp \
            --sign "${APPLE_DEVELOPER_ID_APPLICATION}" \
            "${nested}"
    done < <(find -d "${app_path}/Contents" \
        \( -name '*.framework' -o -name '*.dylib' \) \
        -print0)

    tunnel_appex="${app_path}/Contents/PlugIns/QuantumLinkTunnel.appex"
    if [[ -d "${tunnel_appex}" ]]; then
        echo "==> Codesigning QuantumLinkTunnel.appex"
        codesign --force --options runtime --timestamp \
            --entitlements "${resolved_tunnel_entitlements}" \
            --sign "${APPLE_DEVELOPER_ID_APPLICATION}" \
            "${tunnel_appex}"
    else
        echo "Missing bundled packet tunnel extension at ${tunnel_appex}" >&2
        exit 1
    fi

    echo "==> Codesigning QuantumLink.app"
    codesign --force --options runtime --timestamp \
        --entitlements "${resolved_app_entitlements}" \
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
        --wait \
        --output-format json | tee "${out_dir}/notary-app.json"

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
hdiutil verify "${dmg_path}"

if [[ "${skip_sign}" == "false" ]]; then
    echo "==> Codesigning DMG"
    codesign --force --sign "${APPLE_DEVELOPER_ID_APPLICATION}" "${dmg_path}"
    echo "==> Notarizing DMG"
    xcrun notarytool submit "${dmg_path}" \
        --keychain-profile "${APPLE_NOTARY_PROFILE}" \
        --wait \
        --output-format json | tee "${out_dir}/notary-dmg.json"
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
            --wait \
            --output-format json | tee "${out_dir}/notary-pkg.json"
        xcrun stapler staple "${pkg_path}"
    fi
fi

write_release_checksums

echo "==> Release artifacts under ${out_dir}:"
ls -lh "${out_dir}"
