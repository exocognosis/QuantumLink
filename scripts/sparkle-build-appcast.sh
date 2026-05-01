#!/usr/bin/env bash
# Build (or extend) appcast.xml for a QuantumLink update artifact.
#
# Inputs (env or flags):
#   --artifact      Path to the signed/notarized .dmg or .pkg to publish.
#   --version       Marketing version, e.g. 0.2.0.
#   --build         CFBundleVersion build number, e.g. 42.
#   --feed-url      Final URL the artifact will be served from.
#   --release-notes URL or path to release notes (HTML).
#   --appcast-out   Path to write/update appcast.xml. Default build/sparkle/appcast.xml.
#
# Sparkle's `sign_update` binary signs the artifact with the EdDSA private key
# stored in the Keychain (created by sparkle-generate-keys.sh). The signature
# is embedded in the appcast item as `sparkle:edSignature`.

set -euo pipefail

artifact=""
version=""
build=""
feed_url=""
release_notes=""
appcast_out="build/sparkle/appcast.xml"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --artifact)      artifact="$2"; shift 2 ;;
        --version)       version="$2"; shift 2 ;;
        --build)         build="$2"; shift 2 ;;
        --feed-url)      feed_url="$2"; shift 2 ;;
        --release-notes) release_notes="$2"; shift 2 ;;
        --appcast-out)   appcast_out="$2"; shift 2 ;;
        *) echo "Unknown flag: $1" >&2; exit 64 ;;
    esac
done

for required in artifact version build feed_url; do
    if [[ -z "${!required}" ]]; then
        echo "Missing --${required//_/-}" >&2
        exit 64
    fi
done

if [[ ! -f "${artifact}" ]]; then
    echo "Artifact does not exist: ${artifact}" >&2
    exit 1
fi

sign_update_bin="$(find "${HOME}/Library/Developer/Xcode/DerivedData" \
    -type f \
    -name sign_update \
    -path '*Sparkle*' \
    2>/dev/null | head -n 1 || true)"

if [[ -z "${sign_update_bin}" ]]; then
    echo "Could not locate Sparkle's sign_update binary; build the Xcode project first." >&2
    exit 1
fi

signature="$("${sign_update_bin}" --account QuantumLink "${artifact}")"
file_size=$(stat -f%z "${artifact}")
pub_date="$(date -u '+%a, %d %b %Y %H:%M:%S +0000')"

mkdir -p "$(dirname "${appcast_out}")"

cat > "${appcast_out}" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
    <channel>
        <title>QuantumLink macOS</title>
        <link>${feed_url}</link>
        <description>QuantumLink update feed</description>
        <language>en</language>
        <item>
            <title>Version ${version}</title>
            <pubDate>${pub_date}</pubDate>
            <sparkle:version>${build}</sparkle:version>
            <sparkle:shortVersionString>${version}</sparkle:shortVersionString>
            <sparkle:minimumSystemVersion>14.0</sparkle:minimumSystemVersion>
EOF

if [[ -n "${release_notes}" ]]; then
    cat >> "${appcast_out}" <<EOF
            <sparkle:releaseNotesLink>${release_notes}</sparkle:releaseNotesLink>
EOF
fi

cat >> "${appcast_out}" <<EOF
            <enclosure
                url="${feed_url}"
                length="${file_size}"
                type="application/octet-stream"
                ${signature} />
        </item>
    </channel>
</rss>
EOF

echo "Wrote ${appcast_out}"
echo "Signature attribute: ${signature}"
