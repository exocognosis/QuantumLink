# macOS Release Operator Checklist

Use this checklist after Apple Developer approval, Developer ID certificates,
notary credentials, and the Network Extension entitlement are available.

## Before Building

- Confirm the release version, changelog, and release owner.
- Confirm the working tree is clean except intentional release metadata.
- Confirm the CI/release variables:
  `QLINK_APP_BUNDLE_ID`, `QLINK_TUNNEL_BUNDLE_ID`, `QLINK_APP_GROUP`,
  `QLINK_DEVELOPMENT_TEAM`, `QLINK_APP_PROVISIONING_PROFILE_SPECIFIER`,
  `QLINK_TUNNEL_PROVISIONING_PROFILE_SPECIFIER`,
  `QLINK_SPARKLE_FEED_URL`, and `QLINK_SPARKLE_PUBLIC_ED_KEY`.
- Confirm the CI/release secrets: Developer ID certificate P12, certificate
  password, notary API key, notary key ID, notary issuer ID, app and tunnel
  provisioning profile payloads, and Sparkle EdDSA private key.
- Confirm none of the signed release values use placeholder IDs:
  `com.quantumlink.macos`, `com.quantumlink.macos.PacketTunnel`, or
  `group.com.quantumlink.macos`.
- Confirm Developer ID Application, Developer ID Installer, and notary profile
  values are available on the release runner.
- Confirm app and tunnel provisioning profiles match their bundle IDs and team.
- Confirm Sparkle feed URL and EdDSA public key are set for signed release
  packaging.
- Run `./macos/scripts/preapple-check.sh`.
- Run `./macos/scripts/macos-release-readiness.sh --require-signing-env`.
- For PKG releases, run
  `./macos/scripts/macos-release-readiness.sh --require-pkg-signing-env`.

## Build And Sign

```sh
./macos/scripts/package-macos.sh --pkg
```

Record:

- App archive path.
- DMG path and SHA256 from `build/release/SHA256SUMS.txt`.
- PKG path and SHA256 from `build/release/SHA256SUMS.txt`.
- Notary JSON evidence files under `build/release/notary-*.json`.
- Sparkle appcast signature evidence under `build/sparkle/appcast-evidence.txt`.
- Stapling result.

## Validation

- Run `codesign --verify --deep --strict --verbose=2` on the exported app.
- Run `spctl --assess --type execute --verbose=4` on the exported app.
- Run `spctl --assess --type install --verbose=4` on the signed PKG.
- Install on a clean test Mac.
- Confirm the packet tunnel extension installs, prompts correctly, starts, and
  stops.
- Confirm public mesh Dytallix verification fails closed when RPC or registry
  status is unavailable.
- Confirm private/development meshes can opt out of identity verification.
- Export a default support bundle and confirm no wallet private keys,
  passphrases, keystore paths, raw peer IDs, raw mesh IDs, or raw IP endpoints
  are present.

## Publish

- Verify Sparkle appcast signature before publishing.
- Upload artifacts and checksums to the release channel.
- Publish release notes that label Dytallix identity as testnet-backed beta
  trust infrastructure until production registry/mainnet hardening is complete.
- Keep the previous signed release available for rollback.

## Rollback

- Pull the appcast update entry if Sparkle rollout is active.
- Re-publish the previous signed artifact and checksum.
- Notify beta testers to export default redacted diagnostics before downgrading
  if they hit a blocking failure.
