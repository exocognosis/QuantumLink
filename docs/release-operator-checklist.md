# Release Operator Checklists

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

# Windows Release Operator Checklist

Use this checklist for Windows MSI beta artifacts after the Wintun source,
Authenticode signing, and Windows validation gates are available.

## Before Building

- Confirm the release version, changelog, release owner, and exact release
  commit.
- Confirm the Windows CI workflow is green for the release commit.
- Confirm repository variables `WINTUN_DOWNLOAD_URL` and `WINTUN_SHA256` point
  to a pinned official Wintun archive and checksum.
- Confirm tag releases have `WINDOWS_SIGNING_CERT_PFX_BASE64` and
  `WINDOWS_SIGNING_CERT_PASSWORD` configured. Confirm
  `WINDOWS_SIGNING_TIMESTAMP_URL` if using a timestamp URL other than the
  workflow default.
- For manual workflow runs, decide whether to enforce publisher identity with
  `expected_publisher_subject` and/or `expected_publisher_thumbprint`.
- For optional upgrade validation, configure `upgrade_from_msi_url` and
  `upgrade_from_msi_sha256` as a complete URL/SHA pair.
- For optional rollback validation, set `validate_rollback`, keep
  `upgrade_from_msi_url` configured, choose `rollback_mode`
  (`UninstallReinstall` or `DirectDowngrade`), and configure
  `rollback_to_msi_url` plus `rollback_to_msi_sha256` only when rolling back to
  a target other than the upgrade source.

## Build And Sign

- Run the Windows release workflow from the release commit or tag.
- Confirm the workflow downloads the pinned Wintun archive, verifies its
  SHA-256, stages `bin/amd64/wintun.dll`, and includes
  `WINTUN-LICENSE.txt`.
- Confirm `QuantumLink.msi` is Authenticode-signed and timestamped for tag
  releases.
- Confirm `SHA256SUMS.txt` covers the staged MSI selected for publication.

## Validation

- If `run_install_validation` was enabled, confirm
  `windows/build/validation/install-validation-report.json` was uploaded as
  `QuantumLink-Windows-InstallValidation-<run-number>`.
- Confirm `windows/build/release/windows-release-evidence.json` was generated
  before artifact upload and uploaded beside the MSI, `SHA256SUMS.txt`, and
  `WINTUN-LICENSE.txt`.
- Confirm `windows-release-evidence.json` records the selected MSI, checksum
  verification, Wintun DLL/license evidence, signature/timestamp policy, and
  any expected publisher subject or thumbprint checks.
- If install validation ran, confirm release evidence required
  `install-validation-report.json` and matched its MSI SHA-256 to the staged
  release MSI.
- Run the Windows beta runbook on clean Windows 10 22H2 and Windows 11 x64 VMs
  plus at least one physical x64 Windows machine.
- Block publication for any install, upgrade, rollback, Wintun, WFP, leak-test,
  service lifecycle, checksum, publisher, or timestamp failure.

## Publish

- Upload the signed MSI, `SHA256SUMS.txt`, `WINTUN-LICENSE.txt`, and
  `windows-release-evidence.json` to the release channel.
- For tag releases, confirm the GitHub Release attachment includes
  `windows-release-evidence.json` alongside the MSI/checksums/license.
- Publish release notes that label Windows artifacts according to the current
  beta readiness status.

## Rollback

- Keep the previous signed MSI, checksum, Wintun license, and release evidence
  available for rollback.
- Re-publish the previous signed MSI and checksum if rollout is halted.
- Ask beta testers to export default redacted diagnostics before uninstalling
  or downgrading when they hit a blocking failure.
