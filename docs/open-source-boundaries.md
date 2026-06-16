# Open Source Boundaries

QuantumLink is published as an open-source product monorepo under
Apache-2.0. The public repository is intended to include the shared
protocol core, native macOS and Windows clients, developer
documentation, tests, example configuration, and CI definitions needed
to inspect and build the product from source.

## Public Repository

The public source tree contains:

- `qlink-core/`: Rust mesh protocol, crypto orchestration, packet
  framing, traversal, relay/rendezvous development tools, metrics, and
  FFI surfaces.
- `macos/`: SwiftUI app, Network Extension tunnel, managed deployment
  helpers, package scripts, tests, and XcodeGen source.
- `windows/`: Rust service, Wintun/WFP integration, DPAPI secret store,
  named-pipe IPC, WinUI client, WiX installer source, and tests.
- `steam/`: product direction for the Steam/SteamOS track.
- `docs/`, `config/`, and `.github/`: public documentation, example
  mesh configuration, issue templates, pull request templates, and CI.

## Private Production Operations

The public repository does not include:

- Apple Developer, Developer ID, provisioning, notarization, Sparkle, or
  app-store credentials.
- Authenticode certificates, timestamping credentials, Windows Store
  identities, private Wintun redistribution records, or enterprise
  deployment credentials.
- Hosted production rendezvous, STUN/TURN, relay, telemetry, update,
  billing, account, abuse-monitoring, or customer-support
  infrastructure.
- Production environment variables, secrets, service tokens, Terraform
  state, customer configs, private logs, support bundles, crash dumps, or
  packet captures.
- Proprietary third-party assets or dependencies that cannot be
  redistributed under their own license terms.

## Releases

Official production binaries are signed artifacts attached to GitHub
Releases or another channel named by the maintainers. Unsigned CI
artifacts, local development packages, and workflow uploads are for
validation only and must not be treated as production distributions.

macOS production releases require Developer ID signing, notarization,
stapling, and release-channel update metadata. Windows production
releases require Authenticode signing and installer integrity checks.
Those signing workflows consume private credentials outside this
repository.

## Contributions

Unless a separate written agreement says otherwise, contributions are
submitted under the same Apache-2.0 terms as the repository. Do not
submit secrets, signing material, private support data, generated
binaries, customer data, or code/assets that cannot be redistributed.
