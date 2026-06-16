# Contributing

QuantumLink is a cross-platform Swift, Rust, C#, and packaging project.
Keep changes scoped, reproducible, and privacy-preserving by default.

## Development Setup

Required local tools:

- Rust stable toolchain
- macOS 14 or newer, Swift toolchain, Xcode command line tools, and
  XcodeGen for macOS work
- Windows 11, .NET 8 SDK, WiX, and the Rust MSVC target for Windows work

Optional but recommended:

- GitHub CLI (`gh`) for issue and pull request work
- A local Apple Developer setup for signing and notarization work
- A local Windows code-signing setup for installer distribution work

## Local Validation

Run focused validation for the platform you changed before opening a
pull request.

```sh
cargo test --workspace
cargo fmt --all -- --check
```

macOS:

```sh
cd macos
swift test
./scripts/build-rust-xcframework.sh
./scripts/generate-xcode-project.sh
```

Windows:

```powershell
cargo run -p quantumlink-service -- smoke
dotnet build windows\ui\QuantumLink.Windows -c Release -p:Platform=x64
```

If your change touches packaging, Xcode generation, installer source, or
release automation, run the relevant script and include the command
output in the pull request.

## Contribution Terms

Unless a separate written agreement says otherwise, contributions are
submitted under the same Apache-2.0 terms that cover this repository.
This is the inbound-equals-outbound policy for QuantumLink.

Do not submit secrets, signing material, private support data,
proprietary third-party code or assets, generated binaries, customer
data, or material with license terms that are incompatible with public
redistribution.

## Pull Requests

- Explain the user-visible or developer-visible behavior change.
- Include validation commands that were actually run.
- Call out Apple signing, Network Extension entitlement, notarization,
  MDM, Authenticode, Wintun, WFP, service privilege, or installer
  assumptions.
- Do not commit local build products, private signing material, support
  bundles, `.env` files, customer configs, or production credentials.
- Keep generated artifacts out of source unless the repository explicitly tracks that artifact type.

## Security and Privacy

Do not report suspected vulnerabilities in public issues. Follow `SECURITY.md`.

Privacy-sensitive changes should preserve these defaults unless the pull request explains why they must change:

- diagnostics remain local unless explicitly exported
- discovery uses pseudonymous peer metadata
- mDNS/local discovery is not silently enabled for untrusted networks
- support exports redact network identifiers by default
