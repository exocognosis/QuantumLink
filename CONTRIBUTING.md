# Contributing

QuantumLink is a macOS-first Swift and Rust project. Keep changes scoped, reproducible, and privacy-preserving by default.

## Development Setup

Required local tools:

- macOS 14 or newer
- Swift 6 toolchain
- Rust stable toolchain
- Xcode command line tools
- XcodeGen for unsigned Xcode project smoke builds

Optional but recommended:

- GitHub CLI (`gh`) for issue and pull request work
- A local Apple Developer setup for signing and notarization work

## Local Validation

Run the full pre-Apple validation pass before opening a pull request:

```sh
./macos/scripts/preapple-check.sh
```

For focused iteration:

```sh
swift test
cargo test --workspace
cargo fmt --all -- --check
cargo run -p qlink-core --bin qlinkctl -- quic-loopback
```

If your change touches packaging, Xcode generation, or release automation, also run the relevant script under `scripts/` and include the command output in the pull request.

## Pull Requests

- Explain the user-visible or developer-visible behavior change.
- Include validation commands that were actually run.
- Call out Apple signing, Network Extension entitlement, notarization, or MDM assumptions.
- Do not commit local build products, private signing material, support bundles, or `.env` files.
- Keep generated artifacts out of source unless the repository explicitly tracks that artifact type.

## Security and Privacy

Do not report suspected vulnerabilities in public issues. Follow `SECURITY.md`.

Privacy-sensitive changes should preserve these defaults unless the pull request explains why they must change:

- diagnostics remain local unless explicitly exported
- discovery uses pseudonymous peer metadata
- mDNS/local discovery is not silently enabled for untrusted networks
- support exports redact network identifiers by default
