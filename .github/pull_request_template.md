## Summary

- 

## Validation

- [ ] `swift test`
- [ ] `cargo test --workspace`
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo run -p quantumlink-service -- smoke`
- [ ] `dotnet build windows/ui/QuantumLink.Windows -c Release -p:Platform=x64`
- [ ] Other:

## Security and Privacy

- [ ] No secrets, signing material, support bundles, or generated build artifacts are included.
- [ ] Privacy defaults remain local-first and redacted by default, or the exception is explained above.
- [ ] Security-sensitive behavior is documented in `docs/security.md` or `SECURITY.md`.

## License and Provenance

- [ ] New source, docs, and assets are compatible with Apache-2.0 distribution.
- [ ] Third-party code or assets include attribution and license notes where required.
- [ ] No proprietary customer, partner, or private operational material is included.

## Platform, Release, and Operations Impact

- [ ] No Apple signing, Network Extension entitlement, notarization, MDM, or Sparkle release assumptions changed.
- [ ] Apple platform assumptions changed and are documented above.
- [ ] No Windows service privilege, Wintun, WFP, DPAPI, MSI, Authenticode, or update assumptions changed.
- [ ] Windows platform assumptions changed and are documented above.
- [ ] Public/private release boundaries in `docs/open-source-boundaries.md` still hold.
