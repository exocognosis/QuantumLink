# Windows Validation Reports

Run Windows-native validation from an elevated PowerShell session at the
repository root. Reports are written under `windows/build/validation/` by
default and are build evidence, not source files.

## Automated validation bundle

```powershell
.\windows\scripts\run-beta-validation.ps1 `
    -MsiPath .\windows\QuantumLink.msi
```

The runner invokes install validation with uninstall deferred, then runs the
security validator against the live installed service. It always writes:

- `windows/build/validation/windows-beta-validation-manifest.json`
- `windows/build/validation/install-validation-report.json`
- `windows/build/validation/windows-security-validation-report.json`

If a validator cannot run, its file is an explicit blocked placeholder rather
than absent or reusable stale evidence. The top-level manifest references the
two component reports by filename. It
exits nonzero when a required component is blocked, skipped, missing,
malformed, or failed. A `passed` manifest covers only the automated
Windows-native scope. It keeps `productionReady` set to `false` because the
manual leak, hardware, mesh, interop, upgrade, rollback, uninstall, signing,
and release gates still require separate evidence.

The installed product is intentionally left in place after this bundle so the
security validator can inspect the running service, named pipe, Wintun DLL,
WFP probe, DPAPI store, and ACLs. Collect uninstall and residue evidence with
the separate command in `beta-runbook-windows.md` after preserving the bundle.

Use network-check skipping only on a constrained runner:

```powershell
.\windows\scripts\run-beta-validation.ps1 `
    -MsiPath .\windows\QuantumLink.msi `
    -SkipNetworkChecks
```

That command still collects the available component evidence, but the manifest
is `blocked` and the runner exits nonzero because required network evidence was
skipped. It does not satisfy the Windows 10, Windows 11, physical-host, WFP
leak, route/DNS, or interoperability gates.

## Security report only

For an already installed MSI, run:

```powershell
.\windows\scripts\validate-windows-security.ps1 `
    -MsiPath .\windows\QuantumLink.msi `
    -CheckPipeAcl `
    -ReportPath .\windows\build\validation\windows-security-validation-report.json
```

Normal execution exits `0` only when required security checks pass. It exits
`1` on validation failure or an unhandled validator error and still attempts
to write a failed JSON report. When `-CheckPipeAcl` is requested, inability to
read the named-pipe ACL is a failure, not a warning.

## Privacy and bounds

Reports redact `computerName` and `userName` by default. Use
`-IncludeHostIdentifiers` only when the evidence storage location is approved
for those identifiers. Reports do not collect environment dumps, credentials,
tokens, private keys, seed material, DPAPI blob contents, or raw runtime-probe
output. Evidence arrays and strings are bounded; truncation is explicit in the
security report.

Schema-only validation is available for parser and contract testing:

```powershell
.\windows\scripts\validate-windows-security.ps1 `
    -ContractOnly `
    -ReportPath .\windows\build\validation\windows-security-contract.json

.\windows\scripts\run-beta-validation.ps1 `
    -ContractOnly `
    -OutputDirectory .\windows\build\validation\contract
```

The security contract command exits `0` but emits `status: contract_only` and
`passed: false`. The bundle contract command exits nonzero and emits a blocked,
non-promotable manifest because contract-only output is not Windows-native
evidence.

## Release evidence handling

Preserve all three JSON files together for each candidate and record the
release commit, MSI SHA-256, host class, Windows version, and manual evidence
links in the release evidence index. Do not edit a generated report after the
run. Re-run validation if evidence is incomplete or malformed.
