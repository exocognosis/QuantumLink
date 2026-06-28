# QuantumLink Windows Release Handoff

Use this file as the short operational handoff for a new chat or agent working
on the Windows version of QuantumLink. It is not the product README.

## Current Position

- Repository: `exocognosis/QuantumLink`
- Working branch: `windows-beta-deployment-validation`
- Pull request: `https://github.com/exocognosis/QuantumLink/pull/19`
- PR base branch: `windows-release-pipeline`
- Latest pushed commit: `b32e26c0ea7ba9a394b53971aa70d9bd2acb5caa`
- Local worktree used for this effort: `/tmp/quantumlink-windows-push`

The Windows release pipeline now builds far enough to produce an MSI, run the
manual Windows install validation job, and upload validation evidence even when
validation fails. PR checks are green at the current head.

## Current Completion Estimate

Estimated Windows beta deployment readiness: about 90%.

This is not production deployment-ready yet. The remaining gap is no longer the
basic CI or packaging scaffold; it is install-validation correctness on a real
Windows runner, followed by signed release validation and beta evidence across
Windows 10/11, physical hardware, two-machine mesh, and macOS interop.

## What Has Been Completed

- Windows release workflow exists and runs from GitHub Actions.
- WiX toolchain is pinned for reproducible MSI packaging.
- MSI packaging now passes the previously discovered WiX version, extension,
  XML comment, and invalid ACL-authoring failures.
- Install validation report upload is observable even when validation fails.
- Fallback validation evidence is emitted when early workflow or validator
  failure would otherwise leave no JSON report.
- Local Ruby contract tests cover the release workflow, installer contract, and
  validation script expectations.

Recent commits:

- `fca1694` Fix Windows installer WiX XML comment
- `75d590e` Fix Windows installer state directory ACL authoring
- `e0492ed` Emit fallback Windows install validation evidence
- `ed1a042` Guarantee Windows install validation workflow evidence
- `b32e26c` Keep Windows validation report upload observable

## Latest Validation Evidence

Latest manual Windows Release run:

- Run id: `27834637677`
- Run number: `8`
- Head SHA: `b32e26c0ea7ba9a394b53971aa70d9bd2acb5caa`
- URL: `https://github.com/exocognosis/QuantumLink/actions/runs/27834637677`
- Result: failed at `Validate MSI install and uninstall`
- Important improvement: `Upload install validation report` succeeded

Downloaded evidence path:

- `/tmp/ql-install-validation-27834637677/install-validation-report.json`

Key report findings:

- MSI install succeeded with exit code `0`.
- `QuantumLinkService` existed and was running.
- Service path was under `C:\Program Files (x86)\QuantumLink\`.
- State directory existed at `C:\ProgramData\QuantumLink`.
- State directory had inherited broad `BUILTIN\Users` read/write ACLs.
- Expected UI executable was missing at
  `C:\Program Files\QuantumLink\QuantumLink.Windows.exe`.
- Uninstall succeeded with exit code `0`.
- Validator cleanup wait timed out because `Add-ResidualFinding` rejects an
  empty collection.

## Current Blocking Failures

1. The MSI is being authored as a 32-bit package.

   Evidence: installed service path is under `C:\Program Files (x86)`.

   Root cause: `windows/scripts/build-windows.ps1` invokes WiX without
   `-arch x64`.

2. ProgramData ACL inheritance remains too broad.

   Evidence: validation detected inherited `BUILTIN\Users` read/write ACLs on
   `C:\ProgramData\QuantumLink`.

   Root cause: the current WiX state directory ACL grants explicit ACEs but
   does not protect the DACL from parent inheritance.

3. Validator residual cleanup has a PowerShell parameter bug.

   Evidence: cleanup wait repeatedly fails with:

   ```text
   Cannot bind argument to parameter 'Items' because it is an empty collection.
   ```

   Root cause: `Add-ResidualFinding` marks `$Items` mandatory but does not
   allow an empty collection.

## Next Logical Batch

Patch the three live install-validation blockers, then rerun the manual
Windows Release workflow.

Required edits:

1. In `windows/scripts/build-windows.ps1`, add `-arch x64` to the `wix build`
   invocation.

2. In `windows/installer/README.md`, update the manual WiX build command to
   include `-arch x64`.

3. In `windows/installer/QuantumLink.wxs`, protect the ProgramData state
   directory DACL with core WiX `PermissionEx` SDDL:

   ```xml
   <CreateFolder>
     <PermissionEx Id="StateFolderAcl" Sddl="D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" />
   </CreateFolder>
   ```

4. In `windows/scripts/validate-install.ps1`, add
   `[AllowEmptyCollection()]` to the `Add-ResidualFinding` `Items` parameter.

5. Update contract tests:

   - `windows/scripts/windows_release_workflow_contract_test.rb`
   - `windows/scripts/validate_install_contract_test.rb`

Optional if available:

- Add a matching Pester regression in `windows/scripts/validate-install.Tests.ps1`.

## Verification Commands

Run before committing:

```bash
ruby windows/scripts/windows_release_workflow_contract_test.rb
ruby windows/scripts/validate_install_contract_test.rb
ruby windows/scripts/verify_windows_release_contract_test.rb
git diff --check
```

Then commit and push:

```bash
git add windows/scripts/build-windows.ps1 windows/installer/README.md \
  windows/installer/QuantumLink.wxs \
  windows/scripts/windows_release_workflow_contract_test.rb \
  windows/scripts/validate-install.ps1 \
  windows/scripts/validate_install_contract_test.rb
git commit -m "Fix Windows MSI validation blockers"
git push origin windows-beta-deployment-validation
```

Then rerun manual validation:

```bash
gh workflow run windows-release.yml \
  --repo exocognosis/QuantumLink \
  --ref windows-beta-deployment-validation \
  -f run_install_validation=true \
  -f skip_validation_network_checks=false \
  -f validate_rollback=false
```

Watch and inspect:

```bash
gh run watch --repo exocognosis/QuantumLink
gh run view --repo exocognosis/QuantumLink --log
```

If it fails, download the install validation artifact and inspect
`install-validation-report.json`.

## What Comes After This Batch

If the next validation run passes, raise the estimate to roughly 91-92% for
Windows beta deployment readiness. The next work should be:

- Authenticode signing and timestamp proof.
- Clean Windows 10 and Windows 11 validation.
- Physical-host validation, not only GitHub-hosted runner validation.
- Two-Windows-machine mesh validation.
- Windows-to-macOS interop validation.
- Leak/WFP kill-switch proof with captured evidence.
- Service hardening workstream from
  `docs/superpowers/plans/2026-06-15-windows-full-buildout.md`.
