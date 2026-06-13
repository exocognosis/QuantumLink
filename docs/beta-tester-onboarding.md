# QuantumLink macOS Beta Tester Onboarding

QuantumLink macOS beta builds are for validating the desktop app, onboarding,
Dytallix testnet identity binding, diagnostics, and unsigned/signed packaging
flow before Apple Network Extension distribution is approved.

## Tester Prerequisites

- macOS 14 or newer.
- A disposable Dytallix testnet wallet.
- Testnet funds from the Dytallix wallet/faucet page:
  `https://dytallix.com/build/wallet`.
- A QuantumLink beta build from the project release channel.
- No production wallet private keys on the test machine.

## Identity Setup

1. Open QuantumLink and start Onboarding.
2. Choose the deployment mode supplied by the beta coordinator.
3. For public meshes, keep Dytallix identity enabled. Public meshes fail closed
   when registry verification is missing, stale, or rejected.
4. Open the Dytallix testnet wallet/faucet page if the wallet is missing,
   locked, unfunded, or rate limited.
5. Register the device identity from QuantumLink.
6. Confirm the app shows Dytallix Testnet Verified before joining a public mesh.

Private and development meshes may leave Dytallix identity off, but any
verification result shown in those modes is beta trust infrastructure and not a
production root of trust.

## Privacy Expectations

- Verified mode proves registry membership without displaying the wallet
  address in normal discovery surfaces.
- Public Wallet mode intentionally exposes the wallet address and may link the
  node, mesh activity, and timing metadata.
- QuantumLink does not store wallet private keys, passphrases, or Dytallix
  keystore paths in app settings, tunnel configuration, or support bundles.
- Default support bundles redact mesh IDs, device aliases, peer IDs, registry
  peer IDs, IP addresses, and endpoint literals.

## What To Test

- First launch onboarding and deployment mode selection.
- Dytallix testnet wallet setup and faucet flow.
- Register, refresh, update, revoke, and re-register identity.
- Public mesh failure when verification is missing or rejected.
- Private/development mesh behavior when identity is optional.
- Key rotation guardrails: active registry records must be updated or revoked
  before rotating the QuantumLink device identity.
- Support bundle export in default redacted mode.
- App relaunch and persistence of non-secret enrollment state.

## What Not To Attach

Do not attach raw contents of `build/dytallix-identity-e2e/`, wallet keystores,
private keys, passphrases, seed phrases, raw support bundles, or screenshots
showing a private wallet key.

If a beta coordinator needs raw diagnostics, export them only on a disposable
test wallet and label the attachment as raw.
