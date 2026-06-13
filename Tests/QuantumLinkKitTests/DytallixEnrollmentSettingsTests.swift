import XCTest
@testable import QuantumLinkKit

final class DytallixEnrollmentSettingsTests: XCTestCase {
  func testCompleteSettingsProduceLookupOnlyRuntimeConfiguration() throws {
    let settings = DytallixEnrollmentSettings(
      endpoint: " https://dytallix.example ",
      contractAddress: " 0x9a9671441249ee2c364f9b4bc8049e61b082449a ",
      networkID: " dytallix-testnet ",
      chainID: " dytallix-testnet-1 ",
      allowedRPCEndpoints: [" https://dytallix.example/ ", " "],
      walletName: "quantumlink",
      walletAddress: "dytallix1operator",
      registeredPeerID: "qlink_peer",
      status: .registered
    )

    let runtime = try XCTUnwrap(settings.runtimeConfiguration(mode: .publicWallet))

    XCTAssertEqual(runtime.endpoint, "https://dytallix.example")
    XCTAssertEqual(runtime.contractAddress, "0x9a9671441249ee2c364f9b4bc8049e61b082449a")
    XCTAssertEqual(runtime.networkID, "dytallix-testnet")
    XCTAssertEqual(runtime.chainID, "dytallix-testnet-1")
    XCTAssertEqual(runtime.allowedRPCEndpoints, ["https://dytallix.example/"])
    XCTAssertTrue(runtime.publishWalletAddress)
  }

  func testIncompleteSettingsDoNotProduceRuntimeConfiguration() {
    let missingContract = DytallixEnrollmentSettings(
      endpoint: "https://dytallix.example",
      contractAddress: " ",
      walletName: nil,
      walletAddress: nil,
      registeredPeerID: nil,
      status: .notConfigured
    )

    XCTAssertNil(missingContract.runtimeConfiguration(mode: .verified))
  }

  func testStoredJSONRoundTripsWithoutSecrets() throws {
    let settings = DytallixEnrollmentSettings(
      endpoint: "https://dytallix.example",
      contractAddress: "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
      walletName: "quantumlink",
      walletAddress: "dytallix1operator",
      registeredPeerID: "qlink_peer",
      status: .registered
    )

    let stored = try settings.storedJSONString()
    let decoded = DytallixEnrollmentSettings(storedJSONString: stored)

    XCTAssertEqual(decoded, settings)
    XCTAssertFalse(stored.contains("private"))
    XCTAssertFalse(stored.contains("keystore"))
  }

  func testStoredJSONWithoutPinFieldsDecodesWithDefaults() throws {
    let stored = """
      {
        "endpoint": "https://dytallix.example",
        "contractAddress": "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
        "walletName": "quantumlink",
        "walletAddress": "dytallix1operator",
        "registeredPeerID": "qlink_peer",
        "status": "registered"
      }
      """

    let decoded = DytallixEnrollmentSettings(storedJSONString: stored)

    XCTAssertNil(decoded.networkID)
    XCTAssertNil(decoded.chainID)
    XCTAssertEqual(decoded.allowedRPCEndpoints, [])
    XCTAssertEqual(decoded.status, .registered)
  }

  func testInvalidStoredJSONFallsBackToEmptySettings() {
    let decoded = DytallixEnrollmentSettings(storedJSONString: "{not-json")

    XCTAssertEqual(decoded, .empty)
    XCTAssertNil(decoded.runtimeConfiguration(mode: .verified))
  }

  func testRegisteredIdentityBlocksDeviceKeyRotation() {
    let settings = DytallixEnrollmentSettings(
      endpoint: "https://dytallix.example",
      contractAddress: "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
      walletName: "quantumlink",
      walletAddress: "dytallix1operator",
      registeredPeerID: "qlink_peer",
      status: .registered
    )

    XCTAssertTrue(settings.rotationBlockedByActiveRegistryRecord)
    XCTAssertFalse(settings.canRotateDeviceIdentity)
    XCTAssertEqual(settings.rotatingDeviceIdentity(), settings)
  }

  func testRotatingRevokedDeviceIdentityClearsStalePeerAndKeepsWallet() {
    let settings = DytallixEnrollmentSettings(
      endpoint: "https://dytallix.example",
      contractAddress: "0x9a9671441249ee2c364f9b4bc8049e61b082449a",
      walletName: "quantumlink",
      walletAddress: "dytallix1operator",
      registeredPeerID: "qlink_peer",
      status: .revoked
    )

    let rotated = settings.rotatingDeviceIdentity()

    XCTAssertFalse(settings.rotationBlockedByActiveRegistryRecord)
    XCTAssertTrue(settings.canRotateDeviceIdentity)
    XCTAssertEqual(rotated.endpoint, settings.endpoint)
    XCTAssertEqual(rotated.contractAddress, settings.contractAddress)
    XCTAssertEqual(rotated.walletName, settings.walletName)
    XCTAssertEqual(rotated.walletAddress, settings.walletAddress)
    XCTAssertNil(rotated.registeredPeerID)
    XCTAssertEqual(rotated.status, .walletReady)
  }

  func testWalletPresentationRequiresWalletForVerifiedModeWhenAddressMissing() {
    let presentation = DytallixWalletReadinessPresentation(
      settings: DytallixEnrollmentSettings.empty,
      mode: .verified
    )

    XCTAssertEqual(presentation.state, .unavailable)
    XCTAssertEqual(presentation.status, "Wallet needed")
    XCTAssertEqual(presentation.actionTitle, "Open Testnet Wallet/Faucet")
    XCTAssertEqual(presentation.actionURL.absoluteString, "https://dytallix.com/build/wallet")
  }

  func testWalletPresentationMarksPublicWalletAsPublishedWhenAddressExists() {
    let settings = DytallixEnrollmentSettings(
      endpoint: "https://dytallix.example",
      contractAddress: "0xregistry",
      walletName: "quantumlink",
      walletAddress: "dytallix1operator",
      registeredPeerID: nil,
      status: .walletReady
    )

    let presentation = DytallixWalletReadinessPresentation(
      settings: settings,
      mode: .publicWallet
    )

    XCTAssertEqual(presentation.state, .availablePublic)
    XCTAssertEqual(presentation.status, "Published")
    XCTAssertEqual(presentation.actionTitle, "Open Testnet Wallet/Faucet")
  }

  func testWalletPresentationDisablesWalletRequirementWhenIdentityModeOff() {
    let presentation = DytallixWalletReadinessPresentation(
      settings: DytallixEnrollmentSettings.empty,
      mode: .off
    )

    XCTAssertEqual(presentation.state, .notRequired)
    XCTAssertEqual(presentation.status, "Not required")
  }

  func testCommandOutputAppliesRegisteredEnrollmentState() throws {
    let output = """
      identity_operation=enroll
      wallet_name=quantumlink
      wallet_address=dytallix1operator
      created_wallet=true
      keystore_path=/Users/example/.dytallix/keystore.json
      peer_id=qlink_peer
      tx_hash=0xabc
      """

    let parsed = try DytallixEnrollmentCommandOutput(output: output)
    let settings = DytallixEnrollmentSettings.empty.applying(commandOutput: parsed)

    XCTAssertTrue(parsed.createdWallet)
    XCTAssertEqual(parsed.txHash, "0xabc")
    XCTAssertEqual(settings.walletName, "quantumlink")
    XCTAssertEqual(settings.walletAddress, "dytallix1operator")
    XCTAssertEqual(settings.registeredPeerID, "qlink_peer")
    XCTAssertEqual(settings.status, .registered)
  }

  func testCommandOutputRejectsMissingPeerID() {
    XCTAssertThrowsError(
      try DytallixEnrollmentCommandOutput(
        output: """
          wallet_name=quantumlink
          wallet_address=dytallix1operator
          """
      )
    )
  }
}
