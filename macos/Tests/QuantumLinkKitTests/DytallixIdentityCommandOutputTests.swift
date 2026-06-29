import XCTest
@testable import QuantumLinkKit

final class DytallixIdentityCommandOutputTests: XCTestCase {
  func testParsesRegisterOutputWithoutWalletFields() throws {
    let output = try DytallixIdentityCommandOutput(
      output: """
      identity_operation=register
      peer_id=qlink_peer_123
      tx_hash=0xabc
      response_json={"ok":true}
      """
    )

    XCTAssertEqual(output.operation, .register)
    XCTAssertEqual(output.peerID, "qlink_peer_123")
    XCTAssertEqual(output.txHash, "0xabc")
    XCTAssertNil(output.walletName)
    XCTAssertNil(output.walletAddress)
    XCTAssertNil(output.found)
  }

  func testParsesStatusNotFoundOutput() throws {
    let output = try DytallixIdentityCommandOutput(
      output: """
      identity_operation=status
      peer_id=qlink_peer_123
      found=false
      """
    )

    XCTAssertEqual(output.operation, .status)
    XCTAssertEqual(output.peerID, "qlink_peer_123")
    XCTAssertEqual(output.found, false)
  }

  func testApplyingRevokeOutputMarksIdentityRevokedButKeepsWallet() throws {
    let settings = DytallixEnrollmentSettings(
      endpoint: "https://dytallix.example",
      contractAddress: "0xregistry",
      walletName: "quantumlink",
      walletAddress: "dytx1wallet",
      registeredPeerID: "qlink_peer_123",
      status: .registered
    )

    let output = try DytallixIdentityCommandOutput(
      output: """
      identity_operation=revoke
      peer_id=qlink_peer_123
      tx_hash=0xdef
      """
    )

    let updated = settings.applying(identityCommandOutput: output)

    XCTAssertEqual(updated.walletName, "quantumlink")
    XCTAssertEqual(updated.walletAddress, "dytx1wallet")
    XCTAssertEqual(updated.registeredPeerID, "qlink_peer_123")
    XCTAssertEqual(updated.status, .revoked)
  }

  func testApplyingStatusNotFoundMarksIdentityNotRegistered() throws {
    let settings = DytallixEnrollmentSettings(
      endpoint: "https://dytallix.example",
      contractAddress: "0xregistry",
      walletName: "quantumlink",
      walletAddress: "dytx1wallet",
      registeredPeerID: "qlink_peer_123",
      status: .registered
    )

    let output = try DytallixIdentityCommandOutput(
      output: """
      identity_operation=status
      peer_id=qlink_peer_123
      found=false
      """
    )

    let updated = settings.applying(identityCommandOutput: output)

    XCTAssertEqual(updated.registeredPeerID, "qlink_peer_123")
    XCTAssertEqual(updated.status, .notRegistered)
  }

  func testFailurePresentationExplainsDuplicateRegistrationContractRejection() {
    let presentation = DytallixIdentityFailurePresentation(
      operation: .enroll,
      commandOutput: """
      Error: protocol error: dytallix registry contract rejected request: node already registered
      """
    )

    XCTAssertEqual(
      presentation.message,
      "This peer is already registered in the Dytallix registry. Use Update Registry Record, or rotate the device key after revoking the current record."
    )
  }

  func testFailurePresentationExplainsMissingRegistryRecord() {
    let presentation = DytallixIdentityFailurePresentation(
      operation: .status,
      commandOutput: """
      Error: protocol error: dytallix registry lookup failed: node not found
      """
    )

    XCTAssertEqual(
      presentation.message,
      "No Dytallix registry record exists for this peer. Register the identity before refreshing, updating, or revoking it."
    )
  }

  func testFailurePresentationFallsBackToOperationMessage() {
    let presentation = DytallixIdentityFailurePresentation(
      operation: .revoke,
      commandOutput: nil
    )

    XCTAssertEqual(presentation.message, "Dytallix identity revoke failed.")
  }
}
