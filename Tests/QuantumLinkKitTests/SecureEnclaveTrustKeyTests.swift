import Foundation
import XCTest
import CryptoKit
@testable import QuantumLinkKit

final class SecureEnclaveTrustKeyTests: XCTestCase {
    func testGenerateLoadAndSignRoundTripWhenSecureEnclaveIsAvailable() throws {
        try XCTSkipUnless(SecureEnclaveTrustKey.isAvailable, "Secure Enclave is not available on this host")

        let store = KeychainSecretStore(service: "com.quantumlink.tests.\(UUID().uuidString)")
        let trustKey = SecureEnclaveTrustKey(store: store, account: "trust-test")
        defer { try? trustKey.wipe() }

        let generated: SecureEnclave.P256.Signing.PrivateKey
        do {
            try XCTAssertNil(trustKey.load(), "There should be no key before generation")
            generated = try trustKey.generateAndPersist()
        } catch let KeychainSecretStoreError.unexpectedStatus(status) where status == errSecMissingEntitlement {
            throw XCTSkip("Keychain access requires a signed test host (errSecMissingEntitlement)")
        }

        let loaded = try XCTUnwrap(try trustKey.load())
        XCTAssertEqual(generated.publicKey.derRepresentation, loaded.publicKey.derRepresentation)

        let challenge = Data("device-attestation-challenge".utf8)
        let signature = try XCTUnwrap(try trustKey.sign(challenge: challenge))
        let parsed = try P256.Signing.ECDSASignature(derRepresentation: signature)
        XCTAssertTrue(generated.publicKey.isValidSignature(parsed, for: challenge))
    }

    func testWipeRemovesPersistedKey() throws {
        try XCTSkipUnless(SecureEnclaveTrustKey.isAvailable, "Secure Enclave is not available on this host")

        let store = KeychainSecretStore(service: "com.quantumlink.tests.\(UUID().uuidString)")
        let trustKey = SecureEnclaveTrustKey(store: store, account: "trust-wipe")
        do {
            try trustKey.generateAndPersist()
        } catch let KeychainSecretStoreError.unexpectedStatus(status) where status == errSecMissingEntitlement {
            throw XCTSkip("Keychain access requires a signed test host (errSecMissingEntitlement)")
        }
        XCTAssertNotNil(try trustKey.load())
        try trustKey.wipe()
        XCTAssertNil(try trustKey.load())
    }

    func testAvailabilityFlagMatchesCryptoKit() {
        XCTAssertEqual(SecureEnclaveTrustKey.isAvailable, SecureEnclave.isAvailable)
    }
}
