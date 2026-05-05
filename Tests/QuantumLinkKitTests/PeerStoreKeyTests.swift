import Foundation
import XCTest
@testable import QuantumLinkKit

final class PeerStoreKeyTests: XCTestCase {
    private func uniqueKeychain() -> KeychainSecretStore {
        KeychainSecretStore(service: "com.quantumlink.tests.peerstore.\(UUID().uuidString)")
    }

    /// Same skip-on-entitlement pattern as DeviceKeypairStoreTests:
    /// SPM test binaries can't reach the Keychain, but the signed
    /// app bundle exercises this code path.
    private func skipIfKeychainEntitlementMissing(_ body: () throws -> Void) throws {
        do {
            try body()
        } catch let KeychainSecretStoreError.unexpectedStatus(status)
            where status == errSecMissingEntitlement
        {
            throw XCTSkip("Keychain entitlement unavailable in SPM test runner; covered in signed-app tests.")
        }
    }

    func testLoadOrGenerateMintsAndPersistsAStableKey() throws {
        let keychain = uniqueKeychain()
        let store = PeerStoreKey(keychain: keychain)
        defer { try? store.forget() }

        try skipIfKeychainEntitlementMissing {
            let first = try store.loadOrGenerate()
            XCTAssertEqual(first.count, 32, "ChaCha20-Poly1305 key must be exactly 32 bytes")

            let second = try store.loadOrGenerate()
            XCTAssertEqual(first, second, "second load must reuse the persisted key")

            // Direct Keychain inspection.
            let stored = try keychain.load(account: PeerStoreKey.defaultAccount)
            XCTAssertEqual(stored, first)
        }
    }

    func testForgetMakesNextLoadMintAFreshKey() throws {
        let keychain = uniqueKeychain()
        let store = PeerStoreKey(keychain: keychain)
        defer { try? store.forget() }

        try skipIfKeychainEntitlementMissing {
            let original = try store.loadOrGenerate()
            try store.forget()
            let regenerated = try store.loadOrGenerate()
            XCTAssertNotEqual(original, regenerated, "forget must roll the key")
        }
    }

    func testReplacesMalformedKeyMaterial() throws {
        let keychain = uniqueKeychain()
        let store = PeerStoreKey(keychain: keychain)
        defer { try? store.forget() }

        try skipIfKeychainEntitlementMissing {
            // A previous version of the app stored a 16-byte value.
            try keychain.store(Data(count: 16), account: PeerStoreKey.defaultAccount)

            let recovered = try store.loadOrGenerate()
            XCTAssertEqual(recovered.count, 32, "must mint fresh when stored item is wrong size")

            // The Keychain item now matches the regenerated key.
            let stored = try keychain.load(account: PeerStoreKey.defaultAccount)
            XCTAssertEqual(stored, recovered)
        }
    }

    func testLoadOrGenerateBase64EncodesTheRawKey() throws {
        let keychain = uniqueKeychain()
        let store = PeerStoreKey(keychain: keychain)
        defer { try? store.forget() }

        try skipIfKeychainEntitlementMissing {
            let raw = try store.loadOrGenerate()
            let b64 = try store.loadOrGenerateBase64()
            XCTAssertEqual(Data(base64Encoded: b64), raw)
        }
    }
}
