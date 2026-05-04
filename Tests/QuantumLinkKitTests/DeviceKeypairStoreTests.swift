import Foundation
import XCTest
@testable import QuantumLinkKit

final class DeviceKeypairStoreTests: XCTestCase {
    private func openLibraryOrSkip() throws -> RustCoreLibrary {
        guard
            let path = ProcessInfo.processInfo.environment["QLINK_CORE_DYLIB"],
            FileManager.default.fileExists(atPath: path)
        else {
            throw XCTSkip("Set QLINK_CORE_DYLIB to libqlink_core.dylib to exercise the Rust device keypair FFI.")
        }
        return try RustCoreLibrary(path: path)
    }

    private func uniqueKeychain() -> KeychainSecretStore {
        // Each test gets its own service so concurrent runs and
        // forgotten teardown can't pollute each other's view.
        KeychainSecretStore(service: "com.quantumlink.tests.keypair.\(UUID().uuidString)")
    }

    func testGenerateProducesAValidKeypairWithPersistableSeed() throws {
        let library = try openLibraryOrSkip()
        let keypair = try RustDeviceKeypair.generate(library: library)
        XCTAssertEqual(keypair.seed.count, 32, "ML-DSA seed must be exactly 32 bytes")
        XCTAssertTrue(keypair.peerID.hasPrefix("qlink_"), "peer_id format must match crypto::DevicePublicKey::peer_id")
    }

    func testLoadFromSeedProducesIdenticalPeerID() throws {
        let library = try openLibraryOrSkip()
        let original = try RustDeviceKeypair.generate(library: library)
        let restored = try RustDeviceKeypair.load(library: library, seed: original.seed)
        XCTAssertEqual(original.peerID, restored.peerID)
        XCTAssertEqual(original.seed, restored.seed)
    }

    func testLoadRejectsSeedOfWrongLength() throws {
        let library = try openLibraryOrSkip()
        XCTAssertThrowsError(try RustDeviceKeypair.load(library: library, seed: Data(count: 16)))
    }

    /// SPM-built test binaries don't have the Keychain access-group
    /// entitlement, so any `SecItemAdd` / `SecItemDelete` returns
    /// `errSecMissingEntitlement`. Skip in that environment — the
    /// signed app bundle exercises the same code path with full
    /// entitlements.
    private func skipIfKeychainEntitlementMissing(_ body: () throws -> Void) throws {
        do {
            try body()
        } catch let KeychainSecretStoreError.unexpectedStatus(status)
            where status == errSecMissingEntitlement
        {
            throw XCTSkip("Keychain entitlement unavailable in SPM test runner; covered in signed-app tests.")
        }
    }

    func testKeypairStoreLoadOrGenerateMintsAndPersists() throws {
        let library = try openLibraryOrSkip()
        let keychain = uniqueKeychain()
        let store = DeviceKeypairStore(keychain: keychain)
        defer { try? store.forget() }

        try skipIfKeychainEntitlementMissing {
            let first = try store.loadOrGenerate(library: library)
            let second = try store.loadOrGenerate(library: library)

            XCTAssertEqual(first.peerID, second.peerID, "second load must reuse the persisted seed")
            XCTAssertEqual(first.seed, second.seed)

            let stored = try keychain.load(account: DeviceKeypairStore.defaultAccount)
            XCTAssertEqual(stored, first.seed)
        }
    }

    func testKeypairStoreForgetMakesNextLoadMintAFreshKeypair() throws {
        let library = try openLibraryOrSkip()
        let keychain = uniqueKeychain()
        let store = DeviceKeypairStore(keychain: keychain)
        defer { try? store.forget() }

        try skipIfKeychainEntitlementMissing {
            let original = try store.loadOrGenerate(library: library)
            try store.forget()
            let regenerated = try store.loadOrGenerate(library: library)

            XCTAssertNotEqual(original.peerID, regenerated.peerID, "forget must roll the identity")
        }
    }

    func testKeypairStoreReplacesMalformedSeedRatherThanFailingEveryLaunch() throws {
        let library = try openLibraryOrSkip()
        let keychain = uniqueKeychain()
        let store = DeviceKeypairStore(keychain: keychain)
        defer { try? store.forget() }

        try skipIfKeychainEntitlementMissing {
            // Simulate a previous app version that wrote a 16-byte
            // seed under the same Keychain account.
            try keychain.store(Data(count: 16), account: DeviceKeypairStore.defaultAccount)

            let recovered = try store.loadOrGenerate(library: library)
            XCTAssertEqual(recovered.seed.count, 32)
            XCTAssertTrue(recovered.peerID.hasPrefix("qlink_"))

            let stored = try keychain.load(account: DeviceKeypairStore.defaultAccount)
            XCTAssertEqual(stored, recovered.seed)
        }
    }
}
