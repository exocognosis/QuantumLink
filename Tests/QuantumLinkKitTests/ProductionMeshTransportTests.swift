import Foundation
import XCTest
@testable import QuantumLinkKit

final class ProductionMeshTransportTests: XCTestCase {
    private func openLibraryOrSkip() throws -> RustCoreLibrary {
        guard
            let path = ProcessInfo.processInfo.environment["QLINK_CORE_DYLIB"],
            FileManager.default.fileExists(atPath: path)
        else {
            throw XCTSkip("Set QLINK_CORE_DYLIB to libqlink_core.dylib to exercise production mesh-transport wiring.")
        }
        return try RustCoreLibrary(path: path)
    }

    private func uniqueKeychain() -> KeychainSecretStore {
        KeychainSecretStore(service: "com.quantumlink.tests.production-mesh.\(UUID().uuidString)")
    }

    private func skipIfKeychainEntitlementMissing(_ body: () throws -> Void) throws {
        do {
            try body()
        } catch let KeychainSecretStoreError.unexpectedStatus(status)
            where status == errSecMissingEntitlement
        {
            throw XCTSkip("Keychain entitlement unavailable in SPM test runner; covered in signed-app tests.")
        } catch let TunnelTransportFactoryError.deviceKeypairLoadFailed(underlying) {
            // The factory wraps Keychain errors in its own enum, so
            // unwrap one layer to detect the same skip condition.
            if let kc = underlying as? KeychainSecretStoreError,
               case .unexpectedStatus(let status) = kc,
               status == errSecMissingEntitlement
            {
                throw XCTSkip("Keychain entitlement unavailable in SPM test runner; covered in signed-app tests.")
            }
            throw TunnelTransportFactoryError.deviceKeypairLoadFailed(underlying)
        }
    }

    func testMakeProductionMeshTransportLoadsKeypairAndStitchesConfig() throws {
        // The library load happens inside the factory but it
        // surfaces a clean error if missing — so still gate on the
        // env var to avoid a noisy failure when the dylib isn't
        // available (the library would throw inside the factory and
        // fail the test rather than skip).
        _ = try openLibraryOrSkip()

        let keychain = uniqueKeychain()
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("qlink-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try skipIfKeychainEntitlementMissing {
            let configuration = TunnelConfiguration.defaultDevelopment

            let bundle = try TunnelTransportFactory.makeProductionMeshTransport(
                configuration: configuration,
                bindAddress: "127.0.0.1:0",
                peerStoreDirectory: tempDir,
                keychainStore: keychain
            )
            // Tear down the cached keypair entries afterward.
            defer {
                try? DeviceKeypairStore(keychain: keychain).forget()
                try? PeerStoreKey(keychain: keychain).forget()
            }

            XCTAssertTrue(bundle.keypair.peerID.hasPrefix("qlink_"))
            XCTAssertTrue(bundle.peerStoreEncryptionEnabled)
            XCTAssertNotNil(bundle.rendezvousURL, "default development config has at least one rendezvous server")
            XCTAssertEqual(bundle.transport.localPeerID, bundle.keypair.peerID)
        }
    }

    func testMakeProductionMeshTransportRoundTripsKeypairAcrossCalls() throws {
        // Calling the factory twice with the same Keychain account
        // must produce the same peer_id — the persistence contract
        // that lets `publishSelf` keep a stable identity across
        // process restarts.
        _ = try openLibraryOrSkip()

        let keychain = uniqueKeychain()
        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("qlink-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try skipIfKeychainEntitlementMissing {
            let configuration = TunnelConfiguration.defaultDevelopment

            let firstBundle = try TunnelTransportFactory.makeProductionMeshTransport(
                configuration: configuration,
                bindAddress: "127.0.0.1:0",
                peerStoreDirectory: tempDir,
                keychainStore: keychain
            )
            let firstPeerID = firstBundle.keypair.peerID
            // Drop the first transport before constructing the second
            // (so they don't fight over the same UDP bind).
            firstBundle.transport.stop()

            let secondBundle = try TunnelTransportFactory.makeProductionMeshTransport(
                configuration: configuration,
                bindAddress: "127.0.0.1:0",
                peerStoreDirectory: tempDir,
                keychainStore: keychain
            )
            defer {
                secondBundle.transport.stop()
                try? DeviceKeypairStore(keychain: keychain).forget()
                try? PeerStoreKey(keychain: keychain).forget()
            }

            XCTAssertEqual(firstPeerID, secondBundle.keypair.peerID)
        }
    }
}
