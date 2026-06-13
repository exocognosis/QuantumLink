import Foundation
import XCTest
@testable import QuantumLinkKit

final class ManagedConfigurationTests: XCTestCase {
    func testNilManagedDictReturnsBaseUntouched() {
        let base = TunnelConfiguration.defaultDevelopment
        let result = ManagedConfigurationLoader.apply(managed: nil, to: base)
        XCTAssertEqual(result.configuration, base)
        XCTAssertFalse(result.isManaged)
        XCTAssertTrue(result.appliedKeys.isEmpty)
        XCTAssertTrue(result.rejectedKeys.isEmpty)
    }

    func testValidManagedKeysOverlayBase() {
        let base = TunnelConfiguration.defaultDevelopment
        let managed: [String: Any] = [
            "meshID": "managed-mesh",
            "deviceAlias": "managed-mac",
            "protectedRoutes": ["10.0.0.0/8", "100.64.0.0/10"],
            "routeMode": "fullTunnel",
            "killSwitch": "strict",
            "mtu": 1400
        ]

        let result = ManagedConfigurationLoader.apply(managed: managed, to: base)

        XCTAssertTrue(result.isManaged)
        XCTAssertEqual(result.configuration.meshID, "managed-mesh")
        XCTAssertEqual(result.configuration.deviceAlias, "managed-mac")
        XCTAssertEqual(result.configuration.protectedRoutes, ["10.0.0.0/8", "100.64.0.0/10"])
        XCTAssertEqual(result.configuration.routeMode, .fullTunnel)
        XCTAssertEqual(result.configuration.killSwitch, .strict)
        XCTAssertEqual(result.configuration.mtu, 1400)
        XCTAssertEqual(
            result.appliedKeys,
            ["deviceAlias", "killSwitch", "meshID", "mtu", "protectedRoutes", "routeMode"]
        )
        XCTAssertTrue(result.rejectedKeys.isEmpty)
    }

    func testMalformedValuesAreRejectedNotFatal() {
        let base = TunnelConfiguration.defaultDevelopment
        let managed: [String: Any] = [
            "meshID": 42, // wrong type
            "killSwitch": "openSesame", // invalid enum
            "mtu": 100, // too small
            "unknownKey": "ignored"
        ]

        let result = ManagedConfigurationLoader.apply(managed: managed, to: base)

        XCTAssertEqual(result.configuration, base, "Base must be unchanged when nothing is valid")
        XCTAssertTrue(result.appliedKeys.isEmpty)
        XCTAssertEqual(
            result.rejectedKeys,
            ["killSwitch", "meshID", "mtu", "unknownKey"]
        )
        XCTAssertFalse(result.isManaged)
    }

    func testReadingFromUserDefaults() {
        let suite = "QuantumLinkTests.ManagedConfigurationTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }

        defaults.set(
            ["meshID": "from-defaults", "routeMode": "protectedPrefixesOnly"],
            forKey: ManagedConfigurationLoader.managedConfigurationKey
        )

        let base = TunnelConfiguration.defaultDevelopment
        let result = ManagedConfigurationLoader.currentManagedOverride(base: base, defaults: defaults)
        XCTAssertEqual(result.configuration.meshID, "from-defaults")
        XCTAssertEqual(result.configuration.routeMode, .protectedPrefixesOnly)
        XCTAssertTrue(result.isManaged)
    }
}
