import XCTest
@testable import QuantumLinkKit

final class IPv4CIDRTests: XCTestCase {
    func testParsesNetworkAndMask() throws {
        let cidr = try IPv4CIDR("10.42.5.9/16")
        XCTAssertEqual(cidr.networkAddress, "10.42.0.0")
        XCTAssertEqual(cidr.prefixLength, 16)
        XCTAssertEqual(cidr.subnetMask, "255.255.0.0")
    }

    func testRejectsInvalidPrefix() {
        XCTAssertThrowsError(try IPv4CIDR("10.0.0.0/33"))
    }

    func testDefaultDevelopmentConfigurationUsesValidRoutes() throws {
        for route in TunnelConfiguration.defaultDevelopment.protectedRoutes {
            XCTAssertNoThrow(try IPv4CIDR(route))
        }
    }
}

