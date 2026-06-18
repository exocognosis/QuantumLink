import XCTest
@testable import QuantumLinkKit

final class PQCAlgorithmTests: XCTestCase {
    func testFIPSAlgorithmsMapToSuiteIdentifiers() {
        XCTAssertEqual(PQCAlgorithm.fips203.suiteIdentifier, "QLINK-FIPS203-MLKEM768-SHAKE256-v1")
        XCTAssertEqual(PQCAlgorithm.fips204.suiteIdentifier, "QLINK-FIPS204-MLDSA65-SHAKE256-v1")
        XCTAssertEqual(PQCAlgorithm.fips205.suiteIdentifier, "QLINK-FIPS205-SLHDSA-SHAKE128S-SHAKE256-v1")
    }

    func testCryptoPolicyUsesSelectedPQCAlgorithmSuite() {
        let policy = CryptoPolicy(pqcAlgorithm: .fips203)

        XCTAssertEqual(policy.suite, PQCAlgorithm.fips203.suiteIdentifier)
        XCTAssertEqual(policy.pqcAlgorithm, .fips203)
    }

    func testConnectionProfileStableKeyIncludesPQCAlgorithm() {
        let fips204Profile = ConnectionProfile(
            sourceIPAddress: "100.127.0.2",
            destinationIPAddress: "100.127.0.10",
            connectionType: .ssh,
            pqcAlgorithm: .fips204
        )
        let fips205Profile = ConnectionProfile(
            sourceIPAddress: "100.127.0.2",
            destinationIPAddress: "100.127.0.10",
            connectionType: .ssh,
            pqcAlgorithm: .fips205
        )

        XCTAssertNotEqual(fips204Profile.stableKey, fips205Profile.stableKey)
    }
}
