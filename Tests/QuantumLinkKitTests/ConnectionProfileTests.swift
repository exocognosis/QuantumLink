import XCTest
@testable import QuantumLinkKit

final class ConnectionProfileTests: XCTestCase {
    func testAddingRecentProfileMovesDuplicateToFrontAndKeepsThree() {
        let first = ConnectionProfile(
            sourceIPAddress: "100.127.0.2",
            destinationIPAddress: "100.127.0.10",
            connectionType: .ssh
        )
        let second = ConnectionProfile(
            sourceIPAddress: "100.127.0.2",
            destinationIPAddress: "100.127.0.11",
            connectionType: .https
        )
        let third = ConnectionProfile(
            sourceIPAddress: "100.127.0.2",
            destinationIPAddress: "100.127.0.12",
            connectionType: .rdp
        )
        let fourthDuplicate = ConnectionProfile(
            sourceIPAddress: "100.127.0.2",
            destinationIPAddress: "100.127.0.10",
            connectionType: .ssh
        )

        var recents: [ConnectionProfile] = []
        recents = ConnectionProfileLibrary.addRecent(first, to: recents)
        recents = ConnectionProfileLibrary.addRecent(second, to: recents)
        recents = ConnectionProfileLibrary.addRecent(third, to: recents)
        recents = ConnectionProfileLibrary.addRecent(fourthDuplicate, to: recents)

        XCTAssertEqual(recents.count, 3)
        XCTAssertEqual(recents[0].destinationIPAddress, "100.127.0.10")
        XCTAssertEqual(recents.map(\.destinationIPAddress), ["100.127.0.10", "100.127.0.12", "100.127.0.11"])
    }

    func testFavoriteToggleAddsAndRemovesProfile() {
        let profile = ConnectionProfile(
            sourceIPAddress: "100.127.0.2",
            destinationIPAddress: "100.127.0.10",
            connectionType: .ssh
        )

        let favorites = ConnectionProfileLibrary.toggleFavorite(profile, in: [])
        XCTAssertEqual(favorites.count, 1)
        XCTAssertEqual(favorites[0].stableKey, profile.stableKey)

        let removed = ConnectionProfileLibrary.toggleFavorite(profile, in: favorites)
        XCTAssertTrue(removed.isEmpty)
    }

    func testDefaultPortsFollowConnectionType() {
        XCTAssertEqual(QuantumLinkConnectionType.ssh.defaultPort, 22)
        XCTAssertEqual(QuantumLinkConnectionType.https.defaultPort, 443)
        XCTAssertEqual(QuantumLinkConnectionType.rdp.defaultPort, 3389)
    }

    func testRedactedDisplayHelpersHideStoredNetworkAddresses() {
        let profile = ConnectionProfile(
            sourceIPAddress: "100.127.0.2",
            destinationIPAddress: "192.168.1.42",
            connectionType: .ssh
        )

        XCTAssertEqual(profile.redactedDisplayName, "SSH [redacted-ip]")
        XCTAssertEqual(profile.redactedRouteSummary, "[redacted-ip] to [redacted-ip]")
    }
}
