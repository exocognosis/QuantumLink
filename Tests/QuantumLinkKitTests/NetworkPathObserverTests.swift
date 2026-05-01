import Foundation
import XCTest
@testable import QuantumLinkKit

final class NetworkPathObserverTests: XCTestCase {
    func testDecisionForPathChangedRecommendsReprobeAndInvalidates() {
        let decision = NetworkEventDecision.decide(
            for: .pathChanged(interfaceSummary: "satisfied:wifi+ethernet")
        )
        XCTAssertTrue(decision.reprobeRecommended)
        XCTAssertTrue(decision.invalidateCachedPaths)
    }

    func testDecisionForPostWakeMatchesPathChanged() {
        let decision = NetworkEventDecision.decide(for: .postWake)
        XCTAssertTrue(decision.reprobeRecommended)
        XCTAssertTrue(decision.invalidateCachedPaths)
    }

    func testDecisionForPreSleepPausesProbing() {
        let decision = NetworkEventDecision.decide(for: .preSleep)
        XCTAssertFalse(decision.reprobeRecommended)
        XCTAssertFalse(decision.invalidateCachedPaths)
    }

    func testDecisionForReachabilityRegainedRecommendsReprobeWithoutClearing() {
        let decision = NetworkEventDecision.decide(for: .reachabilityChanged(reachable: true))
        XCTAssertTrue(decision.reprobeRecommended)
        XCTAssertFalse(decision.invalidateCachedPaths)
    }

    func testDecisionForReachabilityLostPausesProbing() {
        let decision = NetworkEventDecision.decide(for: .reachabilityChanged(reachable: false))
        XCTAssertFalse(decision.reprobeRecommended)
        XCTAssertFalse(decision.invalidateCachedPaths)
    }

    @MainActor
    func testObserverDeliversManualEventsToHandlerInOrder() {
        let observer = NetworkPathObserver()
        let source = ManualNetworkEventSource()
        var received: [NetworkLifecycleEvent] = []

        observer.start(source: source) { event in
            received.append(event)
        }

        source.emit(.pathChanged(interfaceSummary: "satisfied:wifi"))
        source.emit(.preSleep)
        source.emit(.postWake)
        source.emit(.reachabilityChanged(reachable: false))
        source.emit(.reachabilityChanged(reachable: true))

        XCTAssertEqual(received.count, 5)
        XCTAssertEqual(received[0], .pathChanged(interfaceSummary: "satisfied:wifi"))
        XCTAssertEqual(received[1], .preSleep)
        XCTAssertEqual(received[2], .postWake)
        XCTAssertEqual(received[3], .reachabilityChanged(reachable: false))
        XCTAssertEqual(received[4], .reachabilityChanged(reachable: true))

        observer.stop()
    }

    @MainActor
    func testStopHaltsEventDelivery() {
        let observer = NetworkPathObserver()
        let source = ManualNetworkEventSource()
        var received: [NetworkLifecycleEvent] = []

        observer.start(source: source) { event in
            received.append(event)
        }
        source.emit(.pathChanged(interfaceSummary: "satisfied:wifi"))
        observer.stop()
        source.emit(.postWake) // must not be delivered
        XCTAssertEqual(received.count, 1)
    }

    @MainActor
    func testRestartReplacesPriorHandler() {
        let observer = NetworkPathObserver()
        let source = ManualNetworkEventSource()
        var first: [NetworkLifecycleEvent] = []
        var second: [NetworkLifecycleEvent] = []

        observer.start(source: source) { first.append($0) }
        source.emit(.preSleep)

        observer.start(source: source) { second.append($0) }
        source.emit(.postWake)

        XCTAssertEqual(first, [.preSleep])
        XCTAssertEqual(second, [.postWake])

        observer.stop()
    }
}
