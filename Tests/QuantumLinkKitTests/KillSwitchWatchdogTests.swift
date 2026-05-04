import Foundation
import XCTest
@testable import QuantumLinkKit

final class KillSwitchWatchdogTests: XCTestCase {
    func testFailClosedPolicyNeverFiresTheHandler() {
        var clockNow = Date(timeIntervalSince1970: 0)
        var fired = 0
        let watchdog = KillSwitchWatchdog(
            policy: .failClosed,
            deadlineSeconds: 1,
            clock: { clockNow },
            readyCheck: { false },
            deadlineHandler: { fired += 1 }
        )

        watchdog.evaluate()
        clockNow = Date(timeIntervalSince1970: 1_000)
        watchdog.evaluate()
        clockNow = Date(timeIntervalSince1970: 1_000_000)
        watchdog.evaluate()

        XCTAssertEqual(fired, 0)
        XCTAssertFalse(watchdog.isArmed, "failClosed must never even arm")
        XCTAssertFalse(watchdog.hasFired)
    }

    func testStrictModeFiresOnceAfterDeadlineExpires() {
        var clockNow = Date(timeIntervalSince1970: 0)
        var fired = 0
        let watchdog = KillSwitchWatchdog(
            policy: .strict,
            deadlineSeconds: 30,
            clock: { clockNow },
            readyCheck: { false },
            deadlineHandler: { fired += 1 }
        )

        // First tick: arms the timer, doesn't fire.
        watchdog.evaluate()
        XCTAssertTrue(watchdog.isArmed)
        XCTAssertEqual(fired, 0)

        // 29s later: still under the deadline.
        clockNow = Date(timeIntervalSince1970: 29)
        watchdog.evaluate()
        XCTAssertEqual(fired, 0)

        // 30s elapsed: deadline reached, handler fires.
        clockNow = Date(timeIntervalSince1970: 30)
        watchdog.evaluate()
        XCTAssertEqual(fired, 1)
        XCTAssertTrue(watchdog.hasFired)

        // Subsequent evaluations while still not-ready: handler must
        // not fire again — that would queue redundant tunnel
        // cancellations.
        clockNow = Date(timeIntervalSince1970: 100)
        watchdog.evaluate()
        clockNow = Date(timeIntervalSince1970: 1_000)
        watchdog.evaluate()
        XCTAssertEqual(fired, 1, "handler must be one-shot per arming")
    }

    func testRecoveryToReadyResetsTheTimer() {
        var clockNow = Date(timeIntervalSince1970: 0)
        var ready = false
        var fired = 0
        let watchdog = KillSwitchWatchdog(
            policy: .strict,
            deadlineSeconds: 10,
            clock: { clockNow },
            readyCheck: { ready },
            deadlineHandler: { fired += 1 }
        )

        // Arm the timer.
        watchdog.evaluate()
        XCTAssertTrue(watchdog.isArmed)

        // Transport recovers before the deadline.
        clockNow = Date(timeIntervalSince1970: 5)
        ready = true
        watchdog.evaluate()
        XCTAssertFalse(watchdog.isArmed, "recovery must disarm")
        XCTAssertEqual(fired, 0)

        // Stays ready well past the original deadline window.
        clockNow = Date(timeIntervalSince1970: 1_000)
        watchdog.evaluate()
        XCTAssertEqual(fired, 0)
    }

    func testReArmsAfterRecoveryAndSecondFailure() {
        var clockNow = Date(timeIntervalSince1970: 0)
        var ready = false
        var fired = 0
        let watchdog = KillSwitchWatchdog(
            policy: .strict,
            deadlineSeconds: 10,
            clock: { clockNow },
            readyCheck: { ready },
            deadlineHandler: { fired += 1 }
        )

        // First failure cycle.
        watchdog.evaluate()
        clockNow = Date(timeIntervalSince1970: 11)
        watchdog.evaluate()
        XCTAssertEqual(fired, 1)

        // Recovery clears the fired flag.
        ready = true
        clockNow = Date(timeIntervalSince1970: 12)
        watchdog.evaluate()
        XCTAssertFalse(watchdog.hasFired, "recovery must reset hasFired")

        // Second failure cycle: deadline is fresh, must fire again.
        ready = false
        clockNow = Date(timeIntervalSince1970: 100)
        watchdog.evaluate()
        XCTAssertTrue(watchdog.isArmed)
        XCTAssertEqual(fired, 1, "second failure has not yet hit the deadline")

        clockNow = Date(timeIntervalSince1970: 110)
        watchdog.evaluate()
        XCTAssertEqual(fired, 2, "second failure must trigger a fresh handler call")
    }

    func testNeverFiresWhenTransportStaysReadyThroughout() {
        var clockNow = Date(timeIntervalSince1970: 0)
        var fired = 0
        let watchdog = KillSwitchWatchdog(
            policy: .strict,
            deadlineSeconds: 1,
            clock: { clockNow },
            readyCheck: { true },
            deadlineHandler: { fired += 1 }
        )

        for elapsed in stride(from: 0, through: 1_000, by: 30) {
            clockNow = Date(timeIntervalSince1970: TimeInterval(elapsed))
            watchdog.evaluate()
        }

        XCTAssertEqual(fired, 0)
        XCTAssertFalse(watchdog.isArmed)
    }
}
