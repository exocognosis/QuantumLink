import Foundation

/// Runtime enforcement for `KillSwitchPolicy.strict`. The pump's
/// per-batch kill switch already drops protected-prefix packets when
/// the transport is unhealthy, but it does not by itself bring the
/// tunnel down — so a strict deployment that loses connectivity stays
/// "up but dropping" indefinitely. This watchdog closes that gap by
/// calling its `deadlineHandler` (typically `cancelTunnelWithError`)
/// once the transport has been unhealthy for at least `deadline`
/// seconds.
///
/// `KillSwitchPolicy.failClosed` is a no-op for this type — drop
/// behavior is the only contract the policy makes.
///
/// The watchdog is clock-injectable so tests can drive it
/// deterministically without sleeping.
public final class KillSwitchWatchdog {
    public typealias ReadyCheck = () -> Bool
    public typealias DeadlineHandler = () -> Void

    public static let defaultDeadlineSeconds: TimeInterval = 30

    private let policy: KillSwitchPolicy
    private let deadline: TimeInterval
    private let clock: () -> Date
    private let readyCheck: ReadyCheck
    private let deadlineHandler: DeadlineHandler

    private var notReadySince: Date?
    private var hasFiredHandler: Bool = false

    public init(
        policy: KillSwitchPolicy,
        deadlineSeconds: TimeInterval = KillSwitchWatchdog.defaultDeadlineSeconds,
        clock: @escaping () -> Date = { Date() },
        readyCheck: @escaping ReadyCheck,
        deadlineHandler: @escaping DeadlineHandler
    ) {
        self.policy = policy
        self.deadline = deadlineSeconds
        self.clock = clock
        self.readyCheck = readyCheck
        self.deadlineHandler = deadlineHandler
    }

    /// Re-evaluates whether the strict-mode deadline has expired.
    /// Idempotent. Safe to call from any timer cadence (production
    /// uses a periodic Task; tests call directly).
    ///
    /// Behavior:
    /// - `policy == .failClosed` → never fires the handler.
    /// - `policy == .strict` and the transport is healthy → resets the
    ///   not-ready timer and disarms a previously-armed deadline.
    /// - `policy == .strict` and the transport is not healthy →
    ///   records the first-not-ready timestamp; if the elapsed time
    ///   exceeds `deadline`, fires the handler exactly once until the
    ///   transport becomes healthy again (recovery re-arms the
    ///   watchdog so a subsequent failure is also caught).
    public func evaluate() {
        guard policy == .strict else { return }
        if readyCheck() {
            notReadySince = nil
            hasFiredHandler = false
            return
        }
        let now = clock()
        let firstSeen = notReadySince ?? now
        if notReadySince == nil {
            notReadySince = firstSeen
        }
        if hasFiredHandler {
            return
        }
        if now.timeIntervalSince(firstSeen) >= deadline {
            hasFiredHandler = true
            deadlineHandler()
        }
    }

    /// Test hook: read-only inspection of internal state. Kept
    /// minimal so production callers don't grow accidental dependence
    /// on internals.
    public var isArmed: Bool { notReadySince != nil }
    public var hasFired: Bool { hasFiredHandler }
}
