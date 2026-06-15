import Foundation
import os

#if canImport(Network)
import Network
#endif

#if canImport(AppKit)
import AppKit
#endif

/// Mirrors the Rust `qlink_core::mesh_connection::NetworkEvent` enum.
public enum NetworkLifecycleEvent: Equatable, Sendable {
    case pathChanged(interfaceSummary: String)
    case preSleep
    case postWake
    case reachabilityChanged(reachable: Bool)
}

/// Anything that can deliver `NetworkLifecycleEvent`s. Production builds wire
/// this to `NWPathMonitor` + `NSWorkspace` notifications; tests inject a
/// `ManualNetworkEventSource` to drive the observer deterministically.
public protocol NetworkEventSource: AnyObject {
    func start(handler: @escaping (NetworkLifecycleEvent) -> Void)
    func stop()
}

/// Manual source for tests and offline scenarios. The observer treats it like
/// any other source; tests can call `emit(_:)` to feed events through the
/// production code path without depending on real OS notifications.
public final class ManualNetworkEventSource: NetworkEventSource, @unchecked Sendable {
    private var handler: ((NetworkLifecycleEvent) -> Void)?
    private let lock = NSLock()

    public init() {}

    public func start(handler: @escaping (NetworkLifecycleEvent) -> Void) {
        lock.lock()
        self.handler = handler
        lock.unlock()
    }

    public func stop() {
        lock.lock()
        handler = nil
        lock.unlock()
    }

    public func emit(_ event: NetworkLifecycleEvent) {
        lock.lock()
        let handler = self.handler
        lock.unlock()
        handler?(event)
    }
}

/// Watches the system for events that warrant re-validating active mesh
/// paths. Calls a single `handler` closure on each event; the consumer is
/// responsible for translating that into Rust-core re-probe calls and for
/// flipping the tunnel provider's `reasserting` flag.
///
/// The observer is intentionally thin: it does not own any peer state and it
/// does not throttle or coalesce events — that's the consumer's job.
@MainActor
public final class NetworkPathObserver {
    private let logger = Logger(subsystem: "com.quantumlink.macos", category: "network-path")
    private var source: NetworkEventSource?
    private var handler: ((NetworkLifecycleEvent) -> Void)?

    public init() {}

    /// Starts the observer with a custom event source. Useful for tests; the
    /// production app should call `startWithSystemSources(handler:)` instead.
    public func start(
        source: NetworkEventSource,
        handler: @escaping (NetworkLifecycleEvent) -> Void
    ) {
        stop()
        self.source = source
        self.handler = handler
        source.start { [weak self] event in
            self?.dispatch(event)
        }
    }

    public func stop() {
        source?.stop()
        source = nil
        handler = nil
    }

    /// Convenience: wires up the system event sources (NWPathMonitor +
    /// NSWorkspace sleep/wake notifications) and starts observing.
    public func startWithSystemSources(handler: @escaping (NetworkLifecycleEvent) -> Void) {
        let aggregate = AggregateNetworkEventSource()
        start(source: aggregate, handler: handler)
    }

    private func dispatch(_ event: NetworkLifecycleEvent) {
        logger.info("network event: \(String(describing: event), privacy: .public)")
        handler?(event)
    }
}

/// Production source that fans in `NWPathMonitor` (path / interface changes,
/// reachability) and `NSWorkspace` (sleep / wake) into a single
/// `NetworkLifecycleEvent` stream.
public final class AggregateNetworkEventSource: NetworkEventSource, @unchecked Sendable {
#if canImport(Network)
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "com.quantumlink.macos.network-path", qos: .utility)
#endif
    private var lastReachable: Bool?
    private var sleepObserver: NSObjectProtocol?
    private var wakeObserver: NSObjectProtocol?
    private var handler: ((NetworkLifecycleEvent) -> Void)?
    private let lock = NSLock()

    public init() {}

    public func start(handler: @escaping (NetworkLifecycleEvent) -> Void) {
        lock.lock()
        self.handler = handler
        lock.unlock()

#if canImport(Network)
        monitor.pathUpdateHandler = { [weak self] path in
            self?.handlePathUpdate(path)
        }
        monitor.start(queue: queue)
#endif
        attachSleepWakeObservers()
    }

    public func stop() {
#if canImport(Network)
        monitor.cancel()
#endif
        detachSleepWakeObservers()
        lock.lock()
        handler = nil
        lock.unlock()
    }

#if canImport(Network)
    private func handlePathUpdate(_ path: NWPath) {
        let summary = pathSummary(path)
        emit(.pathChanged(interfaceSummary: summary))

        let reachable = path.status == .satisfied
        let changed: Bool
        lock.lock()
        if lastReachable != reachable {
            lastReachable = reachable
            changed = true
        } else {
            changed = false
        }
        lock.unlock()
        if changed {
            emit(.reachabilityChanged(reachable: reachable))
        }
    }

    private func pathSummary(_ path: NWPath) -> String {
        // Don't surface SSIDs or interface MAC-equivalents — only the kind of
        // interface and the system-level reachability bit.
        let kinds = path.availableInterfaces
            .map { interface -> String in
                switch interface.type {
                case .wifi: return "wifi"
                case .cellular: return "cellular"
                case .wiredEthernet: return "ethernet"
                case .loopback: return "loopback"
                case .other: return "other"
                @unknown default: return "unknown"
                }
            }
            .joined(separator: "+")
        let status: String
        switch path.status {
        case .satisfied: status = "satisfied"
        case .unsatisfied: status = "unsatisfied"
        case .requiresConnection: status = "requires-connection"
        @unknown default: status = "unknown"
        }
        return kinds.isEmpty ? status : "\(status):\(kinds)"
    }
#endif

    private func attachSleepWakeObservers() {
#if canImport(AppKit)
        let center = NSWorkspace.shared.notificationCenter
        sleepObserver = center.addObserver(
            forName: NSWorkspace.willSleepNotification,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            self?.emit(.preSleep)
        }
        wakeObserver = center.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            self?.emit(.postWake)
        }
#endif
    }

    private func detachSleepWakeObservers() {
#if canImport(AppKit)
        let center = NSWorkspace.shared.notificationCenter
        if let sleepObserver {
            center.removeObserver(sleepObserver)
        }
        if let wakeObserver {
            center.removeObserver(wakeObserver)
        }
#endif
        sleepObserver = nil
        wakeObserver = nil
    }

    private func emit(_ event: NetworkLifecycleEvent) {
        lock.lock()
        let handler = self.handler
        lock.unlock()
        handler?(event)
    }
}

/// Translates `NetworkLifecycleEvent`s into the same response shape the Rust
/// `MeshConnector::handle_network_event` returns. Lets the Swift side reason
/// about events without round-tripping through FFI when the live tunnel
/// hasn't yet been wired to the Rust connector at runtime.
public struct NetworkEventDecision: Equatable, Sendable {
    public let reprobeRecommended: Bool
    public let invalidateCachedPaths: Bool

    public init(reprobeRecommended: Bool, invalidateCachedPaths: Bool) {
        self.reprobeRecommended = reprobeRecommended
        self.invalidateCachedPaths = invalidateCachedPaths
    }

    public static func decide(for event: NetworkLifecycleEvent) -> NetworkEventDecision {
        switch event {
        case .pathChanged, .postWake:
            return NetworkEventDecision(reprobeRecommended: true, invalidateCachedPaths: true)
        case .preSleep:
            return NetworkEventDecision(reprobeRecommended: false, invalidateCachedPaths: false)
        case .reachabilityChanged(let reachable):
            return NetworkEventDecision(reprobeRecommended: reachable, invalidateCachedPaths: false)
        }
    }
}
