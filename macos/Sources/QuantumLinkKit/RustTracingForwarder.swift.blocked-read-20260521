import Foundation
import os

/// Drains the Rust core's tracing-bridge ring buffer and forwards
/// each captured event into the Swift host's unified logger,
/// **redacted** at the seam.
///
/// Why this exists: the Rust core emits diagnostics via `tracing::`
/// macros (warnings on rendezvous failure, falling back to cached
/// records, ACL rejections, etc). When the dylib runs inside
/// `NEPacketTunnelProvider` no subscriber is installed by default,
/// so those diagnostics are silently dropped — making real-world
/// tunnel issues much harder to debug. The forwarder closes that
/// gap by:
///
/// 1. Calling `RustCoreLibrary.installTracingBridge()` once to wire
///    a process-wide capturing subscriber on the Rust side.
/// 2. Polling `popTracingEvent()` on a Task at a steady cadence.
/// 3. Running each event's `message` field through
///    `PrivacyDefaults.redactForLog` — Rust errors routinely embed
///    peer_ids, addresses, and rendezvous URLs verbatim, and the
///    unified logging system is a user-shareable artifact.
/// 4. Forwarding to `Logger` with a level that matches the Rust
///    severity (warn → `.error`, error → `.fault`).
///
/// The forwarder is `@MainActor` so its lifecycle (start/stop) is
/// trivially serializable; the polling Task itself runs off-main.
public final class RustTracingForwarder: @unchecked Sendable {
    private let library: RustCoreLibrary
    private let logger: Logger
    private let pollInterval: Duration
    private var task: Task<Void, Never>?

    /// 250ms is chatty enough for sub-second visibility without
    /// burning CPU on an idle tunnel. Operators on a tail-of-logs
    /// workflow won't notice the cadence; the buffer is bounded so
    /// even longer intervals wouldn't lose events under normal load.
    public static let defaultPollInterval: Duration = .milliseconds(250)

    public init(
        library: RustCoreLibrary,
        logger: Logger = Logger(subsystem: "com.quantumlink.macos", category: "rust-tracing"),
        pollInterval: Duration = RustTracingForwarder.defaultPollInterval
    ) {
        self.library = library
        self.logger = logger
        self.pollInterval = pollInterval
    }

    /// Installs the Rust-side bridge (idempotent) and starts the
    /// polling Task. Calling `start` while already running is a
    /// no-op. Returns `false` if the Rust bridge couldn't be
    /// installed (some other code already set a global tracing
    /// subscriber); the forwarder is a no-op in that state but
    /// otherwise safe to keep around.
    @discardableResult
    public func start() -> Bool {
        guard task == nil else { return true }
        let installed = library.installTracingBridge()
        guard installed else {
            logger.info("Rust tracing bridge unavailable: another subscriber is already installed")
            return false
        }
        let library = self.library
        let logger = self.logger
        let pollInterval = self.pollInterval
        task = Task.detached {
            // Per-Task drop counter rather than instance state so
            // the closure doesn't have to capture `self` (which
            // can't cross task boundaries safely under Swift 6
            // strict concurrency).
            var lastDroppedCount: UInt64 = 0
            while !Task.isCancelled {
                while let raw = library.popTracingEvent() {
                    Self.forward(raw: raw, logger: logger)
                }
                let current = library.tracingDroppedCount()
                if current > lastDroppedCount {
                    let delta = current - lastDroppedCount
                    logger.error("Rust tracing bridge dropped \(delta, privacy: .public) event(s) since last poll")
                    lastDroppedCount = current
                }
                try? await Task.sleep(for: pollInterval)
            }
        }
        return true
    }

    public func stop() {
        task?.cancel()
        task = nil
    }

    deinit {
        task?.cancel()
    }

    /// Test hook: drains the buffer once synchronously, redacts +
    /// forwards each event, and returns the number forwarded. The
    /// production path uses the Task-driven loop in `start`; this
    /// is here so unit tests can drive a deterministic pump cycle.
    @discardableResult
    public func drainOnce() -> Int {
        var forwarded = 0
        while let raw = library.popTracingEvent() {
            Self.forward(raw: raw, logger: logger)
            forwarded += 1
        }
        return forwarded
    }

    private static func forward(raw: String, logger: Logger) {
        guard let event = RustTracingEvent.parse(raw) else {
            // Bridge encoded something we can't parse — log the raw
            // string after redaction so we don't completely lose
            // the diagnostic. Truncate aggressively to avoid filling
            // the unified log with malformed payloads if this turns
            // into a hot path.
            let trimmed = raw.prefix(1024)
            let redacted = PrivacyDefaults.redactForLog(String(trimmed))
            logger.error("rust-tracing: malformed event payload — \(redacted, privacy: .public)")
            return
        }
        let redactedMessage = PrivacyDefaults.redactForLog(event.message)
        // The `target` is a Rust module path like
        // `qlink_core::mesh_connection`. Module paths are
        // configuration-stable and not sensitive — log at .public.
        switch event.level {
        case .error:
            logger.fault("[rust-tracing \(event.target, privacy: .public)] \(redactedMessage, privacy: .public)")
        case .warn:
            logger.error("[rust-tracing \(event.target, privacy: .public)] \(redactedMessage, privacy: .public)")
        case .info:
            logger.notice("[rust-tracing \(event.target, privacy: .public)] \(redactedMessage, privacy: .public)")
        case .debug, .trace:
            logger.debug("[rust-tracing \(event.target, privacy: .public)] \(redactedMessage, privacy: .public)")
        }
    }
}

/// Decoded shape of one Rust tracing event coming over the FFI.
public struct RustTracingEvent: Equatable, Sendable {
    public enum Level: String, Sendable {
        case error
        case warn
        case info
        case debug
        case trace
    }

    public let level: Level
    public let target: String
    public let message: String

    public init(level: Level, target: String, message: String) {
        self.level = level
        self.target = target
        self.message = message
    }

    /// Parses the JSON payload emitted by `qlink_tracing_pop_event`.
    /// Returns `nil` on any decode failure — the forwarder treats
    /// that as "log the raw string with a malformed-payload tag"
    /// rather than failing hard.
    public static func parse(_ raw: String) -> RustTracingEvent? {
        guard let data = raw.data(using: .utf8) else { return nil }
        struct Wire: Decodable {
            let level: String
            let target: String
            let message: String
        }
        guard let wire = try? JSONDecoder().decode(Wire.self, from: data) else {
            return nil
        }
        guard let level = Level(rawValue: wire.level) else {
            return nil
        }
        return RustTracingEvent(level: level, target: wire.target, message: wire.message)
    }
}
