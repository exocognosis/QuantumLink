import Darwin
import Foundation

/// Live runtime that owns the bridged utun device. After the
/// privileged helper hands us a file descriptor via SCM_RIGHTS,
/// we adopt it into the Rust `utun_pump` which spawns two async
/// halves (OS→app + app→OS) and exposes running counters.
///
/// ## Difference from `PrivacyOrchestrator`
///
/// `PrivacyOrchestrator` manages the Rust services that run
/// independently of any system-level packet capture (DNS resolver,
/// SOCKS5 listener, cover-traffic scheduler). `RealTunnelingController`
/// manages the *system-level* tunnel — the bridged utun device that
/// turns QuantumLink into a real OS-wide VPN, not a per-app proxy.
///
/// Both can run concurrently; they're complementary.
///
/// ## Lifecycle
///
/// 1. `start()` runs the helper-install path (if needed), opens
///    the utun device, hands the FD to the Rust pump.
/// 2. `metrics()` returns live counters the GUI polls for the
///    "X packets captured / Y MB exchanged" display.
/// 3. `stop()` tears the pump down and closes the device.
public final class RealTunnelingController: @unchecked Sendable {

    public static let shared = RealTunnelingController()

    public enum State: Equatable, Sendable {
        case idle
        case starting
        case running(interfaceName: String)
        case error(String)
    }

    public struct Metrics: Equatable, Sendable {
        public let packetsOSToApp: UInt64
        public let packetsAppToOS: UInt64
        public let bytesOSToApp: UInt64
        public let bytesAppToOS: UInt64
        public let readErrors: UInt64
        public let writeErrors: UInt64

        public static let empty = Metrics(
            packetsOSToApp: 0,
            packetsAppToOS: 0,
            bytesOSToApp: 0,
            bytesAppToOS: 0,
            readErrors: 0,
            writeErrors: 0
        )
    }

    private let bridge: UtunPumpFFIBridge?
    private let lock = NSLock()
    private var pumpHandle: OpaquePointer?
    private var currentState: State = .idle

    private init() {
        self.bridge = UtunPumpFFIBridge.bestEffort()
    }

    public var state: State {
        lock.lock()
        defer { lock.unlock() }
        return currentState
    }

    /// Start the bridged tunnel. Asks the helper for a fresh utun
    /// FD and adopts it into the Rust pump. Throws if the helper
    /// is unavailable or the pump can't start.
    public func start() throws {
        guard let bridge else {
            throw RealTunnelingError.ffiUnavailable
        }
        lock.lock()
        defer { lock.unlock() }

        if pumpHandle != nil {
            return // already running
        }
        currentState = .starting

        let openResult: QuantumLinkHelper.OpenTunResult
        do {
            openResult = try QuantumLinkHelper.shared.openTun()
        } catch {
            currentState = .error((error as? LocalizedError)?.errorDescription
                                  ?? error.localizedDescription)
            throw error
        }

        guard let h = bridge.pumpCreate(openResult.fileDescriptor) else {
            // Failure path: close the FD ourselves so we don't leak it.
            Darwin.close(openResult.fileDescriptor)
            currentState = .error("Pump failed to adopt utun FD")
            throw RealTunnelingError.pumpStartFailed
        }
        pumpHandle = h
        currentState = .running(interfaceName: openResult.interfaceName)
    }

    public func stop() {
        guard let bridge else { return }
        lock.lock()
        defer { lock.unlock() }
        if let h = pumpHandle {
            bridge.pumpDestroy(h)
            pumpHandle = nil
        }
        currentState = .idle
    }

    /// Snapshot the live counters. Returns empty metrics if the
    /// pump isn't running.
    public func metrics() -> Metrics {
        guard let bridge else { return .empty }
        lock.lock()
        defer { lock.unlock() }
        guard let h = pumpHandle else { return .empty }
        return bridge.pumpMetrics(h)
    }
}

public enum RealTunnelingError: Error, LocalizedError {
    case ffiUnavailable
    case pumpStartFailed

    public var errorDescription: String? {
        switch self {
        case .ffiUnavailable:
            return "qlink_core utun_pump symbols are not available in this build."
        case .pumpStartFailed:
            return "Pump failed to adopt the utun file descriptor. The kernel may have refused the dup; check the helper log at /var/log/quantumlink-helper.log."
        }
    }
}

// MARK: - dlsym-loaded FFI bindings

/// Mirrors the C struct `QlinkUtunPumpMetrics` from
/// `rust/qlink-core/src/ffi_privacy.rs`. Layout MUST match (six
/// `u64` fields, no padding) or the FFI will read garbage.
@frozen
public struct QlinkUtunPumpMetricsCStruct {
    public let packetsOSToApp: UInt64
    public let packetsAppToOS: UInt64
    public let bytesOSToApp: UInt64
    public let bytesAppToOS: UInt64
    public let readErrors: UInt64
    public let writeErrors: UInt64
}

private final class UtunPumpFFIBridge {
    typealias PumpCreate = @convention(c) (Int32) -> OpaquePointer?
    /// Raw-pointer signature so Swift's Obj-C bridging accepts it.
    /// Rust writes a `QlinkUtunPumpMetrics` (six packed u64s, no
    /// padding) at the buffer; Swift loads via .load(as:).
    typealias PumpMetrics = @convention(c) (OpaquePointer, UnsafeMutableRawPointer) -> Void
    typealias PumpDestroy = @convention(c) (OpaquePointer) -> Void

    let pumpCreateFn: PumpCreate
    let pumpMetricsFn: PumpMetrics
    let pumpDestroyFn: PumpDestroy

    static func bestEffort() -> UtunPumpFFIBridge? {
        let handle = UnsafeMutableRawPointer(bitPattern: -2) // RTLD_DEFAULT
        guard let create = sym(handle, "qlink_utun_pump_create") else { return nil }
        guard let metrics = sym(handle, "qlink_utun_pump_metrics") else { return nil }
        guard let destroy = sym(handle, "qlink_utun_pump_destroy") else { return nil }
        return UtunPumpFFIBridge(
            pumpCreateFn: unsafeBitCast(create, to: PumpCreate.self),
            pumpMetricsFn: unsafeBitCast(metrics, to: PumpMetrics.self),
            pumpDestroyFn: unsafeBitCast(destroy, to: PumpDestroy.self)
        )
    }

    init(
        pumpCreateFn: PumpCreate,
        pumpMetricsFn: PumpMetrics,
        pumpDestroyFn: PumpDestroy
    ) {
        self.pumpCreateFn = pumpCreateFn
        self.pumpMetricsFn = pumpMetricsFn
        self.pumpDestroyFn = pumpDestroyFn
    }

    func pumpCreate(_ fd: Int32) -> OpaquePointer? { pumpCreateFn(fd) }
    func pumpMetrics(_ h: OpaquePointer) -> RealTunnelingController.Metrics {
        var raw = QlinkUtunPumpMetricsCStruct(
            packetsOSToApp: 0,
            packetsAppToOS: 0,
            bytesOSToApp: 0,
            bytesAppToOS: 0,
            readErrors: 0,
            writeErrors: 0
        )
        withUnsafeMutablePointer(to: &raw) { typedPtr in
            pumpMetricsFn(h, UnsafeMutableRawPointer(typedPtr))
        }
        return RealTunnelingController.Metrics(
            packetsOSToApp: raw.packetsOSToApp,
            packetsAppToOS: raw.packetsAppToOS,
            bytesOSToApp: raw.bytesOSToApp,
            bytesAppToOS: raw.bytesAppToOS,
            readErrors: raw.readErrors,
            writeErrors: raw.writeErrors
        )
    }
    func pumpDestroy(_ h: OpaquePointer) { pumpDestroyFn(h) }
}

private func sym(_ handle: UnsafeMutableRawPointer?, _ name: String) -> UnsafeMutableRawPointer? {
    guard let h = handle else { return nil }
    return name.withCString { cstr in dlsym(h, cstr) }
}
