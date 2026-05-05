import Foundation

/// Live runtime that owns the running privacy services. Created
/// once per app launch; takes a `PrivacySettings` and starts/stops
/// the corresponding Rust modules through the qlink_core FFI.
///
/// ## Lifecycle
///
/// 1. App startup constructs the singleton.
/// 2. `apply(_:)` reconciles the running services against the
///    requested settings: starts what's enabled and not running,
///    stops what's running and not enabled.
/// 3. Settings changes (the GUI saves on every toggle) re-call
///    `apply(_:)`.
/// 4. App shutdown calls `shutdown()` to free all FFI handles.
///
/// ## Error handling
///
/// Each service starts independently. A failure to start one
/// (e.g. a port-1080 conflict for SOCKS5) does NOT prevent the
/// others from starting. Failures are surfaced via the
/// `lastErrors` dictionary so the GUI can show "SOCKS5 unavailable
/// — port already in use" without blocking the rest of the
/// privacy stack.
public final class PrivacyOrchestrator: @unchecked Sendable {

    public static let shared = PrivacyOrchestrator()

    public enum Service: String, CaseIterable, Sendable {
        case dnsResolver
        case socks5Proxy
        case coverTraffic
    }

    public struct Status: Sendable {
        public let running: Set<Service>
        public let lastErrors: [Service: String]
        public let dnsBoundAddress: String?
        public let socks5BoundAddress: String?
        public let coverTrafficRateBps: UInt64

        public static let empty = Status(
            running: [],
            lastErrors: [:],
            dnsBoundAddress: nil,
            socks5BoundAddress: nil,
            coverTrafficRateBps: 0
        )
    }

    private let bridge: PrivacyFFIBridge?
    private let lock = NSLock()
    private var dnsHandle: OpaquePointer?
    private var socks5Handle: OpaquePointer?
    private var coverHandle: OpaquePointer?
    private var status: Status = .empty

    private init() {
        self.bridge = PrivacyFFIBridge.bestEffort()
        if bridge == nil {
            // Likely a build that wasn't linked against the
            // qlink_core FFI library (test runs, mocks, etc.).
            // The orchestrator stays alive as a no-op so the rest
            // of the app keeps working.
            NSLog("PrivacyOrchestrator: qlink_core FFI symbols unavailable; running as no-op")
        }
    }

    public func currentStatus() -> Status {
        lock.lock()
        defer { lock.unlock() }
        return status
    }

    /// Apply a settings struct, starting/stopping services to match.
    /// Cheap to call repeatedly; idempotent for unchanged services.
    public func apply(_ settings: PrivacySettings) {
        guard let bridge else { return }
        lock.lock()
        defer { lock.unlock() }

        var running = status.running
        var errors = status.lastErrors

        // --- DNS-over-QuantumLink ---------------------------------------
        if settings.enableDnsOverQuantumLink {
            if dnsHandle == nil {
                // Bind to 127.0.0.53:0 by default — the OS
                // resolver-replacement work picks the right port
                // and configures scutil. For the reviewer build,
                // 127.0.0.1:0 is enough to demonstrate the resolver
                // works without requiring privileged port :53.
                let bind = "127.0.0.1:0".cString(using: .utf8)!
                let upstream = "9.9.9.9:53".cString(using: .utf8)!
                let h = bind.withUnsafeBufferPointer { bindBuf in
                    upstream.withUnsafeBufferPointer { upBuf in
                        bridge.dnsCreate(bindBuf.baseAddress!, upBuf.baseAddress!)
                    }
                }
                if let h {
                    dnsHandle = h
                    running.insert(.dnsResolver)
                    errors.removeValue(forKey: .dnsResolver)
                } else {
                    errors[.dnsResolver] = "failed to bind DNS resolver"
                }
            }
        } else {
            if let h = dnsHandle {
                bridge.dnsDestroy(h)
                dnsHandle = nil
                running.remove(.dnsResolver)
            }
        }

        // --- SOCKS5 proxy -----------------------------------------------
        if settings.enableSocks5Proxy {
            if socks5Handle == nil {
                let bind = "127.0.0.1:1080".cString(using: .utf8)!
                let h = bind.withUnsafeBufferPointer { buf in
                    bridge.socksCreate(buf.baseAddress!)
                }
                if let h {
                    socks5Handle = h
                    running.insert(.socks5Proxy)
                    errors.removeValue(forKey: .socks5Proxy)
                } else {
                    errors[.socks5Proxy] = "couldn't bind 127.0.0.1:1080 (port may be in use)"
                }
            }
        } else {
            if let h = socks5Handle {
                bridge.socksDestroy(h)
                socks5Handle = nil
                running.remove(.socks5Proxy)
            }
        }

        // --- Cover traffic ----------------------------------------------
        let desiredRate: UInt64 = {
            switch settings.coverTrafficLevel {
            case .off: return 0
            case .low: return 10_000
            case .medium: return 100_000
            case .high: return 1_000_000
            }
        }()

        if desiredRate > 0 && coverHandle == nil {
            if let h = bridge.coverCreate(desiredRate) {
                coverHandle = h
                running.insert(.coverTraffic)
                errors.removeValue(forKey: .coverTraffic)
            } else {
                errors[.coverTraffic] = "failed to start scheduler"
            }
        } else if desiredRate == 0, let h = coverHandle {
            bridge.coverDestroy(h)
            coverHandle = nil
            running.remove(.coverTraffic)
        }

        // --- Read back bound addresses for the status surface ---------
        let dnsAddr = dnsHandle.flatMap { bridge.dnsLocalAddr($0) }
        let socksAddr = socks5Handle.flatMap { bridge.socksLocalAddr($0) }
        let coverRate = coverHandle.map { bridge.coverRate($0) } ?? 0

        status = Status(
            running: running,
            lastErrors: errors,
            dnsBoundAddress: dnsAddr,
            socks5BoundAddress: socksAddr,
            coverTrafficRateBps: coverRate
        )
    }

    /// Tear down all running services. Called from
    /// `applicationWillTerminate` (and idempotent so test cleanup
    /// can call it freely).
    public func shutdown() {
        guard let bridge else { return }
        lock.lock()
        defer { lock.unlock() }
        if let h = dnsHandle {
            bridge.dnsDestroy(h)
            dnsHandle = nil
        }
        if let h = socks5Handle {
            bridge.socksDestroy(h)
            socks5Handle = nil
        }
        if let h = coverHandle {
            bridge.coverDestroy(h)
            coverHandle = nil
        }
        status = .empty
    }
}

// MARK: - FFI bridge (dlsym-loaded function pointers)

/// Holds typed function pointers for the privacy FFI symbols. We
/// dlsym() them at startup so a build that doesn't link the dylib
/// (CI tests, previews) doesn't fail to launch — it just runs the
/// orchestrator as a no-op.
private final class PrivacyFFIBridge {
    typealias DnsCreate = @convention(c) (UnsafePointer<Int8>, UnsafePointer<Int8>) -> OpaquePointer?
    typealias DnsLocalAddr = @convention(c) (OpaquePointer) -> UnsafeMutablePointer<Int8>?
    typealias DnsDestroy = @convention(c) (OpaquePointer) -> Void

    typealias SocksCreate = @convention(c) (UnsafePointer<Int8>) -> OpaquePointer?
    typealias SocksLocalAddr = @convention(c) (OpaquePointer) -> UnsafeMutablePointer<Int8>?
    typealias SocksDestroy = @convention(c) (OpaquePointer) -> Void

    typealias CoverCreate = @convention(c) (UInt64) -> OpaquePointer?
    typealias CoverRate = @convention(c) (OpaquePointer) -> UInt64
    typealias CoverDestroy = @convention(c) (OpaquePointer) -> Void

    typealias StringFree = @convention(c) (UnsafeMutablePointer<Int8>) -> Void

    let dnsCreateFn: DnsCreate
    let dnsLocalAddrFn: DnsLocalAddr
    let dnsDestroyFn: DnsDestroy
    let socksCreateFn: SocksCreate
    let socksLocalAddrFn: SocksLocalAddr
    let socksDestroyFn: SocksDestroy
    let coverCreateFn: CoverCreate
    let coverRateFn: CoverRate
    let coverDestroyFn: CoverDestroy
    let stringFreeFn: StringFree

    static func bestEffort() -> PrivacyFFIBridge? {
        // Use RTLD_DEFAULT so we resolve symbols from whatever's
        // already linked into the process — the qlink_core dylib
        // is a dependency of QuantumLinkKit so by the time this
        // runs it's been loaded.
        let handle = UnsafeMutableRawPointer(bitPattern: -2) // RTLD_DEFAULT
        guard let dnsCreate = sym(handle, "qlink_dns_resolver_create") else { return nil }
        guard let dnsLocal = sym(handle, "qlink_dns_resolver_local_addr") else { return nil }
        guard let dnsDestroy = sym(handle, "qlink_dns_resolver_destroy") else { return nil }
        guard let socksCreate = sym(handle, "qlink_socks5_proxy_create") else { return nil }
        guard let socksLocal = sym(handle, "qlink_socks5_proxy_local_addr") else { return nil }
        guard let socksDestroy = sym(handle, "qlink_socks5_proxy_destroy") else { return nil }
        guard let coverCreate = sym(handle, "qlink_cover_traffic_create") else { return nil }
        guard let coverRate = sym(handle, "qlink_cover_traffic_rate_bps") else { return nil }
        guard let coverDestroy = sym(handle, "qlink_cover_traffic_destroy") else { return nil }
        guard let stringFree = sym(handle, "qlink_string_free") else { return nil }
        return PrivacyFFIBridge(
            dnsCreateFn: unsafeBitCast(dnsCreate, to: DnsCreate.self),
            dnsLocalAddrFn: unsafeBitCast(dnsLocal, to: DnsLocalAddr.self),
            dnsDestroyFn: unsafeBitCast(dnsDestroy, to: DnsDestroy.self),
            socksCreateFn: unsafeBitCast(socksCreate, to: SocksCreate.self),
            socksLocalAddrFn: unsafeBitCast(socksLocal, to: SocksLocalAddr.self),
            socksDestroyFn: unsafeBitCast(socksDestroy, to: SocksDestroy.self),
            coverCreateFn: unsafeBitCast(coverCreate, to: CoverCreate.self),
            coverRateFn: unsafeBitCast(coverRate, to: CoverRate.self),
            coverDestroyFn: unsafeBitCast(coverDestroy, to: CoverDestroy.self),
            stringFreeFn: unsafeBitCast(stringFree, to: StringFree.self)
        )
    }

    init(
        dnsCreateFn: @escaping DnsCreate,
        dnsLocalAddrFn: @escaping DnsLocalAddr,
        dnsDestroyFn: @escaping DnsDestroy,
        socksCreateFn: @escaping SocksCreate,
        socksLocalAddrFn: @escaping SocksLocalAddr,
        socksDestroyFn: @escaping SocksDestroy,
        coverCreateFn: @escaping CoverCreate,
        coverRateFn: @escaping CoverRate,
        coverDestroyFn: @escaping CoverDestroy,
        stringFreeFn: @escaping StringFree
    ) {
        self.dnsCreateFn = dnsCreateFn
        self.dnsLocalAddrFn = dnsLocalAddrFn
        self.dnsDestroyFn = dnsDestroyFn
        self.socksCreateFn = socksCreateFn
        self.socksLocalAddrFn = socksLocalAddrFn
        self.socksDestroyFn = socksDestroyFn
        self.coverCreateFn = coverCreateFn
        self.coverRateFn = coverRateFn
        self.coverDestroyFn = coverDestroyFn
        self.stringFreeFn = stringFreeFn
    }

    // Convenience helpers that take care of the C-string memory
    // management on the way out.
    func dnsCreate(_ bind: UnsafePointer<Int8>, _ upstream: UnsafePointer<Int8>) -> OpaquePointer? {
        dnsCreateFn(bind, upstream)
    }
    func dnsLocalAddr(_ h: OpaquePointer) -> String? {
        guard let raw = dnsLocalAddrFn(h) else { return nil }
        let s = String(cString: raw)
        stringFreeFn(raw)
        return s
    }
    func dnsDestroy(_ h: OpaquePointer) { dnsDestroyFn(h) }

    func socksCreate(_ bind: UnsafePointer<Int8>) -> OpaquePointer? { socksCreateFn(bind) }
    func socksLocalAddr(_ h: OpaquePointer) -> String? {
        guard let raw = socksLocalAddrFn(h) else { return nil }
        let s = String(cString: raw)
        stringFreeFn(raw)
        return s
    }
    func socksDestroy(_ h: OpaquePointer) { socksDestroyFn(h) }

    func coverCreate(_ rate: UInt64) -> OpaquePointer? { coverCreateFn(rate) }
    func coverRate(_ h: OpaquePointer) -> UInt64 { coverRateFn(h) }
    func coverDestroy(_ h: OpaquePointer) { coverDestroyFn(h) }
}

// MARK: - dlsym wrapper

private func sym(_ handle: UnsafeMutableRawPointer?, _ name: String) -> UnsafeMutableRawPointer? {
    guard let h = handle else { return nil }
    return name.withCString { cstr in
        dlsym(h, cstr)
    }
}
