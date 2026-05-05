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
        case decoyRunner
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
    private var decoyHandle: OpaquePointer?
    private var lastAppliedDecoyCadence: PrivacySettings.DecoyCadence = .off
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

        // --- Pluggable transport (config setter, no handle) -------------
        bridge.setTransportObfuscation(settings.transportObfuscation.ffiCode)

        // --- Onion routing (config setter, no handle) -------------------
        bridge.setOnionRouting(
            enabled: settings.enableOnionRouting,
            length: UInt32(settings.onionCircuitLength)
        )

        // --- Identity rotation policy ----------------------------------
        bridge.setRotationPolicy(settings.rotationPolicy.ffiCode)

        // --- Decoy runner ---------------------------------------------
        // Cadence change requires teardown + respawn since the
        // running task captures the cadence at spawn time.
        let cadenceCode = settings.decoyCadence.ffiCode
        let cadenceChanged = settings.decoyCadence != lastAppliedDecoyCadence
        if cadenceCode == 0 {
            // Off — destroy any running runner.
            if let h = decoyHandle {
                bridge.decoyDestroy(h)
                decoyHandle = nil
                running.remove(.decoyRunner)
            }
        } else if cadenceChanged || decoyHandle == nil {
            // Either cadence shifted or runner isn't up — restart.
            if let h = decoyHandle {
                bridge.decoyDestroy(h)
                decoyHandle = nil
            }
            if let h = bridge.decoyCreate(cadence: cadenceCode) {
                decoyHandle = h
                running.insert(.decoyRunner)
                errors.removeValue(forKey: .decoyRunner)
            } else {
                errors[.decoyRunner] = "failed to start decoy runner"
            }
        }
        lastAppliedDecoyCadence = settings.decoyCadence

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
        if let h = decoyHandle {
            bridge.decoyDestroy(h)
            decoyHandle = nil
        }
        status = .empty
    }
}

// MARK: - FFI code translation

extension PrivacySettings.TransportObfuscation {
    var ffiCode: UInt8 {
        switch self {
        case .none: return 0
        case .tlsLikeFraming: return 1
        case .obfs4XorScramble: return 2
        }
    }
}

extension PrivacySettings.DecoyCadence {
    var ffiCode: UInt8 {
        switch self {
        case .off: return 0
        case .light: return 1
        case .steady: return 2
        case .aggressive: return 3
        }
    }
}

extension PrivacySettings.RotationPolicy {
    var ffiCode: UInt8 {
        switch self {
        case .manual: return 0
        case .weekly: return 1
        case .daily: return 2
        }
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

    typealias SetTransport = @convention(c) (UInt8) -> Void
    typealias SetOnion = @convention(c) (UInt32, UInt32) -> Void
    typealias SetRotation = @convention(c) (UInt8) -> Void

    typealias DecoyCreate = @convention(c) (UInt8, UnsafePointer<Int8>?) -> OpaquePointer?
    typealias DecoyDestroy = @convention(c) (OpaquePointer) -> Void
    typealias DecoyCount = @convention(c) () -> Int

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
    let setTransportFn: SetTransport
    let setOnionFn: SetOnion
    let setRotationFn: SetRotation
    let decoyCreateFn: DecoyCreate
    let decoyDestroyFn: DecoyDestroy
    let decoyCountFn: DecoyCount
    let stringFreeFn: StringFree

    static func bestEffort() -> PrivacyFFIBridge? {
        let handle = UnsafeMutableRawPointer(bitPattern: -2) // RTLD_DEFAULT
        guard let dnsCreate = sym(handle, "qlink_dns_resolver_create"),
              let dnsLocal = sym(handle, "qlink_dns_resolver_local_addr"),
              let dnsDestroy = sym(handle, "qlink_dns_resolver_destroy"),
              let socksCreate = sym(handle, "qlink_socks5_proxy_create"),
              let socksLocal = sym(handle, "qlink_socks5_proxy_local_addr"),
              let socksDestroy = sym(handle, "qlink_socks5_proxy_destroy"),
              let coverCreate = sym(handle, "qlink_cover_traffic_create"),
              let coverRate = sym(handle, "qlink_cover_traffic_rate_bps"),
              let coverDestroy = sym(handle, "qlink_cover_traffic_destroy"),
              let setTransport = sym(handle, "qlink_set_transport_obfuscation"),
              let setOnion = sym(handle, "qlink_set_onion_routing"),
              let setRotation = sym(handle, "qlink_set_rotation_policy"),
              let decoyCreate = sym(handle, "qlink_decoy_create"),
              let decoyDestroy = sym(handle, "qlink_decoy_destroy"),
              let decoyCount = sym(handle, "qlink_decoy_completed_count"),
              let stringFree = sym(handle, "qlink_string_free") else { return nil }
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
            setTransportFn: unsafeBitCast(setTransport, to: SetTransport.self),
            setOnionFn: unsafeBitCast(setOnion, to: SetOnion.self),
            setRotationFn: unsafeBitCast(setRotation, to: SetRotation.self),
            decoyCreateFn: unsafeBitCast(decoyCreate, to: DecoyCreate.self),
            decoyDestroyFn: unsafeBitCast(decoyDestroy, to: DecoyDestroy.self),
            decoyCountFn: unsafeBitCast(decoyCount, to: DecoyCount.self),
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
        setTransportFn: @escaping SetTransport,
        setOnionFn: @escaping SetOnion,
        setRotationFn: @escaping SetRotation,
        decoyCreateFn: @escaping DecoyCreate,
        decoyDestroyFn: @escaping DecoyDestroy,
        decoyCountFn: @escaping DecoyCount,
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
        self.setTransportFn = setTransportFn
        self.setOnionFn = setOnionFn
        self.setRotationFn = setRotationFn
        self.decoyCreateFn = decoyCreateFn
        self.decoyDestroyFn = decoyDestroyFn
        self.decoyCountFn = decoyCountFn
        self.stringFreeFn = stringFreeFn
    }

    // Convenience helpers for the new symbols.
    func setTransportObfuscation(_ code: UInt8) { setTransportFn(code) }
    func setOnionRouting(enabled: Bool, length: UInt32) {
        setOnionFn(enabled ? 1 : 0, length)
    }
    func setRotationPolicy(_ code: UInt8) { setRotationFn(code) }
    func decoyCreate(cadence: UInt8) -> OpaquePointer? {
        decoyCreateFn(cadence, nil) // built-in pool
    }
    func decoyDestroy(_ h: OpaquePointer) { decoyDestroyFn(h) }
    func decoyCompletedCount() -> Int { decoyCountFn() }

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
