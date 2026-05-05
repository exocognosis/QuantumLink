import Darwin
import Foundation

/// Bridge to the privileged `qlinkhelper` daemon. The helper opens a
/// `utun` device as root and ships the file descriptor back to the
/// unprivileged app over a Unix domain socket via `SCM_RIGHTS`. This
/// is the same architecture WireGuard's `wireguard-go` uses on macOS:
/// a small privileged sidecar that does the one privileged syscall
/// (open utun) and hands the resulting FD to the unprivileged app
/// for all subsequent I/O.
///
/// Why we need this on a Mac without an Apple Developer cert:
/// `NEPacketTunnelProvider` (Apple's blessed packet tunnel API)
/// requires the `com.apple.developer.networking.networkextension`
/// entitlement, which Apple grants only to Developer-ID-signed
/// bundles. By opening utun directly we sidestep that entirely —
/// the Mac kernel happily accepts a `connect()` on the
/// `com.apple.net.utun_control` kernel control socket from any
/// process running as root, no entitlement required.
///
/// ## Lifecycle
///
/// 1. `QuantumLinkHelper.shared.status()` reports whether the helper
///    is installed / running. Cheap; just stats a few paths.
/// 2. If not installed, `install()` runs an `osascript "do shell
///    script with administrator privileges"` one-shot that copies
///    the helper binary into `/usr/local/libexec`, drops the
///    `LaunchDaemon` plist into `/Library/LaunchDaemons`, and
///    `launchctl load`s it. One admin password prompt per machine,
///    forever.
/// 3. Once installed, the helper auto-starts at boot via launchd
///    and listens on `/var/run/quantumlink-helper.sock`.
/// 4. `connect()` opens the socket, sends `{"command":"open_tun"}`,
///    receives a status JSON line on stdout AND the utun FD as
///    SCM_RIGHTS ancillary data on the same `recvmsg`.
/// 5. Caller wraps the FD in `FileHandle` (or hands it to Rust via
///    `UtunDevice::from_fd`) and reads/writes raw IP packets.
///
/// ## When the helper is unavailable
///
/// Every method tagged `throws HelperError` surfaces the failure to
/// the caller; the GUI is responsible for falling back to SOCKS5
/// proxy mode (per-app, no system-level packet capture) or showing
/// the user "Real Tunneling Unavailable" with a one-button retry on
/// the Configuration → Network panel.
public final class QuantumLinkHelper: @unchecked Sendable {

    public static let shared = QuantumLinkHelper()

    /// Path conventions. Hardcoded because the LaunchDaemon plist
    /// has to reference an absolute path; we can't make these
    /// configurable without breaking the install flow.
    public enum Paths {
        public static let helperBinary = "/usr/local/libexec/qlinkhelper"
        public static let launchDaemonPlist = "/Library/LaunchDaemons/com.quantumlink.macos.Helper.plist"
        public static let socketPath = "/var/run/quantumlink-helper.sock"
        public static let labelIdentifier = "com.quantumlink.macos.Helper"
    }

    public enum Status: Equatable, Sendable {
        case notInstalled
        case installedNotRunning
        case running
    }

    public enum HelperError: Error, LocalizedError, Equatable {
        case bundledBinaryMissing
        case userCancelledInstall
        case installScriptFailed(String)
        case socketUnavailable
        case socketIO(String)
        case helperReportedError(String)
        case fdNotReceived

        public var errorDescription: String? {
            switch self {
            case .bundledBinaryMissing:
                return "QuantumLink.app was built without the qlinkhelper binary."
            case .userCancelledInstall:
                return "Installation cancelled. Real tunneling needs the helper to be authorized once."
            case .installScriptFailed(let detail):
                return "Helper install failed: \(detail)"
            case .socketUnavailable:
                return "The helper socket is not available. The helper may not be running."
            case .socketIO(let detail):
                return "Helper socket I/O failed: \(detail)"
            case .helperReportedError(let detail):
                return "Helper reported an error: \(detail)"
            case .fdNotReceived:
                return "Helper did not return a file descriptor."
            }
        }
    }

    public struct OpenTunResult: Sendable {
        public let fileDescriptor: Int32
        public let interfaceName: String
    }

    private init() {}

    // MARK: - Status

    public func status() -> Status {
        let fm = FileManager.default
        if !fm.fileExists(atPath: Paths.helperBinary) || !fm.fileExists(atPath: Paths.launchDaemonPlist) {
            return .notInstalled
        }
        if fm.fileExists(atPath: Paths.socketPath) {
            return .running
        }
        return .installedNotRunning
    }

    // MARK: - Install

    /// Runs the install flow synchronously on a background queue.
    /// Returns when the helper is loaded into launchd and the socket
    /// is reachable, or throws.
    public func install() throws {
        guard let bundledBinary = Bundle.main.url(forResource: "qlinkhelper", withExtension: nil) else {
            // Fallback search: the helper might be in Contents/MacOS
            // alongside the main executable depending on how it
            // was added to the bundle.
            let candidate = Bundle.main.bundleURL
                .appendingPathComponent("Contents/MacOS/qlinkhelper")
            if !FileManager.default.fileExists(atPath: candidate.path) {
                throw HelperError.bundledBinaryMissing
            }
            try installFromSource(candidate.path)
            return
        }
        try installFromSource(bundledBinary.path)
    }

    private func installFromSource(_ sourcePath: String) throws {
        let plist = launchDaemonPlist()
        let escapedPlist = plist.replacingOccurrences(of: "\"", with: "\\\"")

        // The shell command runs as a single line under
        // `osascript ... with administrator privileges`. macOS
        // shows one Touch ID / password prompt and then runs the
        // entire command as root. We chain everything with `&&`
        // so a partial failure aborts cleanly.
        let installScript = """
        mkdir -p /usr/local/libexec && \
        cp '\(sourcePath)' /usr/local/libexec/qlinkhelper && \
        chown root:wheel /usr/local/libexec/qlinkhelper && \
        chmod 755 /usr/local/libexec/qlinkhelper && \
        printf '%s' "\(escapedPlist)" > \(Paths.launchDaemonPlist) && \
        chown root:wheel \(Paths.launchDaemonPlist) && \
        chmod 644 \(Paths.launchDaemonPlist) && \
        launchctl unload \(Paths.launchDaemonPlist) 2>/dev/null; \
        launchctl load \(Paths.launchDaemonPlist)
        """

        let appleScript = """
        do shell script "\(installScript.replacingOccurrences(of: "\"", with: "\\\""))" with administrator privileges
        """

        var errorInfo: NSDictionary?
        guard let script = NSAppleScript(source: appleScript) else {
            throw HelperError.installScriptFailed("could not parse osascript")
        }
        let result = script.executeAndReturnError(&errorInfo)
        if let errorInfo {
            // Code -128 is "user cancelled" — treat distinctly.
            if let code = errorInfo[NSAppleScript.errorNumber] as? Int, code == -128 {
                throw HelperError.userCancelledInstall
            }
            let msg = errorInfo[NSAppleScript.errorMessage] as? String ?? "unknown osascript error"
            throw HelperError.installScriptFailed(msg)
        }
        _ = result // We don't need stdout — exit-code-only via error dict.

        // Wait briefly for launchd to bring the helper up. The
        // socket appears within a few hundred ms in practice.
        let deadline = Date().addingTimeInterval(5.0)
        while Date() < deadline {
            if FileManager.default.fileExists(atPath: Paths.socketPath) {
                return
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
        // Helper got installed but socket never appeared — likely a
        // launchd permissions issue worth surfacing to the user.
        throw HelperError.installScriptFailed(
            "helper installed but socket did not appear at \(Paths.socketPath)"
        )
    }

    /// LaunchDaemon plist body. Written verbatim to disk by the
    /// install script. KeepAlive=true so the helper auto-restarts
    /// on any crash; standard error to /var/log for postmortem.
    private func launchDaemonPlist() -> String {
        return """
        <?xml version=\"1.0\" encoding=\"UTF-8\"?>
        <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
        <plist version=\"1.0\">
        <dict>
            <key>Label</key>
            <string>\(Paths.labelIdentifier)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(Paths.helperBinary)</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
            <key>StandardErrorPath</key>
            <string>/var/log/quantumlink-helper.log</string>
            <key>StandardOutPath</key>
            <string>/var/log/quantumlink-helper.log</string>
        </dict>
        </plist>
        """
    }

    // MARK: - IPC

    /// Connect to the helper, request a fresh utun device, and
    /// return the file descriptor + interface name. The FD is
    /// owned by the caller after this returns; close it when
    /// done with the tunnel.
    public func openTun() throws -> OpenTunResult {
        let fd = try connectToHelperSocket()
        defer { Darwin.close(fd) }

        // Send request line.
        let request = "{\"command\":\"open_tun\"}\n"
        try sendAll(fd: fd, data: Array(request.utf8))

        // Receive response (one cmsghdr with the FD + a JSON status
        // line on the data stream).
        return try recvFD(fd: fd)
    }

    private func connectToHelperSocket() throws -> Int32 {
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        if s < 0 {
            throw HelperError.socketUnavailable
        }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        // Copy socket path bytes into sun_path. sockaddr_un's
        // sun_path is 104 bytes on macOS.
        let pathBytes = Array(Paths.socketPath.utf8)
        let maxPath = MemoryLayout.size(ofValue: addr.sun_path)
        if pathBytes.count >= maxPath {
            Darwin.close(s)
            throw HelperError.socketUnavailable
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { rawPtr in
            for (i, byte) in pathBytes.enumerated() {
                rawPtr[i] = byte
            }
            rawPtr[pathBytes.count] = 0
        }
        let result: Int32 = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(s, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if result < 0 {
            Darwin.close(s)
            throw HelperError.socketUnavailable
        }
        return s
    }

    private func sendAll(fd: Int32, data: [UInt8]) throws {
        var sent = 0
        while sent < data.count {
            let n = data.withUnsafeBufferPointer { buf in
                Darwin.send(fd, buf.baseAddress!.advanced(by: sent), data.count - sent, 0)
            }
            if n < 0 {
                throw HelperError.socketIO(String(cString: strerror(errno)))
            }
            if n == 0 {
                throw HelperError.socketIO("write returned 0 (peer closed)")
            }
            sent += n
        }
    }

    /// Receive a single FD via SCM_RIGHTS along with up to 1 KiB of
    /// inline data containing the helper's status JSON.
    private func recvFD(fd: Int32) throws -> OpenTunResult {
        // Inline data buffer.
        var dataBuf = [UInt8](repeating: 0, count: 1024)
        // Control-message buffer sized for one i32 FD.
        let cmsgSpace = Int(CMSG_SPACE(socklen_t(MemoryLayout<Int32>.size)))
        var cmsgBuf = [UInt8](repeating: 0, count: cmsgSpace)

        var iov = iovec()
        var msg = msghdr()

        let received: ssize_t = dataBuf.withUnsafeMutableBufferPointer { dataPtr in
            cmsgBuf.withUnsafeMutableBufferPointer { cmsgPtr in
                iov.iov_base = UnsafeMutableRawPointer(dataPtr.baseAddress)
                iov.iov_len = dataPtr.count
                return withUnsafeMutablePointer(to: &iov) { iovPtr in
                    msg.msg_iov = iovPtr
                    msg.msg_iovlen = 1
                    msg.msg_control = UnsafeMutableRawPointer(cmsgPtr.baseAddress)
                    msg.msg_controllen = socklen_t(cmsgPtr.count)
                    return Darwin.recvmsg(fd, &msg, 0)
                }
            }
        }

        if received < 0 {
            throw HelperError.socketIO(String(cString: strerror(errno)))
        }

        // Parse the inline status JSON.
        let statusJSON = String(decoding: dataBuf.prefix(Int(received)), as: UTF8.self)
        let trimmed = statusJSON.trimmingCharacters(in: .whitespacesAndNewlines)

        // Cheap parse: we only need to detect error and pull the
        // interface name on success. Full JSON parsing is overkill.
        if trimmed.contains("\"status\":\"error\"") || trimmed.contains("\"status\": \"error\"") {
            let msg = extractField(trimmed, key: "message") ?? "unknown helper error"
            throw HelperError.helperReportedError(msg)
        }

        // Extract the FD from the cmsghdr.
        let extractedFD: Int32 = try cmsgBuf.withUnsafeBufferPointer { cmsgPtr -> Int32 in
            let storedMsg = msg
            return try withUnsafePointer(to: storedMsg) { msgPtr -> Int32 in
                guard let cmsg = QLINK_CMSG_FIRSTHDR(UnsafeMutablePointer(mutating: msgPtr)) else {
                    throw HelperError.fdNotReceived
                }
                guard cmsg.pointee.cmsg_level == SOL_SOCKET,
                      cmsg.pointee.cmsg_type == SCM_RIGHTS else {
                    throw HelperError.fdNotReceived
                }
                let dataPtr = QLINK_CMSG_DATA(cmsg).assumingMemoryBound(to: Int32.self)
                _ = cmsgPtr // keep the buffer alive for the duration of the read above
                return dataPtr.pointee
            }
        }

        let name = extractField(trimmed, key: "name") ?? "utun?"
        return OpenTunResult(fileDescriptor: extractedFD, interfaceName: name)
    }

    /// Quick-and-dirty JSON field extractor for `"key":"value"`.
    /// Avoids dragging JSONDecoder + a Codable struct into the
    /// helper IPC path; the protocol is fixed and small.
    private func extractField(_ json: String, key: String) -> String? {
        let needle = "\"\(key)\":"
        guard let keyRange = json.range(of: needle) else { return nil }
        var i = keyRange.upperBound
        // Skip whitespace after the colon.
        while i < json.endIndex, json[i].isWhitespace { i = json.index(after: i) }
        guard i < json.endIndex, json[i] == "\"" else { return nil }
        i = json.index(after: i)
        var out = ""
        while i < json.endIndex, json[i] != "\"" {
            out.append(json[i])
            i = json.index(after: i)
        }
        return out
    }
}

// MARK: - CMSG helpers

/// Swift can't call the `CMSG_FIRSTHDR` and `CMSG_DATA` macros
/// directly because they're C macros, not functions; libc's Swift
/// bindings don't expose them as `@_silgen_name` either. We
/// reimplement the alignment math here. Both macros are stable
/// kernel APIs — the formulas come from `<sys/socket.h>` on
/// Darwin.
private func QLINK_ALIGN(_ value: Int) -> Int {
    let alignment = MemoryLayout<UInt32>.alignment
    return (value + alignment - 1) & ~(alignment - 1)
}

private func QLINK_CMSG_FIRSTHDR(_ msg: UnsafeMutablePointer<msghdr>) -> UnsafeMutablePointer<cmsghdr>? {
    let m = msg.pointee
    if Int(m.msg_controllen) < MemoryLayout<cmsghdr>.size {
        return nil
    }
    return m.msg_control?.assumingMemoryBound(to: cmsghdr.self)
}

private func QLINK_CMSG_DATA(_ cmsg: UnsafeMutablePointer<cmsghdr>) -> UnsafeMutableRawPointer {
    return UnsafeMutableRawPointer(cmsg).advanced(by: QLINK_ALIGN(MemoryLayout<cmsghdr>.size))
}

private func CMSG_SPACE(_ length: socklen_t) -> Int {
    return QLINK_ALIGN(Int(length)) + QLINK_ALIGN(MemoryLayout<cmsghdr>.size)
}
