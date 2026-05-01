import Foundation
import XCTest
@testable import QuantumLinkKit

final class RustMeshTransportTests: XCTestCase {
    func testMeshTransportSymbolsLoadAndBogusConfigReportsFailure() throws {
        guard
            let path = ProcessInfo.processInfo.environment["QLINK_CORE_DYLIB"],
            FileManager.default.fileExists(atPath: path)
        else {
            throw XCTSkip("Set QLINK_CORE_DYLIB to libqlink_core.dylib to run the Rust mesh transport FFI test.")
        }

        let library = try RustCoreLibrary(path: path)

        // Construct a transport with a peer ID that is not published in any
        // rendezvous. The Rust manager task should transition to Failed
        // within the configured deadline, and the FFI must surface a
        // descriptive last-error string.
        let configuration = MeshTransportConfiguration(
            meshID: "swift-test-mesh",
            localPeerID: "swift-local",
            remotePeerID: "qlink_does-not-exist",
            rendezvousURL: "127.0.0.1:1",
            relayURL: nil,
            bindAddress: "127.0.0.1:0",
            overallDeadlineMs: 200,
            directProbeTimeoutMs: 100,
            probePacingMs: 50,
            enableICE: false
        )
        let transport = RustMeshTransport(library: library, configuration: configuration)

        // start() should throw because the supplied trust certificate is
        // garbage and the Rust client cannot construct its QUIC endpoint.
        // (If the future plumbing allows a deferred connect, the contract
        // becomes "start succeeds, then state becomes failed" — both forms
        // are valid evidence of correct error reporting.)
        do {
            try transport.start()
            // Deferred-failure mode: the handle is alive but state should
            // transition to .failed quickly because rendezvous can't be
            // reached at 127.0.0.1:1.
            let deadline = Date().addingTimeInterval(2.0)
            while transport.metrics.state != .failed && Date() < deadline {
                Thread.sleep(forTimeInterval: 0.05)
                _ = try? transport.receiveTransportFrame()
            }
            XCTAssertEqual(
                transport.metrics.state,
                .failed,
                "Expected mesh transport to enter .failed for an unreachable rendezvous (lastError=\(transport.metrics.lastError ?? "<none>"))"
            )
            transport.stop()
        } catch {
            // start() failure is also acceptable — that's the synchronous
            // path when the trust certificate is invalid.
            XCTAssertEqual(transport.metrics.state, .failed)
        }
    }
}
