import Foundation
import XCTest
@testable import QuantumLinkKit

/// Lightweight performance tests for the live mesh transport. Gated on
/// `QLINK_CORE_DYLIB` because they exercise the real Rust runtime + tokio
/// scheduler. Each `measure` block reports its own clock metric; the perf
/// CI captures these via `xcresult`.
///
/// These tests deliberately don't assert hard SLOs — the Rust scenario
/// benches do that, and Apple Silicon CI runners are noisier than what we
/// want for tight assertions. Numbers here exist to surface regressions
/// when paired with the baseline doc.
final class RustMeshTransportPerformanceTests: XCTestCase {
    func testStartToFailedTransitionWhenRendezvousIsUnreachable() throws {
        guard
            let path = ProcessInfo.processInfo.environment["QLINK_CORE_DYLIB"],
            FileManager.default.fileExists(atPath: path)
        else {
            throw XCTSkip("Set QLINK_CORE_DYLIB to libqlink_core.dylib to run mesh transport perf tests.")
        }
        let library = try RustCoreLibrary(path: path)

        // Time how long it takes to surface a clear failure when no
        // rendezvous is reachable. Acts as a perf canary on the FFI handle
        // construction + the manager task's first connect attempt.
        measure(metrics: [XCTClockMetric()], block: {
            let configuration = MeshTransportConfiguration(
                meshID: "perf-test-mesh",
                localPeerID: "perf-local",
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
            do {
                try transport.start()
                let deadline = Date().addingTimeInterval(2.0)
                while transport.metrics.state != .failed && Date() < deadline {
                    Thread.sleep(forTimeInterval: 0.02)
                    _ = try? transport.receiveTransportFrame()
                }
            } catch {
                // Synchronous failure path — also acceptable.
            }
            transport.stop()
        })
    }

    func testRustMeshTransportFFISymbolsLoadWithinReasonableTime() throws {
        guard
            let path = ProcessInfo.processInfo.environment["QLINK_CORE_DYLIB"],
            FileManager.default.fileExists(atPath: path)
        else {
            throw XCTSkip("Set QLINK_CORE_DYLIB to libqlink_core.dylib to run mesh transport perf tests.")
        }

        // Library opening is dlopen + 23 dlsym calls. This block measures
        // the overhead so a future symbol explosion doesn't go unnoticed.
        measure(metrics: [XCTClockMetric()], block: {
            do {
                _ = try RustCoreLibrary(path: path)
            } catch {
                XCTFail("RustCoreLibrary failed to load: \(error)")
            }
        })
    }
}
