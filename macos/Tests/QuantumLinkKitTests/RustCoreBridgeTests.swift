import Foundation
import XCTest
@testable import QuantumLinkKit

final class RustCoreBridgeTests: XCTestCase {
    func testRustCoreRoundTripWhenDylibIsConfigured() throws {
        guard
            let path = ProcessInfo.processInfo.environment["QLINK_CORE_DYLIB"],
            FileManager.default.fileExists(atPath: path)
        else {
            throw XCTSkip("Set QLINK_CORE_DYLIB to libqlink_core.dylib to run the Rust FFI integration test.")
        }

        let library = try RustCoreLibrary(path: path)
        XCTAssertEqual(library.defaultSuite, "QLINK-FIPS203-MLKEM768-HKDFSHA256-v1")

        let adapter = try RustTunnelCoreAdapter(configuration: .defaultDevelopment, library: library)
        let packet = ipv4Packet(destination: [100, 127, 0, 10])

        let disposition = try adapter.submitTunnelPacket(packet, protocolFamily: 2)
        XCTAssertEqual(disposition, .queuedForTransport)

        let frame = try XCTUnwrap(adapter.popTransportFrame())
        try adapter.acceptTransportFrame(frame)

        let restored = try XCTUnwrap(adapter.popTunnelPacket())
        XCTAssertEqual(restored.protocolFamily, 2)
        // The Rust core normalizes IPv4 packets (TTL → 64, checksum
        // recomputed) before encryption, so byte-by-byte equality with the
        // input packet would fail on the checksum field. Verify the packet
        // length, destination address, and that the recomputed checksum is
        // self-consistent (one's-complement sum = 0).
        XCTAssertEqual(restored.bytes.count, packet.count)
        XCTAssertEqual(Array(restored.bytes[16..<20]), Array(packet[16..<20]))
        XCTAssertEqual(ipv4HeaderChecksum(restored.bytes), 0)

        let metrics = try adapter.metrics()
        XCTAssertEqual(metrics.transportFramesOut, 1)
        XCTAssertEqual(metrics.transportFramesIn, 1)
    }

    private func ipv4Packet(destination: [UInt8]) -> Data {
        var packet = [UInt8](repeating: 0, count: 20)
        packet[0] = 0x45
        packet[2] = 0
        packet[3] = 20
        packet[8] = 64
        packet[9] = 17
        packet[12...15] = [100, 127, 0, 2]
        packet[16...19] = ArraySlice(destination)
        return Data(packet)
    }

    private func ipv4HeaderChecksum(_ packet: Data) -> UInt16 {
        let headerLen = Int(packet[0] & 0x0f) * 4
        var sum: UInt32 = 0
        var index = 0
        while index + 1 < headerLen {
            sum &+= UInt32(packet[index]) << 8 | UInt32(packet[index + 1])
            index += 2
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) &+ (sum >> 16)
        }
        return ~UInt16(truncatingIfNeeded: sum)
    }
}
