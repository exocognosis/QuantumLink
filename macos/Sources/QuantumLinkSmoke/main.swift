import Darwin
import Foundation
import QuantumLinkKit

enum QuantumLinkSmoke {
    static func main() -> Int32 {
        let arguments = Array(CommandLine.arguments.dropFirst())
        let command = arguments.first ?? "validate-config"

        switch command {
        case "transport-loopback":
            return runTransportLoopback(arguments: Array(arguments.dropFirst()))
        case "validate-config":
            return runValidateConfig(arguments: Array(arguments.dropFirst()))
        case "preflight":
            return runPreflight(arguments: Array(arguments.dropFirst()))
        case "help", "--help", "-h":
            printUsage()
            return 0
        default:
            fputs("Unknown command: \(command)\n", stderr)
            printUsage()
            return 2
        }
    }

    private static func runValidateConfig(arguments: [String]) -> Int32 {
        do {
            let options = try ConfigOptions(arguments: arguments)
            let report = try ConfigurationValidator.loadAndValidate(url: options.configURL)
            print("config_path=\(options.configURL.path)")
            print("mesh_id=\(report.configuration.meshID)")
            print("device_alias=\(report.configuration.deviceAlias)")
            print("overlay_ipv4=\(report.configuration.overlayIPv4Address)")
            print("route_mode=\(report.configuration.routeMode.rawValue)")
            print("dns_mode=\(report.configuration.dnsMode.rawValue)")
            print("protected_route_count=\(report.configuration.protectedRoutes.count)")
            print("rendezvous_count=\(report.configuration.rendezvousServers.count)")
            print("relay_count=\(report.configuration.relayServers.count)")
            print("warning_count=\(report.warnings.count)")
            for warning in report.warnings {
                print("warning=\(warning)")
            }
            print("config_valid=true")
            return 0
        } catch {
            fputs("validate-config failed: \(error.localizedDescription)\n", stderr)
            return 1
        }
    }

    private static func runPreflight(arguments: [String]) -> Int32 {
        do {
            let options = try PreflightOptions(arguments: arguments)
            let configReport = try ConfigurationValidator.loadAndValidate(url: options.configURL)
            print("preflight_config_valid=true")
            print("preflight_mesh_id=\(configReport.configuration.meshID)")

            if options.runTransport {
                let transport: TransportSmokeResult
                do {
                    transport = try TransportSmokeRunner.run(
                        configuration: configReport.configuration,
                        mode: options.mode,
                        libraryPath: options.dylibPath
                    )
                } catch {
                    if options.mode == .devQuicLoopback,
                       TransportSmokeRunner.isExpectedDisabledDevQuicLoopback(error) {
                        print("preflight_transport_kind=\(TunnelTransportKind.devQuicLoopback.rawValue)")
                        print("preflight_transport_state=\(TunnelTransportState.failed.rawValue)")
                        print("preflight_transport_path=\(PathType.unavailable.rawValue)")
                        print("preflight_packet_round_trip=false")
                        print("preflight_smoke_outcome=fail-closed")
                        return 1
                    }
                    throw error
                }
                print("preflight_transport_kind=\(transport.transportMetrics.kind.rawValue)")
                print("preflight_transport_state=\(transport.transportMetrics.state.rawValue)")
                print("preflight_transport_path=\(transport.transportMetrics.pathType.rawValue)")
                print("preflight_smoke_outcome=\(transport.transportMetrics.smokeOutcome)")
                print("preflight_packet_round_trip=\(transport.packetRoundTrip)")
                return transport.packetRoundTrip ? 0 : 1
            }

            print("preflight_transport_skipped=true")
            return 0
        } catch {
            fputs("preflight failed: \(error.localizedDescription)\n", stderr)
            return 1
        }
    }

    private static func runTransportLoopback(arguments: [String]) -> Int32 {
        do {
            let options = try TransportLoopbackOptions(arguments: arguments)
            let result = try TransportSmokeRunner.run(
                mode: options.mode,
                libraryPath: options.dylibPath
            )

            print("transport_kind=\(result.transportMetrics.kind.rawValue)")
            print("transport_state=\(result.transportMetrics.state.rawValue)")
            print("transport_path=\(result.transportMetrics.pathType.rawValue)")
            print("transport_smoke_outcome=\(result.transportMetrics.smokeOutcome)")
            print("frames_sent=\(result.transportMetrics.framesSent)")
            print("frames_received=\(result.transportMetrics.framesReceived)")
            print("frames_dropped=\(result.transportMetrics.framesDropped)")
            print("bytes_sent=\(result.transportMetrics.bytesSent)")
            print("bytes_received=\(result.transportMetrics.bytesReceived)")
            print("core_frames_out=\(result.coreMetrics.transportFramesOut)")
            print("core_frames_in=\(result.coreMetrics.transportFramesIn)")
            print("packet_bytes=\(result.packetBytes)")
            print("protocol_family=\(result.protocolFamily.map(String.init) ?? "none")")
            print("packet_round_trip=\(result.packetRoundTrip)")
            return result.packetRoundTrip ? 0 : 1
        } catch {
            fputs("transport-loopback failed: \(error.localizedDescription)\n", stderr)
            return 1
        }
    }

    static func printUsage() {
        print(
            """
            Usage:
              swift run QuantumLinkSmoke validate-config --config ../config/mesh.example.json
              swift run QuantumLinkSmoke preflight --config ../config/mesh.example.json

            Fail-closed transport checks:
              swift run QuantumLinkSmoke transport-loopback --mode dev-quic-loopback --dylib /path/to/libqlink_core.dylib
              swift run QuantumLinkSmoke preflight --config ../config/mesh.example.json --transport --mode dev-quic-loopback --dylib /path/to/libqlink_core.dylib

            Options:
              --mode development-drop|dev-quic-loopback (strict PQC fail-closed only)
              --dylib /path/to/libqlink_core.dylib
              --config /path/to/mesh.json
              --transport
            """
        )
    }
}

struct ConfigOptions {
    let configURL: URL

    init(arguments: [String]) throws {
        var configPath = defaultMeshConfigPath()
        var index = 0

        while index < arguments.count {
            switch arguments[index] {
            case "--config":
                index += 1
                guard index < arguments.count else {
                    throw SmokeArgumentError("Expected --config /path/to/mesh.json")
                }
                configPath = arguments[index]
            case "--help", "-h":
                QuantumLinkSmoke.printUsage()
                Darwin.exit(0)
            default:
                throw SmokeArgumentError("Unknown option: \(arguments[index])")
            }
            index += 1
        }

        self.configURL = URL(fileURLWithPath: configPath)
    }
}

struct PreflightOptions {
    let configURL: URL
    let runTransport: Bool
    let mode: TransportSmokeMode
    let dylibPath: String?

    init(arguments: [String]) throws {
        var configPath = defaultMeshConfigPath()
        var runTransport = false
        var mode = TransportSmokeMode()
        var dylibPath = ProcessInfo.processInfo.environment["QLINK_CORE_DYLIB"]
        var index = 0

        while index < arguments.count {
            switch arguments[index] {
            case "--config":
                index += 1
                guard index < arguments.count else {
                    throw SmokeArgumentError("Expected --config /path/to/mesh.json")
                }
                configPath = arguments[index]
            case "--transport":
                runTransport = true
            case "--mode":
                index += 1
                guard index < arguments.count, let parsed = TransportSmokeMode(rawValue: arguments[index]) else {
                    throw SmokeArgumentError("Expected --mode development-drop|dev-quic-loopback (strict PQC fail-closed only)")
                }
                mode = parsed
            case "--dylib":
                index += 1
                guard index < arguments.count else {
                    throw SmokeArgumentError("Expected --dylib /path/to/libqlink_core.dylib")
                }
                dylibPath = arguments[index]
            case "--help", "-h":
                QuantumLinkSmoke.printUsage()
                Darwin.exit(0)
            default:
                throw SmokeArgumentError("Unknown option: \(arguments[index])")
            }
            index += 1
        }

        self.configURL = URL(fileURLWithPath: configPath)
        self.runTransport = runTransport
        self.mode = mode
        self.dylibPath = dylibPath
    }
}

struct TransportLoopbackOptions {
    let mode: TransportSmokeMode
    let dylibPath: String?

    init(arguments: [String]) throws {
        var mode = TransportSmokeMode()
        var dylibPath = ProcessInfo.processInfo.environment["QLINK_CORE_DYLIB"]
        var index = 0

        while index < arguments.count {
            switch arguments[index] {
            case "--mode":
                index += 1
                guard index < arguments.count, let parsed = TransportSmokeMode(rawValue: arguments[index]) else {
                    throw SmokeArgumentError("Expected --mode development-drop|dev-quic-loopback (strict PQC fail-closed only)")
                }
                mode = parsed
            case "--dylib":
                index += 1
                guard index < arguments.count else {
                    throw SmokeArgumentError("Expected --dylib /path/to/libqlink_core.dylib")
                }
                dylibPath = arguments[index]
            case "--help", "-h":
                QuantumLinkSmoke.printUsage()
                Darwin.exit(0)
            default:
                throw SmokeArgumentError("Unknown option: \(arguments[index])")
            }
            index += 1
        }

        self.mode = mode
        self.dylibPath = dylibPath
    }
}

private func defaultMeshConfigPath() -> String {
    let localPath = "config/mesh.example.json"
    if FileManager.default.fileExists(atPath: localPath) {
        return localPath
    }
    return "../config/mesh.example.json"
}

struct SmokeArgumentError: LocalizedError {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var errorDescription: String? {
        message
    }
}

Darwin.exit(QuantumLinkSmoke.main())
