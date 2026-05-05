import Foundation

/// Persisted user controls for the QuantumLink anonymity stack.
///
/// Each enum here mirrors a corresponding Rust-side enum in the
/// `qlink-core` crate (`pluggable_transport::TransportObfuscation`,
/// `cover_traffic::CoverTrafficLevel`, `decoy::DecoyCadence`,
/// `decoy::RotationPolicy`). Keeping the names + raw values aligned
/// means the FFI bridge can pass them across with `String` raw
/// values (no separate marshaling layer needed).
///
/// All settings live in `UserDefaults` under
/// `com.quantumlink.macos.privacy.*` keys so they survive app
/// restarts. The defaults below are deliberately conservative —
/// nothing is forced on the user, but the recommended defaults
/// turn on the layers that cost almost nothing (SOCKS5 listener
/// on/standby, DNS-over-QL, identity rotation policy = weekly).
public struct PrivacySettings: Codable, Equatable, Sendable {

    // MARK: - Pluggable transport obfuscation

    public enum TransportObfuscation: String, CaseIterable, Codable, Sendable {
        case none
        case tlsLikeFraming
        case obfs4XorScramble

        public var displayName: String {
            switch self {
            case .none: return "None"
            case .tlsLikeFraming: return "TLS-Disguised"
            case .obfs4XorScramble: return "Scrambled (obfs4-style)"
            }
        }

        public var summary: String {
            switch self {
            case .none:
                return "No wire obfuscation. Use only on trusted networks."
            case .tlsLikeFraming:
                return "Wraps traffic in TLS 1.2 record framing so DPI sees what looks like HTTPS."
            case .obfs4XorScramble:
                return "Scrambles bytes against a per-session keystream so traffic looks like uniformly random data — defeats fingerprinting in censored regions."
            }
        }
    }

    // MARK: - Cover traffic

    public enum CoverTrafficLevel: String, CaseIterable, Codable, Sendable {
        case off
        case low
        case medium
        case high

        public var displayName: String {
            switch self {
            case .off: return "Off"
            case .low: return "Low (10 KB/s)"
            case .medium: return "Medium (100 KB/s)"
            case .high: return "High (1 MB/s)"
            }
        }

        public var summary: String {
            switch self {
            case .off:
                return "No cover traffic. Smallest bandwidth footprint, observable activity patterns."
            case .low:
                return "~3 GB/month. Defeats coarse activity inference."
            case .medium:
                return "~30 GB/month. Defeats most volume inference."
            case .high:
                return "~300 GB/month. Defeats correlation attacks across most network observers."
            }
        }
    }

    // MARK: - Decoy cadence

    public enum DecoyCadence: String, CaseIterable, Codable, Sendable {
        case off
        case light
        case steady
        case aggressive

        public var displayName: String {
            switch self {
            case .off: return "Off"
            case .light: return "Light (every 1–6 hours)"
            case .steady: return "Steady (every 5–30 min)"
            case .aggressive: return "Aggressive (every 30–120 sec)"
            }
        }

        public var summary: String {
            switch self {
            case .off:
                return "No decoy traffic. Your actual destinations are the only signal."
            case .light:
                return "Periodic fetches to popular sites. Light interest-profiling defense."
            case .steady:
                return "Recommended for active surveillance environments. Balanced bandwidth + protection."
            case .aggressive:
                return "Heavy decoy traffic — defeats fine-grained timing analysis."
            }
        }
    }

    // MARK: - Identity rotation

    public enum RotationPolicy: String, CaseIterable, Codable, Sendable {
        case manual
        case weekly
        case daily

        public var displayName: String {
            switch self {
            case .manual: return "Manual"
            case .weekly: return "Weekly"
            case .daily: return "Daily"
            }
        }

        public var summary: String {
            switch self {
            case .manual:
                return "Keys rotate only when you trigger it. Maximum stability — same fingerprint until you say otherwise."
            case .weekly:
                return "Recommended default. New fingerprint every 7 days; severs long-window cross-session linkability."
            case .daily:
                return "For users in adversarial environments. Daily rotation; peers must re-verify the new fingerprint each day."
            }
        }
    }

    // MARK: - Real fields

    public var transportObfuscation: TransportObfuscation
    public var coverTrafficLevel: CoverTrafficLevel
    public var decoyCadence: DecoyCadence
    public var rotationPolicy: RotationPolicy

    /// SOCKS5 proxy listener on `127.0.0.1:1080`. Cheap to leave on:
    /// it just binds a loopback port and routes per-app traffic
    /// through the active mesh transport when the user configures
    /// their browser/SSH to use it.
    public var enableSocks5Proxy: Bool

    /// DNS-over-QuantumLink stub resolver. Leaving this on closes
    /// the single biggest privacy leak in consumer VPNs (DNS
    /// queries going to the local resolver in plaintext). The
    /// only reason to leave it off is for split-DNS managed
    /// deployments where the operator pinned a specific resolver.
    public var enableDnsOverQuantumLink: Bool

    /// Multi-hop onion routing. Adds 2x-3x latency but defeats
    /// "single-peer-knows-everything" linkage. Off by default
    /// because most users prefer the latency.
    public var enableOnionRouting: Bool

    public var onionCircuitLength: Int

    // MARK: - Defaults

    public static let defaults = PrivacySettings(
        transportObfuscation: .tlsLikeFraming,
        coverTrafficLevel: .off,
        decoyCadence: .off,
        rotationPolicy: .weekly,
        enableSocks5Proxy: true,
        enableDnsOverQuantumLink: true,
        enableOnionRouting: false,
        onionCircuitLength: 3
    )

    // MARK: - Persistence

    public static let userDefaultsKey = "com.quantumlink.macos.privacy.settings.v1"

    public static func load(from defaults: UserDefaults = .standard) -> PrivacySettings {
        guard let data = defaults.data(forKey: Self.userDefaultsKey) else {
            return Self.defaults
        }
        // If decode fails (schema migration etc.), fall back to
        // defaults rather than crashing. This keeps the GUI
        // resilient across version upgrades.
        return (try? JSONDecoder().decode(PrivacySettings.self, from: data)) ?? Self.defaults
    }

    public func save(to defaults: UserDefaults = .standard) {
        if let data = try? JSONEncoder().encode(self) {
            defaults.set(data, forKey: Self.userDefaultsKey)
        }
    }
}
