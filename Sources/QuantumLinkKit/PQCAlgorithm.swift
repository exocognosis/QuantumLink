import Foundation

public enum PQCAlgorithm: String, Codable, CaseIterable, Hashable, Identifiable, Sendable {
    case fips203
    case fips204
    case fips205

    public var id: Self { self }

    public var standardName: String {
        switch self {
        case .fips203:
            "FIPS 203"
        case .fips204:
            "FIPS 204"
        case .fips205:
            "FIPS 205"
        }
    }

    public var algorithmName: String {
        switch self {
        case .fips203:
            "ML-KEM"
        case .fips204:
            "ML-DSA"
        case .fips205:
            "SLH-DSA"
        }
    }

    public var suiteIdentifier: String {
        switch self {
        case .fips203:
            "QLINK-FIPS203-MLKEM768-SHAKE256-v1"
        case .fips204:
            "QLINK-FIPS204-MLDSA65-SHAKE256-v1"
        case .fips205:
            "QLINK-FIPS205-SLHDSA-SHAKE128S-SHAKE256-v1"
        }
    }

    public init?(suiteIdentifier: String) {
        if let algorithm = Self.allCases.first(where: { $0.suiteIdentifier == suiteIdentifier }) {
            self = algorithm
        } else {
            return nil
        }
    }
}
