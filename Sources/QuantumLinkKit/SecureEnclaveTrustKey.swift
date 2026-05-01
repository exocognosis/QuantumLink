import Foundation
import CryptoKit
import Security

public enum SecureEnclaveTrustError: Error, LocalizedError, Equatable {
    case secureEnclaveUnavailable
    case keychainStatus(OSStatus)
    case malformedStoredKey

    public var errorDescription: String? {
        switch self {
        case .secureEnclaveUnavailable:
            "This device does not expose a Secure Enclave"
        case .keychainStatus(let status):
            "Keychain operation failed with status \(status)"
        case .malformedStoredKey:
            "Stored Secure Enclave key blob could not be reconstructed"
        }
    }
}

/// Hardware-bound device trust key backed by the Secure Enclave on supported Macs.
///
/// The private key never leaves the SE. We keep only the SE-wrapped data
/// representation in the Data Protection keychain and reconstitute the
/// `SecureEnclave.P256.Signing.PrivateKey` on demand for signing operations.
///
/// This complements the mesh's ML-DSA device credential (which protects
/// peer-to-peer traffic at the protocol layer): the SE-backed key is a local
/// platform anchor — used for unlock gating, admin attestation challenges, and
/// proof that key material has not been exfiltrated from this Mac.
public final class SecureEnclaveTrustKey {
    private let store: KeychainSecretStore
    private let account: String

    public init(
        store: KeychainSecretStore = KeychainSecretStore(service: "com.quantumlink.macos.secure-enclave"),
        account: String = "device-trust-key"
    ) {
        self.store = store
        self.account = account
    }

    public static var isAvailable: Bool {
        SecureEnclave.isAvailable
    }

    /// Loads the device's persisted Secure-Enclave key. Returns `nil` if no key
    /// has been provisioned on this device yet.
    public func load() throws -> SecureEnclave.P256.Signing.PrivateKey? {
        guard Self.isAvailable else {
            throw SecureEnclaveTrustError.secureEnclaveUnavailable
        }
        guard let data = try store.load(account: account) else {
            return nil
        }
        do {
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
        } catch {
            throw SecureEnclaveTrustError.malformedStoredKey
        }
    }

    /// Generates a new Secure-Enclave-backed signing key, persists its wrapped
    /// representation in the Data Protection keychain, and returns it.
    @discardableResult
    public func generateAndPersist() throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard Self.isAvailable else {
            throw SecureEnclaveTrustError.secureEnclaveUnavailable
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        try store.store(key.dataRepresentation, account: account)
        return key
    }

    /// Returns the key's persistent public key. Suitable for publishing as the
    /// platform-trust component of a device record or attestation envelope.
    public func currentPublicKey() throws -> P256.Signing.PublicKey? {
        try load()?.publicKey
    }

    /// Signs an arbitrary challenge using the SE key. Used by admin enrollment
    /// flows that need to prove a device retains the same hardware-bound trust
    /// anchor as previously enrolled.
    public func sign(challenge: Data) throws -> Data? {
        guard let key = try load() else {
            return nil
        }
        let signature = try key.signature(for: challenge)
        return signature.derRepresentation
    }

    public func wipe() throws {
        try store.delete(account: account)
    }
}
