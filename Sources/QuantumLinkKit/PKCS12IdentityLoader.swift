import Foundation
import Security

/// Loads a `SecIdentity` (cert + matching private key) from a PKCS#12
/// file on disk. Used by the MDM CLI to bring in an Apple Developer ID /
/// MDM-signing identity, and reused in tests to load a self-signed
/// throwaway identity.
public enum PKCS12IdentityLoader {
    public enum Error: Swift.Error, LocalizedError {
        case fileNotReadable(URL, underlying: Swift.Error)
        case importFailed(OSStatus)
        case noIdentityInArchive

        public var errorDescription: String? {
            switch self {
            case .fileNotReadable(let url, let error):
                "PKCS#12 file at \(url.path) is not readable: \(error.localizedDescription)"
            case .importFailed(let status):
                "SecPKCS12Import failed (\(status)). On modern macOS this is "
                + "usually a passphrase mismatch or an unsupported PBE algorithm; "
                + "regenerate the .p12 with `-keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg SHA1`."
            case .noIdentityInArchive:
                "PKCS#12 archive parsed successfully but contained no identity"
            }
        }
    }

    /// Imports `url` as PKCS#12 using `passphrase` and returns the first
    /// identity it finds. Multi-identity archives are unusual for
    /// configuration-profile signing — if you have one, pre-split it.
    public static func loadIdentity(
        from url: URL,
        passphrase: String
    ) throws -> SecIdentity {
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw Error.fileNotReadable(url, underlying: error)
        }

        var importedItems: CFArray?
        let options: [String: Any] = [
            kSecImportExportPassphrase as String: passphrase,
        ]
        let status = SecPKCS12Import(
            data as CFData,
            options as CFDictionary,
            &importedItems
        )
        guard status == errSecSuccess else {
            throw Error.importFailed(status)
        }
        guard
            let items = importedItems as? [[String: Any]],
            let first = items.first,
            let identityRef = first[kSecImportItemIdentity as String]
        else {
            throw Error.noIdentityInArchive
        }
        return identityRef as! SecIdentity
    }
}
