import Foundation

/// Load-or-generate-and-persist flow for the local device keypair.
/// Wraps `KeychainSecretStore` so the 32-byte ML-DSA seed survives
/// process restarts — without persistence the published `peer_id`
/// changes per launch and the cert-publishing pipeline cannot
/// maintain a stable mesh identity.
///
/// Storage shape: a single Keychain item per `(service, account)`,
/// `kSecClassGenericPassword`, with the raw 32-byte seed as
/// `kSecValueData`. The Keychain provides the at-rest encryption
/// (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` per
/// `KeychainSecretStore`'s defaults), so we don't add a second
/// encryption layer.
public final class DeviceKeypairStore {
    /// Default account name for the local node's primary device
    /// keypair. Apps that manage multiple identities (test harness
    /// vs. production, multi-mesh) should pick distinct accounts.
    public static let defaultAccount = "device-keypair-seed"

    private let keychain: KeychainSecretStore
    private let account: String

    public init(
        keychain: KeychainSecretStore = KeychainSecretStore(service: "com.quantumlink.macos.secrets"),
        account: String = DeviceKeypairStore.defaultAccount
    ) {
        self.keychain = keychain
        self.account = account
    }

    /// Loads the persisted keypair if one exists, otherwise
    /// generates a fresh one and writes its seed to the Keychain
    /// before returning.
    ///
    /// Either branch returns a keypair whose `peer_id` is stable
    /// across subsequent calls within the same Keychain account —
    /// the persistence contract this whole class exists for.
    public func loadOrGenerate(library: RustCoreLibrary) throws -> RustDeviceKeypair {
        if let existing = try keychain.load(account: account) {
            // Defensive: a stored item that's the wrong length
            // means a previous version of the app wrote something
            // different here. Treat it as "no keypair" and
            // overwrite — better than failing every launch with a
            // cryptic seed-decode error.
            if existing.count == 32 {
                if let keypair = try? RustDeviceKeypair.load(library: library, seed: existing) {
                    return keypair
                }
            }
            // Either wrong size or refused to load. Fall through
            // to regenerate + replace.
        }
        let keypair = try RustDeviceKeypair.generate(library: library)
        try keychain.store(keypair.seed, account: account)
        return keypair
    }

    /// Removes the persisted keypair. The next `loadOrGenerate`
    /// call will mint a fresh one with a new `peer_id`. Use this
    /// for "log out" / "rotate identity" flows.
    public func forget() throws {
        try keychain.delete(account: account)
    }
}
