import Foundation

/// Load-or-generate-and-persist flow for the symmetric key that
/// protects the local `peers.json` cache. Mirrors `DeviceKeypairStore`
/// in shape and lifecycle, but stores a 32-byte SHAKE256 envelope key
/// rather than an ML-DSA seed.
///
/// Why this exists: the Rust core's `FilePeerStore` writes signed
/// peer records to disk for cross-restart cache persistence. Records
/// themselves aren't secret (they're publishable to the rendezvous
/// server), but their *aggregate* leaks "who this device talks to"
/// — a real privacy concern for users on shared / corporate
/// machines or in lost-laptop scenarios. The Rust core's v3 envelope
/// wraps the cache with SHAKE256 masking and authentication when
/// supplied a 32-byte key; this class is the Swift host's side of
/// that contract.
///
/// The key is passed across the FFI as base64 in
/// `MeshTransportConfiguration.peerStoreKeyB64`.
public final class PeerStoreKey {
    /// Default Keychain account name for the local node's primary
    /// peer-store cache. Apps managing multiple identities should
    /// pick distinct accounts.
    public static let defaultAccount = "peer-store-key"

    private let keychain: KeychainSecretStore
    private let account: String

    public init(
        keychain: KeychainSecretStore = KeychainSecretStore(service: "com.quantumlink.macos.secrets"),
        account: String = PeerStoreKey.defaultAccount
    ) {
        self.keychain = keychain
        self.account = account
    }

    /// Loads the persisted key if one exists, otherwise generates a
    /// fresh 32-byte key and writes it to the Keychain before
    /// returning. Either branch returns a key that's stable across
    /// subsequent calls within the same Keychain account — the
    /// invariant that lets a previously-protected `peers.json`
    /// remain readable after restart.
    public func loadOrGenerate() throws -> Data {
        if let existing = try keychain.load(account: account), existing.count == 32 {
            return existing
        }
        // Either no item or a stored item that's the wrong size
        // (e.g. previous version of the app stored something
        // different here). Mint fresh + replace — same recovery
        // behavior as `DeviceKeypairStore`.
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, 32, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw PrivacyDefaultsError.randomBytesUnavailable(status)
        }
        let key = Data(bytes)
        try keychain.store(key, account: account)
        return key
    }

    /// Removes the persisted key. The next call to `loadOrGenerate`
    /// will mint a fresh one — which means any pre-existing v3
    /// envelope on disk becomes unreadable. Use this for "rotate
    /// peer-store key" / "scrub local cache" flows; pair with a
    /// `peer_store::FilePeerStore.forget_all`-equivalent (tracked
    /// as a follow-up).
    public func forget() throws {
        try keychain.delete(account: account)
    }

    /// Convenience: returns the key as base64-encoded UTF-8, ready
    /// to drop into `MeshTransportConfiguration.peerStoreKeyB64`.
    public func loadOrGenerateBase64() throws -> String {
        try loadOrGenerate().base64EncodedString()
    }
}
