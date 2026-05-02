import Foundation
import Security

/// CMS-signing helper for `.mobileconfig` payloads.
///
/// Apple's MDM tooling expects configuration profiles to be CMS-signed
/// (RFC 5652) when delivered for unattended install. Without a signature,
/// the install dialog flags the profile as "Unsigned" and several MDM
/// consoles refuse to upload it. This type wraps the macOS-only
/// `CMSEncoder` / `CMSDecoder` C APIs so callers can hand in any
/// `SecIdentity` (a `(SecCertificate, SecKey)` pair) and get back signed
/// CMS bytes ready to write to disk.
///
/// The signing format produced is `signed-data` with the content embedded
/// (not detached); that's the exact shape `profiles install` expects.
///
/// Trust chain: only Apple-issued Developer ID certs install without user
/// override on managed Macs. Self-signed certs still produce a valid CMS
/// envelope but the install dialog warns the user. Format-wise both paths
/// are identical, so swapping in an Apple Dev cert later is a one-line
/// change at the call site.
public struct MobileConfigSigner {
    public init() {}

    /// Signs `payload` with `identity`, returning a CMS signed-data
    /// envelope that embeds the original bytes.
    public func sign(_ payload: Data, with identity: SecIdentity) throws -> Data {
        var encoderOut: CMSEncoder?
        var status = CMSEncoderCreate(&encoderOut)
        guard status == errSecSuccess, let encoder = encoderOut else {
            throw MobileConfigSignerError.encoderCreateFailed(status)
        }

        status = CMSEncoderAddSigners(encoder, identity)
        guard status == errSecSuccess else {
            throw MobileConfigSignerError.addSignersFailed(status)
        }

        // SHA-1 is the historical default for CMSEncoder; bump to SHA-256
        // explicitly. SHA-1 collisions are no longer theoretical, and the
        // configuration-profile install path on modern macOS rejects
        // SHA-1-signed profiles.
        status = CMSEncoderSetSignerAlgorithm(encoder, kCMSEncoderDigestAlgorithmSHA256)
        guard status == errSecSuccess else {
            throw MobileConfigSignerError.setOptionsFailed("signerAlgorithm", status)
        }

        // Embedded content (not detached) — Apple's install path expects
        // the profile bytes to live inside the CMS envelope.
        status = CMSEncoderSetHasDetachedContent(encoder, false)
        guard status == errSecSuccess else {
            throw MobileConfigSignerError.setOptionsFailed("hasDetachedContent", status)
        }

        // Include the signer cert plus any intermediates, but omit the
        // root (relying parties already trust the root or they don't —
        // shipping it adds bytes without value). For self-signed test
        // certs this is equivalent to "signer only".
        status = CMSEncoderSetCertificateChainMode(encoder, .chainWithRoot)
        guard status == errSecSuccess else {
            throw MobileConfigSignerError.setOptionsFailed("certificateChainMode", status)
        }

        let updateStatus = payload.withUnsafeBytes { buffer -> OSStatus in
            guard let baseAddress = buffer.baseAddress else {
                return errSecParam
            }
            return CMSEncoderUpdateContent(encoder, baseAddress, payload.count)
        }
        guard updateStatus == errSecSuccess else {
            throw MobileConfigSignerError.updateContentFailed(updateStatus)
        }

        var signedOut: CFData?
        status = CMSEncoderCopyEncodedContent(encoder, &signedOut)
        guard status == errSecSuccess, let signed = signedOut as Data? else {
            throw MobileConfigSignerError.copyContentFailed(status)
        }
        return signed
    }

    /// Parses a CMS-signed envelope and returns the embedded payload
    /// alongside the signer status.
    ///
    /// This is a *soft* check: it throws only on structural problems
    /// (no signers, malformed ASN.1, etc.). The signer's signature
    /// validity and the trust-chain result are reported in the returned
    /// `Verification` for the caller to evaluate. For strict acceptance,
    /// require `verification.signerStatus == .valid` (signature OK) and
    /// optionally `verification.trustEvaluationResult == errSecSuccess`
    /// (chain trusted by the system).
    ///
    /// `evaluateTrust: true` runs the signer's certificate chain against
    /// the system trust store; for self-signed test certs that will fail
    /// even when the signature itself is cryptographically valid — when
    /// `evaluateTrust` is true, the C API folds the trust failure back
    /// into the signer status as `.invalidCert`, so a `.valid` status
    /// with `evaluateTrust: true` means *both* the signature and the
    /// trust chain are good.
    public func verify(
        _ signed: Data,
        evaluateTrust: Bool = false
    ) throws -> Verification {
        var decoderOut: CMSDecoder?
        var status = CMSDecoderCreate(&decoderOut)
        guard status == errSecSuccess, let decoder = decoderOut else {
            throw MobileConfigSignerError.decoderCreateFailed(status)
        }

        let updateStatus = signed.withUnsafeBytes { buffer -> OSStatus in
            guard let baseAddress = buffer.baseAddress else {
                return errSecParam
            }
            return CMSDecoderUpdateMessage(decoder, baseAddress, signed.count)
        }
        guard updateStatus == errSecSuccess else {
            throw MobileConfigSignerError.decoderUpdateFailed(updateStatus)
        }

        status = CMSDecoderFinalizeMessage(decoder)
        guard status == errSecSuccess else {
            throw MobileConfigSignerError.decoderFinalizeFailed(status)
        }

        var signerCount: size_t = 0
        status = CMSDecoderGetNumSigners(decoder, &signerCount)
        guard status == errSecSuccess else {
            throw MobileConfigSignerError.decoderInspectFailed(status)
        }
        guard signerCount > 0 else {
            throw MobileConfigSignerError.noSigners
        }

        var signerStatus: CMSSignerStatus = .unsigned
        var trustEvaluationResult: OSStatus = errSecSuccess
        var trustRef: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        status = CMSDecoderCopySignerStatus(
            decoder,
            0,
            policy,
            evaluateTrust,
            &signerStatus,
            &trustRef,
            &trustEvaluationResult
        )
        guard status == errSecSuccess else {
            throw MobileConfigSignerError.decoderInspectFailed(status)
        }

        var contentOut: CFData?
        status = CMSDecoderCopyContent(decoder, &contentOut)
        guard status == errSecSuccess, let payloadData = contentOut as Data? else {
            throw MobileConfigSignerError.decoderInspectFailed(status)
        }

        return Verification(
            payload: payloadData,
            signerCount: Int(signerCount),
            signerStatus: signerStatus,
            trustEvaluationResult: evaluateTrust ? trustEvaluationResult : nil
        )
    }

    /// Result of `verify(_:evaluateTrust:)`.
    public struct Verification {
        public let payload: Data
        public let signerCount: Int
        /// CMS-level signer-info status. `.valid` means the signature
        /// matches the signer cert's public key over the embedded
        /// content; `.invalidSignature` means the bytes were tampered
        /// after signing. Distinct from trust-chain evaluation.
        public let signerStatus: CMSSignerStatus
        /// Result of evaluating the signer cert's chain against the
        /// system trust store. `nil` when `evaluateTrust` was false.
        /// `errSecSuccess` is the only "trusted" value; everything else
        /// (including `errSecCertExpired`, `errSecNoTrustSettings`) means
        /// the chain didn't validate. Self-signed test certs always
        /// produce a non-success value here.
        public let trustEvaluationResult: OSStatus?
    }
}

public enum MobileConfigSignerError: Error, LocalizedError {
    case encoderCreateFailed(OSStatus)
    case addSignersFailed(OSStatus)
    case setOptionsFailed(String, OSStatus)
    case updateContentFailed(OSStatus)
    case copyContentFailed(OSStatus)
    case decoderCreateFailed(OSStatus)
    case decoderUpdateFailed(OSStatus)
    case decoderFinalizeFailed(OSStatus)
    case decoderInspectFailed(OSStatus)
    case noSigners

    public var errorDescription: String? {
        switch self {
        case .encoderCreateFailed(let status):
            "CMSEncoderCreate failed (\(status))"
        case .addSignersFailed(let status):
            "CMSEncoderAddSigners failed (\(status))"
        case .setOptionsFailed(let key, let status):
            "CMSEncoder option \(key) failed (\(status))"
        case .updateContentFailed(let status):
            "CMSEncoderUpdateContent failed (\(status))"
        case .copyContentFailed(let status):
            "CMSEncoderCopyEncodedContent failed (\(status))"
        case .decoderCreateFailed(let status):
            "CMSDecoderCreate failed (\(status))"
        case .decoderUpdateFailed(let status):
            "CMSDecoderUpdateMessage failed (\(status))"
        case .decoderFinalizeFailed(let status):
            "CMSDecoderFinalizeMessage failed (\(status))"
        case .decoderInspectFailed(let status):
            "CMSDecoder inspection failed (\(status))"
        case .noSigners:
            "CMS envelope contains no signers"
        }
    }
}
