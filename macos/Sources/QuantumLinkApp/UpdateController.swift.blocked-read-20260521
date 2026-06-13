import Foundation
import os

#if canImport(Sparkle)
import Sparkle
#endif

/// Wraps Sparkle 2's `SPUStandardUpdaterController` so the rest of the app talks
/// to a stable, optional surface. Sparkle is wired through XcodeGen for the
/// signed/notarized .app bundle; the SPM `swift run` development build does not
/// link it, in which case this controller becomes a logging no-op.
///
/// Sparkle picks up its feed URL and trusted EdDSA public key from the app's
/// Info.plist (`SUFeedURL`, `SUPublicEDKey`). Both default to placeholder
/// `$(QLINK_SPARKLE_*)` build settings; CI / packaging fills them in.
@MainActor
public final class UpdateController {
    private let logger = Logger(subsystem: "com.quantumlink.macos", category: "updates")

#if canImport(Sparkle)
    private var sparkleController: SPUStandardUpdaterController?
#endif

    public init() {}

    public func start() {
#if canImport(Sparkle)
        guard runningInsideAppBundle() else {
            logger.info("Sparkle disabled: not running from a bundled .app — fine for development builds")
            return
        }
        guard hasFeedURL() else {
            logger.info("Sparkle disabled: SUFeedURL is not configured in Info.plist")
            return
        }

        let controller = SPUStandardUpdaterController(
            startingUpdater: true,
            updaterDelegate: nil,
            userDriverDelegate: nil
        )
        sparkleController = controller
        logger.info("Sparkle 2 updater started; periodic check interval is governed by SUScheduledCheckInterval")
#else
        logger.info("Sparkle is not linked in this build; updates are not available")
#endif
    }

    public func checkForUpdates() {
#if canImport(Sparkle)
        sparkleController?.checkForUpdates(nil)
#endif
    }

#if canImport(Sparkle)
    private func runningInsideAppBundle() -> Bool {
        let path = Bundle.main.bundlePath
        return path.hasSuffix(".app")
    }

    private func hasFeedURL() -> Bool {
        guard let value = Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") as? String else {
            return false
        }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return !trimmed.isEmpty && !trimmed.hasPrefix("$(")
    }
#endif
}
