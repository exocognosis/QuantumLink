import Foundation

public enum DytallixIdentityOperation: String, Codable, CaseIterable, Sendable {
  case enroll
  case register
  case update
  case revoke
  case status
}

public struct DytallixIdentityCommandOutput: Equatable, Sendable {
  public let operation: DytallixIdentityOperation
  public let peerID: String
  public let walletName: String?
  public let walletAddress: String?
  public let txHash: String?
  public let createdWallet: Bool
  public let found: Bool?
  public let registryStatus: String?

  public init(output: String) throws {
    let values = Self.keyValueLines(from: output)
    guard
      let operationValue = values["identity_operation"],
      let operation = DytallixIdentityOperation(rawValue: operationValue),
      let peerID = values["peer_id"],
      !peerID.isEmpty
    else {
      throw DytallixEnrollmentCommandOutputError.missingRequiredField
    }

    self.operation = operation
    self.peerID = peerID
    self.walletName = values["wallet_name"]
    self.walletAddress = values["wallet_address"]
    self.txHash = values["tx_hash"]
    self.createdWallet = values["created_wallet"] == "true"
    self.found = values["found"].map { $0 == "true" }
    self.registryStatus = values["status"] ?? Self.registryStatus(from: output)
  }

  fileprivate static func keyValueLines(from output: String) -> [String: String] {
    var values: [String: String] = [:]
    for line in output.split(whereSeparator: \.isNewline) {
      guard let separator = line.firstIndex(of: "=") else { continue }
      let key = String(line[..<separator]).trimmingCharacters(in: .whitespacesAndNewlines)
      let value = String(line[line.index(after: separator)...])
        .trimmingCharacters(in: .whitespacesAndNewlines)
      values[key] = value
    }
    return values
  }

  private static func registryStatus(from output: String) -> String? {
    for line in output.split(whereSeparator: \.isNewline) {
      let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
      guard trimmed.hasPrefix("\"status\"") else { continue }
      let pieces = trimmed.split(separator: ":", maxSplits: 1)
      guard pieces.count == 2 else { continue }
      return pieces[1]
        .trimmingCharacters(in: CharacterSet(charactersIn: " \","))
    }
    return nil
  }
}

public struct DytallixEnrollmentCommandOutput: Equatable, Sendable {
  public let walletName: String
  public let walletAddress: String
  public let peerID: String
  public let txHash: String?
  public let createdWallet: Bool

  public init(output: String) throws {
    let identityOutput = try DytallixIdentityCommandOutput(output: output)
    guard
      identityOutput.operation == .enroll,
      let walletName = identityOutput.walletName, !walletName.isEmpty,
      let walletAddress = identityOutput.walletAddress, !walletAddress.isEmpty
    else {
      throw DytallixEnrollmentCommandOutputError.missingRequiredField
    }

    self.walletName = walletName
    self.walletAddress = walletAddress
    self.peerID = identityOutput.peerID
    self.txHash = identityOutput.txHash
    self.createdWallet = identityOutput.createdWallet
  }
}

public enum DytallixEnrollmentCommandOutputError: Error, Equatable {
  case missingRequiredField
}

public struct DytallixIdentityFailurePresentation: Equatable, Sendable {
  public let message: String

  public init(operation: DytallixIdentityOperation, commandOutput: String?) {
    let reason = Self.normalizedReason(from: commandOutput)
    self.message = Self.message(operation: operation, reason: reason)
  }

  private static func normalizedReason(from commandOutput: String?) -> String? {
    guard let commandOutput else { return nil }
    let markers = [
      "dytallix registry contract rejected request:",
      "dytallix registry lookup failed:",
      "protocol error:",
    ]
    let trimmed = commandOutput.trimmingCharacters(in: .whitespacesAndNewlines)
    let lowercased = trimmed.lowercased()
    for marker in markers {
      guard let range = lowercased.range(of: marker) else { continue }
      return String(trimmed[range.upperBound...])
        .trimmingCharacters(in: .whitespacesAndNewlines)
    }
    return trimmed.isEmpty ? nil : trimmed
  }

  private static func message(operation: DytallixIdentityOperation, reason: String?) -> String {
    guard let reason, !reason.isEmpty else {
      return operation.defaultFailureMessage
    }

    let normalized = reason.lowercased()
    if normalized.contains("node already registered") {
      return "This peer is already registered in the Dytallix registry. Use Update Registry Record, or rotate the device key after revoking the current record."
    }
    if normalized.contains("node not found") || normalized.contains("not found") {
      return "No Dytallix registry record exists for this peer. Register the identity before refreshing, updating, or revoking it."
    }
    if normalized.contains("node revoked") || normalized.contains("registry record is revoked") {
      return "This Dytallix registry record is revoked. Rotate the device key, then register a new identity."
    }
    if normalized.contains("suspended") {
      return "This Dytallix registry record is suspended. Use a different registered identity or contact the mesh operator before connecting."
    }
    if normalized.contains("expired") {
      return "This Dytallix registry record has expired. Update the registry record before joining a public mesh."
    }
    if normalized.contains("mismatch") || normalized.contains("does not match") {
      return "The peer record does not match the Dytallix registry binding. Refresh discovery, then update or re-register the identity."
    }

    return "\(operation.defaultFailureMessage) \(reason)"
  }
}

extension DytallixIdentityOperation {
  public var defaultFailureMessage: String {
    switch self {
    case .enroll, .register:
      "Dytallix identity registration failed."
    case .update:
      "Dytallix registry update failed."
    case .revoke:
      "Dytallix identity revoke failed."
    case .status:
      "Dytallix identity status refresh failed."
    }
  }
}

extension DytallixEnrollmentSettings {
  public func applying(commandOutput: DytallixEnrollmentCommandOutput) -> Self {
    replacing(
      walletName: .some(commandOutput.walletName),
      walletAddress: .some(commandOutput.walletAddress),
      registeredPeerID: .some(commandOutput.peerID),
      status: .registered
    )
  }

  public func applying(identityCommandOutput output: DytallixIdentityCommandOutput) -> Self {
    switch output.operation {
    case .enroll:
      return replacing(
        walletName: output.walletName.map(Optional.some) ?? nil,
        walletAddress: output.walletAddress.map(Optional.some) ?? nil,
        registeredPeerID: .some(output.peerID),
        status: .registered
      )
    case .register, .update:
      return replacing(
        registeredPeerID: .some(output.peerID),
        status: .registered
      )
    case .revoke:
      return replacing(
        registeredPeerID: .some(output.peerID),
        status: .revoked
      )
    case .status:
      if output.found == false {
        return replacing(registeredPeerID: .some(output.peerID), status: .notRegistered)
      }
      switch output.registryStatus {
      case "active":
        return replacing(registeredPeerID: .some(output.peerID), status: .registered)
      case "revoked":
        return replacing(registeredPeerID: .some(output.peerID), status: .revoked)
      case "suspended":
        return replacing(registeredPeerID: .some(output.peerID), status: .failed)
      default:
        return replacing(registeredPeerID: .some(output.peerID))
      }
    }
  }
}
