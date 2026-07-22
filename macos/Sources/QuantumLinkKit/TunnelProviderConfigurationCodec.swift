import Foundation

public enum TunnelProviderConfigurationCodec {
  public static let configurationJSONKey = "configurationJSON"

  public static func providerConfiguration(for configuration: TunnelConfiguration) throws -> [String:
    String]
  {
    let data = try JSONEncoder().encode(configuration)
    let json = String(data: data, encoding: .utf8) ?? "{}"
    return [
      "meshID": configuration.meshID,
      "deviceAlias": configuration.deviceAlias,
      configurationJSONKey: json,
    ]
  }

  public static func configuration(from providerConfiguration: [String: Any]?) -> TunnelConfiguration?
  {
    guard
      let json = providerConfiguration?[configurationJSONKey] as? String,
      let data = json.data(using: .utf8)
    else {
      return nil
    }
    return try? JSONDecoder().decode(TunnelConfiguration.self, from: data)
  }
}
