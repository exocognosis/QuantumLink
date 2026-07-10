// UI-side mirror of the IPC schema defined in
// rust/quantumlink-proto (src/ipc.rs + src/models.rs).
//
// Wire format: newline-delimited camelCase JSON over the
// \\.\pipe\QuantumLinkService named pipe. Keep these records in sync
// with the Rust types; the schemaVersion handshake catches drift at
// connect time.

using System.Text.Json.Serialization;

namespace QuantumLink.Windows.Models;

public static class IpcProtocol
{
    public const string PipeName = "QuantumLinkService";
    public const uint SchemaVersion = 1;
}

public sealed record PipeRequest
{
    [JsonPropertyName("id")] public ulong Id { get; init; }
    [JsonPropertyName("command")] public string Command { get; init; } = "";
    [JsonPropertyName("schemaVersion")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? SchemaVersion { get; init; }
    [JsonPropertyName("configuration")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public TunnelConfiguration? Configuration { get; init; }
    [JsonPropertyName("peerId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PeerId { get; init; }
}

public sealed record PipeResponse
{
    [JsonPropertyName("id")] public ulong Id { get; init; }
    [JsonPropertyName("kind")] public string Kind { get; init; } = "";
    [JsonPropertyName("status")] public TunnelStatus? Status { get; init; }
    [JsonPropertyName("text")] public string? Text { get; init; }
    [JsonPropertyName("message")] public string? Message { get; init; }
    [JsonPropertyName("schemaVersion")] public uint? SchemaVersion { get; init; }
    [JsonPropertyName("serviceVersion")] public string? ServiceVersion { get; init; }
}

public sealed record TunnelStatus
{
    [JsonPropertyName("phase")] public string Phase { get; init; } = "idle";
    [JsonPropertyName("pathType")] public string PathType { get; init; } = "unavailable";
    [JsonPropertyName("routeMode")] public string RouteMode { get; init; } = "splitTunnel";
    [JsonPropertyName("dnsMode")] public string DnsMode { get; init; } = "tunnelProvided";
    [JsonPropertyName("overlayIPv4Address")] public string OverlayIPv4Address { get; init; } = "";
    [JsonPropertyName("protectedRoutes")] public List<string> ProtectedRoutes { get; init; } = [];
    [JsonPropertyName("peers")] public List<PeerStatus> Peers { get; init; } = [];
    [JsonPropertyName("metrics")] public MeshMetrics Metrics { get; init; } = new();
    [JsonPropertyName("peerTrust")] public DytallixPeerTrustSummary PeerTrust { get; init; } = new();
    [JsonPropertyName("transport")] public TunnelTransportMetrics? Transport { get; init; }
    [JsonPropertyName("pump")] public PacketPumpMetrics? Pump { get; init; }
    [JsonPropertyName("killSwitchEngaged")] public bool? KillSwitchEngaged { get; init; }
    [JsonPropertyName("lastError")] public string? LastError { get; init; }
}

public sealed record PeerIdentity
{
    [JsonPropertyName("peerID")] public string PeerId { get; init; } = "";
    [JsonPropertyName("alias")] public string Alias { get; init; } = "";
    [JsonPropertyName("publicKeyFingerprint")] public string PublicKeyFingerprint { get; init; } = "";
}

public sealed record PeerStatus
{
    [JsonPropertyName("identity")] public PeerIdentity Identity { get; init; } = new();
    [JsonPropertyName("pathType")] public string PathType { get; init; } = "probing";
    [JsonPropertyName("endpoints")] public List<PeerEndpoint> Endpoints { get; init; } = [];
    [JsonPropertyName("overlayAddress")] public string OverlayAddress { get; init; } = "";
    [JsonPropertyName("rttMilliseconds")] public int? RttMilliseconds { get; init; }
    [JsonPropertyName("lastRekeyUnix")] public ulong? LastRekeyUnix { get; init; }
    [JsonPropertyName("bytesIn")] public ulong BytesIn { get; init; }
    [JsonPropertyName("bytesOut")] public ulong BytesOut { get; init; }
}

public sealed record PeerEndpoint
{
    [JsonPropertyName("candidateType")] public string CandidateType { get; init; } = "";
    [JsonPropertyName("address")] public string Address { get; init; } = "";
    [JsonPropertyName("port")] public ushort Port { get; init; }
    [JsonPropertyName("priority")] public long Priority { get; init; }
}

public sealed record MeshMetrics
{
    [JsonPropertyName("peerCount")] public uint PeerCount { get; init; }
    [JsonPropertyName("directPeerCount")] public uint DirectPeerCount { get; init; }
    [JsonPropertyName("relayPeerCount")] public uint RelayPeerCount { get; init; }
    [JsonPropertyName("bytesIn")] public ulong BytesIn { get; init; }
    [JsonPropertyName("bytesOut")] public ulong BytesOut { get; init; }
    [JsonPropertyName("replayDrops")] public ulong ReplayDrops { get; init; }
    [JsonPropertyName("lastPathProbeUnix")] public ulong? LastPathProbeUnix { get; init; }
}

public sealed record DytallixPeerTrustSummary
{
    [JsonPropertyName("required")] public bool Required { get; init; }
    [JsonPropertyName("policy")] public string Policy { get; init; } = "development_optional";
    [JsonPropertyName("identityMode")] public string IdentityMode { get; init; } = "off";
    [JsonPropertyName("registryConfigured")] public bool RegistryConfigured { get; init; }
    [JsonPropertyName("verifiedPeerCount")] public uint VerifiedPeerCount { get; init; }
    [JsonPropertyName("unverifiedPeerCount")] public uint UnverifiedPeerCount { get; init; }
    [JsonPropertyName("pendingPeerCount")] public uint PendingPeerCount { get; init; }
    [JsonPropertyName("failedPeerCount")] public uint FailedPeerCount { get; init; }
    [JsonPropertyName("lastCheckedAtUnix")] public ulong? LastCheckedAtUnix { get; init; }
    [JsonPropertyName("lastFailureCode")] public string? LastFailureCode { get; init; }
    [JsonPropertyName("lastFailureSummary")] public string? LastFailureSummary { get; init; }
    [JsonPropertyName("warning")] public string? Warning { get; init; }
}

public sealed record TunnelTransportMetrics
{
    [JsonPropertyName("stateCode")] public uint StateCode { get; init; }
    [JsonPropertyName("pathKindCode")] public uint PathKindCode { get; init; }
    [JsonPropertyName("framesSent")] public ulong FramesSent { get; init; }
    [JsonPropertyName("framesReceived")] public ulong FramesReceived { get; init; }
    [JsonPropertyName("bytesSent")] public ulong BytesSent { get; init; }
    [JsonPropertyName("bytesReceived")] public ulong BytesReceived { get; init; }
    [JsonPropertyName("sendFailures")] public ulong SendFailures { get; init; }
    [JsonPropertyName("receiveFailures")] public ulong ReceiveFailures { get; init; }
    [JsonPropertyName("networkEventCount")] public ulong NetworkEventCount { get; init; }
    [JsonPropertyName("reconnectCount")] public ulong ReconnectCount { get; init; }
}

public sealed record PacketPumpMetrics
{
    [JsonPropertyName("packetsObserved")] public ulong PacketsObserved { get; init; }
    [JsonPropertyName("queuedForTransport")] public ulong QueuedForTransport { get; init; }
    [JsonPropertyName("droppedUnprotected")] public ulong DroppedUnprotected { get; init; }
    [JsonPropertyName("droppedFailClosed")] public ulong DroppedFailClosed { get; init; }
    [JsonPropertyName("droppedKillSwitch")] public ulong DroppedKillSwitch { get; init; }
    [JsonPropertyName("failedSubmissions")] public ulong FailedSubmissions { get; init; }
    [JsonPropertyName("transportFramesEmitted")] public ulong TransportFramesEmitted { get; init; }
    [JsonPropertyName("transportFramesAccepted")] public ulong TransportFramesAccepted { get; init; }
    [JsonPropertyName("failedInboundFrames")] public ulong FailedInboundFrames { get; init; }
    [JsonPropertyName("tunnelPacketsEmitted")] public ulong TunnelPacketsEmitted { get; init; }
}

public sealed record CryptoPolicy
{
    [JsonPropertyName("suite")] public string Suite { get; init; } = "QLINK-FIPS203-MLKEM768-SHAKE256-v1";
    [JsonPropertyName("rekeyAfterSeconds")] public double RekeyAfterSeconds { get; init; } = 3600;
    [JsonPropertyName("rekeyAfterBytes")] public ulong RekeyAfterBytes { get; init; } = 1_073_741_824;
}

public sealed record DytallixIdentityConfiguration
{
    [JsonPropertyName("mode")] public string Mode { get; init; } = "verified";
    [JsonPropertyName("registryEndpoint")] public string RegistryEndpoint { get; init; } = "";
    [JsonPropertyName("contract")] public string Contract { get; init; } = "quantumlink-node-registry";
    [JsonPropertyName("cachedProofGraceSeconds")] public ulong CachedProofGraceSeconds { get; init; }
    [JsonPropertyName("contractAddress")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ContractAddress { get; init; }
    [JsonPropertyName("publishWalletAddress")] public bool PublishWalletAddress { get; init; }
    [JsonPropertyName("networkID")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NetworkId { get; init; }
    [JsonPropertyName("chainID")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ChainId { get; init; }
    [JsonPropertyName("allowedRPCEndpoints")] public List<string> AllowedRpcEndpoints { get; init; } = [];
    [JsonPropertyName("keystorePath")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? KeystorePath { get; init; }
    [JsonPropertyName("walletName")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? WalletName { get; init; }
}

public sealed record TunnelConfiguration
{
    [JsonPropertyName("meshID")] public string MeshId { get; init; } = "";
    [JsonPropertyName("deviceAlias")] public string DeviceAlias { get; init; } = "";
    [JsonPropertyName("overlayIPv4Address")] public string OverlayIPv4Address { get; init; } = "";
    [JsonPropertyName("tunnelRemoteAddress")] public string TunnelRemoteAddress { get; init; } = "100.64.0.1";
    [JsonPropertyName("protectedRoutes")] public List<string> ProtectedRoutes { get; init; } = ["100.64.0.0/10"];
    [JsonPropertyName("excludedRoutes")] public List<string> ExcludedRoutes { get; init; } = [];
    [JsonPropertyName("dnsServers")] public List<string> DnsServers { get; init; } = ["100.64.0.1"];
    [JsonPropertyName("dnsSearchDomains")] public List<string> DnsSearchDomains { get; init; } = [];
    [JsonPropertyName("routeMode")] public string RouteMode { get; init; } = "splitTunnel";
    [JsonPropertyName("dnsMode")] public string DnsMode { get; init; } = "tunnelProvided";
    [JsonPropertyName("discoveryModes")] public List<string> DiscoveryModes { get; init; } = ["rendezvous"];
    [JsonPropertyName("rendezvousServers")] public List<string> RendezvousServers { get; init; } = [];
    [JsonPropertyName("relayServers")] public List<string> RelayServers { get; init; } = [];
    [JsonPropertyName("mtu")] public uint Mtu { get; init; } = 1280;
    [JsonPropertyName("crypto")] public CryptoPolicy Crypto { get; init; } = new();
    [JsonPropertyName("killSwitch")] public string KillSwitch { get; init; } = "failClosed";
    [JsonPropertyName("meshType")] public string MeshType { get; init; } = "development";
    [JsonPropertyName("meshTrustPolicy")] public string MeshTrustPolicy { get; init; } = "development_optional";
    [JsonPropertyName("discoveryIdentityMode")] public string DiscoveryIdentityMode { get; init; } = "off";
    [JsonPropertyName("dytallixIdentity")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DytallixIdentityConfiguration? DytallixIdentity { get; init; }
}
