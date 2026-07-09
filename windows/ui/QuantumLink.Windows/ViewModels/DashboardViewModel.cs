// Dashboard view model — matches the macOS app's product concepts
// (connection phase, path type, peers, kill switch, diagnostics), not
// its SwiftUI implementation.

using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using QuantumLink.Windows.Models;
using QuantumLink.Windows.Services;

namespace QuantumLink.Windows.ViewModels;

public partial class DashboardViewModel : ObservableObject
{
    private readonly ServicePipeClient _client = new();
    private Microsoft.UI.Dispatching.DispatcherQueueTimer? _refreshTimer;

    [ObservableProperty] private string _phase = "idle";
    [ObservableProperty] private string _pathType = "unavailable";
    [ObservableProperty] private string _routeMode = "splitTunnel";
    [ObservableProperty] private string _dnsMode = "tunnelProvided";
    [ObservableProperty] private string _overlayAddress = "";
    [ObservableProperty] private string _routeSummary = "";
    [ObservableProperty] private bool _killSwitchEngaged;
    [ObservableProperty] private string? _lastError;
    [ObservableProperty] private string _serviceState = "Connecting to service…";
    [ObservableProperty] private string _peerSummary = "0 peers";
    [ObservableProperty] private string _trafficSummary = "Zero B in · Zero B out";
    [ObservableProperty] private string _transportSummary = "Transport metrics not reported yet";
    [ObservableProperty] private string _packetPumpSummary = "Packet pump metrics not reported yet";
    [ObservableProperty] private string _trustSummary = "Dytallix trust status not reported yet";
    [ObservableProperty] private string _registrySummary = "Registry not configured";
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ConnectButtonVisibility))]
    [NotifyPropertyChangedFor(nameof(DisconnectButtonVisibility))]
    private bool _isConnected;
    [ObservableProperty] private string _diagnosticsText = "";

    // Visibility is surfaced directly from the view model rather than via
    // an XAML value converter: WinUI 3 does not support `x:Bind` with a
    // Converter when the XAML root is a `Window`, because the generated
    // binding code calls SetConverterLookupRoot(this), which requires a
    // FrameworkElement (microsoft/microsoft-ui-xaml#5902, #6369). MainWindow
    // is a Window, so a converter binding fails to compile.
    public Microsoft.UI.Xaml.Visibility ConnectButtonVisibility =>
        IsConnected ? Microsoft.UI.Xaml.Visibility.Collapsed : Microsoft.UI.Xaml.Visibility.Visible;

    public Microsoft.UI.Xaml.Visibility DisconnectButtonVisibility =>
        IsConnected ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;

    public string PlatformBadge => "Windows alpha";
    public string ReadinessSummary => "WinUI dashboard over the privileged QuantumLink Windows service; Wintun, WFP, MSI/WiX, and service validation remain Windows-host gated.";
    public string IdentitySummary => "Dytallix identity follows shared qlink-core policy while Windows-local secrets stay behind service-owned DPAPI storage boundaries.";
    public string PolicySummary => "Routes, DNS, Wintun adapter state, and WFP kill-switch policy are owned by the Windows service, not this unprivileged dashboard.";
    public string HelpSummary => "Use redacted support exports plus Event Viewer service logs. Security reports should follow SECURITY.md.";

    public ObservableCollection<string> OnboardingItems { get; } =
    [
        "Confirm the QuantumLink Windows service is installed and running",
        "Verify named-pipe IPC from the WinUI dashboard to the service",
        "Connect through the LocalSystem tunnel service, not direct UI networking",
        "Verify Wintun adapter state and WFP kill-switch policy from service status",
        "Use MSI/WiX install logs and Event Viewer before reinstalling",
        "Export redacted diagnostics before sharing logs"
    ];

    public ObservableCollection<string> HelpTopics { get; } =
    [
        "Windows service setup: install the MSI, start the service, and confirm named-pipe IPC",
        "Tunnel control: Connect and Disconnect ask the service to manage Wintun and routes",
        "WFP kill switch: service status should report fail-closed policy state",
        "DPAPI identity storage: keep Windows-local secrets out of dashboard state",
        "Diagnostics: export redacted JSON and check Event Viewer service logs",
        "Packaging: use MSI/WiX validation before treating the build as releasable",
        "Security reports: keep raw wallet, peer, DNS, route, and packet data out of tickets"
    ];

    public ObservableCollection<PeerStatus> Peers { get; } = [];

    public async Task InitializeAsync()
    {
        try
        {
            await _client.ConnectAsync();
            ServiceState = "Service connected";
            await RefreshAsync();

            var dispatcher = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread();
            _refreshTimer = dispatcher.CreateTimer();
            _refreshTimer.Interval = TimeSpan.FromSeconds(2);
            _refreshTimer.Tick += async (_, _) =>
            {
                try
                {
                    await RefreshAsync();
                }
                catch (Exception error)
                {
                    ServiceState = $"Status refresh failed: {error.Message}";
                }
            };
            _refreshTimer.Start();
        }
        catch (Exception error)
        {
            ServiceState = $"Service unavailable: {error.Message}";
        }
    }

    [RelayCommand]
    private async Task ConnectTunnelAsync()
    {
        // null configuration => service uses its persisted config (or
        // privacy defaults on first run).
        var response = await _client.ConnectTunnelAsync(null);
        ApplyResponse(response);
    }

    [RelayCommand]
    private async Task DisconnectTunnelAsync()
    {
        var response = await _client.DisconnectTunnelAsync();
        ApplyResponse(response);
    }

    [RelayCommand]
    private async Task RefreshStatusAsync()
    {
        await RefreshAsync();
    }

    [RelayCommand]
    private async Task ExportDiagnosticsAsync()
    {
        var response = await _client.ExportDiagnosticsAsync();
        DiagnosticsText = response.Text ?? response.Message ?? "";
    }

    private async Task RefreshAsync()
    {
        if (!_client.IsConnected)
        {
            return;
        }
        try
        {
            ApplyResponse(await _client.GetStatusAsync());
        }
        catch (Exception error)
        {
            ServiceState = $"Status refresh failed: {error.Message}";
        }
    }

    private void ApplyResponse(PipeResponse response)
    {
        if (response.Kind == "error")
        {
            LastError = response.Message;
            return;
        }
        var status = response.Status;
        if (status is null)
        {
            return;
        }
        Phase = status.Phase;
        PathType = status.PathType;
        RouteMode = status.RouteMode;
        DnsMode = status.DnsMode;
        OverlayAddress = status.OverlayIPv4Address;
        RouteSummary = string.Join(", ", status.ProtectedRoutes);
        KillSwitchEngaged = status.KillSwitchEngaged ?? false;
        LastError = status.LastError;
        IsConnected = status.Phase is "connected" or "degraded" or "reconnecting";
        PeerSummary = $"{status.Metrics.PeerCount} peers ({status.Metrics.DirectPeerCount} direct, {status.Metrics.RelayPeerCount} relay)";
        TrafficSummary = $"{FormatBytes(status.Metrics.BytesIn)} in · {FormatBytes(status.Metrics.BytesOut)} out · {status.Metrics.ReplayDrops} replay drops";
        TrustSummary =
            $"{FormatIdentityMode(status.PeerTrust.IdentityMode)} · {FormatTrustPolicy(status.PeerTrust.Policy)} · {(status.PeerTrust.Required ? "required" : "optional")}";
        RegistrySummary = FormatRegistrySummary(status.PeerTrust);
        TransportSummary = status.Transport is null
            ? "Transport metrics not reported yet"
            : $"state {status.Transport.StateCode} · path {status.Transport.PathKindCode} · {FormatBytes(status.Transport.BytesSent)} sent · {FormatBytes(status.Transport.BytesReceived)} received · {status.Transport.ReconnectCount} reconnects · {status.Transport.NetworkEventCount} network events";
        PacketPumpSummary = status.Pump is null
            ? "Packet pump metrics not reported yet"
            : $"{status.Pump.PacketsObserved} observed · {status.Pump.QueuedForTransport} queued · {status.Pump.TransportFramesEmitted} emitted · {status.Pump.FailedSubmissions} failed submissions";

        Peers.Clear();
        foreach (var peer in status.Peers)
        {
            Peers.Add(peer);
        }
    }

    private static string FormatBytes(ulong bytes)
    {
        var units = new[] { "B", "KB", "MB", "GB", "TB" };
        double value = bytes;
        var unitIndex = 0;
        while (value >= 1024 && unitIndex < units.Length - 1)
        {
            value /= 1024;
            unitIndex++;
        }
        return unitIndex == 0 ? $"{bytes} {units[unitIndex]}" : $"{value:0.##} {units[unitIndex]}";
    }

    private static string FormatRegistrySummary(DytallixPeerTrustSummary peerTrust)
    {
        var parts = new List<string>
        {
            peerTrust.RegistryConfigured ? "Registry configured" : "Registry not configured"
        };
        if (peerTrust.RegistryConfigured)
        {
            parts.Add($"{peerTrust.VerifiedPeerCount} verified");
            parts.Add($"{peerTrust.FailedPeerCount} blocked");
        }
        if (!string.IsNullOrWhiteSpace(peerTrust.LastFailureCode))
        {
            var label = FormatFailureCode(peerTrust.LastFailureCode);
            var detail = string.IsNullOrWhiteSpace(peerTrust.LastFailureSummary)
                ? label
                : $"{label}: {peerTrust.LastFailureSummary}";
            parts.Add(detail);
        }
        if (!string.IsNullOrWhiteSpace(peerTrust.Warning))
        {
            parts.Add($"Warning: {peerTrust.Warning}");
        }
        return string.Join(" · ", parts);
    }

    private static string FormatIdentityMode(string value) => value switch
    {
        "verified" => "Verified",
        "public_wallet" => "Public Wallet",
        "off" => "Off",
        _ => value
    };

    private static string FormatFailureCode(string value) => value switch
    {
        "rejected_missing_registry" => "Missing registry record",
        "rejected_revoked" => "Revoked registry record",
        "rejected_suspended" => "Suspended registry record",
        "rejected_expired" => "Expired registry record",
        "rejected_key_mismatch" => "Key mismatch",
        "rejected_record_hash_mismatch" => "Record hash mismatch",
        "rejected_stake_or_reputation" => "Stake or reputation check failed",
        "registry_unavailable" => "Registry unavailable",
        _ => value
    };

    private static string FormatTrustPolicy(string value) => value switch
    {
        "public_required" => "Public required",
        "private_preferred" => "Private preferred",
        "development_optional" => "Development optional",
        _ => value
    };
}
