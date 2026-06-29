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
    [ObservableProperty] private string _overlayAddress = "";
    [ObservableProperty] private string _routeSummary = "";
    [ObservableProperty] private bool _killSwitchEngaged;
    [ObservableProperty] private string? _lastError;
    [ObservableProperty] private string _serviceState = "Connecting to service…";
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
        OverlayAddress = status.OverlayIPv4Address;
        RouteSummary = string.Join(", ", status.ProtectedRoutes);
        KillSwitchEngaged = status.KillSwitchEngaged ?? false;
        LastError = status.LastError;
        IsConnected = status.Phase is "connected" or "degraded" or "reconnecting";

        Peers.Clear();
        foreach (var peer in status.Peers)
        {
            Peers.Add(peer);
        }
    }
}
