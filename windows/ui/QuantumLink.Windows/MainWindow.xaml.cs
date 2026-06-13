using Microsoft.UI.Xaml;
using QuantumLink.Windows.ViewModels;

namespace QuantumLink.Windows;

public sealed partial class MainWindow : Window
{
    public DashboardViewModel ViewModel { get; } = new();

    public MainWindow()
    {
        InitializeComponent();
        _ = ViewModel.InitializeAsync();
    }
}
