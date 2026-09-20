using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using MissionController.UI.ViewModels;

namespace MissionController.UI.Views;

public sealed partial class SecurityAuditView : Page
{
    public SecurityAuditViewModel ViewModel { get; }

    public SecurityAuditView()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<SecurityAuditViewModel>();
        DataContext = ViewModel;

        Loaded += async (s, e) =>
        {
            await ViewModel.RefreshAllAsync();
            await ViewModel.VerifyChainIntegrityAsync();
        };
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.RefreshAllAsync();
    }

    private async void VerifyButton_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.VerifyChainIntegrityAsync();
    }

    private async void ExportRunRecord_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.ExportRunRecordAsync();
    }

    private async void ExportSoc2_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.ExportSoc2CompliancePackageAsync();
    }

    private async void ExportHipaa_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.ExportHipaaCompliancePackageAsync();
    }

    private async void ExportCmmc_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.ExportCmmcCompliancePackageAsync();
    }

    private async void TestSentinel_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.TestSiemSentinelAsync();
    }

    private async void TestSyslog_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.TestSiemSyslogCefAsync();
    }

    private async void TripCircuitBreaker_Click(object sender, RoutedEventArgs e)
    {
        var target = ViewModel.RevocationTarget?.Trim();
        if (string.IsNullOrEmpty(target))
        {
            var missingTargetDialog = new ContentDialog
            {
                XamlRoot = XamlRoot,
                Title = "Revocation target required",
                Content = "Enter an operator ID or token fingerprint before using the circuit breaker.",
                CloseButtonText = "Close"
            };
            await missingTargetDialog.ShowAsync();
            return;
        }

        var confirmationDialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = "Confirm emergency revocation",
            Content = $"Immediately revoke access for '{target}' and append the action to the audit ledger?",
            PrimaryButtonText = "Revoke access",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close
        };

        if (await confirmationDialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }

        await ViewModel.TriggerEmergencyRevocationAsync();
    }

    private async void ProactiveRenew_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.ProactiveRenewTokensAsync();
    }
}

