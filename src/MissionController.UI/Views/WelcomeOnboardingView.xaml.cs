using System;
using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using MissionController.Core;
using MissionController.UI.ViewModels;

namespace MissionController.UI.Views;

public sealed partial class WelcomeOnboardingView : Page
{
    public WelcomeOnboardingViewModel ViewModel { get; }

    public WelcomeOnboardingView()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<WelcomeOnboardingViewModel>();
        DataContext = ViewModel;
    }

    public Visibility GetStep1Visibility(int step) => step == 1 ? Visibility.Visible : Visibility.Collapsed;
    public Visibility GetStep2Visibility(int step) => step == 2 ? Visibility.Visible : Visibility.Collapsed;
    public Visibility GetStep3Visibility(int step) => step == 3 ? Visibility.Visible : Visibility.Collapsed;
    public Visibility GetBackVisibility(int step) => step > 1 ? Visibility.Visible : Visibility.Collapsed;
    public Visibility GetBoolVisibility(bool visible) => visible ? Visibility.Visible : Visibility.Collapsed;
    public Visibility GetNoticeVisibility(string? notice) => string.IsNullOrWhiteSpace(notice) ? Visibility.Collapsed : Visibility.Visible;

    public string GetLegalExpandButtonText(bool expanded) => expanded ? "Hide Legal Text" : "Read Full Agreements";

    public string GetNextButtonText(int step)
    {
        return step switch
        {
            1 => "Accept & Continue",
            2 => "Save & Proceed",
            3 => "Enter Mission Control",
            _ => "Continue"
        };
    }

    private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox pb)
        {
            ViewModel.ApiKeyInput = pb.Password;
        }
    }

    private async void PasswordBox_KeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
    {
        if (e.Key == Windows.System.VirtualKey.Enter && !ViewModel.IsTestingKey)
        {
            await ViewModel.ValidateKeyAsync();
        }
    }

    /// <summary>
    /// Opens the Field Guide that shipped with this build in the default browser. A failure is
    /// reported in place rather than swallowed: a link that does nothing when clicked is the same
    /// dead end as the private-repository URL this replaced, just quieter.
    /// </summary>
    private void FieldGuideButton_Click(object sender, RoutedEventArgs e)
    {
        string? guide = ShippedFieldGuide.Locate();

        if (guide is null)
        {
            Report($"This build did not ship {ShippedFieldGuide.FileName}. Expected it in the docs "
                   + $"folder beside {AppContext.BaseDirectory}");
            return;
        }

        try
        {
            // UseShellExecute is required: the target is a document, and the browser that opens it
            // is whatever this machine has associated with .html.
            Process.Start(new ProcessStartInfo(guide) { UseShellExecute = true });
            FieldGuideStatus.Visibility = Visibility.Collapsed;
        }
        catch (Exception ex)
        {
            Report($"Could not open {guide}: {ex.Message}");
        }

        void Report(string message)
        {
            FieldGuideStatus.Text = message;
            FieldGuideStatus.Visibility = Visibility.Visible;
        }
    }

    private void NextOrFinishButton_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.CurrentStep < 3)
        {
            ViewModel.NextStep();
        }
        else
        {
            // Finish Onboarding and enter main Quick Diagnostician / Monitor
            if (App.MainWindowInstance is MainWindow mainWin)
            {
                mainWin.NavigateTo(typeof(QuickDiagnosticianView));
            }
        }
    }
}
