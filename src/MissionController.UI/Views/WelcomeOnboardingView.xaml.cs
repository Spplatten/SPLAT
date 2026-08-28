using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
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
