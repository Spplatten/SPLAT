using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Xaml;
using MissionController.Core;
using MissionController.Core.Crew;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.UI.ViewModels;

public record LaunchMissionRequest(
    SingleToolTemplate Template,
    Dictionary<string, string> Parameters,
    string OperatorIdentity);

public partial class LiveMissionMonitorViewModel : ObservableObject
{
    private readonly IMissionExecutionEngine _engine;
    private readonly IProjectExecutionEngine _projectEngine;
    private CancellationTokenSource? _cts;

    [ObservableProperty]
    private string _currentStatus = "Idle";

    [ObservableProperty]
    private string _missionLog = string.Empty;

    [ObservableProperty]
    private string _stdoutStream = string.Empty;

    [ObservableProperty]
    private string _aiAnalysisStream = string.Empty;

    [ObservableProperty]
    private double _cpuUsagePercent = 0.0;

    [ObservableProperty]
    private long _memoryUsageBytes = 0;

    [ObservableProperty]
    private bool _isRunning = false;

    [ObservableProperty]
    private string _jailPath = "None";

    // True once the engine signals no live model is connected. Drives a persistent banner so the
    // simulated analysis in the AI pane can never be mistaken for genuine model output.
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SimulatedBannerVisibility))]
    private bool _isSimulatedAnalysis;

    public Visibility SimulatedBannerVisibility =>
        IsSimulatedAnalysis ? Visibility.Visible : Visibility.Collapsed;

    private readonly IOperatorIdentityProvider _identityProvider;
    private readonly IGovernedCrewEngine? _crewEngine;

    public LiveMissionMonitorViewModel(
        IMissionExecutionEngine engine,
        IProjectExecutionEngine projectEngine,
        IOperatorIdentityProvider identityProvider,
        IGovernedCrewEngine? crewEngine = null)
    {
        _engine = engine;
        _projectEngine = projectEngine;
        _identityProvider = identityProvider;
        _crewEngine = crewEngine;
    }

    [RelayCommand]
    public async Task LaunchAsync(LaunchMissionRequest request)
    {
        await StartMissionAsync(request.Template, request.Parameters);
    }

    // The operatorIdentity parameter these two used to take was supplied by the caller as a string
    // literal - "Operator_SecOpsTier1", "Operator_ProjectLead" - so the ledger's actor column was
    // decided by whichever view happened to dispatch. Resolving it here removes the opportunity.
    public async Task StartMissionAsync(SingleToolTemplate template, Dictionary<string, string> parameters)
    {
        if (IsRunning) return;

        var actor = await _identityProvider.ResolveAsync();
        PrepareRun("Starting Mission...");
        await RunStreamAsync(_engine.ExecuteMissionAsync(template, parameters, actor.ToLedgerIdentity(), _cts!.Token));
    }

    public async Task StartProjectAsync(ProjectTemplate project, Dictionary<string, string> parameters)
    {
        if (IsRunning) return;

        var actor = await _identityProvider.ResolveAsync();
        PrepareRun("Starting Project...");
        await RunStreamAsync(_projectEngine.ExecuteProjectAsync(project, parameters, actor.ToLedgerIdentity(), _cts!.Token));
    }

    public async Task StartCrewAsync(GovernedCrewDefinition crew, Dictionary<string, string> parameters)
    {
        if (IsRunning) return;
        if (_crewEngine == null) return;

        var actor = await _identityProvider.ResolveAsync();
        PrepareRun($"Starting Governed Crew '{crew.Name}'...");
        await RunStreamAsync(_crewEngine.ExecuteCrewAsync(crew, parameters, actor.ToLedgerIdentity(), _cts!.Token));
    }

    [RelayCommand]
    public void CancelMission()
    {
        _cts?.Cancel();
    }

    private void PrepareRun(string status)
    {
        IsRunning = true;
        CurrentStatus = status;
        MissionLog = string.Empty;
        StdoutStream = string.Empty;
        AiAnalysisStream = string.Empty;
        IsSimulatedAnalysis = false;
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
    }

    private async Task RunStreamAsync(IAsyncEnumerable<MissionChunk> stream)
    {
        try
        {
            await foreach (var chunk in stream)
            {
                switch (chunk.ChunkType)
                {
                    case MissionChunkType.StatusChange:
                        CurrentStatus = chunk.Content;
                        MissionLog += $"[{chunk.TimestampUtc:HH:mm:ss}] STATUS: {chunk.Content}\n";
                        break;
                    case MissionChunkType.Stdout:
                        StdoutStream += chunk.Content;
                        break;
                    case MissionChunkType.Stderr:
                        MissionLog += $"[{chunk.TimestampUtc:HH:mm:ss}] STDERR: {chunk.Content}\n";
                        break;
                    case MissionChunkType.AiToken:
                        AiAnalysisStream += chunk.Content;
                        break;
                    case MissionChunkType.SimulatedNotice:
                        IsSimulatedAnalysis = true;
                        MissionLog += $"[{chunk.TimestampUtc:HH:mm:ss}] SIMULATED: {chunk.Content}\n";
                        break;
                    case MissionChunkType.Metric:
                        MissionLog += $"[{chunk.TimestampUtc:HH:mm:ss}] METRIC: {chunk.Content}\n";
                        break;
                    case MissionChunkType.Completed:
                        CurrentStatus = "Completed";
                        MissionLog += $"[{chunk.TimestampUtc:HH:mm:ss}] {chunk.Content}\n";
                        break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            CurrentStatus = "Mission Aborted";
            MissionLog += "\n[ABORT] Mission terminated by operator.\n";
        }
        catch (Exception ex)
        {
            CurrentStatus = "Mission Failed";
            MissionLog += $"\n[ERROR] {ex.Message}\n";
        }
        finally
        {
            IsRunning = false;
        }
    }
}
