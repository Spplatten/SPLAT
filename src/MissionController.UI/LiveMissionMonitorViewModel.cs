using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
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

    public LiveMissionMonitorViewModel(IMissionExecutionEngine engine)
    {
        _engine = engine;
    }

    [RelayCommand]
    public async Task LaunchAsync(LaunchMissionRequest request)
    {
        await StartMissionAsync(request.Template, request.Parameters, request.OperatorIdentity);
    }

    public async Task StartMissionAsync(SingleToolTemplate template, Dictionary<string, string> parameters, string operatorIdentity)
    {
        if (IsRunning) return;

        IsRunning = true;
        CurrentStatus = "Starting Mission...";
        MissionLog = string.Empty;
        StdoutStream = string.Empty;
        AiAnalysisStream = string.Empty;
        _cts = new CancellationTokenSource();

        try
        {
            await foreach (var chunk in _engine.ExecuteMissionAsync(template, parameters, operatorIdentity, _cts.Token))
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

    [RelayCommand]
    public void CancelMission()
    {
        _cts?.Cancel();
    }
}
