using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MissionController.Core;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.UI.ViewModels;

public record FriendlyDiagnosticTile(
    string TileId,
    string TemplateId,
    string Title,
    string Subtitle,
    string IconGlyph,
    string AccentColor);

public partial class QuickDiagnosticianViewModel : ObservableObject
{
    private readonly IMissionExecutionEngine _engine;
    private readonly ITemplateRegistry _templateRegistry;
    private readonly IRemediationEngine _remediationEngine;
    private readonly IDiagnosticFindingsExtractor _findingsExtractor;
    private readonly IAgentBrain? _agentBrain;
    private readonly IOperatorIdentityProvider _identityProvider;

    /// <summary>
    /// The ledger actor for whatever this view model dispatches. Every call site below used to pass
    /// a string literal - "Operator_AuntMaryTier1" for missions, "Operator_1Click" for remediation -
    /// so the audit trail's actor column recorded a name nobody had established.
    /// </summary>
    private async Task<string> ResolveActorAsync() =>
        (await _identityProvider.ResolveAsync()).ToLedgerIdentity();

    [ObservableProperty]
    private ObservableCollection<FriendlyDiagnosticTile> _tiles = new();

    [ObservableProperty]
    private string _customAskText = string.Empty;

    [ObservableProperty]
    private bool _isRunning;

    [ObservableProperty]
    private bool _hasResult;

    [ObservableProperty]
    private string _executiveStatusTitle = "🟢 ALL CLEAR — System Healthy";

    [ObservableProperty]
    private string _executiveStatusColor = "#6CCB5F";

    [ObservableProperty]
    private ObservableCollection<string> _executiveFindings = new();

    [ObservableProperty]
    private ObservableCollection<RemediationAction> _availableFixes = new();

    [ObservableProperty]
    private string _remediationStatusMessage = string.Empty;

    [ObservableProperty]
    private bool _isRemediating;

    [ObservableProperty]
    private string _technicalRawLog = string.Empty;

    [ObservableProperty]
    private string _activeDiagnosticTitle = string.Empty;

    public QuickDiagnosticianViewModel(
        IMissionExecutionEngine engine,
        ITemplateRegistry templateRegistry,
        IRemediationEngine remediationEngine,
        IDiagnosticFindingsExtractor? findingsExtractor = null,
        IAgentBrain? agentBrain = null,
        IOperatorIdentityProvider? identityProvider = null)
    {
        _engine = engine;
        _templateRegistry = templateRegistry;
        _remediationEngine = remediationEngine;
        _findingsExtractor = findingsExtractor ?? new JsonFindingsExtractor();
        _agentBrain = agentBrain;
        _identityProvider = identityProvider
            ?? new StaticOperatorIdentityProvider(OperatorIdentity.Unknown("winui-console"));

        // Populate the frontline governed autonomous AI agents.
        Tiles.Add(new FriendlyDiagnosticTile("network", "net-dns-audit", "Atlas-Net", "Diagnoses connection drops, high latency, and listening sockets", "\uE774", "#00E5FF"));
        Tiles.Add(new FriendlyDiagnosticTile("security", "secops-auth-inspector", "Sentinel-SecOps", "Hunts for unauthorized login attempts and brute-force attacks", "\uE72E", "#FF7043"));
        Tiles.Add(new FriendlyDiagnosticTile("disk", "sysops-disk-space", "Titan-SysOps", "Analyzes hard drive space exhaustion and suggests safe cleanup targets", "\uEDA2", "#AB47BC"));
        Tiles.Add(new FriendlyDiagnosticTile("antivirus", "secops-defender-status", "Aegis-Endpoint", "Verifies Microsoft Defender real-time shield and signature freshness", "\uE815", "#6CCB5F"));
        Tiles.Add(new FriendlyDiagnosticTile("activedirectory", "identity-ad-group-hygiene", "Vanguard-AD", "Audits Active Directory identity, Kerberos tickets, and privileged SIDs", "\uE716", "#FFD700"));
        Tiles.Add(new FriendlyDiagnosticTile("azurecloud", "identity-entra-hybrid-join", "Zephyr-Azure", "Audits Microsoft Entra ID hybrid sync and cloud login latency", "\uE753", "#38B6FF"));
        Tiles.Add(new FriendlyDiagnosticTile("patches", "sysops-patch-compliance", "Chronos-Patch", "Audits installed Windows Quality updates, CVEs, and missing hotfixes", "\uE895", "#FFA726"));
        Tiles.Add(new FriendlyDiagnosticTile("registry", "endpoint-persistence-audit", "Cypher-Registry", "Audits startup Run/RunOnce persistence keys and malware hooks", "\uE72D", "#BA68C8"));
    }

    [RelayCommand]
    public async Task RunTileDiagnosticAsync(FriendlyDiagnosticTile tile)
    {
        ActiveDiagnosticTitle = $"Agent Dispatched: {tile.Title}";
        await ExecuteQuickDiagnosticAsync(tile.TemplateId, tile.Title, string.Empty);
    }

    [RelayCommand]
    public async Task RunCustomAskAsync()
    {
        if (string.IsNullOrWhiteSpace(CustomAskText))
            return;

        ActiveDiagnosticTitle = $"🧠 Autonomous Agent Brain: \"{CustomAskText}\"";

        if (_agentBrain != null)
        {
            await ExecuteAutonomousBrainAsync(CustomAskText);
            return;
        }

        // Fallback if brain is not registered
        await ExecuteQuickDiagnosticAsync("net-dns-audit", "Custom Agent Mission", CustomAskText);
    }

    private async Task ExecuteAutonomousBrainAsync(string userGoal)
    {
        IsRunning = true;
        HasResult = false;
        ExecutiveFindings.Clear();
        AvailableFixes.Clear();
        RemediationStatusMessage = string.Empty;
        TechnicalRawLog = string.Empty;

        var rawLogSb = new System.Text.StringBuilder();
        var progress = new Progress<MissionChunk>(chunk =>
        {
            if (chunk.ChunkType == MissionChunkType.StatusChange || chunk.ChunkType == MissionChunkType.Completed)
            {
                rawLogSb.AppendLine($"[{chunk.TimestampUtc:HH:mm:ss}] {chunk.Content}");
                TechnicalRawLog = rawLogSb.ToString();
            }
            else if (chunk.ChunkType == MissionChunkType.Stdout || chunk.ChunkType == MissionChunkType.AiToken)
            {
                rawLogSb.Append(chunk.Content);
                TechnicalRawLog = rawLogSb.ToString();
            }
        });

        try
        {
            var result = await _agentBrain!.ProcessGoalAsync(
                userGoal: userGoal,
                operatorIdentity: await ResolveActorAsync(),
                maxReasoningSteps: 3,
                progress: progress);

            ExecutiveStatusTitle = result.ExecutiveHeadline;
            ExecutiveStatusColor = result.OverallStatus switch
            {
                DiagnosticHealthStatus.Critical => "#E53935",
                DiagnosticHealthStatus.Warning => "#FFB300",
                DiagnosticHealthStatus.Unknown => "#FFB300",
                _ => "#6CCB5F"
            };

            foreach (var finding in result.GroundedKeyFindings)
            {
                ExecutiveFindings.Add(finding);
            }

            if (!string.IsNullOrWhiteSpace(result.RootCauseAnalysis))
            {
                ExecutiveFindings.Add($"🔬 {result.RootCauseAnalysis}");
            }

            foreach (var fix in result.AvailableRemediations)
            {
                AvailableFixes.Add(fix);
            }

            HasResult = true;
        }
        catch (Exception ex)
        {
            ExecutiveStatusTitle = "🔴 Agent Brain Alert";
            ExecutiveStatusColor = "#E53935";
            ExecutiveFindings.Add($"Autonomous reasoning encountered an error: {ex.Message}");
            HasResult = true;
        }
        finally
        {
            IsRunning = false;
        }
    }

    [RelayCommand]
    public void Reset()
    {
        HasResult = false;
        IsRunning = false;
        ExecutiveFindings.Clear();
        AvailableFixes.Clear();
        TechnicalRawLog = string.Empty;
        ActiveDiagnosticTitle = string.Empty;
        RemediationStatusMessage = string.Empty;
    }

    [RelayCommand]
    public async Task ApplyFixAsync(RemediationAction fix)
    {
        if (fix == null) return;

        IsRemediating = true;
        RemediationStatusMessage = $"Applying Governed Fix: {fix.Title}...";

        try
        {
            var result = await _remediationEngine.ExecuteFixAsync(fix, await ResolveActorAsync());
            if (result.Success)
            {
                if (result.Verdict == RemediationVerdict.VerifiedFix)
                {
                    RemediationStatusMessage = $"⚡ Fix Applied & Verified: {fix.Title}";
                    ExecutiveFindings.Add($"✓ Self-Healing Fix Verified: {fix.Title} (postcondition confirmed)");
                }
                else
                {
                    RemediationStatusMessage = $"⚡ Fix Executed (Unverified): {fix.Title}";
                    ExecutiveFindings.Add($"⚡ Fix Executed: {fix.Title} (unverified: no postcondition declared)");
                }
            }
            else
            {
                RemediationStatusMessage = $"🔴 Fix Failed: {result.ErrorMessage}";
                if (result.Verdict == RemediationVerdict.PostconditionFailed)
                {
                    ExecutiveFindings.Add($"🔴 Fix Postcondition Failed: {fix.Title} - {result.ErrorMessage}");
                }
            }
        }
        catch (Exception ex)
        {
            RemediationStatusMessage = $"🔴 Fix Error: {ex.Message}";
        }
        finally
        {
            IsRemediating = false;
        }
    }

    [RelayCommand]
    public async Task ApplyRollbackAsync(RemediationAction fix)
    {
        if (fix == null || !fix.CanRollback) return;

        IsRemediating = true;
        RemediationStatusMessage = $"Rolling back fix: {fix.Title}...";

        try
        {
            var result = await _remediationEngine.ExecuteRollbackAsync(fix, await ResolveActorAsync());
            if (result.Success)
            {
                if (result.Verdict == RemediationVerdict.Restored)
                {
                    RemediationStatusMessage = $"↩️ Rollback Completed & Restored: {fix.Title}";
                    ExecutiveFindings.Add($"↩️ Rollback Verified: Restored previous state for {fix.Title} (postcondition confirmed)");
                }
                else
                {
                    RemediationStatusMessage = $"↩️ Rollback Executed (Unverified): {fix.Title}";
                    ExecutiveFindings.Add($"↩️ Rollback Executed: {fix.Title} (unverified: no postcondition declared)");
                }
            }
            else
            {
                RemediationStatusMessage = $"🔴 Rollback Failed: {result.ErrorMessage}";
                if (result.Verdict == RemediationVerdict.PostconditionFailed)
                {
                    ExecutiveFindings.Add($"🔴 Rollback Postcondition Failed: {fix.Title} - {result.ErrorMessage}");
                }
            }
        }
        catch (Exception ex)
        {
            RemediationStatusMessage = $"🔴 Rollback Error: {ex.Message}";
        }
        finally
        {
            IsRemediating = false;
        }
    }

    private async Task ExecuteQuickDiagnosticAsync(string templateId, string categoryTitle, string userDirective)
    {
        IsRunning = true;
        HasResult = false;
        ExecutiveFindings.Clear();
        AvailableFixes.Clear();
        RemediationStatusMessage = string.Empty;
        TechnicalRawLog = string.Empty;

        try
        {
            var template = await _templateRegistry.GetTemplateByIdAsync(templateId);
            if (template == null)
            {
                ExecutiveStatusTitle = "🟡 Agent Template Unavailable";
                ExecutiveStatusColor = "#FFB300";
                ExecutiveFindings.Add($"The requested AI agent template '{templateId}' is not found in the local registry.");
                HasResult = true;
                return;
            }

            // Populate available self-healing remediations for this agent
            foreach (var fix in template.Remediations)
            {
                AvailableFixes.Add(fix);
            }

            var parameters = new Dictionary<string, string>();
            if (!string.IsNullOrWhiteSpace(userDirective))
            {
                parameters["UserInstruction"] = userDirective;
            }

            var rawOutput = new System.Text.StringBuilder();
            var aiOutput = new System.Text.StringBuilder();

            await foreach (var chunk in _engine.ExecuteMissionAsync(template, parameters, await ResolveActorAsync()))
            {
                if (chunk.ChunkType == MissionChunkType.Stdout)
                {
                    rawOutput.Append(chunk.Content);
                }
                else if (chunk.ChunkType == MissionChunkType.AiToken)
                {
                    aiOutput.Append(chunk.Content);
                }
            }

            TechnicalRawLog = $"{rawOutput}\n\n--- AI Agent Reasoning Stream ---\n{aiOutput}";

            var diagnosisResult = _findingsExtractor.ExtractFindings(
                aiOutput.ToString(),
                rawOutput.ToString(),
                template.Name);

            ExecutiveStatusTitle = diagnosisResult.StatusHeadline;
            ExecutiveStatusColor = diagnosisResult.OverallStatus switch
            {
                DiagnosticHealthStatus.Critical => "#E53935",
                DiagnosticHealthStatus.Warning => "#FFB300",
                // Unknown means the extractor got neither a model verdict nor usable telemetry.
                // It must NOT share Healthy's green: painting an absence of evidence as a clean
                // bill of health is the exact failure mode the structured-findings work removes.
                DiagnosticHealthStatus.Unknown => "#FFB300",
                _ => "#6CCB5F"
            };

            foreach (var finding in diagnosisResult.KeyFindings)
            {
                ExecutiveFindings.Add(finding);
            }

            if (diagnosisResult.RecommendedActions != null && diagnosisResult.RecommendedActions.Count > 0)
            {
                foreach (var action in diagnosisResult.RecommendedActions)
                {
                    ExecutiveFindings.Add($"⚡ Recommended Action: {action}");
                }
            }

            HasResult = true;
        }
        catch (Exception ex)
        {
            ExecutiveStatusTitle = "🔴 Agent Alert";
            ExecutiveStatusColor = "#E53935";
            ExecutiveFindings.Add($"Agent execution encountered an error: {ex.Message}");
            HasResult = true;
        }
        finally
        {
            IsRunning = false;
        }
    }
}
