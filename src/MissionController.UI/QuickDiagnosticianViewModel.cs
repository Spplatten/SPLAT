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
        IDiagnosticFindingsExtractor? findingsExtractor = null)
    {
        _engine = engine;
        _templateRegistry = templateRegistry;
        _remediationEngine = remediationEngine;
        _findingsExtractor = findingsExtractor ?? new JsonFindingsExtractor();

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

        ActiveDiagnosticTitle = $"Custom Agent Mission: \"{CustomAskText}\"";
        string templateId = "net-dns-audit";

        string lower = CustomAskText.ToLowerInvariant();
        if (lower.Contains("login") || lower.Contains("hack") || lower.Contains("attack") || lower.Contains("intrud"))
            templateId = "secops-auth-inspector";
        else if (lower.Contains("disk") || lower.Contains("space") || lower.Contains("storage") || lower.Contains("clean"))
            templateId = "sysops-disk-space";
        else if (lower.Contains("virus") || lower.Contains("defender") || lower.Contains("malware"))
            templateId = "secops-defender-status";
        else if (lower.Contains("active directory") || lower.Contains("domain") || lower.Contains("kerberos") || lower.Contains("ad"))
            templateId = "identity-ad-group-hygiene";
        else if (lower.Contains("azure") || lower.Contains("cloud") || lower.Contains("entra") || lower.Contains("sso"))
            templateId = "identity-entra-hybrid-join";
        else if (lower.Contains("patch") || lower.Contains("update") || lower.Contains("hotfix") || lower.Contains("cve"))
            templateId = "sysops-patch-compliance";
        else if (lower.Contains("registry") || lower.Contains("startup") || lower.Contains("autorun") || lower.Contains("persist"))
            templateId = "endpoint-persistence-audit";

        await ExecuteQuickDiagnosticAsync(templateId, "Custom Agent Mission", CustomAskText);
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
            var result = await _remediationEngine.ExecuteFixAsync(fix, "Operator_1Click");
            if (result.Success)
            {
                RemediationStatusMessage = $"⚡ Fix Applied Successfully: {fix.Title}";
                ExecutiveFindings.Add($"✓ Self-Healing Fix Applied: {fix.Title}");
            }
            else
            {
                RemediationStatusMessage = $"🔴 Fix Failed: {result.ErrorMessage}";
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
            var result = await _remediationEngine.ExecuteRollbackAsync(fix, "Operator_1Click");
            if (result.Success)
            {
                RemediationStatusMessage = $"↩️ Rollback Completed: {fix.Title} restored.";
                ExecutiveFindings.Add($"↩️ Rollback Verified: Restored previous state for {fix.Title}");
            }
            else
            {
                RemediationStatusMessage = $"🔴 Rollback Failed: {result.ErrorMessage}";
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

            await foreach (var chunk in _engine.ExecuteMissionAsync(template, parameters, "Operator_AuntMaryTier1"))
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
