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
using MissionController.Infrastructure.Network.Siem;

namespace MissionController.UI.ViewModels;

public partial class SecurityAuditViewModel : ObservableObject
{
    private readonly IAuditLedger _auditLedger;
    private readonly IMerkleProofEngine _merkleEngine;
    private readonly IComplianceArchiveExporter _archiveExporter;
    private readonly IMissionRunRecordAssembler _runRecords;
    private readonly ISiemForwarder _siemForwarder;
    private readonly IEdrIngestionBridge _edrBridge;
    private readonly IIncidentRevocationManager _revocationManager;
    private readonly ITokenLifecycleManager _tokenLifecycleManager;
    private readonly ICredentialVault _vault;
    private readonly IOperatorIdentityProvider _identityProvider;

    /// <summary>
    /// The actor recorded against a compliance export or an emergency revocation. These used to pass
    /// Environment.UserName, which is a display string with no provenance behind it - and the
    /// compliance package records this value, so its provenance must not be caller-controlled.
    /// </summary>
    private async Task<string> ResolveActorAsync() =>
        (await _identityProvider.ResolveAsync()).ToLedgerIdentity();

    [ObservableProperty]
    private ObservableCollection<AuditLogEntry> _auditLogs = new();

    [ObservableProperty]
    private ObservableCollection<EdrSecurityAlert> _edrAlerts = new();

    [ObservableProperty]
    private string _runRecordMissionId = string.Empty;

    [ObservableProperty]
    private string _runRecordStatus = "Export one mission's run record: what it was permitted to do, what it did, and its ledger entries with proofs.";

    [ObservableProperty]
    private ObservableCollection<RevocationEntry> _activeRevocations = new();

    [ObservableProperty]
    private string _integrityStatus = "Ledger Integrity Unchecked";

    [ObservableProperty]
    private bool _isLedgerValid = true;

    [ObservableProperty]
    private string _merkleRootHash = "Not Computed";

    [ObservableProperty]
    private string _merkleVerificationStatus = "Merkle Tree Unverified";

    [ObservableProperty]
    private string _complianceExportStatus = "Export selected rows as unsigned evidence; this is not an assessment or continuous coverage report.";

    [ObservableProperty]
    private string _lastExportedPackagePath = string.Empty;

    [ObservableProperty]
    private EdrDevicePosture? _devicePosture;

    [ObservableProperty]
    private string _edrStatusSummary = "EDR Status: Fetching...";

    [ObservableProperty]
    private string _siemStatusMessage = "SIEM Forwarding: Idle";

    [ObservableProperty]
    private string _revocationTarget = string.Empty;

    [ObservableProperty]
    private string _revocationReason = "Compromised credential / operator revocation";

    [ObservableProperty]
    private string _revocationType = "OPERATOR_IDENTITY";

    [ObservableProperty]
    private string _revocationActionMessage = "Circuit Breaker: Armed";

    [ObservableProperty]
    private string _oAuthTokenTtlStatus = "OAuth Token: Checking...";

    [ObservableProperty]
    private string _saTokenTtlStatus = "Service Account Token: Checking...";

    [ObservableProperty]
    private string _tokenRenewalStatusMessage = "Token Lifecycle: Automated Auto-Renew Active";

    [ObservableProperty]
    private bool _isProcessing = false;

    public SecurityAuditViewModel(
        IAuditLedger auditLedger,
        IMerkleProofEngine merkleEngine,
        IComplianceArchiveExporter archiveExporter,
        IMissionRunRecordAssembler runRecords,
        ISiemForwarder siemForwarder,
        IEdrIngestionBridge edrBridge,
        IIncidentRevocationManager revocationManager,
        ITokenLifecycleManager tokenLifecycleManager,
        ICredentialVault vault,
        IOperatorIdentityProvider? identityProvider = null)
    {
        _auditLedger = auditLedger;
        _merkleEngine = merkleEngine;
        _archiveExporter = archiveExporter;
        _runRecords = runRecords;
        _siemForwarder = siemForwarder;
        _edrBridge = edrBridge;
        _revocationManager = revocationManager;
        _tokenLifecycleManager = tokenLifecycleManager;
        _vault = vault;
        _identityProvider = identityProvider
            ?? new StaticOperatorIdentityProvider(OperatorIdentity.Unknown("winui-console"));
    }


    [RelayCommand]
    public async Task RefreshAllAsync()
    {
        await RefreshAuditLogsAsync();
        await RefreshEdrPostureAsync();
        await CheckTokenHealthAsync();
    }

    [RelayCommand]
    public async Task RefreshAuditLogsAsync()
    {
        var logs = await _auditLedger.GetAuditLogsAsync(null, 200);
        AuditLogs.Clear();
        foreach (var log in logs)
        {
            AuditLogs.Add(log);
        }

        if (AuditLogs.Count > 0)
        {
            var tree = _merkleEngine.BuildTree(AuditLogs.ToList());
            MerkleRootHash = tree.RootHash;
        }
        else
        {
            MerkleRootHash = "0000000000000000000000000000000000000000000000000000000000000000";
        }
    }

    [RelayCommand]
    public async Task VerifyChainIntegrityAsync()
    {
        bool isChainValid = await _auditLedger.VerifyLedgerIntegrityAsync();
        IsLedgerValid = isChainValid;

        if (!isChainValid)
        {
            IntegrityStatus = "ALERT: Cryptographic Hash Chain Mismatch Detected!";
            MerkleVerificationStatus = "FAILED: Audit ledger chain compromised!";
            return;
        }

        IntegrityStatus = "VALIDATED: SHA-256 Chained Hash Integrity Verified (Zero Tampering Detected)";

        // Verify Merkle Tree Proofs across all entries
        if (AuditLogs.Count > 0)
        {
            var entries = AuditLogs.ToList();
            var tree = _merkleEngine.BuildTree(entries);
            MerkleRootHash = tree.RootHash;

            bool allProofsValid = true;
            foreach (var entry in entries)
            {
                var proof = _merkleEngine.GenerateProof(tree, entry.Id);
                if (!_merkleEngine.VerifyProof(proof))
                {
                    allProofsValid = false;
                    break;
                }
            }

            MerkleVerificationStatus = allProofsValid
                ? $"VERIFIED: All {entries.Count} Merkle leaf proofs matched Root ({tree.RootHash.Substring(0, 16)}...)"
                : "ALERT: Merkle proof verification failed!";
        }
        else
        {
            MerkleVerificationStatus = "VERIFIED: Merkle Tree (0 entries / Genesis state)";
        }
    }

    [RelayCommand]
    public async Task RefreshEdrPostureAsync()
    {
        try
        {
            var posture = await _edrBridge.GetLocalDevicePostureAsync();
            DevicePosture = posture;
            EdrStatusSummary = $"{posture.Provider} | Real-Time: {(posture.RealTimeProtectionEnabled ? "ACTIVE" : "DISABLED")} | Isolation: {posture.IsolationState}";

            var alerts = await _edrBridge.GetRecentAlertsAsync(10);
            EdrAlerts.Clear();
            foreach (var alert in alerts)
            {
                EdrAlerts.Add(alert);
            }
        }
        catch (Exception ex)
        {
            EdrStatusSummary = $"EDR Error: {ex.Message}";
        }
    }

    [RelayCommand]
    public async Task ExportSoc2CompliancePackageAsync()
    {
        await ExportPackageInternalAsync(ComplianceFramework.Soc2Type2);
    }

    [RelayCommand]
    public async Task ExportIso27001CompliancePackageAsync()
    {
        await ExportPackageInternalAsync(ComplianceFramework.Iso27001);
    }

    [RelayCommand]
    public async Task ExportHipaaCompliancePackageAsync()
    {
        await ExportPackageInternalAsync(ComplianceFramework.Hipaa);
    }

    [RelayCommand]
    public async Task ExportCmmcCompliancePackageAsync()
    {
        await ExportPackageInternalAsync(ComplianceFramework.CmmcLevel2);
    }

    /// <summary>
    /// Exports one mission's run record. Everything in the bundle comes from the ledger, so a mission
    /// that never sealed its facts is refused here rather than described from its other rows.
    /// </summary>
    [RelayCommand]
    public async Task ExportRunRecordAsync()
    {
        string wanted = RunRecordMissionId.Trim();
        if (wanted.Length == 0)
        {
            wanted = AuditLogs.FirstOrDefault()?.MissionId.ToString("D") ?? string.Empty;
        }

        if (!Guid.TryParse(wanted, out var missionId))
        {
            RunRecordStatus = "Type the mission id of a finished mission, or load the ledger first.";
            return;
        }

        IsProcessing = true;
        RunRecordStatus = $"Assembling the run record for {missionId:D}...";
        try
        {
            string zipPath = await _runRecords.AssembleAndExportBundleAsync(missionId, string.Empty);
            LastExportedPackagePath = zipPath;
            RunRecordStatus = $"Exported {System.IO.Path.GetFileName(zipPath)}. Run verify_proofs inside it to check the bundle.";
        }
        catch (Exception ex)
        {
            RunRecordStatus = $"Not exported: {ex.Message}";
        }
        finally
        {
            IsProcessing = false;
        }
    }

    private async Task ExportPackageInternalAsync(ComplianceFramework framework)
    {
        IsProcessing = true;
        ComplianceExportStatus = $"Exporting {framework} Package (Building Merkle Proofs & ZIP)...";

        try
        {
            var entries = AuditLogs.Count > 0 ? AuditLogs.ToList() : (await _auditLedger.GetAuditLogsAsync(null, 500)).ToList();
            string zipPath = await _archiveExporter.ExportCompliancePackageAsync(framework, "", entries, await ResolveActorAsync());
            LastExportedPackagePath = zipPath;
            ComplianceExportStatus = $"Exported {entries.Count} selected rows for {framework} (unsigned): {System.IO.Path.GetFileName(zipPath)}";
        }
        catch (Exception ex)
        {
            ComplianceExportStatus = $"FAILED: Export error: {ex.Message}";
        }
        finally
        {
            IsProcessing = false;
        }
    }

    [RelayCommand]
    public async Task TestSiemSentinelAsync()
    {
        SiemStatusMessage = "Testing Microsoft Sentinel connection...";
        try
        {
            string? wsId = await _vault.RetrieveSecretStringAsync("Siem.Sentinel.WorkspaceId");
            string? sharedKey = await _vault.RetrieveSecretStringAsync("Siem.Sentinel.SharedKey");

            if (string.IsNullOrWhiteSpace(wsId) || string.IsNullOrWhiteSpace(sharedKey))
            {
                SiemStatusMessage = "Microsoft Sentinel: Not configured. Save 'Siem.Sentinel.WorkspaceId' and 'Siem.Sentinel.SharedKey' in DPAPI vault to enable real-time ingestion.";
                return;
            }

            var testConfig = new SiemConfiguration(
                SiemProtocol.MicrosoftSentinel,
                $"https://{wsId}.ods.opinsights.azure.com",
                443,
                true,
                WorkspaceId: wsId,
                SharedKey: sharedKey);

            bool success = await _siemForwarder.TestConnectionAsync(testConfig);
            SiemStatusMessage = success
                ? $"SENTINEL READY: Verified live HMAC-SHA256 authenticated transmission to Workspace {wsId.Substring(0, 8)}..."
                : "SENTINEL ALERT: Verification request failed or credentials rejected.";
        }
        catch (Exception ex)
        {
            SiemStatusMessage = $"SIEM Test Error: {ex.Message}";
        }
    }

    [RelayCommand]
    public async Task TestSiemSyslogCefAsync()
    {
        SiemStatusMessage = "Validating CEF / RFC 5424 Syslog datagram formatting...";
        try
        {
            var auditEntry = AuditLogs.FirstOrDefault() ?? new AuditLogEntry(
                1, DateTime.UtcNow, Guid.NewGuid(), "SIEM_PROBE", "SYS_HEALTH", "System health probe verified", await ResolveActorAsync(), "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000");
            
            var syslog = new SyslogMessage(
                1, 6, DateTimeOffset.UtcNow, Environment.MachineName.ToLowerInvariant(), "MissionController", Environment.ProcessId.ToString(), "AUDIT_EVENT", auditEntry.Details);
            string formatted = SiemForwarder.FormatRfc5424(syslog);

            string? syslogHost = await _vault.RetrieveSecretStringAsync("Siem.Syslog.Host");
            if (!string.IsNullOrWhiteSpace(syslogHost))
            {
                var cfg = new SiemConfiguration(SiemProtocol.SyslogUdp, syslogHost, 514, false);
                bool connected = await _siemForwarder.TestConnectionAsync(cfg);
                SiemStatusMessage = connected
                    ? $"SYSLOG LIVE: Verified UDP transmission to {syslogHost}:514"
                    : $"SYSLOG ALERT: Could not reach {syslogHost}:514";
            }
            else
            {
                SiemStatusMessage = $"CEF/SYSLOG READY: Validated RFC 5424 framing ({formatted.Substring(0, Math.Min(40, formatted.Length))}...). Configure 'Siem.Syslog.Host' in vault for network dispatch.";
            }
        }
        catch (Exception ex)
        {
            SiemStatusMessage = $"Syslog Error: {ex.Message}";
        }
    }

    [RelayCommand]
    public async Task TriggerEmergencyRevocationAsync()
    {
        if (string.IsNullOrWhiteSpace(RevocationTarget))
        {
            RevocationActionMessage = "ERROR: Please specify target identifier to revoke.";
            return;
        }

        IsProcessing = true;
        try
        {
            string target = RevocationTarget.Trim();
            string reason = string.IsNullOrWhiteSpace(RevocationReason) ? "Immediate security revocation" : RevocationReason.Trim();
            string revBy = await ResolveActorAsync();

            await _revocationManager.RevokeAsync(target, RevocationType, reason, revBy);

            var entry = new RevocationEntry(target, RevocationType, reason, revBy, DateTimeOffset.UtcNow);
            ActiveRevocations.Insert(0, entry);

            RevocationActionMessage = $"CIRCUIT BREAKER TRIPPED: '{target}' ({RevocationType}) revoked and blacklisted.";
            RevocationTarget = string.Empty;

            await RefreshAuditLogsAsync();
        }
        catch (Exception ex)
        {
            RevocationActionMessage = $"Revocation Error: {ex.Message}";
        }
        finally
        {
            IsProcessing = false;
        }
    }

    [RelayCommand]
    public async Task CheckTokenHealthAsync()
    {
        string? anthropicKey = await _vault.RetrieveSecretStringAsync(MissionController.Infrastructure.Network.Ai.ClaudeStreamClient.ApiKeyVaultKey);
        if (string.IsNullOrEmpty(anthropicKey))
        {
            anthropicKey = Environment.GetEnvironmentVariable("ANTHROPIC_API_KEY");
        }

        string? geminiKey = await _vault.RetrieveSecretStringAsync(MissionController.Infrastructure.Network.Ai.GeminiStreamClient.ApiKeyVaultKey);
        if (string.IsNullOrEmpty(geminiKey))
        {
            geminiKey = Environment.GetEnvironmentVariable("GEMINI_API_KEY") ?? Environment.GetEnvironmentVariable("GOOGLE_API_KEY");
        }

        OAuthTokenTtlStatus = string.IsNullOrEmpty(anthropicKey)
            ? "Anthropic Key: Not Configured"
            : $"Anthropic Key: Active ({anthropicKey.Substring(0, Math.Min(8, anthropicKey.Length))}...)";

        SaTokenTtlStatus = string.IsNullOrEmpty(geminiKey)
            ? "Gemini Key: Not Configured"
            : $"Gemini Key: Active ({geminiKey.Substring(0, Math.Min(8, geminiKey.Length))}...)";
    }

    [RelayCommand]
    public async Task ProactiveRenewTokensAsync()
    {
        IsProcessing = true;
        TokenRenewalStatusMessage = "Checking and refreshing credentials...";
        try
        {
            var res = await _tokenLifecycleManager.RefreshTokenAsync("GoogleCloud.OAuthToken");
            if (!res.Success)
            {
                res = await _tokenLifecycleManager.RefreshTokenAsync("GoogleCloud.ServiceAccountToken");
            }

            if (res.Success && res.Token != null)
            {
                TokenRenewalStatusMessage = $"SUCCESS: Refreshed token expires at {res.Token.ExpiresAtUtc:t} UTC";
            }
            else
            {
                TokenRenewalStatusMessage = $"Credential Status: Active (Vault & Environment credentials checked)";
            }

            await CheckTokenHealthAsync();
        }
        catch (Exception ex)
        {
            TokenRenewalStatusMessage = $"Status: {ex.Message}";
        }
        finally
        {
            IsProcessing = false;
        }
    }
}

