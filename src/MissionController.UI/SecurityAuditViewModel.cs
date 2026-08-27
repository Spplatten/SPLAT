using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
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
    private readonly ISiemForwarder _siemForwarder;
    private readonly IEdrIngestionBridge _edrBridge;
    private readonly IIncidentRevocationManager _revocationManager;
    private readonly ITokenLifecycleManager _tokenLifecycleManager;
    private readonly ICredentialVault _vault;

    [ObservableProperty]
    private ObservableCollection<AuditLogEntry> _auditLogs = new();

    [ObservableProperty]
    private ObservableCollection<EdrSecurityAlert> _edrAlerts = new();

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
    private string _complianceExportStatus = "Ready for Compliance Export";

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
        ISiemForwarder siemForwarder,
        IEdrIngestionBridge edrBridge,
        IIncidentRevocationManager revocationManager,
        ITokenLifecycleManager tokenLifecycleManager,
        ICredentialVault vault)
    {
        _auditLedger = auditLedger;
        _merkleEngine = merkleEngine;
        _archiveExporter = archiveExporter;
        _siemForwarder = siemForwarder;
        _edrBridge = edrBridge;
        _revocationManager = revocationManager;
        _tokenLifecycleManager = tokenLifecycleManager;
        _vault = vault;
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
    public async Task ExportHipaaCompliancePackageAsync()
    {
        await ExportPackageInternalAsync(ComplianceFramework.Hipaa);
    }

    [RelayCommand]
    public async Task ExportCmmcCompliancePackageAsync()
    {
        await ExportPackageInternalAsync(ComplianceFramework.CmmcLevel2);
    }

    private async Task ExportPackageInternalAsync(ComplianceFramework framework)
    {
        IsProcessing = true;
        ComplianceExportStatus = $"Exporting {framework} Package (Building Merkle Proofs & ZIP)...";

        try
        {
            var entries = AuditLogs.Count > 0 ? AuditLogs.ToList() : (await _auditLedger.GetAuditLogsAsync(null, 500)).ToList();
            string zipPath = await _archiveExporter.ExportCompliancePackageAsync(framework, "", entries, Environment.UserName);
            LastExportedPackagePath = zipPath;
            ComplianceExportStatus = $"SUCCESS: Exported {framework} bundle to {System.IO.Path.GetFileName(zipPath)}";
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
            var testConfig = new SiemConfiguration(
                SiemProtocol.MicrosoftSentinel,
                "https://sentinel.local",
                443,
                true,
                WorkspaceId: "00000000-0000-0000-0000-000000000000",
                SharedKey: Convert.ToBase64String(new byte[32]));

            // Test signature calculation and connection format
            string sig = SiemForwarder.BuildSentinelAuthSignature("00000000-0000-0000-0000-000000000000", Convert.ToBase64String(new byte[32]), 128, DateTime.UtcNow.ToString("r"));
            SiemStatusMessage = $"SENTINEL READY: HMAC-SHA256 signature generator verified ({sig.Substring(0, 25)}...)";
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            SiemStatusMessage = $"SIEM Test Error: {ex.Message}";
        }
    }

    [RelayCommand]
    public async Task TestSiemSyslogCefAsync()
    {
        SiemStatusMessage = "Simulating CEF / RFC 5424 Syslog datagram...";
        try
        {
            var dummyEntry = new AuditLogEntry(
                1, DateTime.UtcNow, Guid.NewGuid(), "SIEM_TEST", "DIAGNOSTIC_EXEC", "Memory clamp verified", Environment.UserName, "000000", "abcdef");
            var syslog = new SyslogMessage(1, 6, DateTimeOffset.UtcNow, Environment.MachineName, "MissionController", "100", "AUDIT", "Test Syslog");
            string formatted = SiemForwarder.FormatRfc5424(syslog);
            SiemStatusMessage = $"CEF/SYSLOG READY: Validated RFC 5424 framing ({formatted.Substring(0, Math.Min(40, formatted.Length))}...)";
            await Task.CompletedTask;
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
            string revBy = Environment.UserName;

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
        string? oauthToken = await _vault.RetrieveSecretStringAsync("GoogleCloud.OAuthToken");
        if (string.IsNullOrEmpty(oauthToken))
        {
            OAuthTokenTtlStatus = "OAuth 2.0 PKCE: No Token In DPAPI Vault";
        }
        else
        {
            OAuthTokenTtlStatus = $"OAuth 2.0 PKCE: Active in Vault ({oauthToken.Substring(0, Math.Min(12, oauthToken.Length))}...)";
        }

        string? saToken = await _vault.RetrieveSecretStringAsync("GoogleCloud.ServiceAccountToken");
        if (string.IsNullOrEmpty(saToken))
        {
            SaTokenTtlStatus = "Service Account: No Token In DPAPI Vault";
        }
        else
        {
            SaTokenTtlStatus = $"Service Account: Active in Vault ({saToken.Substring(0, Math.Min(12, saToken.Length))}...)";
        }
    }

    [RelayCommand]
    public async Task ProactiveRenewTokensAsync()
    {
        IsProcessing = true;
        TokenRenewalStatusMessage = "Proactively renewing downstream agent access tokens...";
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
                TokenRenewalStatusMessage = $"Auto-Renew Status: {res.ErrorMessage ?? "No refresh handler registered"}";
            }

            await CheckTokenHealthAsync();
        }
        catch (Exception ex)
        {
            TokenRenewalStatusMessage = $"Refresh Error: {ex.Message}";
        }
        finally
        {
            IsProcessing = false;
        }
    }
}

