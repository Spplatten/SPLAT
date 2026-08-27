using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Models;

namespace MissionController.Core.Interfaces;

public interface IJobSandbox : IDisposable
{
    string JobName { get; }
    void ConfigureExtendedLimits(long maxMemoryBytes, int maxCpuPercent);
    void AssignProcess(IntPtr processHandle);
    JobResourceMetrics GetResourceMetrics();
    void TerminateAllProcesses(uint exitCode = 1);
}

public interface IProcessLauncher
{
    Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
        string executable,
        string arguments,
        string workingDirectory,
        IJobSandbox jobSandbox,
        bool dropAdminPrivileges,
        int timeoutSeconds,
        IProgress<string>? stdoutProgress = null,
        IProgress<string>? stderrProgress = null,
        CancellationToken cancellationToken = default);
}

public record ProcessExecutionResult(
    int ExitCode,
    string StandardOutput,
    string StandardError,
    bool TimedOut,
    JobResourceMetrics FinalMetrics);

public interface IJailManager
{
    Task<string> ProvisionJailAsync(Guid missionId, CancellationToken cancellationToken = default);
    Task DrainAndCleanupJailAsync(string jailPath, int maxRetries = 5, int retryDelayMs = 200);
    Task<int> SweepOrphanJailsAsync(CancellationToken cancellationToken = default);
}

public interface IRestrictedTokenProvider
{
    IntPtr CreateLowPrivilegeToken();
}

public interface ICredentialVault
{
    Task StoreSecretAsync(string key, byte[] secretBytes, CancellationToken cancellationToken = default);
    Task<byte[]?> RetrieveSecretAsync(string key, CancellationToken cancellationToken = default);
    Task<string?> RetrieveSecretStringAsync(string key, CancellationToken cancellationToken = default);
    Task StoreSecretStringAsync(string key, string secretString, CancellationToken cancellationToken = default);
    Task DeleteSecretAsync(string key, CancellationToken cancellationToken = default);
}

public interface IEgressFirewall
{
    void ValidateOutboundTarget(Uri requestUri, string expectedFqdn);
}

public record DlpSanitizationResult(
    string SanitizedContent,
    int RedactedCount,
    IReadOnlyList<string> RedactedCategories);

public interface IDataLossPreventionSanitizer
{
    DlpSanitizationResult Sanitize(string input);
}

public interface ICredentialSanitizer
{
    SanitizationResult Sanitize(string input);
}

public interface IIncidentRevocationManager
{
    Task RevokeAsync(string identifier, string revocationType, string reason, string revokedBy, CancellationToken cancellationToken = default);
    Task<RevocationStatus> CheckRevocationAsync(string identifier, CancellationToken cancellationToken = default);
    Task<bool> IsRevokedAsync(string identifier, CancellationToken cancellationToken = default);
}

public interface ITokenValidator
{
    Task<TokenValidationResult> ValidateTokenAsync(string rawToken, CancellationToken cancellationToken = default);
}

public interface IApiKeyValidator
{
    Task<TokenValidationResult> ValidateApiKeyAsync(string apiKey, CancellationToken cancellationToken = default);
}

public interface ITokenLifecycleManager
{
    Task<string?> GetValidAccessTokenAsync(string secretKey, int bufferSeconds = 120, CancellationToken cancellationToken = default);
    Task<TokenRefreshResult> RefreshTokenAsync(string secretKey, CancellationToken cancellationToken = default);
}

public interface IMerkleProofEngine
{
    MerkleTree BuildTree(IReadOnlyList<AuditLogEntry> entries);
    MerkleProof GenerateProof(MerkleTree tree, long entryId);
    bool VerifyProof(MerkleProof proof);
}

public interface IComplianceArchiveExporter
{
    Task<string> ExportCompliancePackageAsync(
        ComplianceFramework framework,
        string outputDirectory,
        IReadOnlyList<AuditLogEntry> entries,
        string operatorIdentity,
        CancellationToken cancellationToken = default);
}

public interface ISiemForwarder
{
    Task ForwardAuditEntryAsync(AuditLogEntry entry, SiemConfiguration config, CancellationToken cancellationToken = default);
    Task ForwardCefEventAsync(CefEvent cefEvent, SiemConfiguration config, CancellationToken cancellationToken = default);
    Task<bool> TestConnectionAsync(SiemConfiguration config, CancellationToken cancellationToken = default);
}

public interface IEdrIngestionBridge
{
    Task<EdrDevicePosture> GetLocalDevicePostureAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<EdrSecurityAlert>> GetRecentAlertsAsync(int maxCount = 20, CancellationToken cancellationToken = default);
    Task<bool> SetDeviceIsolationStateAsync(string deviceId, bool isolate, string justification, CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of probing whether a real AI model is reachable. When <see cref="IsLive"/> is false the
/// caller MUST surface a visible simulated-output notice - never render placeholder text as if it
/// were genuine model output. This is the contract that closes the "silent mannequin" gap.
/// </summary>
public record ModelAvailability(
    bool IsLive,
    string ProviderName,
    string ModelId,
    string? UnavailableReason);

/// <summary>
/// Provider-agnostic streaming AI client. Concrete implementations own their egress host and pin it
/// through the Layer-4 egress firewall themselves, so a swap of provider never widens the whitelist.
/// </summary>
public interface IModelStreamClient
{
    Task<ModelAvailability> CheckAvailabilityAsync(
        string requestedModel,
        CancellationToken cancellationToken = default);

    IAsyncEnumerable<string> StreamAnalysisAsync(
        string requestedModel,
        string systemPrompt,
        string userPrompt,
        CancellationToken cancellationToken = default);
}

public interface IAuditLedger
{
    Task AppendLogAsync(Guid missionId, string templateId, string action, string details, string operatorIdentity, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100, CancellationToken cancellationToken = default);
    Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default);
}

public interface ITemplateRegistry
{
    Task<IReadOnlyList<SingleToolTemplate>> GetAllTemplatesAsync(CancellationToken cancellationToken = default);
    Task<SingleToolTemplate?> GetTemplateByIdAsync(string templateId, CancellationToken cancellationToken = default);
    Task RegisterTemplateAsync(SingleToolTemplate template, CancellationToken cancellationToken = default);
}

public record SemanticSearchResult(
    Guid MissionId,
    string TemplateId,
    string ContentSnippet,
    double SimilarityScore,
    DateTime TimestampUtc);

public interface ISemanticMemoryIndex
{
    Task IndexMissionDocumentAsync(Guid missionId, string templateId, string content, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<SemanticSearchResult>> SearchSimilarMissionsAsync(string query, int topK = 5, double minScore = 0.1, CancellationToken cancellationToken = default);
}

public interface IRemediationEngine
{
    Task<RemediationExecutionResult> ExecuteFixAsync(
        RemediationAction action,
        string operatorIdentity,
        CancellationToken cancellationToken = default);

    Task<RemediationExecutionResult> ExecuteRollbackAsync(
        RemediationAction action,
        string operatorIdentity,
        CancellationToken cancellationToken = default);
}

public interface IMissionExecutionEngine
{
    IAsyncEnumerable<MissionChunk> ExecuteMissionAsync(
        SingleToolTemplate template,
        IReadOnlyDictionary<string, string> parameters,
        string operatorIdentity,
        CancellationToken cancellationToken = default);
}
