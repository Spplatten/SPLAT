using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
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

public interface IMerkleProofEngine
{
    string ComputeRootHash(IReadOnlyList<string> hashes);
}

public interface IComplianceArchiveExporter
{
    Task<string> ExportComplianceArchiveAsync(string outputPath, CancellationToken cancellationToken = default);
}

public interface ISiemForwarder
{
    Task ForwardEventAsync(string eventType, string details, CancellationToken cancellationToken = default);
}

public interface IEdrIngestionBridge
{
    Task IngestTelemetryAsync(string source, string telemetryData, CancellationToken cancellationToken = default);
}

public interface IVertexStreamClient
{
    IAsyncEnumerable<string> StreamGenerateContentAsync(
        string modelName,
        string systemPrompt,
        string userPrompt,
        string allowedEgressFqdn,
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

public interface ITokenValidator
{
    Task<TokenValidationResult> ValidateTokenAsync(string rawToken, CancellationToken cancellationToken = default);
}

public interface IApiKeyValidator
{
    Task<TokenValidationResult> ValidateApiKeyAsync(string apiKey, CancellationToken cancellationToken = default);
    void RegisterApiKey(string apiKey, SecurityIdentityContext identity);
}

public interface ITokenLifecycleManager
{
    Task<string?> GetValidAccessTokenAsync(string secretKey, int bufferSeconds = 120, CancellationToken cancellationToken = default);
    Task<TokenRefreshResult> RefreshTokenAsync(string secretKey, CancellationToken cancellationToken = default);
    void RegisterRefreshHandler(string secretKey, Func<CancellationToken, Task<TokenDescriptor?>> refreshHandler);
    void TrackTokenExpiry(string secretKey, DateTimeOffset expiresAtUtc);
}

public interface ICredentialSanitizer
{
    SanitizationResult Sanitize(string input);
    string RestoreCredentials(string sanitizedInput, IReadOnlyDictionary<string, string> opaqueMap);
    void RegisterKnownSecret(string secret);
}

public interface IIncidentRevocationManager
{
    Task RevokeAsync(string identifier, string revocationType, string reason, string revokedBy, CancellationToken cancellationToken = default);
    Task<RevocationStatus> CheckRevocationAsync(string identifier, CancellationToken cancellationToken = default);
    Task<bool> IsRevokedAsync(string identifier, CancellationToken cancellationToken = default);
}

