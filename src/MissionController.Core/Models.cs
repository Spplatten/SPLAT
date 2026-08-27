using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using MissionController.Core.Enums;

namespace MissionController.Core.Models;

public record EgressRule(
    string AllowedFqdn,
    int AllowedPort = 443,
    bool EnforceHttpsOnly = true,
    string Description = "Approved outbound destination");

public record SingleToolDefinition(
    string ToolId,
    string Name,
    string ExecutablePath,
    string ArgumentsTemplate,
    IReadOnlyList<int> AllowedExitCodes,
    int TimeoutSeconds = 60,
    long MaxMemoryBytes = 256 * 1024 * 1024, // 256 MB default limit
    int MaxCpuPercent = 80,
    bool RequiresRestrictedToken = true,
    ProcessIntegrityLevel IntegrityLevel = ProcessIntegrityLevel.Medium);

public record TemplateParameterField(
    string Key,
    string Label,
    string Description,
    string DefaultValue,
    bool IsRequired = false,
    bool IsMultiLine = false);

public enum RemediationRiskLevel
{
    Safe,
    Moderate,
    High
}

public record RemediationAction(
    string ActionId,
    string TemplateId,
    string Title,
    string Description,
    RemediationRiskLevel RiskLevel,
    bool CanRollback,
    string FixExecutable,
    string FixArguments,
    string? RollbackExecutable = null,
    string? RollbackArguments = null,
    string? ValidationExecutable = null,
    string? ValidationArguments = null);

public record RemediationExecutionResult(
    string ActionId,
    bool Success,
    string Output,
    string? ErrorMessage,
    bool IsRollback,
    DateTime CompletedAtUtc)
{
    public string StandardOutput => Output;
    public string StandardError => ErrorMessage ?? string.Empty;
}


/// <summary>
/// Strict 1:1:1 Constraint Model:
/// Strictly 1 Template -> 1 Model -> 1 Dedicated Native Tool -> 1 Allowed Egress FQDN.
/// </summary>
[method: JsonConstructor]
public record SingleToolTemplate(
    string TemplateId,
    string Name,
    string Description,
    string Category,
    string TargetModel,
    SingleToolDefinition Tool,
    EgressRule EgressRule,
    string SystemPrompt,
    IReadOnlyList<TemplateParameterField> ParameterFields,
    IReadOnlyDictionary<string, string>? ParameterDefaults = null,
    IReadOnlyList<RemediationAction>? AvailableRemediations = null)
{
    public IReadOnlyList<RemediationAction> Remediations => AvailableRemediations ?? Array.Empty<RemediationAction>();


    public SingleToolTemplate(
        string templateId,
        string name,
        string description,
        string category,
        string targetModel,
        SingleToolDefinition tool,
        EgressRule egressRule,
        string systemPrompt,
        IReadOnlyDictionary<string, string> parameterDefaults)
        : this(
            templateId,
            name,
            description,
            category,
            targetModel,
            tool,
            egressRule,
            systemPrompt,
            ConvertDefaultsToFields(parameterDefaults),
            parameterDefaults,
            Array.Empty<RemediationAction>())
    {
    }

    private static IReadOnlyList<TemplateParameterField> ConvertDefaultsToFields(IReadOnlyDictionary<string, string> defaults)
    {
        var list = new List<TemplateParameterField>();
        foreach (var (key, val) in defaults)
        {
            list.Add(new TemplateParameterField(key, key, $"Configurable value for {key}", val));
        }
        return list;
    }

    public IReadOnlyDictionary<string, string> GetEffectiveDefaults()
    {
        var dict = new Dictionary<string, string>();
        foreach (var field in ParameterFields)
        {
            dict[field.Key] = field.DefaultValue;
        }
        if (ParameterDefaults != null)
        {
            foreach (var (k, v) in ParameterDefaults)
            {
                dict[k] = v;
            }
        }
        return dict;
    }

    public void ValidateStrictRules()
    {
        if (string.IsNullOrWhiteSpace(TemplateId))
            throw new InvalidOperationException("TemplateId must not be empty.");
        if (string.IsNullOrWhiteSpace(TargetModel))
            throw new InvalidOperationException("Strict 1:1:1 Rule Violation: Exactly 1 TargetModel must be bound.");
        if (Tool == null || string.IsNullOrWhiteSpace(Tool.ExecutablePath))
            throw new InvalidOperationException("Strict 1:1:1 Rule Violation: Exactly 1 Native Tool must be bound.");
        if (EgressRule == null || string.IsNullOrWhiteSpace(EgressRule.AllowedFqdn))
            throw new InvalidOperationException("Strict 1:1:1 Rule Violation: Exactly 1 Allowed Egress FQDN must be bound.");
    }
}

public record MissionChunk(
    Guid MissionId,
    MissionChunkType ChunkType,
    string Content,
    DateTime TimestampUtc,
    string? AssociatedHash = null,
    long MemoryBytesUsed = 0);

public record AuditLogEntry(
    long Id,
    DateTime TimestampUtc,
    Guid MissionId,
    string TemplateId,
    string Action,
    string Details,
    string OperatorIdentity,
    string PreviousHash,
    string EntryHash)
{
    public long SequenceNumber => Id;
    public string CurrentHash => EntryHash;
}

public record MerkleTreeNode(
    string Hash,
    MerkleTreeNode? Left,
    MerkleTreeNode? Right,
    long? EntryId);

public record MerkleTree(
    string RootHash,
    MerkleTreeNode? RootNode,
    int LeafCount);

public record MerkleProofStep(
    string SiblingHash,
    bool IsLeftSibling);

public record MerkleProof(
    long EntryId,
    string LeafHash,
    string RootHash,
    IReadOnlyList<MerkleProofStep> ProofSteps)
{
    public IReadOnlyList<MerkleProofStep> Steps => ProofSteps;
}

public record CompliancePackageManifest(
    string PackageId,
    ComplianceFramework Framework,
    DateTimeOffset ExportedAtUtc,
    string ExportedBy,
    string MerkleRootHash,
    int TotalAuditEntries,
    string DigitalSignature,
    string SignatureAlgorithm,
    IReadOnlyList<string> IncludedFiles);

public record EdrDevicePosture(
    string DeviceId,
    string Hostname,
    EdrProviderType Provider,
    EndpointIsolationState IsolationState,
    bool RealTimeProtectionEnabled,
    string AntivirusEngineVersion,
    string SecurityIntelligenceVersion,
    DateTimeOffset LastSyncTimeUtc,
    IReadOnlyList<string> ActiveThreats);

public record EdrSecurityAlert(
    string AlertId,
    string Title,
    string Category,
    string Severity,
    string Status,
    DateTimeOffset DetectedTimeUtc,
    string Description,
    string MitreTechniqueId);


public record SiemConfiguration(
    SiemProtocol Protocol,
    string HostOrUrl,
    int Port = 514,
    bool UseTls = true,
    string? WorkspaceId = null,
    string? SharedKey = null,
    string LogType = "MissionControllerAudit",
    int Facility = 16,
    int DefaultSeverity = 6)
{
    public string HostOrEndpoint => HostOrUrl;
}

public record SyslogMessage(
    int Facility,
    int Severity,
    DateTimeOffset Timestamp,
    string Hostname,
    string AppName,
    string ProcessId,
    string MessageId,
    string Message,
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>>? StructuredData = null);

public record CefEvent(
    string DeviceVendor,
    string DeviceProduct,
    string DeviceVersion,
    string DeviceEventClassId,
    string Name,
    int Severity,
    IReadOnlyDictionary<string, string> ExtensionFields)
{
    public IReadOnlyDictionary<string, string> Extensions => ExtensionFields;
}


public record JobResourceMetrics(
    long PeakMemoryBytes,
    long CurrentMemoryBytes,
    long TotalCpuKernelTimeMs,
    long TotalCpuUserTimeMs,
    uint ActiveProcessCount);

public record SecurityIdentityContext(
    string OperatorIdentity,
    string TenantId,
    IReadOnlySet<string> Scopes,
    IReadOnlyDictionary<string, string> Claims,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string AuthMethod)
{
    public bool IsExpired(DateTimeOffset? asOfUtc = null) => (asOfUtc ?? DateTimeOffset.UtcNow) >= ExpiresAtUtc;
    public bool HasScope(string scope) => Scopes.Contains(scope) || Scopes.Contains("*");
    public bool HasAnyScope(params string[] requiredScopes) => requiredScopes.Any(HasScope);
}

public record TokenValidationResult(
    bool IsValid,
    SecurityIdentityContext? IdentityContext,
    string? ErrorMessage = null,
    string? ErrorCode = null)
{
    public static TokenValidationResult Success(SecurityIdentityContext identity) => new(true, identity);
    public static TokenValidationResult Failed(string errorMessage, string errorCode = "AUTH_FAILED") => new(false, null, errorMessage, errorCode);
}

public record TokenDescriptor(
    string AccessToken,
    string TokenType,
    DateTimeOffset ExpiresAtUtc,
    string? RefreshToken = null,
    string? Scope = null)
{
    public bool IsNearExpiry(int bufferSeconds = 120, DateTimeOffset? now = null) =>
        (now ?? DateTimeOffset.UtcNow).AddSeconds(bufferSeconds) >= ExpiresAtUtc;
}

public record TokenRefreshResult(
    bool Success,
    TokenDescriptor? Token,
    string? ErrorMessage = null);

public record SanitizationResult(
    string SanitizedText,
    int RedactedCount,
    IReadOnlyDictionary<string, string> OpaqueToSecretMap);

public record RevocationEntry(
    string Identifier,
    string RevocationType,
    string Reason,
    string RevokedBy,
    DateTimeOffset RevokedAtUtc);

public record RevocationStatus(
    bool IsRevoked,
    RevocationEntry? Entry = null);

public record AiGatewayValidationResult(
    bool IsValid,
    string Message);

