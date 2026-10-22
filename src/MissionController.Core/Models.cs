using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;

namespace MissionController.Core.Models;

public record EgressRule(
    string AllowedFqdn,
    int AllowedPort = 443,
    bool EnforceHttpsOnly = true,
    string Description = "Approved outbound destination",
    EgressScope Scope = EgressScope.ModelGateway,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<string>? AdditionalFqdns = null)
{
    /// <summary>
    /// True when no sensor tool needs a network stack to satisfy this rule, so the tool process can
    /// be denied one outright. Defaulting to the safe answer is deliberate: a template author who
    /// says nothing gets the contained behaviour, and widening it is the edit that has to be
    /// written down.
    /// </summary>
    public bool ToolProcessNeedsNetwork => Scope == EgressScope.ToolProcess;
}

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
    ProcessIntegrityLevel IntegrityLevel = ProcessIntegrityLevel.Medium,
    // Where the tool runs. The default is the Windows sensor sandbox every template used until
    // 2026-09-24; a template that names the Linux lease runs its tool inside the WSL2 guest under
    // the BPF-LSM lease compiled from this template, and never on the Windows side.
    ToolSubstrate Substrate = ToolSubstrate.Windows,
    // A leased HTTPS sensor receives the compiler's IPv4 pins as its final argv value. It keeps TLS
    // hostname verification while avoiding a DNS socket that the lease correctly does not allow.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    bool PassLeaseEgressAsArguments = false,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    ExecutionPolicy? ExecutionPolicy = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    bool PassLeaseHostPinsAsArguments = false);

/// <summary>
/// The substrate a template's tool runs on. It decides which launcher, jail and job the mission
/// engine provisions, and it is recorded in the run facts as the substrate the mission ran on.
/// </summary>
public enum ToolSubstrate
{
    /// <summary>The Windows sensor sandbox: job object, restricted token, ACL jail, and the AppContainer where the tool can take it.</summary>
    Windows,

    /// <summary>The Linux capability lease: the tool runs as nobody in the WSL2 guest, in a cgroup the kernel polices, under the lease compiled from the template.</summary>
    LinuxLease,
}

public record TemplateParameterField(
    string Key,
    string Label,
    string Description,
    string DefaultValue,
    bool IsRequired = false,
    bool IsMultiLine = false,
    TemplateParameterType ValueType = TemplateParameterType.Text);

public enum TemplateParameterType
{
    Text,
    Number,
    Host,
    Multiline
}

public record TemplateOutputContract(
    string Objective,
    IReadOnlyList<string> Deliverables,
    IReadOnlyList<string> SuccessCriteria,
    string OutputFormat = "Executive summary with evidence, risks, and next actions.",
    // Fields this template needs in the engine's ONE closing JSON block, beside status, headline and
    // findings: written into the schema the model is shown, and required by the quality island. A
    // template asking for its own second object competed with the engine's "nothing after it" rule
    // and lost (trends-brief-composer, 2026-10-20). Omitted when null so every template without any
    // keeps the hash its recordings were made against (MissionRunFacts.HashTemplate).
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<TemplateResponseField>? ResponseFields = null);

/// <summary>One template-required field in the closing JSON block: its key, an example value as JSON, and what it holds.</summary>
public record TemplateResponseField(string Name, string ExampleJson, string Meaning);

public enum RemediationRiskLevel
{
    Safe,
    Moderate,
    High
}

public enum RemediationVerdict
{
    /// <summary>
    /// Not run: the action declares no postcondition for this step, so no verdict could be read from a
    /// measurement. Refusing is what makes "each remediation declares what restored means" a rule the
    /// engine keeps rather than a convention an author can skip.
    /// </summary>
    Refused,
    /// <summary>Rollback command exited 0 AND measured postcondition confirmed the prior state was restored.</summary>
    Restored,
    /// <summary>Fix command exited 0 AND measured postcondition confirmed the desired state was achieved.</summary>
    VerifiedFix,
    /// <summary>Process exited non-zero, exceeded execution deadline, or threw an exception.</summary>
    ExecutionFailed,
    /// <summary>Process exited 0, but independent postcondition measurement failed to verify the restored/healthy state.</summary>
    PostconditionFailed
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
    string? ValidationArguments = null,
    string? PostconditionDescription = null,
    string? ValidationExpectedOutput = null,
    string? RollbackValidationExecutable = null,
    string? RollbackValidationArguments = null,
    string? RollbackValidationExpectedOutput = null,
    // Code, not data: SqliteTemplateRegistry stores templates as JSON, and the serializer refuses a
    // delegate, so a template carrying one could not be saved. A check declared this way lives only
    // as long as the catalog that built it; a template read back from the registry has lost it, and
    // the engine then refuses the step rather than run it unmeasured.
    [property: JsonIgnore] Func<CancellationToken, Task<bool>>? PostconditionCheck = null,
    [property: JsonIgnore] Func<CancellationToken, Task<bool>>? RollbackPostconditionCheck = null)
{
    public bool HasFixPostcondition => !string.IsNullOrWhiteSpace(ValidationExecutable) || PostconditionCheck != null;
    public bool HasRollbackPostcondition => !string.IsNullOrWhiteSpace(RollbackValidationExecutable) || RollbackPostconditionCheck != null;
}

public record RemediationExecutionResult(
    string ActionId,
    bool Success,
    string Output,
    string? ErrorMessage,
    bool IsRollback,
    DateTime CompletedAtUtc,
    RemediationVerdict Verdict,
    string? PostconditionMeasurement = null)
{
    public string StandardOutput => Output;
    public string StandardError => ErrorMessage ?? string.Empty;
    public bool IsRestored => Verdict == RemediationVerdict.Restored;
    public bool IsVerifiedFix => Verdict == RemediationVerdict.VerifiedFix;
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
    IReadOnlyList<RemediationAction>? AvailableRemediations = null,
    TemplateKind Kind = TemplateKind.DiagnosticAgent,
    TemplateOutputContract? OutputContract = null,
    string? SourceTemplateId = null,
    bool IsUserCreated = false,
    // Declared, not guessed. See NetworkDenialMeasuredHarmless below.
    bool NetworkDenialMeasuredHarmless = false)
{
    public IReadOnlyList<RemediationAction> Remediations => AvailableRemediations ?? Array.Empty<RemediationAction>();

    /// <summary>
    /// True when denying this tool the network has been MEASURED not to change what it reports.
    ///
    /// Network denial is an AppContainer with no capabilities at Low integrity, and that is a wall
    /// around far more than sockets. Reaching WMI/CIM, the Event Log service, Defender's provider or
    /// the Service Control Manager goes through RPC endpoints whose security descriptors do not
    /// admit an AppContainer SID; `ping` cannot open an ICMP handle; `netsh` answers "the following
    /// command was not found"; a registry read can fail on integrity alone.
    ///
    /// This used to be inferred the other way round - a text match over the command line for eight
    /// cmdlet names, exempting anything that matched. On 2026-09-20 each denied template was run
    /// inside the container and outside it, same jail and same restricted token: 21 of the 33 the
    /// match had left denied answered differently inside, and three returned nothing at all while
    /// exiting 0, which a model reads as "nothing found".
    ///
    /// So the default is now the working sensor, and denial is a claim a template makes about
    /// itself, which <c>NetworkToolsUnderDenialTests</c> proves by running the thing both ways. A
    /// template that forgets the flag loses containment it could have had, and the same test names
    /// it. A template that claims it wrongly fails the build. Those are the right two directions.
    ///
    /// It is still not the control this tier wants: a socket-layer filter would deny the network
    /// without removing RPC. <c>docs/THREAT-MODEL.md</c> has the argument.
    /// </summary>
    public bool ToolNeedsLocalSubsystems => !NetworkDenialMeasuredHarmless;

    public TemplateOutputContract EffectiveOutputContract => OutputContract ?? new TemplateOutputContract(
        "Diagnose the supplied evidence and identify the safest next action.",
        new[] { "Executive status", "Evidence-backed findings", "Prioritised next actions" },
        new[] { "Every conclusion cites observed evidence", "Unknown values are called out explicitly" });


    public SingleToolTemplate(
        string templateId,
        string name,
        string description,
        string category,
        string targetModel,
        SingleToolDefinition tool,
        EgressRule egressRule,
        string systemPrompt,
        IReadOnlyDictionary<string, string> parameterDefaults,
        IReadOnlyList<RemediationAction>? availableRemediations = null)
        : this(
            templateId,
            name,
            description,
            category,
            targetModel,
            tool,
            egressRule,
            systemPrompt,
            FieldsFromDefaults(parameterDefaults),
            parameterDefaults,
            availableRemediations ?? Array.Empty<RemediationAction>())
    {
    }

    private static IReadOnlyList<TemplateParameterField> FieldsFromDefaults(IReadOnlyDictionary<string, string> defaults)
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
        if (string.IsNullOrWhiteSpace(Name))
            throw new InvalidOperationException("Template name must not be empty.");
        if (string.IsNullOrWhiteSpace(Category))
            throw new InvalidOperationException("Template category must not be empty.");
        if (string.IsNullOrWhiteSpace(SystemPrompt))
            throw new InvalidOperationException("Template system prompt must not be empty.");
        if (Tool.AllowedExitCodes == null || Tool.AllowedExitCodes.Count == 0)
            throw new InvalidOperationException("At least one allowed native-tool exit code must be declared.");
        if (Tool.TimeoutSeconds <= 0 || Tool.TimeoutSeconds > 3600)
            throw new InvalidOperationException("Native-tool timeout must be between 1 and 3600 seconds.");
        if (Tool.MaxMemoryBytes <= 0 || Tool.MaxCpuPercent is < 1 or > 100)
            throw new InvalidOperationException("Native-tool resource limits are outside the governed range.");

        if (Tool.ExecutionPolicy is not null)
        {
            if (Tool.Substrate != ToolSubstrate.LinuxLease)
                throw new InvalidOperationException("Execution policies require the Linux lease substrate.");
            Tool.ExecutionPolicy.Validate();
        }

        var fields = ParameterFields ?? Array.Empty<TemplateParameterField>();
        var duplicateKeys = fields
            .Where(field => string.IsNullOrWhiteSpace(field.Key))
            .Select(_ => "<empty>")
            .Concat(fields
                .Where(field => !string.IsNullOrWhiteSpace(field.Key))
                .GroupBy(field => field.Key, StringComparer.OrdinalIgnoreCase)
                .Where(group => group.Count() > 1)
                .Select(group => group.Key))
            .ToList();

        if (duplicateKeys.Count > 0)
            throw new InvalidOperationException($"Template parameter keys must be unique and non-empty: {string.Join(", ", duplicateKeys)}");

        if (OutputContract != null && string.IsNullOrWhiteSpace(OutputContract.Objective))
            throw new InvalidOperationException("Template output objective must not be empty.");
    }
}

public record ProjectStage(
    string StageId,
    string Name,
    string TemplateId,
    string Directive,
    bool ContinueOnFailure = false);

public record ProjectTemplate(
    string ProjectId,
    string Name,
    string Description,
    string Category,
    IReadOnlyList<ProjectStage> Stages,
    IReadOnlyList<string> Deliverables,
    bool IsBuiltIn = false)
{
    public string StageSummary => $"{Stages.Count} ordered stages";

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(ProjectId))
            throw new InvalidOperationException("ProjectId must not be empty.");
        if (string.IsNullOrWhiteSpace(Name))
            throw new InvalidOperationException("Project name must not be empty.");
        if (string.IsNullOrWhiteSpace(Description))
            throw new InvalidOperationException("Project description must not be empty.");
        if (Stages == null || Stages.Count is < 1 or > 6)
            throw new InvalidOperationException("A governed project must contain between 1 and 6 ordered stages.");

        var duplicateStageIds = Stages
            .GroupBy(stage => stage.StageId, StringComparer.OrdinalIgnoreCase)
            .Where(group => string.IsNullOrWhiteSpace(group.Key) || group.Count() > 1)
            .Select(group => string.IsNullOrWhiteSpace(group.Key) ? "<empty>" : group.Key)
            .ToList();

        if (duplicateStageIds.Count > 0)
            throw new InvalidOperationException($"Project stage IDs must be unique and non-empty: {string.Join(", ", duplicateStageIds)}");

        foreach (var stage in Stages)
        {
            if (string.IsNullOrWhiteSpace(stage.Name) || string.IsNullOrWhiteSpace(stage.TemplateId))
                throw new InvalidOperationException("Every project stage needs a name and an agent template.");
            if (string.IsNullOrWhiteSpace(stage.Directive))
                throw new InvalidOperationException($"Project stage '{stage.StageId}' must declare a directive.");
        }

        if (Deliverables == null || Deliverables.Count == 0 || Deliverables.Any(string.IsNullOrWhiteSpace))
            throw new InvalidOperationException("A governed project must declare at least one non-empty deliverable.");
    }
}

public record MissionChunk(
    Guid MissionId,
    MissionChunkType ChunkType,
    string Content,
    DateTime TimestampUtc,
    string? AssociatedHash = null,
    // Null, not 0, when the substrate did not measure memory - see JobResourceMetrics.
    long? MemoryBytesUsed = null);

public record AuditLogEntry(
    long Id,
    DateTime TimestampUtc,
    Guid MissionId,
    string TemplateId,
    string Action,
    string Details,
    string OperatorIdentity,
    string PreviousHash,
    string EntryHash,
    // Which chain the row was written into (SqliteChainedAuditLedger's 1, 2 or 3); 0 when the entry
    // did not come from that ledger and nothing says.
    int HashVersion = 0,
    // Older exports omit both; retention erases the salt while preserving the commitment.
    string? DetailsCommitment = null,
    string? DetailsSalt = null)
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
    int LeafCount,
    // Every level's hashes, leaves first, and each entry's position among the leaves. A proof is
    // then a walk of one sibling lookup per level rather than a search of the whole tree at every
    // level, which is what GenerateProof did before: O(n) per level, O(n log n) per proof, and a
    // bundle of n entries paid it n times over. Null on a tree built without them, which the engine
    // then walks the old way.
    IReadOnlyList<IReadOnlyList<string>>? Levels = null,
    IReadOnlyDictionary<long, int>? LeafPositions = null);

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

// Perfect subtrees covering [0, PreviousLeafCount) and [PreviousLeafCount, LeafCount).
// Their positions and heights come from the signed counts, never from the proof's claims.
public record MerkleConsistencyProof(
    int PreviousLeafCount,
    int LeafCount,
    IReadOnlyList<string> PrefixSubtreeHashes,
    IReadOnlyList<string> AppendedSubtreeHashes,
    int Schema = 1);

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


/// <summary>
/// Resource accounting for one sandboxed execution.
///
/// Every field is nullable and null means EXACTLY ONE thing: this substrate did not measure it.
/// Null is never a stand-in for zero, and a substrate that cannot measure a quantity must leave it
/// null rather than deriving a plausible-looking number - a fabricated metric is indistinguishable
/// from a real one once it reaches the ledger, and this product's entire claim is that its telemetry
/// is evidence. Render null as "unavailable", never as 0.
/// </summary>
/// <summary>
/// The limits a job object holds, queried back from the kernel after they were set. A null field is
/// one the query did not return or a limit that is not set; the requested value must never stand in
/// for it, because the point of reading back is to catch a set call that silently did not take.
/// </summary>
public record JobLimitsReadback(
    long? ProcessMemoryLimitBytes,
    long? JobMemoryLimitBytes,
    int? CpuRatePercent,
    uint? ActiveProcessLimit,
    bool? KillOnJobClose)
{
    /// <summary>Nothing was read back: the sandbox cannot query its limits.</summary>
    public static JobLimitsReadback Unavailable { get; } = new(null, null, null, null, null);
}

public record JobResourceMetrics(
    long? PeakMemoryBytes,
    long? CurrentMemoryBytes,
    long? TotalCpuKernelTimeMs,
    long? TotalCpuUserTimeMs,
    uint? ActiveProcessCount)
{
    /// <summary>Nothing was measured. Use where accounting failed or the substrate exposes none.</summary>
    public static JobResourceMetrics Unavailable { get; } = new(null, null, null, null, null);

    /// <summary>Formats a metric for operator-facing text, distinguishing "none" from "unknown".</summary>
    public static string Describe(long? value, string unit) =>
        value.HasValue ? $"{value.Value}{unit}" : "unavailable";
}

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

public enum DiagnosticHealthStatus
{
    Healthy,
    Warning,
    Critical,
    Unknown
}

public record ExecutiveDiagnosisResult(
    DiagnosticHealthStatus OverallStatus,
    string StatusHeadline,
    IReadOnlyList<string> KeyFindings,
    IReadOnlyList<string>? RecommendedActions = null,
    string? RawAnalysis = null,
    GroundingAttestation? Attestation = null);

/// <summary>
/// Whether a single finding's specifics could be located in the telemetry that produced it.
/// Ordered by decreasing evidentiary strength.
/// </summary>
public enum GroundingState
{
    /// <summary>Every checkable claim appears in the raw sensor output.</summary>
    Grounded,

    /// <summary>Some claims anchored, at least one absent - treat the unanchored specifics with suspicion.</summary>
    PartiallyGrounded,

    /// <summary>Prose with no falsifiable specifics. Neither corroborated nor refuted.</summary>
    Unattributed,

    /// <summary>Specific claims were made and NONE appear in the telemetry. The fabrication signal.</summary>
    Unsupported,

    /// <summary>No telemetry was captured, so nothing could be checked at all.</summary>
    NoTelemetry
}

/// <summary>One finding plus the evidence that does or does not stand behind it.</summary>
public record FindingAttestation(
    string Finding,
    GroundingState State,
    IReadOnlyList<string> AnchoredClaims,
    IReadOnlyList<string> MissingClaims);

/// <summary>
/// Evidence summary for a whole verdict. Carried alongside the findings so the audit ledger records
/// not just WHAT was concluded but how much of it the collected telemetry actually supported.
/// </summary>
public record GroundingAttestation(IReadOnlyList<FindingAttestation> Findings)
{
    public static GroundingAttestation Empty { get; } = new(Array.Empty<FindingAttestation>());

    public int GroundedCount => Findings.Count(f => f.State == GroundingState.Grounded);
    public int PartiallyGroundedCount => Findings.Count(f => f.State == GroundingState.PartiallyGrounded);
    public int UnsupportedCount => Findings.Count(f => f.State == GroundingState.Unsupported);
    public int UnattributedCount => Findings.Count(f => f.State == GroundingState.Unattributed);

    /// <summary>True when at least one finding asserted specifics the telemetry never contained.</summary>
    public bool HasUnsupportedFindings => UnsupportedCount > 0;

    /// <summary>One-line summary for the audit trail and the operator-facing evidence chip.</summary>
    public string Summary => Findings.Count == 0
        ? "No findings to attest."
        : $"Evidence: {GroundedCount} grounded, {PartiallyGroundedCount} partial, " +
          $"{UnsupportedCount} unsupported, {UnattributedCount} unattributed.";
}

/// <summary>One completed Reason-Act-Observe cycle: a full 1:1:1 mission plus why it was chosen.</summary>
public record InvestigationStep(
    int StepNumber,
    string TemplateId,
    string TemplateName,
    string SelectionReason,
    ExecutiveDiagnosisResult Verdict);

/// <summary>Why a bounded investigation stopped. Recorded so an operator never has to guess.</summary>
public enum InvestigationStopReason
{
    SystemHealthy,
    StepBudgetExhausted,
    ModelDeclinedToContinue,
    NoGovernedCandidateRemaining,
    StepFailed
}

public record InvestigationResult(
    Guid InvestigationId,
    IReadOnlyList<InvestigationStep> Steps,
    DiagnosticHealthStatus OverallStatus,
    InvestigationStopReason StopReason,
    string StopExplanation);

