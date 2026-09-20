using System;
using System.Net;
using Microsoft.Win32.SafeHandles;
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
    void AssignProcess(SafeProcessHandle processHandle);
    JobResourceMetrics GetResourceMetrics();
    void TerminateAllProcesses(uint exitCode = 1);

    /// <summary>
    /// The limits the kernel holds for this job, queried rather than remembered from the request. The
    /// default reads nothing back, which is the truth for a sandbox that cannot query its object.
    /// </summary>
    JobLimitsReadback ReadBackLimits() => JobLimitsReadback.Unavailable;

    /// <summary>Whether the kernel has this process in this job; null when the sandbox cannot ask.</summary>
    bool? ContainsProcess(SafeProcessHandle process) => null;
}

public interface IProcessLauncher
{
    /// <param name="denyNetworkAccess">
    /// Launch the tool with no network stack at all (Windows: an AppContainer holding zero capability
    /// SIDs). Defaults to false so existing callers are unchanged, but the mission engine passes true
    /// for every template whose declared egress belongs to the model gateway rather than the sensor -
    /// which is nearly all of them. An implementation that cannot apply the isolation must THROW
    /// rather than launch an unconfined process: silently running a tool with full network because
    /// containment was unavailable is the exact failure this parameter exists to prevent.
    /// </param>
    Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
        string executable,
        string arguments,
        string workingDirectory,
        IJobSandbox jobSandbox,
        bool dropAdminPrivileges,
        int timeoutSeconds,
        IProgress<string>? stdoutProgress = null,
        IProgress<string>? stderrProgress = null,
        CancellationToken cancellationToken = default,
        bool denyNetworkAccess = false);
}

public record ProcessExecutionResult(
    int ExitCode,
    string StandardOutput,
    string StandardError,
    bool TimedOut,
    JobResourceMetrics FinalMetrics,
    string? TerminalReason = null,
    // What confined the process, read back from the suspended process itself before it ran: its job
    // membership and its token. Null when the launcher reads nothing back.
    IReadOnlyList<string>? AppliedControls = null);

public interface IJailManager
{
    Task<string> ProvisionJailAsync(Guid missionId, CancellationToken cancellationToken = default);
    Task DrainAndCleanupJailAsync(string jailPath, int maxRetries = 5, int retryDelayMs = 200);
    Task<int> SweepOrphanJailsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// The jail's access control as it stands on disk, read back rather than assumed from provisioning;
    /// null when the manager cannot read it.
    /// </summary>
    string? DescribeJail(string jailPath) => null;
}

public interface IRestrictedTokenProvider
{
    /// <summary>
    /// The caller owns the returned token and must dispose it. Returning a SafeHandle rather than a
    /// raw IntPtr is what makes that ownership checkable: the old signature handed out a live OS
    /// handle with the obligation to close it recorded nowhere the compiler could see.
    /// </summary>
    SafeAccessTokenHandle CreateLowPrivilegeToken();
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

    Task<string> ExportMissionRunRecordPackageAsync(
        MissionRunRecord runRecord,
        IReadOnlyList<AuditLogEntry> entries,
        string outputDirectory,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Assembles a mission's run record in the six-group evidence schema from the ledger alone: the
/// MISSION_RUN_FACTS row the engine sealed when the mission ended, and the mission's other rows. It
/// takes nothing from its caller, so a record cannot say more than the mission recorded.
/// </summary>
public interface IMissionRunRecordAssembler
{
    Task<MissionRunRecord> AssembleRunRecordAsync(Guid missionId, CancellationToken cancellationToken = default);

    /// <summary>Writes the record's bundle, signed when a signing key is configured, and returns its path.</summary>
    Task<string> AssembleAndExportBundleAsync(Guid missionId, string outputDirectory, CancellationToken cancellationToken = default);
}

/// <summary>
/// Signs a run record bundle. The key is the operator's, like the ledger key: the bundle carries the
/// public half and its fingerprint, and a verifier compares that fingerprint with the one the operator
/// published, because nothing inside a bundle can say whose key signed it.
/// </summary>
public interface IRunRecordSigner
{
    /// <summary>"sha256:" and the hex SHA-256 of <see cref="PublicKeyDer"/>.</summary>
    string KeyId { get; }

    string Algorithm { get; }

    /// <summary>The public key as a PKCS#1 RSAPublicKey, DER-encoded.</summary>
    byte[] PublicKeyDer { get; }

    byte[] Sign(byte[] data);
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

public interface IProjectTemplateRegistry
{
    Task<IReadOnlyList<ProjectTemplate>> GetAllProjectTemplatesAsync(CancellationToken cancellationToken = default);
    Task<ProjectTemplate?> GetProjectTemplateByIdAsync(string projectId, CancellationToken cancellationToken = default);
    Task RegisterProjectTemplateAsync(ProjectTemplate project, CancellationToken cancellationToken = default);
}

public interface IProjectExecutionEngine
{
    IAsyncEnumerable<MissionChunk> ExecuteProjectAsync(
        ProjectTemplate project,
        IReadOnlyDictionary<string, string> parameters,
        string operatorIdentity,
        CancellationToken cancellationToken = default);
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

public interface IDiagnosticFindingsExtractor
{
    ExecutiveDiagnosisResult ExtractFindings(string aiOutput, string? rawToolOutput = null, string? templateName = null);
}

/// <summary>
/// Bounded multi-step investigation. Each step is a complete 1:1:1 mission in its own jail and job
/// object; the loop only decides WHETHER there is a next step and WHICH governed template it uses.
/// </summary>
public interface IGovernedInvestigationLoop
{
    Task<InvestigationResult> InvestigateAsync(
        SingleToolTemplate startingTemplate,
        IReadOnlyDictionary<string, string> parameters,
        string operatorIdentity,
        int maxSteps = 3,
        IProgress<MissionChunk>? progress = null,
        CancellationToken cancellationToken = default);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 2/3 Linux Substrate: BPF-LSM Leased Execution Seams (Phase 3 & 6)
// ─────────────────────────────────────────────────────────────────────────────

public record InodeIdentifierModel(
    ulong InodeNumber,
    uint DeviceId,
    string SourcePath);

public record LeaseResourceLimits(
    ulong MaxMemoryBytes = 256 * 1024 * 1024,
    uint MaxCpuPercent = 50,
    uint MaxPids = 100);

public record OverlayFsSpec(
    bool EnableCow,
    string LowerDir,
    string ScratchDir);

public enum KernelViolationHook
{
    Unspecified = 0,
    Exec = 1,    // bprm_check_security
    Open = 2,    // file_open
    Connect = 3  // socket_connect
}

public record LeaseViolationEvent(
    ulong CgroupId,
    uint ProcessId,
    KernelViolationHook Hook,
    ulong Detail,
    string DetailText,
    string ProcessComm,
    DateTime TimestampUtc);

public record LeaseSpec(
    Guid MissionId,
    string WorkingDirectory,
    bool AllowNetwork,
    IReadOnlyList<string> AllowedEgressIps,
    IReadOnlyList<uint> AllowedEgressPorts,
    bool ReadOnlyFs,
    IReadOnlyList<InodeIdentifierModel> ProtectedInodes,
    IReadOnlyList<InodeIdentifierModel> AllowedExecInodes,
    uint LeaseDurationSeconds,
    LeaseResourceLimits Limits,
    // EnvironmentVariables was declared here and read by nothing - not the bridge, not the
    // envelope, not the daemon. A tool's environment is a real policy dimension and it will need
    // to come back with a hook behind it; as a field nobody consumed it only suggested one existed.
    OverlayFsSpec? OverlayFs = null);

/// <summary>
/// Executes a tool command inside a hardware-isolated WSL2 guest VM under an in-kernel BPF-LSM capability lease.
/// Do NOT overload IProcessLauncher (which is intrinsically Win32 job-object shaped).
/// </summary>
public interface ILeasedExecutor
{
    /// <param name="argv">
    /// The tool's arguments, already separated. This was a single string that the guest daemon then
    /// split on whitespace - so <c>-c '&lt;code&gt;'</c> reached python as the literal
    /// <c>'print(123)'</c>, which evaluates to a discarded string and exits 0 with no output.
    /// Splitting has to happen where the original text is intact; by the time a pre-quoted string
    /// is on the wire the information needed to split it correctly is gone.
    /// </param>
    Task<ProcessExecutionResult> ExecuteLeasedAsync(
        LeaseSpec lease,
        string command,
        IReadOnlyList<string> argv,
        IProgress<string>? stdout = null,
        IProgress<string>? stderr = null,
        IProgress<LeaseViolationEvent>? violations = null,
        CancellationToken ct = default);
}

/// <summary>
/// Compiles a governed SingleToolTemplate into a deterministic in-kernel LeaseSpec capability envelope.
/// </summary>
public interface ITemplatePolicyCompiler
{
    LeaseSpec CompileTemplatePolicy(
        SingleToolTemplate template,
        Guid missionId,
        string workingDirectory,
        uint leaseDurationSeconds = 30);
}

/// <summary>
/// Resolves a host name or IP address string to an array of <see cref="IPAddress"/> instances.
/// Allows injecting mocked or throwing network resolvers for deterministic policy compilation.
/// </summary>
public interface IHostAddressResolver
{
    IPAddress[] GetHostAddresses(string hostNameOrAddress);
}

/// <summary>
/// Thrown when a governed template cannot be safely compiled into an in-kernel capability lease,
/// such as when an egress destination cannot be resolved to valid IP addresses or specifies invalid port ranges.
/// Enforces fail-closed semantics: refuses authority rather than substituting unintended permissions.
/// </summary>
public sealed class PolicyCompilationException : Exception
{
    public PolicyCompilationException(string message) : base(message) { }
    public PolicyCompilationException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Policy engine that evaluates Copilot / Semantic Kernel tool calls against enterprise CISO rules.
/// </summary>
public interface ICopilotSafetyPolicyEngine
{
    CopilotPolicyEvaluationResult EvaluatePolicy(CopilotToolCallContext context, CopilotSafetyPolicy policy);
}

public record CopilotPolicyEvaluationResult(
    bool IsPermitted,
    string? DenialReason,
    IReadOnlyList<CopilotSecurityViolation> Violations);

/// <summary>
/// Native Windows Safety Substrate for Microsoft Copilot, Copilot Studio, and Semantic Kernel.
/// Provides pre-execution policy evaluation, kernel sandboxing (Win32 Job Objects / BPF-LSM),
/// tamper-evident Merkle auditing, and real-time streaming to Microsoft Sentinel.
/// </summary>
public interface ICopilotSafetySubstrate
{
    Task<CopilotExecutionResult> ExecuteSafeToolAsync(
        CopilotToolCallContext context,
        CopilotSafetyPolicy? policy = null,
        CancellationToken cancellationToken = default);

    Task<bool> StreamAlertToSentinelAsync(
        CopilotToolCallContext context,
        CopilotExecutionResult result,
        SiemConfiguration sentinelConfig,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Decomposes complex user directives into structured, governed candidate templates and sub-goals,
/// and dynamically re-plans diagnostic next steps as grounded telemetry is observed during multi-step reasoning.
/// </summary>
public interface ICognitiveGoalDecomposer
{
    Task<Brain.GoalDecompositionResult> DecomposeGoalAsync(
        string userGoal,
        IReadOnlyList<SingleToolTemplate> availableTemplates,
        CancellationToken cancellationToken = default);

    Task<Brain.NextStepPlanResult> DecomposeNextStepAsync(
        string userGoal,
        IReadOnlyList<SingleToolTemplate> availableTemplates,
        Brain.BrainWorkingMemory workingMemory,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Layer 2 Cognitive Planning & Autonomous Reasoning Engine ("The Brain").
/// Orchestrates goal decomposition, working memory synthesis, multi-step ReAct hypotheses evaluation,
/// evidence grounding, and root-cause self-healing formulation.
/// </summary>
public interface IAgentBrain
{
    Task<Brain.BrainExecutionResult> ProcessGoalAsync(
        string userGoal,
        string operatorIdentity,
        int maxReasoningSteps = 3,
        IProgress<MissionChunk>? progress = null,
        CancellationToken cancellationToken = default);

    Task<Brain.GoalDecompositionResult> DecomposeGoalAsync(
        string userGoal,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Governed Multi-Agent Crew Orchestration Engine.
/// Executes sequential and hierarchical multi-agent teams under strict SPLAT kernel sandboxing,
/// in-memory DLP sanitization, anti-deadlock cycle detection, and cryptographic audit ledgers.
/// </summary>
public interface IGovernedCrewEngine
{
    IAsyncEnumerable<MissionChunk> ExecuteCrewAsync(
        Crew.GovernedCrewDefinition crew,
        IReadOnlyDictionary<string, string> parameters,
        string operatorIdentity,
        CancellationToken cancellationToken = default);

    Task<Crew.CrewExecutionResult> RunCrewAsync(
        Crew.GovernedCrewDefinition crew,
        IReadOnlyDictionary<string, string> parameters,
        string operatorIdentity,
        IProgress<MissionChunk>? progress = null,
        CancellationToken cancellationToken = default);
}




