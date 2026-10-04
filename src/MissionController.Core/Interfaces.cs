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
    IReadOnlyList<string>? AppliedControls = null,
    // The ceilings the kernel held over the tool, read back by whoever ran it, when the launcher
    // learns them only by running: the Linux lease reports what its cgroup controllers took. Null
    // when the launcher has nothing to add to what the job object already read back before launch.
    JobLimitsReadback? LimitsReadBack = null,
    // The lease the guest daemon installed, when the tool ran under one.
    LeaseOutcome? Lease = null);

/// <summary>
/// The three things a mission needs from the host it runs on - a jail, a job and a launcher - chosen for
/// one template. The engine holds one set for the Windows sensor sandbox and asks a selector for any other;
/// the selector answers null for a template it does not serve, and the engine's own set runs it.
/// </summary>
public sealed record MissionSubstrate(
    string Name,
    IJailManager Jails,
    Func<string, IJobSandbox> Jobs,
    IProcessLauncher Launcher);

/// <summary>
/// Chooses the substrate a template's tool runs on. Composed by each host: the console and splat-mcp
/// hand the engine a selector that serves <see cref="ToolSubstrate.LinuxLease"/> templates through the
/// WSL2 bridge, so the same engine, scrub, judge and ledger run a mission on either substrate.
/// </summary>
public interface IMissionSubstrateSelector
{
    /// <summary>The substrate for this mission, or null to run it on the engine's default.</summary>
    MissionSubstrate? For(SingleToolTemplate template, Guid missionId);
}

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

    /// <summary>
    /// Whether the jail is gone after <see cref="DrainAndCleanupJailAsync"/>, asked of the manager that
    /// knows where it lived: a Windows jail is a directory this process can look for, a Linux one is
    /// in the guest and only the daemon's word says. Null when nothing can say.
    /// </summary>
    bool? IsJailRemoved(string jailPath) => !System.IO.Directory.Exists(jailPath);
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

/// <summary>
/// The revocation list could not be read. A revocation check that cannot see its own list has no
/// answer to give: reporting "not revoked" would turn an unreachable database into a principal
/// that passes the circuit breaker. Both gates refuse the call instead.
/// </summary>
public sealed class RevocationUnavailableException : Exception
{
    public RevocationUnavailableException(string message, Exception? inner = null) : base(message, inner) { }
}

public interface IRevocationStore
{
    Task<IReadOnlyList<RevocationEntry>> LoadRevocationsAsync(CancellationToken cancellationToken = default);
    Task SaveRevocationAsync(RevocationEntry entry, CancellationToken cancellationToken = default);
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
    MerkleConsistencyProof GenerateConsistencyProof(MerkleTree tree, int previousLeafCount);
    bool VerifyConsistencyProof(MerkleConsistencyProof proof, string previousRoot, string root);
}

public interface IComplianceArchiveExporter
{
    Task<string> ExportCompliancePackageAsync(
        ComplianceFramework framework,
        string outputDirectory,
        IReadOnlyList<AuditLogEntry> entries,
        string operatorIdentity,
        CancellationToken cancellationToken = default);

    /// <param name="anchor">
    /// Where the ledger held this mission when the bundle was made, for a verifier to compare against
    /// the live chain. Null leaves the bundle saying it is unanchored, which is the honest thing for a
    /// ledger that cannot answer - and a much weaker bundle, because everything else in one agrees
    /// with itself however much was left out of it.
    /// </param>
    Task<string> ExportMissionRunRecordPackageAsync(
        MissionRunRecord runRecord,
        IReadOnlyList<AuditLogEntry> entries,
        string outputDirectory,
        CancellationToken cancellationToken = default,
        LedgerAnchor? anchor = null,
        ChainInclusion? chainInclusion = null);
}

/// <summary>
/// Assembles a mission's run record in the six-group evidence schema from the ledger alone: the
/// MISSION_RUN_FACTS row the engine sealed when the mission ended, and the mission's other rows. It
/// takes nothing from its caller, so a record cannot say more than the mission recorded.
/// </summary>
public interface IMissionRunRecordAssembler
{
    Task<MissionRunRecord> AssembleRunRecordAsync(Guid missionId, CancellationToken cancellationToken = default);

    /// <summary>Writes the record's bundle, signed when a signing key is configured, and returns its path.
    /// Supplying a prior checkpoint requires a signed consistency proof or refuses the export.</summary>
    Task<string> AssembleAndExportBundleAsync(Guid missionId, string outputDirectory, CancellationToken cancellationToken = default,
        SignedLedgerCheckpoint? previousCheckpoint = null);
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

    /// <summary>
    /// Where this mission sat in the chain, for a bundle to name. Null from a ledger that cannot say,
    /// and the bundle then states it is unanchored rather than carrying an anchor nobody measured.
    /// </summary>
    Task<LedgerAnchor?> ReadAnchorAsync(Guid missionId, CancellationToken cancellationToken = default) =>
        Task.FromResult<LedgerAnchor?>(null);
}

/// <summary>
/// What ties a bundle to the ledger it came out of.
///
/// Everything else in a bundle is self-consistent by construction: the Merkle root covers the entries
/// the bundle carries, the signature covers the files, and both verify against each other whatever
/// was left out. Exporting four of a mission's nine rows produces a bundle that passes every check
/// in it while reading as the whole of the mission - which is not tampering with evidence, it is
/// choosing it. The anchor is the part a verifier can hold up against the host: which chain, where
/// in it, and exactly which rows the ledger held for this mission at the moment of export.
///
/// It is not itself a proof. A host that lies can write a false anchor as easily as a short bundle.
/// Its job is to name what to compare, so that a disagreement has somewhere to show up.
/// </summary>
public record LedgerAnchor(
    // The chain's identity: the entry hash of its first row, which no later row can change without
    // breaking every hash after it. Two ledgers whose first row differs are two chains.
    string GenesisEntryHash,
    // Where the chain stood when the bundle was made. A mission's rows sit below this.
    long HeadEntryId,
    string HeadEntryHash,
    // Every row the ledger held for this mission, by id and hash, in the order the chain holds them.
    // A bundle carrying fewer is a sample of the mission, and this is what lets a verifier say which
    // row is missing rather than only that something is.
    IReadOnlyList<LedgerAnchorEntry> MissionEntries,
    // The host's own word on its chain at export time. It is a courtesy, not evidence: the check that
    // counts is made against the ledger itself, never read out of the bundle.
    bool LedgerVerifiedAtExport,
    int ChainHashVersion,
    DateTimeOffset AnchoredAtUtc);

public record LedgerAnchorEntry(long Id, string EntryHash, string Action);

/// <summary>
/// A statement about the whole chain at one moment, which the operator publishes.
///
/// The anchor tells a verifier what to compare; this is the thing to compare it against. Every
/// check a bundle's recipient could previously run was a check of the bundle against itself - the
/// Merkle root in it covers the entries in it, and the signature covers the files - so a bundle
/// holding four of a mission's nine rows passed all of them. <see cref="RunRecordLedgerVerifier"/>
/// closes that, and runs on the host. This is the version a stranger can run.
///
/// <see cref="ChainMerkleRoot"/> is the root over EVERY ledger entry up to <see cref="HeadEntryId"/>,
/// not over one mission's. A bundle exported against this head carries an inclusion proof per entry
/// whose own root is this one, so a recipient with the bundle and this statement verifies offline
/// that each row it holds was in the ledger when the statement was signed - without the host, and
/// without being able to see any other mission's rows.
///
/// <para>
/// What it does not do, and the row in the roadmap says so: a proof is valid only against the exact
/// root it was generated for, so a recipient needs the checkpoint for the head their bundle names.
/// An export therefore issues one. Proving that a later checkpoint extends an earlier one needs a
/// consistency proof. When an earlier checkpoint is supplied at export, the bundle also carries
/// that proof and both signed heads. It establishes a shared prefix at those two snapshots, never
/// that nothing changed between them or after the later one.
/// </para>
/// </summary>
public record LedgerCheckpoint(
    string GenesisEntryHash,
    long HeadEntryId,
    string HeadEntryHash,
    string ChainMerkleRoot,
    int ChainHashVersion,
    int TotalEntries,
    DateTimeOffset IssuedAtUtc);

/// <summary>
/// A <see cref="LedgerCheckpoint"/> and the operator's signature over it.
///
/// The signature says the statement came from a holder of that key; it cannot say the holder is
/// honest, which no signature can. What it buys a recipient is that the checkpoint they found
/// published and the bundle they were handed were produced by the same key, so a bundle naming a
/// chain nobody published, or a head beyond anything the host has ever stated, stops being
/// something they have to take on trust.
/// </summary>
public record SignedLedgerCheckpoint(
    LedgerCheckpoint Checkpoint,
    string Algorithm,
    string KeyId,
    string PublicKey,
    string Statement,
    string Signature);

/// <summary>
/// What a bundle carries so that a stranger can check it: the checkpoint it was cut against, and
/// one inclusion proof per entry rooted at that checkpoint's chain root. Both or neither - a proof
/// without the statement it proves against is unverifiable, and the statement without the proofs
/// says only that a chain existed.
/// </summary>
public record ChainInclusion(
    SignedLedgerCheckpoint Checkpoint,
    IReadOnlyList<MerkleProof> Proofs,
    LedgerConsistency? Consistency = null);

public record LedgerConsistency(
    SignedLedgerCheckpoint Earlier,
    SignedLedgerCheckpoint Later,
    MerkleConsistencyProof Proof);

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

/// <summary>
/// One row per mission, already sanitized, in the three columns the retention sweep erases.
/// </summary>
public record MissionHistoryRecord(
    Guid MissionId,
    string TemplateId,
    string Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? StartedAtUtc,
    DateTimeOffset? CompletedAtUtc,
    string JailDirectory,
    string? JobId,
    string InitiatedBy,
    string InputParametersJson,
    string RawOutput,
    string AiAnalysis,
    int? ExitCode,
    string? ErrorMessage);

/// <summary>
/// Mission history, which the storage schema declared and nothing ever wrote.
///
/// The empty table was not merely unused: <c>DataRetentionService</c> scrubs three of its columns
/// and reports how many rows it erased, so a sweep over nothing returned zeroes that read as "your
/// retention policy ran and there was nothing left to erase". That is the same sentence a working
/// sweep produces. The write is what makes those counts mean anything.
/// </summary>
public interface IMissionHistoryStore
{
    Task RecordAsync(MissionHistoryRecord record, CancellationToken cancellationToken = default);
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
    Exec = 1,     // bprm_check_security
    Open = 2,     // file_open
    Connect = 3,  // socket_connect
    // socket_sendmsg: a datagram naming its own destination, which never reaches socket_connect.
    SendDatagram = 4
}

public record LeaseViolationEvent(
    ulong CgroupId,
    uint ProcessId,
    KernelViolationHook Hook,
    ulong Detail,
    string DetailText,
    string ProcessComm,
    DateTime TimestampUtc,
    // The denial's number, assigned by the kernel program before the record was reserved: a number
    // that never arrives was dropped. The kernel's monotonic clock at the denial, in nanoseconds
    // since the guest booted. Both 0 from a daemon that predates them.
    ulong Sequence = 0,
    ulong KernelTimeNs = 0);

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
    OverlayFsSpec? OverlayFs = null,
    // The daemon creates the working directory for this lease under its missions root, owned by
    // the workload, and removes it when the lease ends: a governed mission's jail, on the substrate
    // where only root in the guest can make one. False for a caller that names a directory it owns.
    bool EphemeralWorkspace = false);

/// <summary>
/// What the daemon reported about the lease it installed, from its <c>LEASE</c> and <c>EXIT</c> frames:
/// read back from the guest, never repeated from the request. Null on a daemon that predates the frame.
/// </summary>
public record LeaseOutcome(
    ulong CgroupId,
    string? CgroupPath,
    // The daemon holds live BPF map handles and a real cgroup: the lease is policed. False on the
    // openly non-enforcing path, where the workload still runs as nobody and nothing else holds.
    bool Enforcing,
    bool Jailed,
    bool ReadOnlyFs,
    string? Workspace,
    bool WorkspaceCreated,
    bool? WorkspaceRemoved,
    uint? WorkloadUid,
    // False when the daemon refused after making the workspace and before installing anything: the
    // outcome then carries only what became of the directory, and no control may be claimed from it.
    bool Installed = true,
    // What the kernel refused during this lease, and whether the caller heard all of it.
    //
    // ViolationsCounted is the kernel's own tally for this cgroup, read out of a BPF map after the
    // workload exited; ViolationsReported is how many VIOLATION frames actually arrived here. Null
    // on a daemon with no live program, or one that predates the fields - unknown, not zero.
    //
    // ViolationsComplete is the field that matters to a record. Until 2026-09-25 a lease could only
    // report the refusals it managed to deliver, so "the kernel refused nothing" and "a refusal did
    // not reach us" were the same result. A root probe that day scored its UDP check false while
    // the run's own violation list held the denial: the wall held, the receipt did not. A receipt
    // that cannot say whether it is complete is not evidence, and this is the field that says.
    ulong? ViolationsCounted = null,
    ulong? ViolationsReported = null,
    bool? ViolationsComplete = null,
    ulong ViolationsDropped = 0,
    // Roadmap 2.5: the guest's own signature over what the lease did.
    //
    // SignedOutcome is the exact text the daemon signed, carried verbatim rather than rebuilt here:
    // the daemon, this host and two verifier scripts all have to agree on the bytes, and rebuilding
    // a canonical form in four places is where that agreement is lost. The signature proves the
    // text came from a process holding this guest's private key - not that the guest is honest,
    // which root in the guest could never be made to be, but that nothing between the guest and
    // this record altered what it said. Null on a daemon with no key, and the record then says the
    // outcome is unsigned rather than implying it was checked.
    string? SignedOutcome = null,
    string? OutcomeSignature = null,
    string? OutcomeKeyId = null,
    string? OutcomePublicKey = null);

/// <summary>
/// What the daemon reported about a lease, in the vocabulary the run record reads. Every line is read
/// back from the guest's LEASE and EXIT frames; a lease that reported none leaves this empty rather
/// than assumed.
///
/// One function, because there are two authors and one reader. The mission engine's Linux substrate
/// and the MCP lease tools both describe a lease here, and MissionRunRecordAssembler decides whether
/// egress was enforced by looking for the exact string "lease:enforcing". A second copy of this
/// vocabulary does not read as wrong - it reads as "not recorded", which is worse.
/// </summary>
public static class LeaseControls
{
    public static IReadOnlyList<string>? Describe(LeaseOutcome? lease, IReadOnlyList<string>? existing = null)
    {
        if (lease is null)
        {
            return existing;
        }

        if (!lease.Installed)
        {
            // Refused after the workspace was made and before anything was installed: the only
            // fact the daemon has for the record is what became of the directory. No control is
            // claimed from a lease that never existed.
            return new List<string>(existing ?? Array.Empty<string>())
            {
                lease.WorkspaceRemoved == true
                    ? $"workspace:{lease.Workspace} (created by the daemon, removed with the refusal)"
                    : $"workspace:{lease.Workspace} (created by the daemon, NOT removed with the refusal)",
            };
        }

        var controls = new List<string>(existing ?? Array.Empty<string>())
        {
            lease.Enforcing ? "lease:enforcing" : "lease:NOT-enforcing",
            $"cgroup:{lease.CgroupPath ?? lease.CgroupId.ToString()}",
            lease.Jailed ? (lease.ReadOnlyFs ? "jail:mount-namespace,read-only-workdir" : "jail:mount-namespace") : "jail:none",
        };

        if (lease.WorkloadUid is { } uid)
        {
            controls.Add($"workload:uid={uid}");
        }

        if (lease.Workspace is { } workspace)
        {
            controls.Add(lease.WorkspaceCreated ? $"workspace:{workspace} (created by the daemon)" : $"workspace:{workspace}");
        }

        return controls;
    }
}

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




