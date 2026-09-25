using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.Json;

namespace MissionController.Core.Models;

/// <summary>
/// What the mission engine observed while one mission ran. The engine seals it into the ledger as one
/// MISSION_RUN_FACTS row when the mission ends, on every path, refusals and failures included. The run
/// record is assembled from this row and the mission's other rows, so nothing in a record is inferred
/// afterwards, and the facts sit in the same hash chain as the rest of the mission, keyed when the
/// ledger is.
/// </summary>
public sealed class MissionRunFacts
{
    public const string LedgerAction = "MISSION_RUN_FACTS";
    public const int CurrentSchema = 1;

    public int Schema { get; set; } = CurrentSchema;
    public Guid MissionId { get; set; }
    public string TemplateId { get; set; } = string.Empty;
    public string TemplateSha256 { get; set; } = string.Empty;
    public string Principal { get; set; } = string.Empty;
    public DateTimeOffset StartedAtUtc { get; set; }
    public DateTimeOffset? EndedAtUtc { get; set; }

    // Permission, as the engine asked for it.
    public string ExecutablePath { get; set; } = string.Empty;
    public string? CommandLine { get; set; }
    public string? WorkspacePath { get; set; }
    public string DeclaredEgress { get; set; } = string.Empty;
    public bool NetworkDenialRequested { get; set; }
    public bool PrivilegeDropRequested { get; set; }
    public long RequestedMemoryBytes { get; set; }
    public int RequestedCpuPercent { get; set; }
    public int TimeoutSeconds { get; set; }

    // Enforcement, as read back from the kernel objects.
    public string Substrate { get; set; } = "Windows";
    public string OsDescription { get; set; } = string.Empty;
    public string? JobName { get; set; }
    public JobLimitsReadback? LimitsReadBack { get; set; }
    public List<string> AppliedControls { get; set; } = new();
    public string Admission { get; set; } = "Admitted";

    // What the kernel refused during this mission, and whether the record holds all of it.
    //
    // KernelRefusals is the guest kernel's own count for this lease's cgroup; KernelRefusalsReported
    // is how many of those reached this host as VIOLATION frames. Null on Windows, and on a daemon
    // that predates the count: unknown, never a confident zero.
    //
    // KernelRefusalEvidenceComplete is the one a reader should look at. A record that lists two
    // refusals and cannot say whether there was a third is not evidence of containment, it is a
    // sample of it - and until 2026-09-25 every record of a leased mission was the second kind
    // without saying so.
    public ulong? KernelRefusals { get; set; }
    public ulong? KernelRefusalsReported { get; set; }
    public bool? KernelRefusalEvidenceComplete { get; set; }

    // The guest's own signature over what the lease did (roadmap 2.5). Until 2026-09-25 the
    // kernel-enforced path had the weakest receipt of anything here: a Windows mission sealed its
    // facts into a chained ledger, while a Linux lease reported over a socket to a host that then
    // wrote down whatever it liked. These four close the gap between the guest saying something
    // and this record claiming it. Null on Windows and on a guest with no key, where the bundle
    // says the outcome is unsigned rather than implying someone checked it.
    public string? GuestSignedOutcome { get; set; }
    public string? GuestOutcomeSignature { get; set; }
    public string? GuestOutcomeKeyId { get; set; }
    public string? GuestOutcomePublicKey { get; set; }

    // Outcome.
    public string ExecutionState { get; set; } = "Faulted";
    public int? ExitCode { get; set; }
    public bool? TimedOut { get; set; }
    public List<int> AllowedExitCodes { get; set; } = new();
    public bool? ExitContractMet { get; set; }
    public string? TerminalReason { get; set; }
    public int RedactionCount { get; set; }
    public List<string> RedactedCategories { get; set; } = new();
    public string? Model { get; set; }
    public bool? QualityAccepted { get; set; }

    // Cleanup, as observed at teardown.
    public uint? ProcessesLeftAtTeardown { get; set; }
    public bool? JailRemoved { get; set; }
    public List<string> TeardownOrder { get; set; } = new();

    /// <summary>
    /// The template as the engine ran it. Two versions of one template id are two policies, so the
    /// record names the version by its content rather than by its id.
    /// </summary>
    public static string HashTemplate(SingleToolTemplate template) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(template))).ToLowerInvariant();
}

// In the six groups below a null field means NOT RECORDED: nothing that ran the mission observed it.
// It is never a default standing in for an observation, because a reader of the bundle cannot tell a
// filled-in constant from a measured value.

/// <summary>
/// Group 1: Request Identity
/// Proves who authorized this specific action and prevents replay/permission substitution.
/// </summary>
public record RequestIdentityEvidence(
    string? Principal,
    string? AuthProvenance,
    Guid MissionId,
    string? IdempotencyToken,
    string? ApprovalReference,
    string PolicyVersionOrHash,
    DateTimeOffset? RequestedAtUtc);

/// <summary>
/// Group 2: Effective Permission
/// Describes what the runtime actually permits, including any explicitly unsupported dimension.
/// </summary>
public record EffectivePermissionEvidence(
    string ExecutablePath,
    string? CommandLine,
    string? WorkspaceBoundary,
    string DeclaredEgress,
    string EgressEnforcement,
    ulong MaxMemoryBytes,
    uint MaxCpuPercent,
    uint? DurationCeilingSeconds,
    string? RuntimeIdentity);

/// <summary>
/// Group 3: Enforcement State
/// Prevents policy intent from being mistaken for installed enforcement.
/// </summary>
public record EnforcementStateEvidence(
    string SubstrateType,
    string? KernelOrOsRelease,
    IReadOnlyList<string>? AttachedControls,
    string? CgroupOrJobId,
    JobLimitsReadback? EffectiveLimitsReadback,
    string AdmissionVerdict,
    // See MissionRunFacts: the kernel's own count of what it refused for this lease, how much of it
    // reached the host, and whether this record is therefore the whole of it. Null on Windows and on
    // a daemon that predates the fields.
    ulong? KernelRefusals = null,
    ulong? KernelRefusalsReported = null,
    bool? KernelRefusalEvidenceComplete = null,
    // See MissionRunFacts: the guest's signature over its own outcome, carried verbatim so a
    // verifier checks the bytes the guest signed rather than a rebuild of them.
    string? GuestSignedOutcome = null,
    string? GuestOutcomeSignature = null,
    string? GuestOutcomeKeyId = null,
    string? GuestOutcomePublicKey = null);

/// <summary>
/// Group 4: Outcome
/// Lets callers make safe retry and downstream-memory decisions without parsing prose.
/// </summary>
public record OutcomeEvidence(
    string ExecutionState,
    int? ExitCode,
    IReadOnlyList<int> AllowedExitCodes,
    bool? ExitContractMet,
    string? TerminalReason,
    int RedactionCount,
    IReadOnlyList<string> RedactedCategories,
    string? Model,
    bool? QualityAcceptance);

/// <summary>
/// Group 5: Cleanup
/// Establishes that expiry or disconnect did not leave authority running.
/// </summary>
public record CleanupEvidence(
    uint? ProcessesLeftAtTeardown,
    IReadOnlyList<string>? TeardownOrder,
    string? WorkspaceDisposition,
    bool? ResidualResourcesCleaned);

/// <summary>
/// Group 6: Integrity
/// Makes evidence portable and defines its actual tamper/rewrite/truncation guarantees. The bundle's
/// signature covers the record, so it is carried beside the record rather than inside it.
/// </summary>
public record IntegrityEvidence(
    string? ChainKind,
    int? HashVersion,
    string? MerkleRootHash,
    int TotalAuditEntries,
    string? FactsEntryHash,
    DateTimeOffset AssembledAtUtc);

/// <summary>
/// Complete per-mission run record fulfilling the six-group evidence contract (ROADMAP P3 / Item 3.1).
/// </summary>
public record MissionRunRecord(
    Guid MissionId,
    RequestIdentityEvidence RequestIdentity,
    EffectivePermissionEvidence EffectivePermission,
    EnforcementStateEvidence EnforcementState,
    OutcomeEvidence Outcome,
    CleanupEvidence Cleanup,
    IntegrityEvidence Integrity);
