using System;
using System.Collections.Generic;

namespace MissionController.Core.Models;

/// <summary>
/// Group 1: Request Identity
/// Proves who authorized this specific action and prevents replay/permission substitution.
/// </summary>
public record RequestIdentityEvidence(
    string Principal,
    string AuthProvenance,
    Guid MissionId,
    string? IdempotencyToken,
    string? ApprovalReference,
    string PolicyVersionOrHash,
    DateTimeOffset RequestedAtUtc);

/// <summary>
/// Group 2: Effective Permission
/// Describes what the runtime actually permits, including any explicitly unsupported dimension.
/// </summary>
public record EffectivePermissionEvidence(
    string ExecutablePath,
    IReadOnlyList<string> ArgumentVector,
    string WorkspaceBoundary,
    IReadOnlyList<string> AllowedEgressIps,
    IReadOnlyList<uint> AllowedEgressPorts,
    bool AllowNetwork,
    ulong MaxMemoryBytes,
    uint MaxCpuPercent,
    uint LeaseDurationSeconds,
    string? RuntimeCapabilities = null);

/// <summary>
/// Group 3: Enforcement State
/// Prevents policy intent from being mistaken for installed enforcement.
/// </summary>
public record EnforcementStateEvidence(
    string SubstrateType,
    string KernelOrOsRelease,
    IReadOnlyList<string> AttachedControls,
    string? CgroupOrJobId,
    string? EffectiveLimitsReadback,
    string AdmissionVerdict);

/// <summary>
/// Group 4: Outcome
/// Lets callers make safe retry and downstream-memory decisions without parsing prose.
/// </summary>
public record OutcomeEvidence(
    string ExecutionState,
    int? ExitCode,
    int RedactionCount,
    IReadOnlyList<string> RedactedCategories,
    bool QualityAcceptance,
    string? TerminalReason = null);

/// <summary>
/// Group 5: Cleanup
/// Establishes that expiry or disconnect did not leave authority running.
/// </summary>
public record CleanupEvidence(
    bool ProcessesTerminated,
    IReadOnlyList<string> PolicyRemovalOrder,
    string WorkspaceDisposition,
    bool ResidualResourcesCleaned);

/// <summary>
/// Group 6: Integrity
/// Makes evidence portable and defines its actual tamper/rewrite/truncation guarantees.
/// </summary>
public record IntegrityEvidence(
    string ChainKind,
    int HashVersion,
    string MerkleRootHash,
    int TotalAuditEntries,
    string AttestationSignature,
    string SignatureAlgorithm,
    DateTimeOffset CommittedAtUtc);

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
