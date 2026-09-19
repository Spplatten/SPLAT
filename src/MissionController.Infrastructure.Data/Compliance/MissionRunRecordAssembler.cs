using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Audit;

namespace MissionController.Infrastructure.Data.Compliance;

/// <summary>
/// Assembles and exports a per-mission run record in the six-group evidence schema (ROADMAP P3, item
/// 3.1). It records what its caller hands it and what the ledger holds for the mission, and nothing
/// else: every field neither source gives is null, which the bundle prints as "not recorded".
/// </summary>
public sealed class MissionRunRecordAssembler : IMissionRunRecordAssembler
{
    // A record covers all of a mission's entries or is refused. The ledger returns them newest first,
    // so a cut would drop the mission's start while TotalAuditEntries still read as the whole of it.
    private const int MaxMissionEntries = 100_000;

    private readonly IAuditLedger _auditLedger;
    private readonly IMerkleProofEngine _merkleEngine;
    private readonly IComplianceArchiveExporter _archiveExporter;

    public MissionRunRecordAssembler(
        IAuditLedger auditLedger,
        IMerkleProofEngine merkleEngine,
        IComplianceArchiveExporter archiveExporter)
    {
        _auditLedger = auditLedger ?? throw new ArgumentNullException(nameof(auditLedger));
        _merkleEngine = merkleEngine ?? throw new ArgumentNullException(nameof(merkleEngine));
        _archiveExporter = archiveExporter ?? throw new ArgumentNullException(nameof(archiveExporter));
    }

    public async Task<MissionRunRecord> AssembleRunRecordAsync(
        Guid missionId,
        SingleToolTemplate template,
        LeaseSpec? leaseSpec,
        string operatorIdentity,
        string executionState,
        int? exitCode,
        int redactionCount,
        IReadOnlyList<string> redactedCategories,
        string substrateType,
        string? cgroupOrJobId = null,
        bool? qualityAcceptance = null,
        string? terminalReason = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(template);
        var entries = await ReadMissionEntriesAsync(missionId, cancellationToken);
        return Assemble(entries, missionId, template, leaseSpec, operatorIdentity, executionState, exitCode,
            redactionCount, redactedCategories, substrateType, cgroupOrJobId, qualityAcceptance, terminalReason);
    }

    private MissionRunRecord Assemble(
        IReadOnlyList<AuditLogEntry> entries,
        Guid missionId,
        SingleToolTemplate template,
        LeaseSpec? leaseSpec,
        string? operatorIdentity,
        string executionState,
        int? exitCode,
        int redactionCount,
        IReadOnlyList<string>? redactedCategories,
        string substrateType,
        string? cgroupOrJobId,
        bool? qualityAcceptance,
        string? terminalReason)
    {
        var (chainKind, hashVersion) = ChainOf(entries);

        var requestIdentity = new RequestIdentityEvidence(
            Principal: string.IsNullOrWhiteSpace(operatorIdentity) ? null : operatorIdentity,
            // Nothing in the host records how a principal authenticated, an approval or an
            // idempotency key; a mission id is not one, since nothing deduplicates on it.
            AuthProvenance: null,
            MissionId: missionId,
            IdempotencyToken: null,
            ApprovalReference: null,
            PolicyVersionOrHash: TemplateHash(template),
            FirstRecordedAtUtc: entries.Count == 0 ? null : entries.Min(e => AsUtc(e.TimestampUtc)));

        var effectivePermission = new EffectivePermissionEvidence(
            ExecutablePath: template.Tool.ExecutablePath,
            // The template holds placeholders; the bound vector exists only where the mission ran.
            ArgumentVector: null,
            // The network rules and the workspace exist only in a lease, which only the WSL path has.
            WorkspaceBoundary: leaseSpec?.WorkingDirectory,
            AllowedEgressIps: leaseSpec?.AllowedEgressIps,
            AllowedEgressPorts: leaseSpec?.AllowedEgressPorts,
            AllowNetwork: leaseSpec?.AllowNetwork,
            // Ceilings as requested, from the lease or else the template the job object is sized from.
            MaxMemoryBytes: leaseSpec?.Limits.MaxMemoryBytes ?? (ulong)template.Tool.MaxMemoryBytes,
            MaxCpuPercent: leaseSpec?.Limits.MaxCpuPercent ?? (uint)template.Tool.MaxCpuPercent,
            LeaseDurationSeconds: leaseSpec?.LeaseDurationSeconds,
            RuntimeCapabilities: null);

        var enforcementState = new EnforcementStateEvidence(
            SubstrateType: substrateType,
            // What was attached, the kernel it ran under and the limits as read back are the
            // substrate's to report, and neither substrate returns them with a result yet.
            KernelOrOsRelease: null,
            AttachedControls: null,
            CgroupOrJobId: cgroupOrJobId,
            EffectiveLimitsReadback: null,
            AdmissionVerdict: executionState == "Refused" ? "Refused" : "Admitted");

        var outcome = new OutcomeEvidence(
            ExecutionState: executionState,
            ExitCode: exitCode,
            RedactionCount: redactionCount,
            RedactedCategories: redactedCategories ?? Array.Empty<string>(),
            QualityAcceptance: qualityAcceptance,
            TerminalReason: terminalReason);

        // Teardown happens in the substrate, which does not report it back yet.
        var cleanup = new CleanupEvidence(
            ProcessesTerminated: null,
            PolicyRemovalOrder: null,
            WorkspaceDisposition: null,
            ResidualResourcesCleaned: null);

        var integrity = new IntegrityEvidence(
            ChainKind: chainKind,
            HashVersion: hashVersion,
            MerkleRootHash: entries.Count == 0 ? null : _merkleEngine.BuildTree(entries).RootHash,
            TotalAuditEntries: entries.Count,
            // A digest anyone can recompute is not a signature, and nothing signs a record yet.
            AttestationSignature: null,
            SignatureAlgorithm: null,
            AssembledAtUtc: DateTimeOffset.UtcNow);

        return new MissionRunRecord(
            MissionId: missionId,
            RequestIdentity: requestIdentity,
            EffectivePermission: effectivePermission,
            EnforcementState: enforcementState,
            Outcome: outcome,
            Cleanup: cleanup,
            Integrity: integrity);
    }

    public async Task<string> AssembleAndExportBundleAsync(
        Guid missionId,
        SingleToolTemplate template,
        LeaseSpec? leaseSpec,
        string operatorIdentity,
        string executionState,
        int? exitCode,
        int redactionCount,
        IReadOnlyList<string> redactedCategories,
        string substrateType,
        string outputDirectory,
        string? cgroupOrJobId = null,
        bool? qualityAcceptance = null,
        string? terminalReason = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(template);

        // One read serves the record and the bundle. Two reads let an entry appended between them into
        // the proofs but not under the record's root, and the bundle then failed its own verification.
        var entries = await ReadMissionEntriesAsync(missionId, cancellationToken);
        var record = Assemble(entries, missionId, template, leaseSpec, operatorIdentity, executionState, exitCode,
            redactionCount, redactedCategories, substrateType, cgroupOrJobId, qualityAcceptance, terminalReason);

        return await _archiveExporter.ExportMissionRunRecordPackageAsync(
            record,
            entries,
            outputDirectory,
            cancellationToken);
    }

    private async Task<IReadOnlyList<AuditLogEntry>> ReadMissionEntriesAsync(Guid missionId, CancellationToken cancellationToken)
    {
        var entries = await _auditLedger.GetAuditLogsAsync(missionId, MaxMissionEntries + 1, cancellationToken);
        if (entries.Count > MaxMissionEntries)
        {
            throw new InvalidOperationException(
                $"Mission {missionId:D} has more than {MaxMissionEntries} ledger entries; a record over part of them would read as the whole.");
        }

        return entries;
    }

    // The kind of chain the mission's own rows were written into, read from each row's hash version.
    // The LEDGER_KEYED row belongs to no mission, so looking for it among a mission's rows never finds it.
    private static (string? Kind, int? Version) ChainOf(IReadOnlyList<AuditLogEntry> entries)
    {
        var versions = entries.Select(e => e.HashVersion).Distinct().ToList();
        if (versions.Count == 0 || versions.Contains(0))
        {
            return (null, null);
        }

        if (versions.Count > 1)
        {
            return ("Mixed", null);
        }

        string? kind = versions[0] switch
        {
            SqliteChainedAuditLedger.PlaintextVersion => "Plaintext",
            SqliteChainedAuditLedger.UnkeyedVersion => "Unkeyed",
            SqliteChainedAuditLedger.KeyedVersion => "HmacSha256",
            _ => null
        };
        return kind is null ? (null, null) : (kind, versions[0]);
    }

    // The template as handed in, so two versions of one template id do not read as the same policy.
    private static string TemplateHash(SingleToolTemplate template) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(template))).ToLowerInvariant();

    // TimestampUtc is UTC by contract, so an unspecified kind is read as UTC, not as this machine's local time.
    private static DateTimeOffset AsUtc(DateTime timestamp) =>
        new DateTimeOffset(timestamp.Kind == DateTimeKind.Unspecified
            ? DateTime.SpecifyKind(timestamp, DateTimeKind.Utc)
            : timestamp).ToUniversalTime();
}
