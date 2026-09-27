using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Audit;

namespace MissionController.Infrastructure.Data.Compliance;

/// <summary>
/// Assembles and exports a mission's run record in the six-group evidence schema (ROADMAP P3, item
/// 3.1), from the ledger alone. The mission engine seals what it observed as a MISSION_RUN_FACTS row
/// when the mission ends; this reads that row and the mission's other rows, and adds nothing of its
/// own beyond the Merkle root over them. A field the facts do not carry is null in the record, which
/// the bundle prints as "not recorded".
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

    public async Task<MissionRunRecord> AssembleRunRecordAsync(Guid missionId, CancellationToken cancellationToken = default)
    {
        var entries = await ReadMissionEntriesAsync(missionId, cancellationToken);
        return Assemble(missionId, entries);
    }

    public async Task<string> AssembleAndExportBundleAsync(Guid missionId, string outputDirectory, CancellationToken cancellationToken = default)
    {
        // One read serves the record and the bundle. Two reads let an entry appended between them into
        // the proofs but not under the record's root, and the bundle then failed its own verification.
        var entries = await ReadMissionEntriesAsync(missionId, cancellationToken);
        var record = Assemble(missionId, entries);

        return await _archiveExporter.ExportMissionRunRecordPackageAsync(record, entries, outputDirectory, cancellationToken);
    }

    private MissionRunRecord Assemble(Guid missionId, IReadOnlyList<AuditLogEntry> entries)
    {
        var factsEntry = entries
            .Where(e => e.Action == MissionRunFacts.LedgerAction)
            .OrderBy(e => e.Id)
            .LastOrDefault()
            ?? throw new InvalidOperationException(
                $"Mission {missionId:D} has no {MissionRunFacts.LedgerAction} row. Either it is still running, it ran " +
                "before the engine sealed its facts, or the ledger holds no mission by that id.");

        MissionRunFacts facts;
        try
        {
            facts = JsonSerializer.Deserialize<MissionRunFacts>(factsEntry.Details)
                ?? throw new JsonException("The facts row is empty.");
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                $"The facts sealed for mission {missionId:D} cannot be read, which is what retention leaves once it " +
                $"has redacted a row's details: {ex.Message}", ex);
        }

        if (facts.Schema != MissionRunFacts.CurrentSchema || facts.MissionId != missionId)
        {
            throw new InvalidOperationException(
                $"The facts row for mission {missionId:D} is schema {facts.Schema} for mission {facts.MissionId:D}; " +
                $"this build reads schema {MissionRunFacts.CurrentSchema}.");
        }

        var (chainKind, hashVersion) = ChainOf(entries);
        var tokenControls = facts.AppliedControls.Where(c => c.StartsWith("token:", StringComparison.Ordinal)).ToList();

        var requestIdentity = new RequestIdentityEvidence(
            Principal: string.IsNullOrWhiteSpace(facts.Principal) ? null : facts.Principal,
            AuthProvenance: ProvenanceOf(facts.Principal),
            MissionId: missionId,
            IdempotencyToken: "none: a mission id names one request, and nothing deduplicates requests",
            ApprovalReference: "none: a mission runs on its caller's request, with no separate approval step",
            PolicyVersionOrHash: facts.TemplateSha256,
            RequestedAtUtc: facts.StartedAtUtc);

        var effectivePermission = new EffectivePermissionEvidence(
            ExecutablePath: facts.ExecutablePath,
            CommandLine: facts.CommandLine,
            WorkspaceBoundary: facts.WorkspacePath,
            DeclaredEgress: facts.DeclaredEgress,
            EgressEnforcement: EgressEnforcementOf(facts),
            MaxMemoryBytes: (ulong)Math.Max(0, facts.RequestedMemoryBytes),
            MaxCpuPercent: (uint)Math.Max(0, facts.RequestedCpuPercent),
            DurationCeilingSeconds: (uint)Math.Max(0, facts.TimeoutSeconds),
            RuntimeIdentity: tokenControls.Count == 0 ? null : string.Join(", ", tokenControls));

        var enforcementState = new EnforcementStateEvidence(
            SubstrateType: facts.Substrate,
            KernelOrOsRelease: string.IsNullOrWhiteSpace(facts.OsDescription) ? null : facts.OsDescription,
            AttachedControls: facts.AppliedControls.Count == 0 ? null : facts.AppliedControls,
            CgroupOrJobId: facts.JobName,
            EffectiveLimitsReadback: facts.LimitsReadBack,
            AdmissionVerdict: facts.Admission,
            KernelRefusals: facts.KernelRefusals,
            KernelRefusalsReported: facts.KernelRefusalsReported,
            KernelRefusalEvidenceComplete: facts.KernelRefusalEvidenceComplete,
            GuestSignedOutcome: facts.GuestSignedOutcome,
            GuestOutcomeSignature: facts.GuestOutcomeSignature,
            GuestOutcomeKeyId: facts.GuestOutcomeKeyId,
            GuestOutcomePublicKey: facts.GuestOutcomePublicKey);

        var outcome = new OutcomeEvidence(
            ExecutionState: facts.ExecutionState,
            ExitCode: facts.ExitCode,
            AllowedExitCodes: facts.AllowedExitCodes,
            ExitContractMet: facts.ExitContractMet,
            TerminalReason: facts.TerminalReason,
            RedactionCount: facts.RedactionCount,
            RedactedCategories: facts.RedactedCategories,
            Model: facts.Model,
            QualityAcceptance: facts.QualityAccepted);

        var cleanup = new CleanupEvidence(
            ProcessesLeftAtTeardown: facts.ProcessesLeftAtTeardown,
            TeardownOrder: facts.TeardownOrder.Count == 0 ? null : facts.TeardownOrder,
            WorkspaceDisposition: facts.WorkspacePath is null
                ? "none: nothing was provisioned"
                : facts.JailRemoved switch { true => "removed", false => "remains on disk", null => null },
            ResidualResourcesCleaned: CleanedUp(facts));

        var integrity = new IntegrityEvidence(
            ChainKind: chainKind,
            HashVersion: hashVersion,
            MerkleRootHash: entries.Count == 0 ? null : _merkleEngine.BuildTree(entries).RootHash,
            TotalAuditEntries: entries.Count,
            FactsEntryHash: factsEntry.EntryHash,
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

    // OperatorIdentity.ToLedgerIdentity writes "<method>:<name> [<id>] via <transport>", so the host's
    // own account of how it authenticated the caller is the prefix. Anything else was not written by a
    // host that says, and is not recorded as provenance.
    private static string? ProvenanceOf(string principal)
    {
        int colon = principal.IndexOf(':');
        if (colon <= 0)
        {
            return null;
        }

        string method = principal[..colon] switch
        {
            "windows" => "Windows logon: the operating system authenticated the caller",
            "apikey" => "an API key the host validated",
            "bearer" => "a bearer token the host validated",
            "unauthenticated" => "none: the host could not authenticate the caller",
            _ => string.Empty
        };
        if (method.Length == 0)
        {
            return null;
        }

        int via = principal.LastIndexOf(" via ", StringComparison.Ordinal);
        return via < 0 ? method : $"{method}, over {principal[(via + 5)..]}";
    }

    // Read from the tool's token, not from the request: the AppContainer is what removes the network.
    private static string EgressEnforcementOf(MissionRunFacts facts)
    {
        // The Linux lease reports itself: the kernel's socket hooks hold the tool to the lease's
        // address list, which is empty for a template with no sensor destination. "enforcing" is
        // the daemon's own word for holding live map handles; without it the tool ran as nobody in
        // the guest with nothing policing its sockets, and the record says that instead.
        string? lease = facts.AppliedControls.FirstOrDefault(c => c.StartsWith("lease:", StringComparison.Ordinal));
        if (lease is not null)
        {
            bool enforcing = facts.AppliedControls.Contains("lease:enforcing");
            return enforcing
                ? (facts.NetworkDenialRequested
                    ? "enforced: the Linux lease named no destination, so the kernel refused every connect and datagram (BPF-LSM socket_connect and socket_sendmsg)"
                    : "enforced: the kernel held the tool to the lease's IPv4 allow-list (BPF-LSM socket_connect and socket_sendmsg)")
                : "NOT enforced: the daemon reported it was not enforcing, so no kernel hook held the tool's sockets";
        }

        string? container = facts.AppliedControls.FirstOrDefault(c => c.StartsWith("token:appcontainer=", StringComparison.Ordinal));
        return container switch
        {
            "token:appcontainer=0-capabilities" =>
                "enforced: the tool had no network at all (an AppContainer with no capabilities, read back from its token)",
            "token:appcontainer=none" when facts.NetworkDenialRequested =>
                "NOT enforced: denial was requested but the tool's token shows no AppContainer",
            "token:appcontainer=none" =>
                "declared only: the tool kept a network stack, and Windows does not hold it to the declared destination",
            null when facts.ExitCode is null =>
                "not applicable: no tool ran",
            // Substrate-neutral on purpose: a lease tool reaches here too, when the daemon reported
            // no lease at all. "the tool's token was not read back" is a Windows sentence, and it
            // read as a statement about a token that never existed on the other substrate.
            null =>
                "not recorded: nothing read back what held the tool's sockets",
            _ => $"partly: {container["token:appcontainer=".Length..]} granted to the tool's AppContainer"
        };
    }

    private static bool? CleanedUp(MissionRunFacts facts)
    {
        if (facts.WorkspacePath is null && facts.JobName is null)
        {
            return true; // nothing was provisioned, so nothing can have been left
        }

        // An empty teardown order is not a job left open, it is a teardown nobody watched. The
        // Windows engine writes a line for every step, so "no line" used to be impossible and false
        // was read as "the job stayed open"; a lease tool's cgroup is torn down inside the guest and
        // the daemon's frames say nothing about it, which made every one of those records claim a
        // leak that was never observed.
        bool? jobClosed = facts.JobName is null
            ? true
            : facts.TeardownOrder.Count == 0
                ? null
                : facts.TeardownOrder.Any(s => s.StartsWith("job: closed", StringComparison.Ordinal));

        return facts.JailRemoved switch
        {
            true => jobClosed,
            false => false,
            null => facts.WorkspacePath is null ? jobClosed : null
        };
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
}
