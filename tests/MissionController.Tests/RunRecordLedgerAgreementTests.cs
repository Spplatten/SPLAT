using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Compliance;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Whether a bundle agrees with the ledger it claims to have come out of.
///
/// The thing these tests have to be able to catch is not a forged bundle - it is an honest-looking
/// one. Export four of a mission's nine rows and every check inside the bundle passes: the Merkle
/// root covers the four, the signature covers the files, both scripts print PASS, and the record
/// reads as the whole mission. So the short-bundle cases here are built the way the problem actually
/// occurs, by exporting a subset through the real exporter and signing it properly, rather than by
/// corrupting a good bundle - a corrupted bundle fails on its signature and proves nothing about the
/// check under test.
///
/// The first test is the control. Without it every other assertion here could be satisfied by a
/// verifier that fails everything.
/// </summary>
public class RunRecordLedgerAgreementTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"splat-agree-{Guid.NewGuid():N}");
    private readonly List<string> _dbs = new();

    public RunRecordLedgerAgreementTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        GC.Collect();
        GC.WaitForPendingFinalizers();
        foreach (string db in _dbs)
        {
            try { File.Delete(db); } catch (IOException) { }
        }

        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private static MissionRunFacts Facts(Guid missionId) => new()
    {
        MissionId = missionId,
        TemplateId = "net-dns-audit",
        TemplateSha256 = "sha256:" + new string('b', 64),
        Principal = "windows:Operator Atlas [S-1-5-21-7] via console",
        StartedAtUtc = DateTimeOffset.UtcNow.AddSeconds(-3),
        EndedAtUtc = DateTimeOffset.UtcNow,
        ExecutablePath = "cmd.exe",
        ExecutionState = "Completed",
        ExitCode = 0,
        AllowedExitCodes = { 0 },
        ExitContractMet = true
    };

    /// <summary>
    /// A mission with rows worth leaving out. KERNEL_VIOLATION is the row an exporter with something
    /// to hide would drop, which is why the short-bundle cases below drop exactly that one.
    /// </summary>
    private async Task<(SqliteChainedAuditLedger Ledger, Guid MissionId)> LedgerWithMissionAsync()
    {
        string dbPath = Path.Combine(_dir, $"{Guid.NewGuid():N}.db");
        _dbs.Add(dbPath);

        var ledger = new SqliteChainedAuditLedger(new SqliteStorageContext(dbPath));
        var missionId = Guid.NewGuid();
        var facts = Facts(missionId);

        await ledger.AppendLogAsync(missionId, facts.TemplateId, "MISSION_INITIATED", "Template: DNS audit", facts.Principal);
        await ledger.AppendLogAsync(missionId, facts.TemplateId, "KERNEL_VIOLATION", "-EPERM connect 8.8.8.8:53", facts.Principal);
        await ledger.AppendLogAsync(missionId, facts.TemplateId, "TOOL_EXECUTION_COMPLETED", "ExitCode: 0", facts.Principal);
        await ledger.AppendLogAsync(missionId, facts.TemplateId, MissionRunFacts.LedgerAction, JsonSerializer.Serialize(facts), facts.Principal);
        return (ledger, missionId);
    }

    private static RsaRunRecordSigner NewSigner(string dir)
    {
        string keyPath = Path.Combine(dir, $"{Guid.NewGuid():N}.pem");
        File.WriteAllText(keyPath, RunRecordKeyFile.NewKeyPem(out _));
        return RunRecordKeyFile.Load(keyPath);
    }

    private static MissionRunRecordAssembler AssemblerFor(IAuditLedger ledger, IRunRecordSigner? signer)
    {
        var merkle = new MerkleTreeEngine();
        return new MissionRunRecordAssembler(ledger, merkle, new ComplianceArchiveExporter(merkle, signer));
    }

    private static RunRecordLedgerVerifier VerifierFor(IAuditLedger ledger, IRunRecordSigner? hostSigner = null) =>
        new(ledger, new MerkleTreeEngine(), hostSigner);

    private static LedgerAgreementCheck Check(LedgerAgreementResult result, string name)
    {
        var check = result.Checks.FirstOrDefault(c => c.Name == name);
        Assert.True(check is not null, $"No check named '{name}'. Ran: {string.Join(", ", result.Checks.Select(c => c.Name))}");
        return check!;
    }

    private static void AssertPassedExcept(LedgerAgreementResult result, params string[] expectedFailures)
    {
        var actual = result.Checks.Where(c => c.Passed != true).Select(c => c.Name).OrderBy(n => n).ToList();
        Assert.Equal(expectedFailures.OrderBy(n => n).ToList(), actual);
    }

    [Fact]
    public async Task AGoodBundle_AgreesWithTheLedgerItCameFrom()
    {
        var (ledger, missionId) = await LedgerWithMissionAsync();
        using var signer = NewSigner(_dir);

        string bundle = await AssemblerFor(ledger, signer).AssembleAndExportBundleAsync(missionId, _dir);
        var result = await VerifierFor(ledger, signer).VerifyAsync(bundle);

        // The control. Every other test here asserts a failure; if this one cannot pass, none of
        // them mean anything.
        AssertPassedExcept(result);
        Assert.True(result.Agrees, result.Verdict);
        Assert.Equal(missionId, result.MissionId);
        Assert.Contains("this host's own run record key", Check(result, "bundle-signature").Detail);
        Assert.Contains("All 4 of the mission's rows", Check(result, "bundle-holds-every-row").Detail);
    }

    [Fact]
    public async Task TheBundleCarriesAnAnchorNamingEveryRowTheLedgerHeld()
    {
        var (ledger, missionId) = await LedgerWithMissionAsync();

        string bundle = await AssemblerFor(ledger, null).AssembleAndExportBundleAsync(missionId, _dir);

        using var archive = ZipFile.OpenRead(bundle);
        var entry = archive.GetEntry("ledger_anchor.json");
        Assert.NotNull(entry);

        using var stream = entry!.Open();
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        var bytes = buffer.ToArray();
        var anchor = JsonSerializer.Deserialize<LedgerAnchor>(
            bytes.AsSpan(3), // the exporter writes every text file with a BOM
            new JsonSerializerOptions());

        Assert.NotNull(anchor);
        Assert.Equal(4, anchor!.MissionEntries.Count);
        Assert.Contains(anchor.MissionEntries, e => e.Action == "KERNEL_VIOLATION");
        Assert.True(anchor.LedgerVerifiedAtExport);
        Assert.Equal(4, anchor.HeadEntryId);
        Assert.Equal(SqliteChainedAuditLedger.UnkeyedVersion, anchor.ChainHashVersion);
    }

    /// <summary>
    /// The one that matters. A properly signed bundle, internally perfect, carrying three of the
    /// mission's four rows - the kernel violation dropped - and an anchor that tells the truth about
    /// what the ledger held. Nothing inside the bundle can notice; the host can.
    /// </summary>
    [Fact]
    public async Task AShortBundle_IsCaught_EvenThoughEverythingInsideItAgrees()
    {
        var (ledger, missionId) = await LedgerWithMissionAsync();
        using var signer = NewSigner(_dir);

        var merkle = new MerkleTreeEngine();
        var all = await ledger.GetAuditLogsAsync(missionId, 100);
        var kept = all.Where(e => e.Action != "KERNEL_VIOLATION").ToList();
        var record = await AssemblerFor(ledger, signer).AssembleRunRecordAsync(missionId);

        // Rebuilt over the kept rows only, so the bundle is self-consistent: this is the honest-
        // looking short export, not a corrupted one.
        var shortRecord = record with
        {
            Integrity = record.Integrity with
            {
                MerkleRootHash = merkle.BuildTree(kept).RootHash,
                TotalAuditEntries = kept.Count
            }
        };

        string bundle = await new ComplianceArchiveExporter(merkle, signer)
            .ExportMissionRunRecordPackageAsync(shortRecord, kept, _dir, CancellationToken.None,
                await ledger.ReadAnchorAsync(missionId));

        var result = await VerifierFor(ledger, signer).VerifyAsync(bundle);

        // Everything the bundle can say about itself still passes. That is the point.
        Assert.True(Check(result, "bundle-signature").Passed);
        Assert.True(Check(result, "merkle-root").Passed);

        AssertPassedExcept(result, "bundle-holds-every-row");
        Assert.False(result.Agrees);
        Assert.Contains("row 2 (KERNEL_VIOLATION)", Check(result, "bundle-holds-every-row").Detail);
        Assert.Contains("holds 4 rows", Check(result, "bundle-holds-every-row").Detail);
    }

    [Fact]
    public async Task AShortBundleWithAShortAnchor_IsCaughtTwice()
    {
        var (ledger, missionId) = await LedgerWithMissionAsync();
        using var signer = NewSigner(_dir);

        var merkle = new MerkleTreeEngine();
        var all = await ledger.GetAuditLogsAsync(missionId, 100);
        var kept = all.Where(e => e.Action != "KERNEL_VIOLATION").ToList();
        var record = await AssemblerFor(ledger, signer).AssembleRunRecordAsync(missionId);
        var honest = await ledger.ReadAnchorAsync(missionId);

        // The exporter trims its own anchor to match what it is shipping, which is what anyone
        // shortening a bundle would do next.
        var trimmed = honest! with
        {
            MissionEntries = honest.MissionEntries.Where(e => e.Action != "KERNEL_VIOLATION").ToList()
        };

        string bundle = await new ComplianceArchiveExporter(merkle, signer)
            .ExportMissionRunRecordPackageAsync(
                record with { Integrity = record.Integrity with { MerkleRootHash = merkle.BuildTree(kept).RootHash, TotalAuditEntries = kept.Count } },
                kept, _dir, CancellationToken.None, trimmed);

        var result = await VerifierFor(ledger, signer).VerifyAsync(bundle);

        AssertPassedExcept(result, "bundle-holds-every-row", "anchor-matches-ledger");
        Assert.Contains("lists 3 rows", Check(result, "anchor-matches-ledger").Detail);
    }

    [Fact]
    public async Task ABundleFromAnotherLedger_IsNotCheckedAgainstThisOne()
    {
        var (source, missionId) = await LedgerWithMissionAsync();
        var (other, _) = await LedgerWithMissionAsync();

        string bundle = await AssemblerFor(source, null).AssembleAndExportBundleAsync(missionId, _dir);
        var result = await VerifierFor(other).VerifyAsync(bundle);

        Assert.False(result.Agrees);
        Assert.False(Check(result, "same-chain").Passed);
        Assert.Contains("different ledgers", Check(result, "same-chain").Detail);

        // Once the chains differ there is nothing to compare row by row, and reporting on it anyway
        // would be reporting on a coincidence of ids.
        Assert.DoesNotContain(result.Checks, c => c.Name == "bundle-holds-every-row");
    }

    [Fact]
    public async Task AnUnanchoredBundle_SaysSo_RatherThanPassing()
    {
        var (ledger, missionId) = await LedgerWithMissionAsync();
        var merkle = new MerkleTreeEngine();

        var entries = await ledger.GetAuditLogsAsync(missionId, 100);
        var record = await AssemblerFor(ledger, null).AssembleRunRecordAsync(missionId);
        string bundle = await new ComplianceArchiveExporter(merkle)
            .ExportMissionRunRecordPackageAsync(record, entries, _dir, CancellationToken.None, anchor: null);

        var result = await VerifierFor(ledger).VerifyAsync(bundle);

        // Not a failure and not a pass: nothing could be compared, and that is not a yes.
        Assert.False(result.Agrees);
        Assert.Null(Check(result, "bundle-anchored").Passed);
        Assert.Contains("re-export it from a host that anchors", Check(result, "bundle-anchored").Detail);
    }

    [Fact]
    public async Task ABundleEditedAfterSigning_FailsOnTheSignature()
    {
        var (ledger, missionId) = await LedgerWithMissionAsync();
        using var signer = NewSigner(_dir);

        string bundle = await AssemblerFor(ledger, signer).AssembleAndExportBundleAsync(missionId, _dir);

        using (var archive = ZipFile.Open(bundle, ZipArchiveMode.Update))
        {
            var summary = archive.GetEntry("run_record_summary.md")!;
            using var stream = summary.Open();
            stream.Seek(0, SeekOrigin.End);
            using var writer = new StreamWriter(stream);
            writer.Write("\nand nothing was refused.\n");
        }

        var result = await VerifierFor(ledger, signer).VerifyAsync(bundle);

        Assert.False(result.Agrees);
        Assert.False(Check(result, "bundle-signature").Passed);
        Assert.Contains("run_record_summary.md", Check(result, "bundle-signature").Detail);
    }

    [Fact]
    public async Task AnUnsignedBundle_IsNotTreatedAsSigned()
    {
        var (ledger, missionId) = await LedgerWithMissionAsync();

        string bundle = await AssemblerFor(ledger, null).AssembleAndExportBundleAsync(missionId, _dir);
        var result = await VerifierFor(ledger).VerifyAsync(bundle);

        Assert.Null(Check(result, "bundle-signature").Passed);
        Assert.False(result.Agrees);

        // Everything that does not depend on a signature still has to have been checked, or the
        // result would be useless for the common case of an unsigned host.
        Assert.True(Check(result, "bundle-holds-every-row").Passed);
        Assert.True(Check(result, "host-ledger-chain").Passed);
    }

    [Fact]
    public async Task ARowAppendedAfterTheExport_ShowsUpAsADisagreementNotAsTampering()
    {
        var (ledger, missionId) = await LedgerWithMissionAsync();
        using var signer = NewSigner(_dir);

        string bundle = await AssemblerFor(ledger, signer).AssembleAndExportBundleAsync(missionId, _dir);
        await ledger.AppendLogAsync(missionId, "net-dns-audit", "LATE_ARRIVING_NOTE", "appended after the export", "windows:Operator Atlas [S-1-5-21-7] via console");

        var result = await VerifierFor(ledger, signer).VerifyAsync(bundle);

        // The head moved forward, which is a ledger in use, not a rewritten one.
        Assert.True(Check(result, "head-not-rewound").Passed);
        Assert.True(Check(result, "row-hashes-match").Passed);

        // But the bundle no longer holds every row for this mission, and it says which.
        Assert.False(Check(result, "bundle-holds-every-row").Passed);
        Assert.Contains("LATE_ARRIVING_NOTE", Check(result, "bundle-holds-every-row").Detail);
    }
}
