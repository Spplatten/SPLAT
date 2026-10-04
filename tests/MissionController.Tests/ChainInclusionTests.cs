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
/// Roadmap 3.7: a bundle and a published checkpoint, with no access to the host, show that every
/// row the bundle carries was in the ledger at the checkpoint's head.
///
/// The exit criterion for the whole run-record section has always been that someone who did not run
/// a mission can verify from the bundle **alone**. Until this, every check a recipient could run
/// was a check of the bundle against itself - its Merkle root covers the entries it carries, its
/// signature covers its files, and both agree however many of a mission's rows were left out. The
/// host-side verifier closes that and needs the host.
///
/// These tests never touch the ledger after the export. They take the zip's bytes and check them.
/// </summary>
public class ChainInclusionTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"splat-chain-{Guid.NewGuid():N}");
    private readonly List<string> _dbs = new();

    public ChainInclusionTests() => Directory.CreateDirectory(_dir);

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
        TemplateSha256 = "sha256:" + new string('c', 64),
        Principal = "windows:Operator Atlas [S-1-5-21-7] via console",
        StartedAtUtc = DateTimeOffset.UtcNow.AddSeconds(-2),
        EndedAtUtc = DateTimeOffset.UtcNow,
        ExecutablePath = "cmd.exe",
        ExecutionState = "Completed",
        ExitCode = 0,
        AllowedExitCodes = { 0 },
        ExitContractMet = true,
    };

    /// <summary>
    /// A ledger holding more than the mission being exported. The point of a chain root is that it
    /// covers rows the bundle will never carry, so a corpus of one mission would prove nothing
    /// about whether the proofs reach past it.
    /// </summary>
    private async Task<(SqliteChainedAuditLedger Ledger, Guid MissionId)> LedgerWithTrafficAsync(bool keyed = false)
    {
        string dbPath = Path.Combine(_dir, $"{Guid.NewGuid():N}.db");
        _dbs.Add(dbPath);
        var ledger = new SqliteChainedAuditLedger(new SqliteStorageContext(dbPath),
            keyed ? System.Security.Cryptography.RandomNumberGenerator.GetBytes(32) : null);

        foreach (int i in Enumerable.Range(0, 5))
        {
            var other = Guid.NewGuid();
            await ledger.AppendLogAsync(other, "sysops-disk-space", "MISSION_INITIATED", $"noise {i}", "windows:Someone Else [S-1-5-21-9] via console");
        }

        var missionId = Guid.NewGuid();
        var facts = Facts(missionId);
        await ledger.AppendLogAsync(missionId, facts.TemplateId, "MISSION_INITIATED", "Template: DNS audit", facts.Principal);
        await ledger.AppendLogAsync(missionId, facts.TemplateId, "TOOL_EXECUTION_COMPLETED", "ExitCode: 0", facts.Principal);
        await ledger.AppendLogAsync(missionId, facts.TemplateId, MissionRunFacts.LedgerAction, JsonSerializer.Serialize(facts), facts.Principal);

        foreach (int i in Enumerable.Range(0, 3))
        {
            await ledger.AppendLogAsync(Guid.NewGuid(), "net-dns-audit", "MISSION_INITIATED", $"later {i}", "windows:Someone Else [S-1-5-21-9] via console");
        }

        return (ledger, missionId);
    }

    private static RsaRunRecordSigner NewSigner(string dir)
    {
        string keyPath = Path.Combine(dir, $"{Guid.NewGuid():N}.pem");
        File.WriteAllText(keyPath, RunRecordKeyFile.NewKeyPem(out _));
        return RunRecordKeyFile.Load(keyPath);
    }

    /// <summary>Everything a recipient has: the bytes of the zip, and nothing else.</summary>
    private static (SignedLedgerCheckpoint? Checkpoint, List<MerkleProof>? Proofs, List<AuditLogEntry>? Entries) OpenAsRecipient(string bundle)
    {
        using var archive = ZipFile.OpenRead(bundle);
        T? Read<T>(string name)
        {
            var entry = archive.GetEntry(name);
            if (entry is null) return default;
            using var stream = entry.Open();
            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);
            var bytes = buffer.ToArray();
            var span = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF ? bytes.AsSpan(3) : bytes.AsSpan();
            return JsonSerializer.Deserialize<T>(span, ComplianceArchiveExporterAccess.BundleJson);
        }

        return (Read<SignedLedgerCheckpoint>("checkpoint.json"),
                Read<List<MerkleProof>>("chain_inclusion.json"),
                Read<List<AuditLogEntry>>("audit_chain.json"));
    }

    private MissionRunRecordAssembler AssemblerFor(IAuditLedger ledger, IRunRecordSigner? signer)
    {
        var merkle = new MerkleTreeEngine();
        return new MissionRunRecordAssembler(
            ledger, merkle, new ComplianceArchiveExporter(merkle, signer),
            signer is null ? null : new LedgerCheckpointBuilder(ledger, merkle, signer));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ARecipientWithNothingButTheZip_ProvesEveryRowWasInTheChain(bool keyed)
    {
        var (ledger, missionId) = await LedgerWithTrafficAsync(keyed);
        using var signer = NewSigner(_dir);

        // The global checkpoint read and the filtered mission read must both carry the metadata.
        Assert.All(await ledger.GetAuditLogsAsync(), e =>
            Assert.Equal(SqliteChainedAuditLedger.ComputeDetailsCommitment(e.DetailsSalt!, e.Details), e.DetailsCommitment));
        string bundle = await AssemblerFor(ledger, signer).AssembleAndExportBundleAsync(missionId, _dir);
        var (checkpoint, proofs, entries) = OpenAsRecipient(bundle);

        Assert.NotNull(checkpoint);
        Assert.NotNull(proofs);
        Assert.NotNull(entries);
        Assert.All(entries, e =>
        {
            Assert.False(string.IsNullOrEmpty(e.DetailsSalt));
            Assert.Equal(SqliteChainedAuditLedger.ComputeDetailsCommitment(e.DetailsSalt, e.Details), e.DetailsCommitment);
        });

        var result = ChainInclusionCheck.Verify(checkpoint, proofs, entries);

        // The control for the whole file. Every other test here asserts a refusal, and none of them
        // would mean anything if this could not pass.
        Assert.True(result.Holds, result.Verdict + "\n" + string.Join("\n", result.Failures));

        // The root must cover more than this mission, or it is the bundle's own root again under
        // another name - the thing this was built to replace.
        Assert.True(checkpoint!.Checkpoint.TotalEntries > entries!.Count,
            $"the chain root covers {checkpoint.Checkpoint.TotalEntries} rows and the bundle carries {entries.Count}");
        Assert.Contains("Not established", string.Join(" ", result.Checks));
        Assert.Contains(result.Checks, c => c.Contains("Details text matches the salted commitment", StringComparison.Ordinal));
        Assert.Equal(keyed, result.Checks.Any(c => c.Contains("this offline check has no ledger key", StringComparison.Ordinal)));
    }
    /// <summary>
    /// The leaf alone still accepts this edit. The exported salt and commitment make the changed
    /// narrative detectable without the ledger, including when EntryHash itself is keyed.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnEditedDetailsFieldIsCaughtByItsExportedCommitment(bool keyed)
    {
        var (ledger, missionId) = await LedgerWithTrafficAsync(keyed);
        using var signer = NewSigner(_dir);
        string bundle = await AssemblerFor(ledger, signer).AssembleAndExportBundleAsync(missionId, _dir);
        var (checkpoint, proofs, entries) = OpenAsRecipient(bundle);

        var edited = entries!.Select(e => e.Action == "TOOL_EXECUTION_COMPLETED"
            ? e with { Details = "ExitCode: 0 (nothing was refused)" }
            : e).ToList();

        var result = ChainInclusionCheck.Verify(checkpoint, proofs, edited);

        Assert.False(result.Holds);
        Assert.Contains(result.Failures, c => c.Contains("Details text does not match its salted commitment", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReplacingDetailsAndCommitmentCannotClaimAKeyedBinding(bool keyed)
    {
        var (ledger, missionId) = await LedgerWithTrafficAsync(keyed);
        using var signer = NewSigner(_dir);
        string bundle = await AssemblerFor(ledger, signer).AssembleAndExportBundleAsync(missionId, _dir);
        var (checkpoint, proofs, entries) = OpenAsRecipient(bundle);
        const string forgedDetails = "ExitCode: 0 (nothing was refused)";
        var edited = entries!.Select(e => e.Action == "TOOL_EXECUTION_COMPLETED"
            ? e with
            {
                Details = forgedDetails,
                DetailsCommitment = SqliteChainedAuditLedger.ComputeDetailsCommitment(e.DetailsSalt!, forgedDetails),
            }
            : e).ToList();

        var result = ChainInclusionCheck.Verify(checkpoint, proofs, edited);

        // v2 recomputes to the proven EntryHash. v3 cannot do so without the HMAC key, so its
        // inclusion result must explicitly leave the commitment-to-leaf link unestablished.
        Assert.Equal(keyed, result.Holds);
        if (keyed)
        {
            Assert.Contains(result.Checks, c => c.Contains("Not established:", StringComparison.Ordinal)
                && c.Contains("replacing both Details and commitment can pass", StringComparison.Ordinal));
            Assert.Contains("Details verification and its limits", result.Verdict, StringComparison.Ordinal);
            Assert.DoesNotContain(result.Checks, c => c.Contains("binds to its proven EntryHash", StringComparison.Ordinal));
        }
        else
        {
            Assert.Contains(result.Failures, c => c.Contains("unkeyed row hash does not recompute", StringComparison.Ordinal));
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task MissingMetadataKeepsInclusionWithoutClaimingTheTextWasVerified(bool keyed, bool retainedCommitment)
    {
        var (ledger, missionId) = await LedgerWithTrafficAsync(keyed);
        using var signer = NewSigner(_dir);
        string bundle = await AssemblerFor(ledger, signer).AssembleAndExportBundleAsync(missionId, _dir);
        var (checkpoint, proofs, entries) = OpenAsRecipient(bundle);
        Assert.NotNull(entries);
        var missing = entries.Select(e => e with
        {
            Details = "[REDACTED - this marker is not authenticated]",
            DetailsSalt = null,
            DetailsCommitment = retainedCommitment ? e.DetailsCommitment : null,
        }).ToList();
        // Old JSON omits the fields entirely; a retention sweep omits only the destroyed salt.
        var json = JsonSerializer.Serialize(missing, new JsonSerializerOptions
        {
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        });
        var result = ChainInclusionCheck.Verify(checkpoint, proofs, JsonSerializer.Deserialize<List<AuditLogEntry>>(json));

        Assert.True(result.Holds, string.Join("\n", result.Failures));
        Assert.Equal(entries.Count, result.Checks.Count(c => c.Contains("Details text; its commitment or salt is absent", StringComparison.Ordinal)));
        Assert.DoesNotContain(result.Checks, c => c.Contains("Details text matches", StringComparison.Ordinal));
    }

    /// <summary>
    /// What the leaf binding does catch: a proof left on a row whose identity was substituted.
    /// Without it a bundle could carry rewritten rows and honest proofs side by side.
    /// </summary>
    [Fact]
    public async Task ARowWhoseIdentityWasSubstituted_IsCaught()
    {
        var (ledger, missionId) = await LedgerWithTrafficAsync();
        using var signer = NewSigner(_dir);
        string bundle = await AssemblerFor(ledger, signer).AssembleAndExportBundleAsync(missionId, _dir);
        var (checkpoint, proofs, entries) = OpenAsRecipient(bundle);

        var ordered = entries!.OrderBy(e => e.Id).ToList();
        var swapped = ordered.Select((e, i) => i == 0
            ? e with { Action = ordered[^1].Action, EntryHash = ordered[^1].EntryHash }
            : e).ToList();

        var result = ChainInclusionCheck.Verify(checkpoint, proofs, swapped);

        Assert.False(result.Holds);
        Assert.Contains(result.Failures, f => f.Contains("proof is for a different row", StringComparison.Ordinal));
    }



    [Fact]
    public async Task ACheckpointFromAnotherKey_IsNotThisOperatorsWord()
    {
        var (ledger, missionId) = await LedgerWithTrafficAsync();
        using var signer = NewSigner(_dir);
        string bundle = await AssemblerFor(ledger, signer).AssembleAndExportBundleAsync(missionId, _dir);
        var (checkpoint, proofs, entries) = OpenAsRecipient(bundle);

        // Re-signed by a key the operator never published, over the same statement. The signature
        // holds - it is a real signature - so the only thing that can catch it is the reader
        // comparing the key id, which is why the passing check says so in words rather than
        // claiming the checkpoint is the operator's.
        using var stranger = NewSigner(_dir);
        var forged = checkpoint! with
        {
            KeyId = stranger.KeyId,
            PublicKey = Convert.ToBase64String(stranger.PublicKeyDer),
            Signature = Convert.ToBase64String(stranger.Sign(System.Text.Encoding.UTF8.GetBytes(checkpoint.Statement))),
        };

        var result = ChainInclusionCheck.Verify(forged, proofs, entries);
        Assert.True(result.Holds, "a valid signature by any key passes the arithmetic");
        Assert.Contains(result.Checks, c => c.Contains(stranger.KeyId, StringComparison.Ordinal)
                                         && c.Contains("compare that with the fingerprint", StringComparison.Ordinal));
        Assert.DoesNotContain(result.Checks, c => c.Contains(signer.KeyId, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ACheckpointEditedAfterSigning_IsRefused()
    {
        var (ledger, missionId) = await LedgerWithTrafficAsync();
        using var signer = NewSigner(_dir);
        string bundle = await AssemblerFor(ledger, signer).AssembleAndExportBundleAsync(missionId, _dir);
        var (checkpoint, proofs, entries) = OpenAsRecipient(bundle);

        var moved = checkpoint! with
        {
            Checkpoint = checkpoint.Checkpoint with { HeadEntryId = checkpoint.Checkpoint.HeadEntryId + 500 },
        };

        var result = ChainInclusionCheck.Verify(moved, proofs, entries);
        Assert.False(result.Holds);
        Assert.Contains("signature does not hold", result.Verdict, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnUnsignedHost_ShipsNoCheckpoint_AndTheCheckSaysSoRatherThanFailing()
    {
        var (ledger, missionId) = await LedgerWithTrafficAsync();

        // No run record key, so no checkpoint: a statement anyone could have written is not
        // something a recipient can hold a bundle against.
        string bundle = await AssemblerFor(ledger, null).AssembleAndExportBundleAsync(missionId, _dir);
        var (checkpoint, proofs, entries) = OpenAsRecipient(bundle);

        Assert.Null(checkpoint);
        Assert.Null(proofs);

        var result = ChainInclusionCheck.Verify(checkpoint, proofs, entries);
        Assert.False(result.Holds);
        Assert.Contains("no checkpoint", result.Verdict, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>Reaches the exporter's JSON settings, which are internal to the Data assembly.</summary>
internal static class ComplianceArchiveExporterAccess
{
    public static JsonSerializerOptions BundleJson { get; } = new() { WriteIndented = true };
}
