using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
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

public class MissionRunRecordTests
{
    private static MissionRunFacts SampleFacts(Guid missionId) => new()
    {
        MissionId = missionId,
        TemplateId = "net-dns-audit",
        TemplateSha256 = "sha256:" + new string('a', 64),
        Principal = "windows:Operator Atlas [S-1-5-21-7] via console",
        StartedAtUtc = new DateTimeOffset(2026, 9, 19, 5, 39, 28, TimeSpan.Zero),
        EndedAtUtc = new DateTimeOffset(2026, 9, 19, 5, 39, 31, TimeSpan.Zero),
        ExecutablePath = "cmd.exe",
        CommandLine = "/c ipconfig /all",
        WorkspacePath = @"C:\jails\mission",
        DeclaredEgress = "api.anthropic.com:443 (ModelGateway)",
        NetworkDenialRequested = true,
        PrivilegeDropRequested = true,
        RequestedMemoryBytes = 256 * 1024 * 1024,
        RequestedCpuPercent = 50,
        TimeoutSeconds = 60,
        OsDescription = "Microsoft Windows 10.0.26200",
        JobName = "MissionJob_test",
        LimitsReadBack = new JobLimitsReadback(256 * 1024 * 1024, 256 * 1024 * 1024, 50, 32, true),
        AppliedControls =
        {
            "acl-jail:inheritance-stripped,allow-rules=3,deny-rules=0",
            "job:MissionJob_test",
            "token:integrity=Low",
            "token:administrators=deny-only",
            "token:privileges=1",
            "token:appcontainer=0-capabilities"
        },
        ExecutionState = "Completed",
        ExitCode = 0,
        TimedOut = false,
        AllowedExitCodes = { 0 },
        ExitContractMet = true,
        TerminalReason = "the tool exited",
        RedactionCount = 2,
        RedactedCategories = { "AwsKey", "Credential" },
        Model = "Anthropic/claude-sonnet-5",
        QualityAccepted = true,
        ProcessesLeftAtTeardown = 0,
        JailRemoved = true,
        TeardownOrder = { "job: no process left running", "job: closed, which kills anything left in it", "jail: drained and removed" }
    };

    private static async Task<SqliteChainedAuditLedger> LedgerWithMissionAsync(string dbPath, MissionRunFacts facts, byte[]? key = null)
    {
        var ledger = new SqliteChainedAuditLedger(new SqliteStorageContext(dbPath), key);
        await ledger.AppendLogAsync(facts.MissionId, facts.TemplateId, "MISSION_INITIATED", "Template: DNS audit", facts.Principal);
        await ledger.AppendLogAsync(facts.MissionId, facts.TemplateId, "TOOL_EXECUTION_COMPLETED", "ExitCode: 0", facts.Principal);
        await ledger.AppendLogAsync(facts.MissionId, facts.TemplateId, MissionRunFacts.LedgerAction, JsonSerializer.Serialize(facts), facts.Principal);
        return ledger;
    }

    private static MissionRunRecordAssembler AssemblerFor(IAuditLedger ledger, IRunRecordSigner? signer = null)
    {
        var merkle = new MerkleTreeEngine();
        return new MissionRunRecordAssembler(ledger, merkle, new ComplianceArchiveExporter(merkle, signer));
    }

    private static void DeleteDatabase(string dbPath)
    {
        SqliteConnection.ClearAllPools();
        GC.Collect();
        GC.WaitForPendingFinalizers();
        try { File.Delete(dbPath); } catch (IOException) { }
    }

    [Fact]
    public async Task TheRecord_IsTheFactsTheEngineSealed_AndNothingElse()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"RunRecord_{Guid.NewGuid():N}.db");
        try
        {
            var missionId = Guid.NewGuid();
            var facts = SampleFacts(missionId);
            var ledger = await LedgerWithMissionAsync(dbPath, facts);

            var record = await AssemblerFor(ledger).AssembleRunRecordAsync(missionId);

            // 1. Request identity: the principal as the host wrote it, and how it authenticated them.
            Assert.Equal(facts.Principal, record.RequestIdentity.Principal);
            Assert.Equal("Windows logon: the operating system authenticated the caller, over console", record.RequestIdentity.AuthProvenance);
            Assert.Equal(facts.TemplateSha256, record.RequestIdentity.PolicyVersionOrHash);
            Assert.Equal(facts.StartedAtUtc, record.RequestIdentity.RequestedAtUtc);

            // 2. Effective permission: the bound command line, and the network as the token showed it.
            Assert.Equal("cmd.exe", record.EffectivePermission.ExecutablePath);
            Assert.Equal("/c ipconfig /all", record.EffectivePermission.CommandLine);
            Assert.Equal(@"C:\jails\mission", record.EffectivePermission.WorkspaceBoundary);
            Assert.StartsWith("enforced: the tool had no network at all", record.EffectivePermission.EgressEnforcement);
            Assert.Equal(60u, record.EffectivePermission.DurationCeilingSeconds);
            Assert.Contains("token:integrity=Low", record.EffectivePermission.RuntimeIdentity);
            Assert.DoesNotContain("job:", record.EffectivePermission.RuntimeIdentity);

            // 3. Enforcement: read back from the job object, not repeated from the request.
            Assert.Equal("MissionJob_test", record.EnforcementState.CgroupOrJobId);
            Assert.Equal(50, record.EnforcementState.EffectiveLimitsReadback!.CpuRatePercent);
            Assert.True(record.EnforcementState.EffectiveLimitsReadback!.KillOnJobClose);
            Assert.Contains("token:appcontainer=0-capabilities", record.EnforcementState.AttachedControls!);
            Assert.Equal("Admitted", record.EnforcementState.AdmissionVerdict);

            // 4. Outcome, with the exit contract the template declared.
            Assert.Equal("Completed", record.Outcome.ExecutionState);
            Assert.Equal(0, record.Outcome.ExitCode);
            Assert.Equal(new[] { 0 }, record.Outcome.AllowedExitCodes);
            Assert.True(record.Outcome.ExitContractMet);
            Assert.Equal(2, record.Outcome.RedactionCount);
            Assert.True(record.Outcome.QualityAcceptance);

            // 5. Cleanup as teardown observed it.
            Assert.Equal(0u, record.Cleanup.ProcessesLeftAtTeardown);
            Assert.Equal("removed", record.Cleanup.WorkspaceDisposition);
            Assert.True(record.Cleanup.ResidualResourcesCleaned);

            // 6. Integrity: this ledger is unkeyed, and the record names the row its facts came from.
            Assert.Equal("Unkeyed", record.Integrity.ChainKind);
            Assert.Equal(SqliteChainedAuditLedger.UnkeyedVersion, record.Integrity.HashVersion);
            Assert.Equal(3, record.Integrity.TotalAuditEntries);
            var entries = await ledger.GetAuditLogsAsync(missionId);
            Assert.Equal(entries.Single(e => e.Action == MissionRunFacts.LedgerAction).EntryHash, record.Integrity.FactsEntryHash);
        }
        finally
        {
            DeleteDatabase(dbPath);
        }
    }

    [Fact]
    public async Task AMissionWhoseFactsWereNeverSealed_IsRefused()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"NoFacts_{Guid.NewGuid():N}.db");
        try
        {
            var missionId = Guid.NewGuid();
            var ledger = new SqliteChainedAuditLedger(new SqliteStorageContext(dbPath));
            await ledger.AppendLogAsync(missionId, "net-dns-audit", "MISSION_INITIATED", "started", "operator");

            var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
                () => AssemblerFor(ledger).AssembleRunRecordAsync(missionId));

            Assert.Contains(MissionRunFacts.LedgerAction, refusal.Message);
        }
        finally
        {
            DeleteDatabase(dbPath);
        }
    }

    [Fact]
    public async Task FactsRetentionHasRedacted_AreRefused_NotGuessedAround()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"RedactedFacts_{Guid.NewGuid():N}.db");
        try
        {
            var missionId = Guid.NewGuid();
            var ledger = new SqliteChainedAuditLedger(new SqliteStorageContext(dbPath));
            await ledger.AppendLogAsync(missionId, "net-dns-audit", MissionRunFacts.LedgerAction, "[REDACTED BY RETENTION]", "operator");

            var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
                () => AssemblerFor(ledger).AssembleRunRecordAsync(missionId));

            Assert.Contains("retention", refusal.Message);
        }
        finally
        {
            DeleteDatabase(dbPath);
        }
    }

    [Theory]
    [InlineData(false, "Unkeyed", SqliteChainedAuditLedger.UnkeyedVersion)]
    [InlineData(true, "HmacSha256", SqliteChainedAuditLedger.KeyedVersion)]
    public async Task TheChainKind_IsReadFromTheLedgersOwnRows(bool keyed, string kind, int version)
    {
        // The real ledger, not a stub: the LEDGER_KEYED row an earlier version looked for among a
        // mission's entries belongs to no mission, so against this ledger it never found it.
        string dbPath = Path.Combine(Path.GetTempPath(), $"RunRecordChain_{Guid.NewGuid():N}.db");
        try
        {
            var missionId = Guid.NewGuid();
            var ledger = await LedgerWithMissionAsync(dbPath, SampleFacts(missionId), keyed ? RandomNumberGenerator.GetBytes(32) : null);

            var record = await AssemblerFor(ledger).AssembleRunRecordAsync(missionId);

            Assert.Equal(kind, record.Integrity.ChainKind);
            Assert.Equal(version, record.Integrity.HashVersion);
            Assert.Equal(3, record.Integrity.TotalAuditEntries);
        }
        finally
        {
            DeleteDatabase(dbPath);
        }
    }

    [Fact]
    public async Task AMissionTooLongToCoverWhole_IsRefused_NotCut()
    {
        var missionId = Guid.NewGuid();
        var entries = Enumerable.Range(1, 100_001)
            .Select(i => new AuditLogEntry(i, DateTime.UtcNow, missionId, "t", "TOOL_EXEC", "d", "operator", "p", $"e{i}", 2))
            .ToList();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => AssemblerFor(new StubAuditLedger(entries)).AssembleRunRecordAsync(missionId));
    }

    [Fact]
    public async Task TheBundle_ReadsTheLedgerOnce_SoItsRootCoversItsProofs()
    {
        var missionId = Guid.NewGuid();
        var facts = SampleFacts(missionId);
        // Every read finds one more entry, as it does while a mission is still writing to the ledger.
        var ledger = new StubAuditLedger(new List<AuditLogEntry>
        {
            new(1, DateTime.UtcNow, missionId, facts.TemplateId, MissionRunFacts.LedgerAction, JsonSerializer.Serialize(facts), facts.Principal, "prev0", "hash1", 2)
        }, growsOnEachRead: true);

        string tempDir = Path.Combine(Path.GetTempPath(), "splat_test_once_" + Guid.NewGuid().ToString("N"));
        try
        {
            string zipPath = await AssemblerFor(ledger).AssembleAndExportBundleAsync(missionId, tempDir);

            using var zip = ZipFile.OpenRead(zipPath);
            var record = JsonSerializer.Deserialize<MissionRunRecord>(ReadEntry(zip, "mission_run_record.json"))!;
            var proofs = JsonSerializer.Deserialize<List<MerkleProof>>(ReadEntry(zip, "merkle_proofs.json"))!;

            Assert.Equal(record.Integrity.TotalAuditEntries, proofs.Count);
            Assert.All(proofs, p => Assert.Equal(record.Integrity.MerkleRootHash, p.RootHash));
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task AnUnsignedBundle_VerifiesAsConsistentButSaysSoLoudly()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"Unsigned_{Guid.NewGuid():N}.db");
        string tempDir = Path.Combine(Path.GetTempPath(), "splat_test_unsigned_" + Guid.NewGuid().ToString("N"));
        try
        {
            var missionId = Guid.NewGuid();
            var ledger = await LedgerWithMissionAsync(dbPath, SampleFacts(missionId));
            string bundle = await ExtractBundleAsync(AssemblerFor(ledger), missionId, tempDir);

            var (code, output) = await RunPowerShellVerifierAsync(bundle);

            Assert.True(code == 2, output);
            Assert.Contains("Unsigned", output);
            Assert.Contains("All 3 entries", output);
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true);
            DeleteDatabase(dbPath);
        }
    }

    /// <summary>
    /// Roadmap 2.5: the guest signs what its lease did, and the bundle's own verifier checks it.
    ///
    /// The kernel-enforced path had the weakest receipt of anything this product makes. A Windows
    /// mission sealed its facts into a chained ledger and exported a bundle a stranger could verify;
    /// a Linux lease reported its outcome over a socket to a host that then wrote down whatever it
    /// liked, with nothing binding the words to the guest that said them. This closes the span
    /// between the guest speaking and the record claiming - not the guest's honesty, which root in
    /// the guest could always undo and which no signature has ever fixed.
    ///
    /// The edit is one character inside the signed text, and the kind a host would make if it wanted
    /// a cleaner story than it got: a failed exit reported as a clean one.
    /// </summary>
    [Fact]
    public async Task AGuestSignedLeaseOutcome_Verifies_AndFailsOnceTheRecordSaysSomethingElse()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"GuestSigned_{Guid.NewGuid():N}.db");
        string tempDir = Path.Combine(Path.GetTempPath(), "splat_test_guest_" + Guid.NewGuid().ToString("N"));
        try
        {
            var missionId = Guid.NewGuid();

            // Stands in for the key the daemon generates inside the guest. The encodings are the ones
            // outcome.rs emits: PKCS#1 public DER, PKCS#1 v1.5 over SHA-256, both base64.
            using var guestKey = RSA.Create(2048);
            byte[] publicDer = guestKey.ExportRSAPublicKey();
            string canonical =
                $"splat-lease-outcome/1|mission={missionId}|cgroup=4021|enforcing=true|uid=65534" +
                "|exit=7|counted=2|reported=2|dropped=0|workspace=/var/lib/splat/missions/m|workspaceRemoved=true";

            var facts = SampleFacts(missionId);
            facts.Substrate = "LinuxLease";
            facts.KernelRefusals = 2;
            facts.KernelRefusalsReported = 2;
            facts.KernelRefusalEvidenceComplete = true;
            facts.GuestSignedOutcome = canonical;
            facts.GuestOutcomeSignature = Convert.ToBase64String(guestKey.SignData(
                Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            facts.GuestOutcomeKeyId = Convert.ToHexString(SHA256.HashData(publicDer)).ToLowerInvariant();
            facts.GuestOutcomePublicKey = Convert.ToBase64String(publicDer);

            var ledger = await LedgerWithMissionAsync(dbPath, facts);
            string bundle = await ExtractBundleAsync(AssemblerFor(ledger), missionId, tempDir);

            var (code, output) = await RunPowerShellVerifierAsync(bundle);
            // 2, not 0: nothing signed the BUNDLE here. The guest's signature is a separate claim
            // about a separate thing, and it verified.
            Assert.True(code == 2, output);
            Assert.Contains("The guest signed this lease outcome", output);
            Assert.Contains("exit=7", output);

            // Now the host tells a better story than the guest signed.
            string recordPath = Path.Combine(bundle, "mission_run_record.json");
            string edited = File.ReadAllText(recordPath).Replace("|exit=7|", "|exit=0|", StringComparison.Ordinal);
            Assert.DoesNotContain("|exit=7|", edited, StringComparison.Ordinal);
            File.WriteAllText(recordPath, edited);

            var (tamperedCode, tamperedOutput) = await RunPowerShellVerifierAsync(bundle);
            Assert.True(tamperedCode == 1, tamperedOutput);
            Assert.Contains("not what the guest signed", tamperedOutput);
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true);
            DeleteDatabase(dbPath);
        }
    }

    [Fact]
    public async Task ASignedBundle_Verifies_AndFailsOnceAnyOfItIsEdited()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"Signed_{Guid.NewGuid():N}.db");
        string tempDir = Path.Combine(Path.GetTempPath(), "splat_test_signed_" + Guid.NewGuid().ToString("N"));
        string keyPath = Path.Combine(Path.GetTempPath(), $"splat_test_key_{Guid.NewGuid():N}.pem");
        try
        {
            File.WriteAllText(keyPath, RunRecordKeyFile.NewKeyPem(out string keyId));
            using var signer = RunRecordKeyFile.Load(keyPath);
            Assert.Equal(keyId, signer.KeyId);

            var missionId = Guid.NewGuid();
            var ledger = await LedgerWithMissionAsync(dbPath, SampleFacts(missionId));
            string bundle = await ExtractBundleAsync(AssemblerFor(ledger, signer), missionId, tempDir);

            var (passCode, passOutput) = await RunPowerShellVerifierAsync(bundle);
            Assert.True(passCode == 0, passOutput);
            Assert.Contains(signer.KeyId, passOutput);

            // One edited entry: the Merkle leaf no longer matches, and so does the signed hash of the file.
            string chainPath = Path.Combine(bundle, "audit_chain.json");
            File.WriteAllText(
                chainPath,
                File.ReadAllText(chainPath).Replace("TOOL_EXECUTION_COMPLETED", "TOOL_EXECUTION_SKIPPED"),
                new UTF8Encoding(true));

            var (failCode, failOutput) = await RunPowerShellVerifierAsync(bundle);
            Assert.True(failCode == 1, failOutput);
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true);
            try { File.Delete(keyPath); } catch (IOException) { }
            DeleteDatabase(dbPath);
        }
    }

    [Fact]
    public async Task ASignatureFromAnotherKey_DoesNotPassAsThisOne()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"SwappedKey_{Guid.NewGuid():N}.db");
        string tempDir = Path.Combine(Path.GetTempPath(), "splat_test_swapped_" + Guid.NewGuid().ToString("N"));
        string keyPath = Path.Combine(Path.GetTempPath(), $"splat_test_key_{Guid.NewGuid():N}.pem");
        try
        {
            File.WriteAllText(keyPath, RunRecordKeyFile.NewKeyPem(out _));
            using var signer = RunRecordKeyFile.Load(keyPath);
            var missionId = Guid.NewGuid();
            var ledger = await LedgerWithMissionAsync(dbPath, SampleFacts(missionId));
            string bundle = await ExtractBundleAsync(AssemblerFor(ledger, signer), missionId, tempDir);

            // Another key's public half, put forward under the same key id: the fingerprint no longer
            // matches the key, which is what stops a signature being re-labelled as someone else's.
            string signaturePath = Path.Combine(bundle, "signature.json");
            using var stranger = RSA.Create(RunRecordKeyFile.CreatedKeyBits);
            // Through the parser, not by text: the serializer escapes base64's "+" as +, so a
            // search for the key's own characters finds nothing in the file.
            var signature = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(signaturePath))!;
            signature["PublicKey"] = Convert.ToBase64String(stranger.ExportRSAPublicKey());
            File.WriteAllText(signaturePath, JsonSerializer.Serialize(signature), new UTF8Encoding(true));

            var (code, output) = await RunPowerShellVerifierAsync(bundle);

            Assert.True(code == 1, output);
            Assert.Contains("key id does not match", output);
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true);
            try { File.Delete(keyPath); } catch (IOException) { }
            DeleteDatabase(dbPath);
        }
    }

    [Fact]
    public void AKeyFileThatIsNotAPrivateKey_IsRefusedByPath_NotByGuess()
    {
        string publicOnly = Path.Combine(Path.GetTempPath(), $"splat_pub_{Guid.NewGuid():N}.pem");
        string missing = Path.Combine(Path.GetTempPath(), $"splat_missing_{Guid.NewGuid():N}.pem");
        try
        {
            using var rsa = RSA.Create(RunRecordKeyFile.CreatedKeyBits);
            File.WriteAllText(publicOnly, rsa.ExportSubjectPublicKeyInfoPem());

            var refusal = Assert.Throws<InvalidOperationException>(() => RunRecordKeyFile.Load(publicOnly));
            Assert.Contains(publicOnly, refusal.Message);
            Assert.Contains("no RSA private key", refusal.Message);

            Assert.Contains("does not exist", RunRecordKeyFile.Problem(missing));
        }
        finally
        {
            try { File.Delete(publicOnly); } catch (IOException) { }
        }
    }

    [Fact]
    public void MerkleProofEngine_DetectsTamperedLeafOrSibling()
    {
        var missionId = Guid.NewGuid();
        var entries = new List<AuditLogEntry>
        {
            new(101, DateTime.UtcNow.AddSeconds(-2), missionId, "tool-1", "EXEC", "cmd1", "Op", "p0", "e1"),
            new(102, DateTime.UtcNow.AddSeconds(-1), missionId, "tool-1", "EXEC", "cmd2", "Op", "e1", "e2"),
        };

        var engine = new MerkleTreeEngine();
        var tree = engine.BuildTree(entries);
        var proof = engine.GenerateProof(tree, 101);

        Assert.True(engine.VerifyProof(proof));

        var tamperedProof = proof with { LeafHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" };
        Assert.False(engine.VerifyProof(tamperedProof));
    }

    private static async Task<string> ExtractBundleAsync(MissionRunRecordAssembler assembler, Guid missionId, string tempDir)
    {
        string zipPath = await assembler.AssembleAndExportBundleAsync(missionId, tempDir);
        string bundle = Path.Combine(tempDir, "bundle");
        ZipFile.ExtractToDirectory(zipPath, bundle);
        return bundle;
    }

    private static string ReadEntry(ZipArchive zip, string name)
    {
        // StreamReader drops the byte-order mark the exporter writes, which the serializer would not.
        using var reader = new StreamReader(zip.GetEntry(name)!.Open(), Encoding.UTF8);
        return reader.ReadToEnd();
    }

    // Windows PowerShell 5.1, the one every Windows host has and the one the bundle's summary names.
    private static async Task<(int ExitCode, string Output)> RunPowerShellVerifierAsync(string folder)
    {
        var psi = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", Path.Combine(folder, "verify_proofs.ps1") })
        {
            psi.ArgumentList.Add(arg);
        }

        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(1));
        try
        {
            await process.WaitForExitAsync(deadline.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("verify_proofs.ps1 did not finish within a minute.");
        }

        return (process.ExitCode, await stdout + await stderr);
    }

    private sealed class StubAuditLedger : IAuditLedger
    {
        private readonly List<AuditLogEntry> _entries;
        private readonly bool _growsOnEachRead;

        public StubAuditLedger(IReadOnlyList<AuditLogEntry> entries, bool growsOnEachRead = false)
        {
            _entries = entries.ToList();
            _growsOnEachRead = growsOnEachRead;
        }

        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details, string operatorIdentity, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100, CancellationToken cancellationToken = default)
        {
            if (_growsOnEachRead && _entries.Count > 0)
            {
                var last = _entries[^1];
                long id = _entries.Max(e => e.Id) + 1;
                _entries.Add(last with { Id = id, TimestampUtc = DateTime.UtcNow, Action = "TOOL_OUTPUT", Details = "more", PreviousHash = last.EntryHash, EntryHash = $"hash{id}" });
            }

            if (missionId.HasValue)
            {
                var filtered = _entries.Where(e => e.MissionId == missionId.Value).Take(limit).ToList();
                return Task.FromResult<IReadOnlyList<AuditLogEntry>>(filtered);
            }

            return Task.FromResult<IReadOnlyList<AuditLogEntry>>(_entries.Take(limit).ToList());
        }

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }
    }
}
