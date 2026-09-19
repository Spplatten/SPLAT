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
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Compliance;
using Xunit;

namespace MissionController.Tests;

public class MissionRunRecordTests
{
    private static SingleToolTemplate CreateSampleTemplate(string toolName = "curl.exe")
    {
        var toolDef = new SingleToolDefinition(
            ToolId: "curl-sensor-1",
            Name: "Curl Network Sensor",
            ExecutablePath: toolName,
            ArgumentsTemplate: "-s https://api.grants.gov/v1/health",
            AllowedExitCodes: new[] { 0 },
            TimeoutSeconds: 30,
            MaxMemoryBytes: 256 * 1024 * 1024,
            MaxCpuPercent: 50);

        var egress = new EgressRule(
            AllowedFqdn: "api.grants.gov",
            AllowedPort: 443,
            Scope: EgressScope.ToolProcess);

        return new SingleToolTemplate(
            TemplateId: "sample-network-mission",
            Name: "Sample Network Mission",
            Description: "Sensor network audit",
            Category: "Network",
            TargetModel: "claude-3-opus",
            Tool: toolDef,
            EgressRule: egress,
            SystemPrompt: "Execute network diagnostic",
            ParameterFields: Array.Empty<TemplateParameterField>());
    }

    private static LeaseSpec CreateSampleLease(Guid missionId)
    {
        return new LeaseSpec(
            MissionId: missionId,
            WorkingDirectory: $"/tmp/splat_sandboxes/{missionId:D}",
            AllowNetwork: true,
            AllowedEgressIps: new[] { "93.184.216.34" },
            AllowedEgressPorts: new uint[] { 443 },
            ReadOnlyFs: false,
            ProtectedInodes: new[] { new InodeIdentifierModel(0, 0, "/etc/shadow") },
            AllowedExecInodes: new[] { new InodeIdentifierModel(0, 0, "/bin/curl") },
            LeaseDurationSeconds: 30,
            Limits: new LeaseResourceLimits(256UL * 1024 * 1024, 50u, 50),
            OverlayFs: new OverlayFsSpec(false, "/var/splat/baseline", $"/tmp/splat_scratch/{missionId:D}"));
    }

    [Fact]
    public async Task TheRecord_HoldsWhatItWasHanded_AndLeavesTheRestUnrecorded()
    {
        var missionId = Guid.NewGuid();
        var template = CreateSampleTemplate();
        var lease = CreateSampleLease(missionId);
        var start = DateTime.UtcNow;

        var mockLedger = new StubAuditLedger(new List<AuditLogEntry>
        {
            new(3, start, missionId, template.TemplateId, "MISSION_COMPLETE", "Completed successfully", "Operator-Atlas", "hash2", "hash3"),
            new(2, start.AddSeconds(-1), missionId, template.TemplateId, "TOOL_EXEC", "Executed curl sensor", "Operator-Atlas", "hash1", "hash2"),
            new(1, start.AddSeconds(-2), missionId, template.TemplateId, "MISSION_INIT", "Mission initialized", "Operator-Atlas", "0000000000000000000000000000000000000000000000000000000000000000", "hash1")
        });

        var merkleEngine = new MerkleTreeEngine();
        var archiveExporter = new ComplianceArchiveExporter(merkleEngine);
        var assembler = new MissionRunRecordAssembler(mockLedger, merkleEngine, archiveExporter);

        var record = await assembler.AssembleRunRecordAsync(
            missionId: missionId,
            template: template,
            leaseSpec: lease,
            operatorIdentity: "Operator-Atlas",
            executionState: "Completed",
            exitCode: 0,
            redactionCount: 2,
            redactedCategories: new[] { "AwsKey", "EmailAddress" },
            substrateType: "WSL2-BPF-LSM",
            cgroupOrJobId: "splat-cg-445");

        // 1. Request identity: the principal it was handed, the template's hash, and the ledger's first time.
        Assert.Equal("Operator-Atlas", record.RequestIdentity.Principal);
        Assert.Equal(missionId, record.RequestIdentity.MissionId);
        Assert.Matches("^sha256:[0-9a-f]{64}$", record.RequestIdentity.PolicyVersionOrHash);
        Assert.Equal(new DateTimeOffset(start.AddSeconds(-2)), record.RequestIdentity.FirstRecordedAtUtc);
        Assert.Null(record.RequestIdentity.AuthProvenance);
        Assert.Null(record.RequestIdentity.IdempotencyToken);
        Assert.Null(record.RequestIdentity.ApprovalReference);

        // 2. Effective permission: the lease's rules; the argument vector is not in the template.
        Assert.Equal("curl.exe", record.EffectivePermission.ExecutablePath);
        Assert.True(record.EffectivePermission.AllowNetwork);
        Assert.Contains("93.184.216.34", record.EffectivePermission.AllowedEgressIps!);
        Assert.Contains(443u, record.EffectivePermission.AllowedEgressPorts!);
        Assert.Equal(256UL * 1024 * 1024, record.EffectivePermission.MaxMemoryBytes);
        Assert.Equal(30u, record.EffectivePermission.LeaseDurationSeconds);
        Assert.Null(record.EffectivePermission.ArgumentVector);
        Assert.Null(record.EffectivePermission.RuntimeCapabilities);

        // 3. Enforcement state: nothing reports what was attached or read back, so nothing claims it.
        Assert.Equal("WSL2-BPF-LSM", record.EnforcementState.SubstrateType);
        Assert.Equal("splat-cg-445", record.EnforcementState.CgroupOrJobId);
        Assert.Equal("Admitted", record.EnforcementState.AdmissionVerdict);
        Assert.Null(record.EnforcementState.AttachedControls);
        Assert.Null(record.EnforcementState.KernelOrOsRelease);
        Assert.Null(record.EnforcementState.EffectiveLimitsReadback);

        // 4. Outcome, with no quality verdict because none was given.
        Assert.Equal("Completed", record.Outcome.ExecutionState);
        Assert.Equal(0, record.Outcome.ExitCode);
        Assert.Equal(2, record.Outcome.RedactionCount);
        Assert.Contains("AwsKey", record.Outcome.RedactedCategories);
        Assert.Null(record.Outcome.QualityAcceptance);
        Assert.Null(record.Outcome.TerminalReason);

        // 5. Cleanup is not reported back by either substrate.
        Assert.Equal(new CleanupEvidence(null, null, null, null), record.Cleanup);

        // 6. Integrity: a root over the entries, no chain kind (these entries do not say theirs), no signature.
        Assert.Null(record.Integrity.ChainKind);
        Assert.Null(record.Integrity.HashVersion);
        Assert.Equal(3, record.Integrity.TotalAuditEntries);
        Assert.Equal(merkleEngine.BuildTree(await mockLedger.GetAuditLogsAsync(missionId)).RootHash, record.Integrity.MerkleRootHash);
        Assert.Null(record.Integrity.AttestationSignature);
        Assert.Null(record.Integrity.SignatureAlgorithm);
    }

    [Theory]
    [InlineData(false, "Unkeyed", SqliteChainedAuditLedger.UnkeyedVersion)]
    [InlineData(true, "HmacSha256", SqliteChainedAuditLedger.KeyedVersion)]
    public async Task TheChainKind_IsReadFromTheLedgersOwnRows(bool keyed, string kind, int version)
    {
        // The real ledger, not a stub: the LEDGER_KEYED row the first version looked for among a
        // mission's entries belongs to no mission, so against this ledger it never found it.
        string dbPath = Path.Combine(Path.GetTempPath(), $"RunRecordChain_{Guid.NewGuid():N}.db");
        try
        {
            var ledger = new SqliteChainedAuditLedger(
                new SqliteStorageContext(dbPath), keyed ? RandomNumberGenerator.GetBytes(32) : null);
            var missionId = Guid.NewGuid();
            await ledger.AppendLogAsync(missionId, "sample-network-mission", "MISSION_INIT", "Init", "Operator-Atlas");
            await ledger.AppendLogAsync(missionId, "sample-network-mission", "MISSION_EXIT", "Exit 0", "Operator-Atlas");

            var merkleEngine = new MerkleTreeEngine();
            var record = await new MissionRunRecordAssembler(ledger, merkleEngine, new ComplianceArchiveExporter(merkleEngine))
                .AssembleRunRecordAsync(missionId, CreateSampleTemplate(), null, "Operator-Atlas", "Completed", 0, 0,
                    Array.Empty<string>(), "Windows");

            Assert.Equal(kind, record.Integrity.ChainKind);
            Assert.Equal(version, record.Integrity.HashVersion);
            Assert.Equal(2, record.Integrity.TotalAuditEntries);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            try { File.Delete(dbPath); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task EntriesFromTwoKindsOfChain_AreRecordedAsMixed()
    {
        var missionId = Guid.NewGuid();
        var template = CreateSampleTemplate();
        var ledger = new StubAuditLedger(new List<AuditLogEntry>
        {
            new(2, DateTime.UtcNow, missionId, template.TemplateId, "MISSION_EXIT", "Exit 0", "Operator-Atlas", "hash1", "hash2", SqliteChainedAuditLedger.KeyedVersion),
            new(1, DateTime.UtcNow.AddSeconds(-1), missionId, template.TemplateId, "MISSION_INIT", "Init", "Operator-Atlas", "hash0", "hash1", SqliteChainedAuditLedger.UnkeyedVersion)
        });
        var merkleEngine = new MerkleTreeEngine();

        var record = await new MissionRunRecordAssembler(ledger, merkleEngine, new ComplianceArchiveExporter(merkleEngine))
            .AssembleRunRecordAsync(missionId, template, null, "Operator-Atlas", "Completed", 0, 0, Array.Empty<string>(), "Windows");

        Assert.Equal("Mixed", record.Integrity.ChainKind);
        Assert.Null(record.Integrity.HashVersion);
    }

    [Fact]
    public async Task AMissionTheLedgerHoldsNothingFor_HasNoRootAndNoFirstTime()
    {
        var merkleEngine = new MerkleTreeEngine();
        var record = await new MissionRunRecordAssembler(new StubAuditLedger(Array.Empty<AuditLogEntry>()), merkleEngine,
                new ComplianceArchiveExporter(merkleEngine))
            .AssembleRunRecordAsync(Guid.NewGuid(), CreateSampleTemplate(), null, " ", "Refused", null, 0, Array.Empty<string>(), "Windows");

        // The all-zero root the tree builder returns for no entries would read as a real commitment.
        Assert.Null(record.Integrity.MerkleRootHash);
        Assert.Null(record.RequestIdentity.FirstRecordedAtUtc);
        Assert.Null(record.RequestIdentity.Principal);
        Assert.Equal(0, record.Integrity.TotalAuditEntries);
        Assert.Equal("Refused", record.EnforcementState.AdmissionVerdict);
    }

    [Fact]
    public async Task AMissionTooLongToCoverWhole_IsRefused_NotCut()
    {
        var missionId = Guid.NewGuid();
        var entries = Enumerable.Range(1, 100_001)
            .Select(i => new AuditLogEntry(i, DateTime.UtcNow, missionId, "t", "TOOL_EXEC", "d", "Operator-Atlas", "p", $"e{i}"))
            .ToList();
        var merkleEngine = new MerkleTreeEngine();
        var assembler = new MissionRunRecordAssembler(new StubAuditLedger(entries), merkleEngine, new ComplianceArchiveExporter(merkleEngine));

        await Assert.ThrowsAsync<InvalidOperationException>(() => assembler.AssembleRunRecordAsync(
            missionId, CreateSampleTemplate(), null, "Operator-Atlas", "Completed", 0, 0, Array.Empty<string>(), "Windows"));
    }

    [Fact]
    public async Task ThePolicyHash_ChangesWithTheTemplate_AndOnlyWithIt()
    {
        var missionId = Guid.NewGuid();
        var template = CreateSampleTemplate();
        var edited = template with { Tool = template.Tool with { ArgumentsTemplate = "-s https://example.invalid/" } };
        var merkleEngine = new MerkleTreeEngine();
        var assembler = new MissionRunRecordAssembler(new StubAuditLedger(Array.Empty<AuditLogEntry>()), merkleEngine,
            new ComplianceArchiveExporter(merkleEngine));

        async Task<string> HashOf(SingleToolTemplate t) => (await assembler.AssembleRunRecordAsync(
            missionId, t, null, "Operator-Atlas", "Completed", 0, 0, Array.Empty<string>(), "Windows")).RequestIdentity.PolicyVersionOrHash;

        Assert.Equal(await HashOf(template), await HashOf(CreateSampleTemplate()));
        Assert.NotEqual(await HashOf(template), await HashOf(edited));
    }

    [Fact]
    public async Task AssembleAndExportBundleAsync_CreatesValidVerifiableArchive()
    {
        var missionId = Guid.NewGuid();
        var template = CreateSampleTemplate();
        var lease = CreateSampleLease(missionId);

        var entries = new List<AuditLogEntry>
        {
            new(1, DateTime.UtcNow.AddSeconds(-3), missionId, template.TemplateId, "MISSION_INIT", "Init", "Operator-Atlas", "prev0", "hash1"),
            new(2, DateTime.UtcNow.AddSeconds(-2), missionId, template.TemplateId, "POLICY_APPLIED", "Applied BPF lease", "Operator-Atlas", "hash1", "hash2"),
            new(3, DateTime.UtcNow.AddSeconds(-1), missionId, template.TemplateId, "TOOL_EXEC", "Ran curl", "Operator-Atlas", "hash2", "hash3"),
            new(4, DateTime.UtcNow, missionId, template.TemplateId, "MISSION_EXIT", "Exit 0", "Operator-Atlas", "hash3", "hash4")
        };

        var mockLedger = new StubAuditLedger(entries);
        var merkleEngine = new MerkleTreeEngine();
        var archiveExporter = new ComplianceArchiveExporter(merkleEngine);
        var assembler = new MissionRunRecordAssembler(mockLedger, merkleEngine, archiveExporter);

        string tempDir = Path.Combine(Path.GetTempPath(), "splat_test_export_" + Guid.NewGuid().ToString("N"));
        try
        {
            string zipPath = await assembler.AssembleAndExportBundleAsync(
                missionId: missionId,
                template: template,
                leaseSpec: lease,
                operatorIdentity: "Operator-Atlas",
                executionState: "Completed",
                exitCode: 0,
                redactionCount: 1,
                redactedCategories: new[] { "AwsKey" },
                substrateType: "WSL2-BPF-LSM",
                outputDirectory: tempDir);

            Assert.True(File.Exists(zipPath));

            using var zip = ZipFile.OpenRead(zipPath);
            var entryNames = zip.Entries.Select(e => e.FullName).ToList();

            Assert.Contains("mission_run_record.json", entryNames);
            Assert.Contains("audit_chain.json", entryNames);
            Assert.Contains("merkle_proofs.json", entryNames);
            Assert.Contains("run_record_summary.md", entryNames);
            Assert.Contains("verify_proofs.py", entryNames);
            Assert.Contains("verify_proofs.ps1", entryNames);

            // Read mission_run_record.json
            var recordEntry = zip.GetEntry("mission_run_record.json")!;
            using var recordStream = recordEntry.Open();
            var record = await JsonSerializer.DeserializeAsync<MissionRunRecord>(recordStream);
            Assert.NotNull(record);
            Assert.Equal(missionId, record.MissionId);
            Assert.Equal("Completed", record.Outcome.ExecutionState);
            Assert.Equal(4, record.Integrity.TotalAuditEntries);

            // Read merkle_proofs.json and verify each proof against MerkleTreeEngine
            var proofsEntry = zip.GetEntry("merkle_proofs.json")!;
            using var proofsStream = proofsEntry.Open();
            var proofs = await JsonSerializer.DeserializeAsync<List<MerkleProof>>(proofsStream);
            Assert.NotNull(proofs);
            Assert.Equal(4, proofs.Count);

            foreach (var proof in proofs)
            {
                bool isValid = merkleEngine.VerifyProof(proof);
                Assert.True(isValid, $"Merkle proof for EntryId {proof.EntryId} failed verification!");
            }
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Fact]
    public async Task TheBundle_ReadsTheLedgerOnce_SoItsRootCoversItsProofs()
    {
        var missionId = Guid.NewGuid();
        var template = CreateSampleTemplate();
        // Every read finds one more entry, as it does while a mission is still writing to the ledger.
        var ledger = new StubAuditLedger(new List<AuditLogEntry>
        {
            new(1, DateTime.UtcNow, missionId, template.TemplateId, "MISSION_INIT", "Init", "Operator-Atlas", "prev0", "hash1")
        }, growsOnEachRead: true);
        var merkleEngine = new MerkleTreeEngine();
        var assembler = new MissionRunRecordAssembler(ledger, merkleEngine, new ComplianceArchiveExporter(merkleEngine));

        string tempDir = Path.Combine(Path.GetTempPath(), "splat_test_once_" + Guid.NewGuid().ToString("N"));
        try
        {
            string zipPath = await assembler.AssembleAndExportBundleAsync(
                missionId, template, null, "Operator-Atlas", "Completed", 0, 0, Array.Empty<string>(), "Windows", tempDir);

            using var zip = ZipFile.OpenRead(zipPath);
            var record = JsonSerializer.Deserialize<MissionRunRecord>(ReadEntry(zip, "mission_run_record.json"))!;
            var proofs = JsonSerializer.Deserialize<List<MerkleProof>>(ReadEntry(zip, "merkle_proofs.json"))!;

            Assert.Equal(record.Integrity.TotalAuditEntries, proofs.Count);
            Assert.All(proofs, p => Assert.Equal(record.Integrity.MerkleRootHash, p.RootHash));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Fact]
    public async Task TheBundlesOwnVerifier_Passes_AndFailsOnceAnEntryIsEdited()
    {
        var missionId = Guid.NewGuid();
        var template = CreateSampleTemplate();
        var ledger = new StubAuditLedger(new List<AuditLogEntry>
        {
            // A whole second, whose trailing zeros the serializer's own form drops, and an operator name
            // that is not ASCII: both have to survive the file's text for a leaf to be rebuilt from it.
            new(1, new DateTime(2026, 9, 19, 5, 39, 28, DateTimeKind.Utc), missionId, template.TemplateId, "MISSION_INIT", "Init", "Opérateur-Atlas", "prev0", "hash1"),
            new(2, DateTime.UtcNow.AddSeconds(-2), missionId, template.TemplateId, "POLICY_APPLIED", "Applied", "Opérateur-Atlas", "hash1", "hash2"),
            new(3, DateTime.UtcNow.AddSeconds(-1), missionId, template.TemplateId, "TOOL_EXEC", "Ran curl", "Opérateur-Atlas", "hash2", "hash3")
        });
        var merkleEngine = new MerkleTreeEngine();
        var assembler = new MissionRunRecordAssembler(ledger, merkleEngine, new ComplianceArchiveExporter(merkleEngine));

        string tempDir = Path.Combine(Path.GetTempPath(), "splat_test_verifier_" + Guid.NewGuid().ToString("N"));
        try
        {
            string zipPath = await assembler.AssembleAndExportBundleAsync(
                missionId, template, null, "Opérateur-Atlas", "Completed", 0, 0, Array.Empty<string>(), "Windows", tempDir);
            string bundle = Path.Combine(tempDir, "bundle");
            ZipFile.ExtractToDirectory(zipPath, bundle);

            var (passCode, passOutput) = await RunPowerShellVerifierAsync(bundle);
            Assert.True(passCode == 0, passOutput);
            Assert.Contains("All 3 entries", passOutput);

            // One edited action, and that entry is no longer a leaf under the root.
            string chainPath = Path.Combine(bundle, "audit_chain.json");
            string chain = File.ReadAllText(chainPath);
            Assert.Contains("\"TOOL_EXEC\"", chain);
            File.WriteAllText(chainPath, chain.Replace("\"TOOL_EXEC\"", "\"TOOL_SKIPPED\""), new UTF8Encoding(true));

            var (failCode, failOutput) = await RunPowerShellVerifierAsync(bundle);
            Assert.True(failCode == 1, failOutput);
            Assert.Contains("is not for the entry", failOutput);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
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

        // Tamper with the leaf hash
        var tamperedProof = proof with { LeafHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" };
        Assert.False(engine.VerifyProof(tamperedProof));
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
                _entries.Add(last with { Id = id, TimestampUtc = DateTime.UtcNow, Action = "TOOL_OUTPUT", PreviousHash = last.EntryHash, EntryHash = $"hash{id}" });
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
