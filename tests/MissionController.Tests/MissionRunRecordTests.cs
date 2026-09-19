using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
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
    public async Task AssembleRunRecordAsync_PopulatesAllSixGroupsFaithfully()
    {
        var missionId = Guid.NewGuid();
        var template = CreateSampleTemplate();
        var lease = CreateSampleLease(missionId);

        var mockLedger = new StubAuditLedger(new List<AuditLogEntry>
        {
            new(1, DateTime.UtcNow.AddSeconds(-2), missionId, template.TemplateId, "MISSION_INIT", "Mission initialized", "Operator-Atlas", "0000000000000000000000000000000000000000000000000000000000000000", "hash1"),
            new(2, DateTime.UtcNow.AddSeconds(-1), missionId, template.TemplateId, "TOOL_EXEC", "Executed curl sensor", "Operator-Atlas", "hash1", "hash2"),
            new(3, DateTime.UtcNow, missionId, template.TemplateId, "MISSION_COMPLETE", "Completed successfully", "Operator-Atlas", "hash2", "hash3")
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

        // 1. Request Identity
        Assert.Equal("Operator-Atlas", record.RequestIdentity.Principal);
        Assert.Equal(missionId, record.RequestIdentity.MissionId);
        Assert.Equal("sample-network-mission", record.RequestIdentity.PolicyVersionOrHash);
        Assert.NotEmpty(record.RequestIdentity.AuthProvenance);

        // 2. Effective Permission
        Assert.Equal("curl.exe", record.EffectivePermission.ExecutablePath);
        Assert.True(record.EffectivePermission.AllowNetwork);
        Assert.Contains("93.184.216.34", record.EffectivePermission.AllowedEgressIps);
        Assert.Contains(443u, record.EffectivePermission.AllowedEgressPorts);
        Assert.Equal(256UL * 1024 * 1024, record.EffectivePermission.MaxMemoryBytes);

        // 3. Enforcement State
        Assert.Equal("WSL2-BPF-LSM", record.EnforcementState.SubstrateType);
        Assert.Contains("BPF-LSM", record.EnforcementState.AttachedControls);
        Assert.Equal("splat-cg-445", record.EnforcementState.CgroupOrJobId);
        Assert.Equal("Admitted", record.EnforcementState.AdmissionVerdict);

        // 4. Outcome
        Assert.Equal("Completed", record.Outcome.ExecutionState);
        Assert.Equal(0, record.Outcome.ExitCode);
        Assert.Equal(2, record.Outcome.RedactionCount);
        Assert.Contains("AwsKey", record.Outcome.RedactedCategories);
        Assert.True(record.Outcome.QualityAcceptance);

        // 5. Cleanup
        Assert.True(record.Cleanup.ProcessesTerminated);
        Assert.Contains("PurgeKernelLease", record.Cleanup.PolicyRemovalOrder);
        Assert.Equal("EphemeralScratchPurged", record.Cleanup.WorkspaceDisposition);
        Assert.True(record.Cleanup.ResidualResourcesCleaned);

        // 6. Integrity
        Assert.Equal("Unkeyed", record.Integrity.ChainKind);
        Assert.Equal(SqliteChainedAuditLedger.UnkeyedVersion, record.Integrity.HashVersion);
        Assert.Equal(3, record.Integrity.TotalAuditEntries);
        Assert.NotEmpty(record.Integrity.MerkleRootHash);
        Assert.NotEmpty(record.Integrity.AttestationSignature);
    }

    [Fact]
    public async Task AssembleRunRecordAsync_CarriesKeyedChainKindWhenPresent()
    {
        var missionId = Guid.NewGuid();
        var template = CreateSampleTemplate();
        var lease = CreateSampleLease(missionId);

        var mockLedger = new StubAuditLedger(new List<AuditLogEntry>
        {
            new(1, DateTime.UtcNow.AddSeconds(-2), missionId, template.TemplateId, SqliteChainedAuditLedger.KeyedAction, "Ledger keyed under HMAC", "Operator-Atlas", "0000000000000000000000000000000000000000000000000000000000000000", "hash1"),
            new(2, DateTime.UtcNow.AddSeconds(-1), missionId, template.TemplateId, "TOOL_EXEC", "Executed curl sensor", "Operator-Atlas", "hash1", "hash2")
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
            redactionCount: 0,
            redactedCategories: Array.Empty<string>(),
            substrateType: "WSL2-BPF-LSM");

        Assert.Equal("HmacSha256", record.Integrity.ChainKind);
        Assert.Equal(SqliteChainedAuditLedger.KeyedVersion, record.Integrity.HashVersion);
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

    private sealed class StubAuditLedger : IAuditLedger
    {
        private readonly IReadOnlyList<AuditLogEntry> _entries;

        public StubAuditLedger(IReadOnlyList<AuditLogEntry> entries)
        {
            _entries = entries;
        }

        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details, string operatorIdentity, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100, CancellationToken cancellationToken = default)
        {
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
