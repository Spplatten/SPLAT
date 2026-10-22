using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Compliance;
using Xunit;

namespace MissionController.Tests;

public class MerkleComplianceArchiveTests
{
    [Fact]
    public void MerkleTreeEngine_BuildsTree_AndVerifiesProofsSuccessfully()
    {
        var engine = new MerkleTreeEngine();
        var entries = new List<AuditLogEntry>
        {
            new(1, DateTime.UtcNow.AddMinutes(-10), Guid.NewGuid(), "tpl-1", "START", "Mission Start", "Admin", "0000", "hash1"),
            new(2, DateTime.UtcNow.AddMinutes(-8), Guid.NewGuid(), "tpl-1", "EXEC", "Running tool", "Admin", "hash1", "hash2"),
            new(3, DateTime.UtcNow.AddMinutes(-5), Guid.NewGuid(), "tpl-2", "DLP_PASS", "Sanitization clean", "Tier1", "hash2", "hash3"),
            new(4, DateTime.UtcNow.AddMinutes(-2), Guid.NewGuid(), "tpl-2", "AI_INFERENCE", "Token stream completed", "Tier1", "hash3", "hash4"),
            new(5, DateTime.UtcNow, Guid.NewGuid(), "tpl-2", "DRAIN_JAIL", "Directory removed", "SYSTEM", "hash4", "hash5")
        };

        var tree = engine.BuildTree(entries);
        Assert.NotNull(tree.RootHash);
        Assert.Equal(5, tree.LeafCount);

        // Verify Merkle Proof for every single entry in the tree
        foreach (var entry in entries)
        {
            var proof = engine.GenerateProof(tree, entry.Id);
            Assert.Equal(entry.Id, proof.EntryId);
            Assert.Equal(tree.RootHash, proof.RootHash);
            Assert.NotEmpty(proof.ProofSteps);

            bool isValid = engine.VerifyProof(proof);
            Assert.True(isValid, $"Merkle proof failed for EntryId {entry.Id}");
        }
    }

    [Fact]
    public void MerkleTreeEngine_DetectsTamperedProof()
    {
        var engine = new MerkleTreeEngine();
        var entries = new List<AuditLogEntry>
        {
            new(1, DateTime.UtcNow, Guid.NewGuid(), "tpl-1", "START", "Detail 1", "Admin", "0000", "hash1"),
            new(2, DateTime.UtcNow, Guid.NewGuid(), "tpl-1", "EXEC", "Detail 2", "Admin", "hash1", "hash2")
        };

        var tree = engine.BuildTree(entries);
        var proof = engine.GenerateProof(tree, 1);

        // Tamper with the leaf hash
        var tamperedProof = new MerkleProof(proof.EntryId, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", proof.RootHash, proof.ProofSteps);
        Assert.False(engine.VerifyProof(tamperedProof));

        // Tamper with root hash
        var tamperedRootProof = new MerkleProof(proof.EntryId, proof.LeafHash, "0000000000000000000000000000000000000000000000000000000000000000", proof.ProofSteps);
        Assert.False(engine.VerifyProof(tamperedRootProof));
    }

    [Fact]
    public async Task ComplianceArchiveExporter_GeneratesValidSignedZipBundle()
    {
        var engine = new MerkleTreeEngine();
        var exporter = new ComplianceArchiveExporter(engine);
        string tempDir = Path.Combine(Path.GetTempPath(), $"compliance_test_{Guid.NewGuid():N}");

        try
        {
            var entries = new List<AuditLogEntry>
            {
                new(1, DateTime.UtcNow.AddMinutes(-20), Guid.NewGuid(), "sec-audit", "START", "Audit initialized", "LeadSecOps", "0000", "hashA"),
                new(2, DateTime.UtcNow.AddMinutes(-10), Guid.NewGuid(), "sec-audit", "DLP_FILTER", "Redacted 2 tokens", "LeadSecOps", "hashA", "hashB"),
                new(3, DateTime.UtcNow, Guid.NewGuid(), "sec-audit", "COMPLETE", "Audit finalized", "LeadSecOps", "hashB", "hashC")
            };

            string zipPath = await exporter.ExportCompliancePackageAsync(
                ComplianceFramework.CmmcLevel2,
                tempDir,
                entries,
                "LeadSecOps");

            Assert.True(File.Exists(zipPath));

            // Inspect ZIP archive contents
            using var zipStream = File.OpenRead(zipPath);
            using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);

            Assert.NotNull(archive.GetEntry("manifest.json"));
            Assert.NotNull(archive.GetEntry("audit_chain.json"));
            Assert.NotNull(archive.GetEntry("merkle_proofs.json"));
            Assert.NotNull(archive.GetEntry("compliance_summary.md"));
            Assert.NotNull(archive.GetEntry("verify_proofs.py"));
            Assert.NotNull(archive.GetEntry("verify_proofs.ps1"));

            // Parse manifest and verify Merkle root matching
            var manifestEntry = archive.GetEntry("manifest.json");
            using var manifestReader = new StreamReader(manifestEntry!.Open());
            string manifestJson = await manifestReader.ReadToEndAsync();
            var manifest = JsonSerializer.Deserialize<CompliancePackageManifest>(manifestJson);

            Assert.NotNull(manifest);
            Assert.Equal(ComplianceFramework.CmmcLevel2, manifest.Framework);
            Assert.Equal(3, manifest.TotalAuditEntries);
            Assert.Equal("LeadSecOps", manifest.ExportedBy);
            Assert.Empty(manifest.DigitalSignature);
            Assert.Equal("None (unsigned Merkle evidence)", manifest.SignatureAlgorithm);
            using var summaryReader = new StreamReader(archive.GetEntry("compliance_summary.md")!.Open());
            string summary = await summaryReader.ReadToEndAsync();
            Assert.Contains("not authenticity or completeness", summary);
            Assert.DoesNotContain("verifying non-repudiation", summary);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }
    }
}
