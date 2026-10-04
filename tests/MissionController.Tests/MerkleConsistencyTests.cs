using System;
using System.Linq;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Compliance;
using Xunit;

namespace MissionController.Tests;

public class MerkleConsistencyTests
{
    private static AuditLogEntry[] Entries(int count) => Enumerable.Range(1, count).Select(i =>
        new AuditLogEntry(i, DateTime.UnixEpoch.AddSeconds(i), Guid.Empty, "test", "ACTION", "detail", "operator",
            "previous", i.ToString("x64"))).ToArray();

    [Fact]
    public void EveryPrefixAcrossOddAndPowerOfTwoSizesMatchesTheExistingTreeRoots()
    {
        var engine = new MerkleTreeEngine();
        var entries = Entries(65);
        var roots = Enumerable.Range(1, entries.Length).Select(n => engine.BuildTree(entries.Take(n).ToArray())).ToArray();
        for (int size = 1; size <= entries.Length; size++)
        {
            for (int prefix = 1; prefix <= size; prefix++)
            {
                var proof = engine.GenerateConsistencyProof(roots[size - 1], prefix);
                // BuildTree closes and pads each tree independently; it does not use the proof's
                // frontier reconstruction, so this catches a disagreement in the padding rules.
                Assert.True(engine.VerifyConsistencyProof(proof, roots[prefix - 1].RootHash, roots[size - 1].RootHash),
                    $"prefix {prefix}, total {size}");
                Assert.True(proof.PrefixSubtreeHashes.Count + proof.AppendedSubtreeHashes.Count <= 14);
            }
        }
    }

    [Fact]
    public void RewritingOrRemovingAnEarlierRowCannotProveTheOriginalPrefix()
    {
        var engine = new MerkleTreeEngine();
        var entries = Entries(18);
        var earlier = engine.BuildTree(entries.Take(7).ToArray());
        var honest = engine.BuildTree(entries.Take(17).ToArray());
        Assert.True(engine.VerifyConsistencyProof(engine.GenerateConsistencyProof(honest, 7), earlier.RootHash, honest.RootHash));

        var rewritten = entries.Take(17).Select(e => e.Id == 4 ? e with { Action = "REWRITTEN" } : e).ToArray();
        var removed = entries.Where(e => e.Id != 4).ToArray();
        foreach (var rows in new[] { rewritten, removed })
        {
            var changed = engine.BuildTree(rows);
            Assert.False(engine.VerifyConsistencyProof(engine.GenerateConsistencyProof(changed, 7), earlier.RootHash, changed.RootHash));
        }
    }

    [Fact]
    public void ChangedMissingExtraOrMalformedProofNodesAreRefused()
    {
        var engine = new MerkleTreeEngine();
        var entries = Entries(17);
        var earlier = engine.BuildTree(entries.Take(7).ToArray());
        var later = engine.BuildTree(entries);
        var proof = engine.GenerateConsistencyProof(later, 7);
        Assert.True(engine.VerifyConsistencyProof(proof, earlier.RootHash, later.RootHash));

        var broken = new[]
        {
            proof with { PrefixSubtreeHashes = proof.PrefixSubtreeHashes.Skip(1).ToArray() },
            proof with { AppendedSubtreeHashes = proof.AppendedSubtreeHashes.Append(new string('0', 64)).ToArray() },
            proof with { PrefixSubtreeHashes = proof.PrefixSubtreeHashes.Select((h, i) => i == 0 ? new string('0', 64) : h).ToArray() },
            proof with { AppendedSubtreeHashes = proof.AppendedSubtreeHashes.Select((h, i) => i == 0 ? new string('0', 64) : h).ToArray() },
            proof with { PrefixSubtreeHashes = proof.PrefixSubtreeHashes.Select(_ => "bad hash").ToArray() },
            proof with { PreviousLeafCount = 0 },
            proof with { LeafCount = 6 },
            proof with { Schema = 2 },
            proof with { PrefixSubtreeHashes = null! },
        };
        foreach (var invalid in broken)
            Assert.False(engine.VerifyConsistencyProof(invalid, earlier.RootHash, later.RootHash));
        Assert.False(engine.VerifyConsistencyProof(proof, new string('0', 64), later.RootHash));
        Assert.False(engine.VerifyConsistencyProof(proof, earlier.RootHash, new string('0', 64)));
        Assert.Throws<ArgumentOutOfRangeException>(() => engine.GenerateConsistencyProof(later, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => engine.GenerateConsistencyProof(later, 18));
    }
}
