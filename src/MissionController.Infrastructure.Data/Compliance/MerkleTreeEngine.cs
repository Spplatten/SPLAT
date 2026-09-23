using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Compliance;

public sealed class MerkleTreeEngine : IMerkleProofEngine
{
    public MerkleTree BuildTree(IReadOnlyList<AuditLogEntry> entries)
    {
        if (entries == null || entries.Count == 0)
        {
            return new MerkleTree("0000000000000000000000000000000000000000000000000000000000000000", null, 0);
        }

        // Build leaf nodes, and remember where each entry sits among them.
        var currentLevel = new List<MerkleTreeNode>();
        var leafPositions = new Dictionary<long, int>();
        foreach (var entry in entries.OrderBy(e => e.Id))
        {
            string leafHash = ComputeLeafHash(entry);
            // First occurrence wins, which is the leaf the root-down search used to find.
            leafPositions.TryAdd(entry.Id, currentLevel.Count);
            currentLevel.Add(new MerkleTreeNode(leafHash, null, null, entry.Id));
        }

        int leafCount = currentLevel.Count;
        var levels = new List<IReadOnlyList<string>> { currentLevel.Select(n => n.Hash).ToList() };

        // Build tree bottom-up
        while (currentLevel.Count > 1)
        {
            var nextLevel = new List<MerkleTreeNode>();
            for (int i = 0; i < currentLevel.Count; i += 2)
            {
                var left = currentLevel[i];
                var right = (i + 1 < currentLevel.Count) ? currentLevel[i + 1] : left; // Duplicate last if odd

                string combinedHash = ComputeParentHash(left.Hash, right.Hash);
                nextLevel.Add(new MerkleTreeNode(combinedHash, left, right, null));
            }
            currentLevel = nextLevel;
            levels.Add(currentLevel.Select(n => n.Hash).ToList());
        }

        var rootNode = currentLevel[0];
        return new MerkleTree(rootNode.Hash, rootNode, leafCount, levels, leafPositions);
    }

    public MerkleProof GenerateProof(MerkleTree tree, long entryId)
    {
        if (tree.RootNode == null)
        {
            throw new InvalidOperationException("Cannot generate proof on an empty Merkle tree.");
        }

        if (tree.Levels is { Count: > 0 } levels && tree.LeafPositions is not null)
        {
            return ProveByPosition(tree, levels, entryId);
        }

        // A tree built without its levels - by hand, or by an older engine - is walked from the root,
        // asking every subtree whether it holds the entry. Correct, and O(n log n) per proof.
        var proofSteps = new List<MerkleProofStep>();
        string? leafHash = null;

        bool found = FindProofPath(tree.RootNode, entryId, proofSteps, ref leafHash);
        if (!found || leafHash == null)
        {
            throw new KeyNotFoundException($"EntryId {entryId} was not found in the Merkle tree.");
        }

        return new MerkleProof(entryId, leafHash, tree.RootHash, proofSteps);
    }

    /// <summary>
    /// One sibling per level, read by position. The steps are ordered leaf-first, and each says
    /// which side its sibling was hashed on, exactly as the root-down walk recorded them - so a
    /// proof from either path verifies under the same <see cref="VerifyProof"/> and rebuilds under
    /// the bundle's own scripts, which only ever knew the leaf-first shape. An odd level's last
    /// node was paired with itself when its parent was built, and its sibling here is itself.
    /// </summary>
    private static MerkleProof ProveByPosition(MerkleTree tree, IReadOnlyList<IReadOnlyList<string>> levels, long entryId)
    {
        if (!tree.LeafPositions!.TryGetValue(entryId, out int index) || index >= levels[0].Count)
        {
            throw new KeyNotFoundException($"EntryId {entryId} was not found in the Merkle tree.");
        }

        string leafHash = levels[0][index];
        var steps = new List<MerkleProofStep>(levels.Count);
        for (int level = 0; level < levels.Count - 1; level++)
        {
            var row = levels[level];
            bool isRightChild = (index & 1) == 1;
            int siblingIndex = isRightChild ? index - 1 : index + 1;
            string sibling = siblingIndex < row.Count ? row[siblingIndex] : row[index];
            steps.Add(new MerkleProofStep(sibling, IsLeftSibling: isRightChild));
            index >>= 1;
        }

        return new MerkleProof(entryId, leafHash, tree.RootHash, steps);
    }

    public bool VerifyProof(MerkleProof proof)
    {
        if (proof == null || string.IsNullOrWhiteSpace(proof.LeafHash) || string.IsNullOrWhiteSpace(proof.RootHash))
        {
            return false;
        }

        string currentHash = proof.LeafHash;
        foreach (var step in proof.ProofSteps)
        {
            currentHash = step.IsLeftSibling
                ? ComputeParentHash(step.SiblingHash, currentHash)
                : ComputeParentHash(currentHash, step.SiblingHash);
        }

        return string.Equals(currentHash, proof.RootHash, StringComparison.OrdinalIgnoreCase);
    }

    private static bool FindProofPath(MerkleTreeNode current, long targetEntryId, List<MerkleProofStep> proofSteps, ref string? leafHash)
    {
        if (current.Left == null && current.Right == null)
        {
            if (current.EntryId == targetEntryId)
            {
                leafHash = current.Hash;
                return true;
            }
            return false;
        }

        if (current.Left != null && ContainsEntry(current.Left, targetEntryId))
        {
            if (FindProofPath(current.Left, targetEntryId, proofSteps, ref leafHash))
            {
                var sibling = current.Right ?? current.Left;
                proofSteps.Add(new MerkleProofStep(sibling.Hash, IsLeftSibling: false));
                return true;
            }
        }
        else if (current.Right != null && ContainsEntry(current.Right, targetEntryId))
        {
            if (FindProofPath(current.Right, targetEntryId, proofSteps, ref leafHash))
            {
                var sibling = current.Left ?? current.Right;
                proofSteps.Add(new MerkleProofStep(sibling.Hash, IsLeftSibling: true));
                return true;
            }
        }

        return false;
    }

    private static bool ContainsEntry(MerkleTreeNode node, long targetEntryId)
    {
        if (node.EntryId == targetEntryId) return true;
        if (node.Left != null && ContainsEntry(node.Left, targetEntryId)) return true;
        if (node.Right != null && ContainsEntry(node.Right, targetEntryId)) return true;
        return false;
    }

    public static string ComputeLeafHash(AuditLogEntry entry)
    {
        string raw = $"{entry.Id}:{entry.EntryHash}:{entry.TimestampUtc:O}:{entry.Action}:{entry.OperatorIdentity}";
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static string ComputeParentHash(string leftHash, string rightHash)
    {
        string raw = $"{leftHash}:{rightHash}";
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
