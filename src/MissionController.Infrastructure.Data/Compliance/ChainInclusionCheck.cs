using System;
using System.Collections.Generic;
using System.Linq;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Compliance;

/// <summary>
/// The check a bundle's recipient can run alone (roadmap 3.7).
///
/// Everything else in a bundle verifies the bundle against itself: its Merkle root covers the
/// entries it carries and its signature covers its files, so both agree however many of a mission's
/// rows were left out. <see cref="RunRecordLedgerVerifier"/> answers that properly and needs the
/// host's live ledger. This needs nothing but the zip and the operator's published key fingerprint,
/// and answers a narrower question honestly: every row in this bundle was in that ledger when the
/// checkpoint was signed.
///
/// <para>
/// What it cannot say, and the caller must not imply: that nothing was removed from the chain
/// afterwards, that the checkpoint is the operator's rather than someone's, or that rows exist
/// which the bundle does not carry. The first needs a consistency proof over an append-only tree,
/// the second needs the reader to compare the key id with a fingerprint published somewhere they
/// already trust, and the third is what the host-side verifier is for.
/// </para>
/// </summary>
public static class ChainInclusionCheck
{
    public sealed record Result(bool Holds, IReadOnlyList<string> Checks, IReadOnlyList<string> Failures)
    {
        public string Verdict => Holds
            ? "Every row in this bundle was in the chain the checkpoint describes, at the head it names."
            : Failures.Count > 0 ? Failures[0] : "The bundle could not be checked.";
    }

    public static Result Verify(
        SignedLedgerCheckpoint? checkpoint,
        IReadOnlyList<MerkleProof>? proofs,
        IReadOnlyList<AuditLogEntry>? bundledEntries)
    {
        var passed = new List<string>();
        var failed = new List<string>();

        if (checkpoint is null || proofs is null || bundledEntries is null)
        {
            // Not a failure of the chain - a bundle that was exported before this shipped, or by a
            // host with no run record key. It cannot be checked here, which is not the same as
            // failing, and a caller that reports it as tampering would be wrong.
            failed.Add("This bundle carries no checkpoint and inclusion proofs, so nothing here can be checked without the host.");
            return new Result(false, passed, failed);
        }

        if (!LedgerCheckpointBuilder.SignatureHolds(checkpoint))
        {
            failed.Add("The checkpoint's signature does not hold over its own statement, so the statement was edited or was never signed by the key it carries.");
            return new Result(false, passed, failed);
        }

        passed.Add($"The checkpoint is signed by key {checkpoint.KeyId}; compare that with the fingerprint the operator published.");

        var byId = proofs.GroupBy(p => p.EntryId).ToDictionary(g => g.Key, g => g.First());
        string root = checkpoint.Checkpoint.ChainMerkleRoot;
        long head = checkpoint.Checkpoint.HeadEntryId;

        foreach (var entry in bundledEntries.OrderBy(e => e.Id))
        {
            if (entry.Id > head)
            {
                failed.Add($"Row {entry.Id} is past the checkpoint's head of {head}: the chain had not reached it when the statement was signed.");
                continue;
            }

            if (!byId.TryGetValue(entry.Id, out var proof))
            {
                failed.Add($"Row {entry.Id} has no inclusion proof, so nothing places it in the chain.");
                continue;
            }

            // Bind the proof to the row this bundle actually carries. Without this a bundle could
            // ship honest proofs for rows it does not contain and edited rows with no proof of
            // their own, and every other check here would still pass.
            string expectedLeaf = MerkleTreeEngine.ComputeLeafHash(entry);
            if (!string.Equals(proof.LeafHash, expectedLeaf, StringComparison.OrdinalIgnoreCase))
            {
                failed.Add($"Row {entry.Id}'s proof is for a different row: it proves leaf {Short(proof.LeafHash)} and this bundle holds {Short(expectedLeaf)}.");
                continue;
            }

            if (!string.Equals(proof.RootHash, root, StringComparison.OrdinalIgnoreCase))
            {
                failed.Add($"Row {entry.Id}'s proof is rooted at {Short(proof.RootHash)}, which is not the checkpoint's chain root {Short(root)}.");
                continue;
            }

            if (!new MerkleTreeEngine().VerifyProof(proof))
            {
                failed.Add($"Row {entry.Id}'s inclusion proof does not recompute to the root it names.");
            }
        }

        if (failed.Count == 0)
        {
            passed.Add($"All {bundledEntries.Count} rows prove into the chain root {Short(root)} at head {head} ({checkpoint.Checkpoint.TotalEntries} entries, issued {checkpoint.Checkpoint.IssuedAtUtc:O}).");
            passed.Add("Not established: that nothing was removed from the chain after this head, which needs a consistency proof this build does not produce.");

            // Found by the test that was written to catch an edited row and did not. The leaf is
            // ComputeLeafHash's id, entry hash, timestamp, action and actor - the row's identity -
            // and NOT its Details. So inclusion places the row in the chain and says nothing about
            // the narrative a person actually reads. The ledger does bind them: EntryHash commits
            // to a salted commitment over Details. A recipient cannot check that here because
            // audit_chain.json carries neither the commitment nor the salt, which is the one thing
            // standing between this and a complete offline check.
            passed.Add("Not established: the Details text of these rows. The Merkle leaf covers a row's identity - id, entry hash, timestamp, action, actor - not its narrative, and this bundle carries no details commitment to recompute against.");
        }

        return new Result(failed.Count == 0, passed, failed);
    }

    private static string Short(string hash) => hash.Length <= 16 ? hash : hash[..16] + "...";
}
