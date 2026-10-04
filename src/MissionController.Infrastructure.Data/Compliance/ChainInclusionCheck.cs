using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Audit;

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
/// Details are compared with their exported salted commitments. Only unkeyed row hashes can be
/// recomputed here to bind that text to a proven leaf; keyed v3 rows retain that explicit limit.
///
/// <para>
/// What it cannot say, and the caller must not imply: that nothing was removed from the chain
/// after the latest signed snapshot, that the checkpoint is the operator's rather than someone's,
/// or that rows exist which the bundle does not carry. A supplied consistency proof checks the
/// prefix only at its two signed snapshots. The second needs the reader to compare the key id with
/// a fingerprint published somewhere they already trust, and the third needs the host-side verifier.
/// </para>
/// </summary>
public static class ChainInclusionCheck
{
    public sealed record Result(bool Holds, IReadOnlyList<string> Checks, IReadOnlyList<string> Failures)
    {
        public string Verdict => Holds
            ? "Every row's identity proves into the checkpoint's chain root. Details verification and its limits are listed in Checks."
            : Failures.Count > 0 ? Failures[0] : "The bundle could not be checked.";
    }

    public static Result Verify(
        SignedLedgerCheckpoint? checkpoint,
        IReadOnlyList<MerkleProof>? proofs,
        IReadOnlyList<AuditLogEntry>? bundledEntries,
        LedgerConsistency? consistency = null)
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

        if (consistency is not null)
        {
            var continuation = LedgerConsistencyCheck.Verify(consistency);
            if (!continuation.Holds)
                failed.Add(continuation.Verdict);
            else if (checkpoint.KeyId != consistency.Earlier.KeyId ||
                (checkpoint.Statement != consistency.Earlier.Statement && checkpoint.Statement != consistency.Later.Statement))
                failed.Add("The consistency proof does not include this bundle's checkpoint.");
            else
                passed.Add(continuation.Verdict);
        }

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
                continue;
            }

            CheckDetails(entry, passed, failed);
        }

        if (failed.Count == 0)
        {
            passed.Add($"All {bundledEntries.Count} rows prove into the chain root {Short(root)} at head {head} ({checkpoint.Checkpoint.TotalEntries} entries, issued {checkpoint.Checkpoint.IssuedAtUtc:O}).");
            if (consistency is null)
                passed.Add("Not established: that a later chain preserves this head; no consistency proof between signed checkpoints was supplied.");
        }

        return new Result(failed.Count == 0, passed, failed);
    }

    private static void CheckDetails(AuditLogEntry entry, List<string> passed, List<string> failed)
    {
        if (entry.DetailsCommitment is not null && entry.DetailsSalt is not null)
        {
            if (!string.Equals(
                    SqliteChainedAuditLedger.ComputeDetailsCommitment(entry.DetailsSalt, entry.Details),
                    entry.DetailsCommitment, StringComparison.OrdinalIgnoreCase))
            {
                failed.Add($"Row {entry.Id}'s Details text does not match its salted commitment.");
                return;
            }

            passed.Add($"Row {entry.Id}'s Details text matches the salted commitment carried in the bundle.");
        }
        else if (entry.HashVersion != SqliteChainedAuditLedger.PlaintextVersion)
        {
            // Absence cannot distinguish an old export, retention erasure and stripped metadata.
            // Preserve the inclusion result, but never treat missing material as verified text.
            passed.Add($"Not established: row {entry.Id}'s Details text; its commitment or salt is absent. Older exports and retention erasure can leave these unavailable.");
        }

        // A commitment matching its text is only the first link. Unkeyed rows let a recipient
        // recompute the second link to EntryHash, which is already bound to the Merkle leaf.
        // Keyed rows need the operator's HMAC key; accepting SHA-256 as a fallback would lie.
        string? expectedEntryHash = entry.HashVersion switch
        {
            SqliteChainedAuditLedger.PlaintextVersion => SqliteChainedAuditLedger.ComputeEntryHash(
                entry.PreviousHash, entry.TimestampUtc.ToString("O", CultureInfo.InvariantCulture),
                entry.MissionId.ToString("D"), entry.TemplateId, entry.Action, entry.Details, entry.OperatorIdentity),
            SqliteChainedAuditLedger.UnkeyedVersion when entry.DetailsCommitment is not null =>
                SqliteChainedAuditLedger.ComputeEntryHashV2(
                    entry.PreviousHash, entry.TimestampUtc.ToString("O", CultureInfo.InvariantCulture),
                    entry.MissionId.ToString("D"), entry.TemplateId, entry.Action, entry.DetailsCommitment, entry.OperatorIdentity),
            _ => null,
        };

        if (expectedEntryHash is not null)
        {
            if (!string.Equals(expectedEntryHash, entry.EntryHash, StringComparison.OrdinalIgnoreCase))
            {
                failed.Add($"Row {entry.Id}'s Details do not bind to its proven EntryHash: the unkeyed row hash does not recompute.");
                return;
            }

            passed.Add($"Row {entry.Id}'s {(entry.HashVersion == SqliteChainedAuditLedger.PlaintextVersion ? "Details text" : "Details commitment")} binds to its proven EntryHash.");
        }
        else if (entry.HashVersion == SqliteChainedAuditLedger.KeyedVersion)
        {
            passed.Add($"Not established: row {entry.Id}'s Details commitment is bound to its proven EntryHash. Version 3 uses HMAC-SHA256 and this offline check has no ledger key; replacing both Details and commitment can pass the text comparison without changing the proven leaf.");
        }
        else
        {
            passed.Add($"Not established: row {entry.Id}'s Details binding to its proven EntryHash; hash version {entry.HashVersion} or its commitment is unavailable to this check.");
        }
    }

    private static string Short(string hash) => hash.Length <= 16 ? hash : hash[..16] + "...";
}
