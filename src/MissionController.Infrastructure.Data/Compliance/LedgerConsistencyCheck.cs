using System;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Data.Compliance;

/// <summary>Checks two signed snapshots without the ledger or any other mission's rows.</summary>
public static class LedgerConsistencyCheck
{
    public sealed record Result(bool Holds, string Verdict);

    public static Result Verify(LedgerConsistency? consistency)
    {
        if (consistency?.Earlier is null || consistency.Later is null || consistency.Proof is null)
            return new(false, "No pair of checkpoints and consistency proof was supplied.");

        var earlier = consistency.Earlier;
        var later = consistency.Later;
        if (!LedgerCheckpointBuilder.SignatureHolds(earlier) || !LedgerCheckpointBuilder.SignatureHolds(later))
            return new(false, "A checkpoint signature or its key fingerprint does not hold.");
        if (!string.Equals(earlier.KeyId, later.KeyId, StringComparison.Ordinal))
            return new(false, "The checkpoints were signed by different keys; key rotation is not established by this proof.");

        var before = earlier.Checkpoint;
        var after = later.Checkpoint;
        if (before.TotalEntries <= 0 || after.TotalEntries < before.TotalEntries ||
            before.HeadEntryId <= 0 || after.HeadEntryId < before.HeadEntryId ||
            before.TotalEntries > before.HeadEntryId || after.TotalEntries > after.HeadEntryId ||
            before.GenesisEntryHash != after.GenesisEntryHash || before.IssuedAtUtc > after.IssuedAtUtc)
            return new(false, "The checkpoints disagree on their genesis, order or ledger bounds.");

        if (after.TotalEntries == before.TotalEntries
            ? after.HeadEntryId != before.HeadEntryId || after.HeadEntryHash != before.HeadEntryHash
            : after.HeadEntryId <= before.HeadEntryId)
            return new(false, "The checkpoint heads do not agree with their entry counts.");

        // Counts are signed separately because duplicate-last trees can share a root across
        // different leaf counts. A proof must not choose a shorter prefix than the signed head.
        if (consistency.Proof.PreviousLeafCount != before.TotalEntries || consistency.Proof.LeafCount != after.TotalEntries ||
            !new MerkleTreeEngine().VerifyConsistencyProof(consistency.Proof, before.ChainMerkleRoot, after.ChainMerkleRoot))
            return new(false, "The later chain root does not prove the earlier entries as an unchanged prefix.");

        return new(true,
            $"Checkpoint head {after.HeadEntryId} preserves all {before.TotalEntries} entries at head {before.HeadEntryId} as its prefix. " +
            $"Both are signed by {earlier.KeyId}; compare that fingerprint with the operator's publication. " +
            "This checks the two snapshots, not changes between them or after the later checkpoint, and adds no binding for keyed Details commitments.");
    }
}
