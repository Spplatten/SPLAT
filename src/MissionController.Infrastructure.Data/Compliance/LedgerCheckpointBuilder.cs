using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Compliance;

/// <summary>
/// Builds and signs a statement about the whole chain, and the inclusion proofs that tie a bundle's
/// rows to it (roadmap 3.7).
///
/// The tree is built over EVERY ledger entry, not one mission's. That is the whole point and it is
/// also the cost: an export walks the chain rather than the mission, and the walk grows with the
/// ledger. It is paid once per export and it is what buys a recipient the ability to check a bundle
/// without the host, which nothing before this could do.
/// </summary>
public sealed class LedgerCheckpointBuilder
{
    /// <summary>
    /// The chain is read whole or not at all. A checkpoint over part of it would carry a root that
    /// no honest bundle could ever prove against, and a reader cannot tell a truncated chain from a
    /// short one.
    /// </summary>
    public const int MaxChainEntries = 1_000_000;

    /// <summary>First line of the signed statement, so a checkpoint signature cannot pass as a bundle's.</summary>
    public const string StatementHeader = "splat-ledger-checkpoint-v1";

    private readonly IAuditLedger _ledger;
    private readonly IMerkleProofEngine _merkle;
    private readonly IRunRecordSigner? _signer;

    public LedgerCheckpointBuilder(IAuditLedger ledger, IMerkleProofEngine merkle, IRunRecordSigner? signer = null)
    {
        _ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));
        _merkle = merkle ?? throw new ArgumentNullException(nameof(merkle));
        _signer = signer;
    }

    /// <summary>
    /// The chain as one tree, with the entries that built it. The caller keeps the entries so the
    /// proofs it then asks for are generated against this same tree rather than a second read -
    /// a row appended between two reads gives a different root, and every proof against the first
    /// would fail for a reason that is not tampering.
    /// </summary>
    public async Task<(MerkleTree Tree, IReadOnlyList<AuditLogEntry> Entries)> ReadChainAsync(CancellationToken ct = default)
    {
        var entries = await _ledger.GetAuditLogsAsync(null, MaxChainEntries + 1, ct);
        if (entries.Count > MaxChainEntries)
        {
            throw new InvalidOperationException(
                $"The ledger holds more than {MaxChainEntries} entries, so a checkpoint over it would be a checkpoint over part of it.");
        }

        if (entries.Count == 0)
        {
            throw new InvalidOperationException("An empty ledger has no chain to checkpoint.");
        }

        return (_merkle.BuildTree(entries), entries);
    }

    /// <summary>
    /// The statement for this head. <paramref name="entries"/> must be the list
    /// <see cref="ReadChainAsync"/> returned, for the reason given there.
    /// </summary>
    public LedgerCheckpoint Describe(MerkleTree tree, IReadOnlyList<AuditLogEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(tree);
        ArgumentNullException.ThrowIfNull(entries);
        if (entries.Count == 0)
        {
            throw new ArgumentException("An empty chain has no head.", nameof(entries));
        }

        // GetAuditLogsAsync returns newest first, so the head is the first row and the genesis the
        // last. Reading them the other way round names a chain that does not exist, and the error
        // would only surface at a recipient who could not match any published checkpoint.
        var ordered = entries.OrderBy(e => e.Id).ToList();
        var genesis = ordered[0];
        var head = ordered[^1];

        var versions = ordered.Select(e => e.HashVersion).Distinct().ToList();

        return new LedgerCheckpoint(
            GenesisEntryHash: genesis.EntryHash,
            HeadEntryId: head.Id,
            HeadEntryHash: head.EntryHash,
            ChainMerkleRoot: tree.RootHash,
            // One version, or the lowest present: a mixed chain is reported by its weakest row
            // rather than by its newest, because that is what a reader's trust in it rests on.
            ChainHashVersion: versions.Min(),
            TotalEntries: ordered.Count,
            IssuedAtUtc: DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Signs a checkpoint, or returns null when the host holds no run record key. An unsigned
    /// checkpoint is not published: a statement anyone could have written is not something a
    /// recipient can hold a bundle against, and offering one would read as more than it is.
    /// </summary>
    public SignedLedgerCheckpoint? Sign(LedgerCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        if (_signer is null)
        {
            return null;
        }

        string statement = StatementFor(checkpoint);
        return new SignedLedgerCheckpoint(
            checkpoint,
            _signer.Algorithm,
            _signer.KeyId,
            Convert.ToBase64String(_signer.PublicKeyDer),
            statement,
            Convert.ToBase64String(_signer.Sign(Encoding.UTF8.GetBytes(statement))));
    }

    /// <summary>
    /// The exact bytes a checkpoint's signature covers. One function, because the signer and every
    /// verifier have to agree on them and rebuilding a canonical form in several places is where
    /// that agreement is lost - the same reason the guest's signed outcome is carried verbatim
    /// rather than reassembled.
    /// </summary>
    public static string StatementFor(LedgerCheckpoint c)
    {
        ArgumentNullException.ThrowIfNull(c);
        var sb = new StringBuilder();
        sb.Append(StatementHeader).Append('\n');
        sb.Append("genesis ").Append(c.GenesisEntryHash).Append('\n');
        sb.Append("head ").Append(c.HeadEntryId).Append(' ').Append(c.HeadEntryHash).Append('\n');
        sb.Append("root ").Append(c.ChainMerkleRoot).Append('\n');
        sb.Append("entries ").Append(c.TotalEntries).Append('\n');
        sb.Append("hashversion ").Append(c.ChainHashVersion).Append('\n');
        sb.Append("issued ").Append(c.IssuedAtUtc.ToUniversalTime().ToString("O")).Append('\n');
        return sb.ToString();
    }

    /// <summary>
    /// Whether a signed checkpoint's signature holds over its own statement. Offline, and the only
    /// check of it a recipient can make alone: it says the statement came from a holder of the key
    /// it carries, never that the key is the operator's. Comparing the key id with a published
    /// fingerprint is the recipient's half, and no code here can do it for them.
    /// </summary>
    public static bool SignatureHolds(SignedLedgerCheckpoint signed)
    {
        ArgumentNullException.ThrowIfNull(signed);
        if (signed.Statement != StatementFor(signed.Checkpoint))
        {
            // The statement and the fields disagree, so one of them was edited after signing.
            return false;
        }

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(Convert.FromBase64String(signed.PublicKey), out _);
            return rsa.VerifyData(
                Encoding.UTF8.GetBytes(signed.Statement),
                Convert.FromBase64String(signed.Signature),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// An inclusion proof against the chain's root for each of a mission's entries.
    ///
    /// These are not the proofs a bundle already carries. Those are rooted at the mission's own
    /// entries, which proves the bundle consistent with itself and nothing more; these are rooted
    /// at the whole chain, which is what makes them worth anything to someone who was not there.
    /// </summary>
    public IReadOnlyList<MerkleProof> ProveInChain(MerkleTree chain, IReadOnlyList<AuditLogEntry> missionEntries)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(missionEntries);
        return missionEntries.OrderBy(e => e.Id).Select(e => _merkle.GenerateProof(chain, e.Id)).ToList();
    }
}
