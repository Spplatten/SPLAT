using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Compliance;

/// <summary>One named question asked of a bundle. Null is "could not be asked", which is never a pass.</summary>
public sealed record LedgerAgreementCheck(string Name, bool? Passed, string Detail);

/// <summary>
/// What the host says about a bundle someone brought it.
/// </summary>
/// <param name="Agrees">
/// True only when every check ran and passed. A check that could not be made leaves this false, because
/// the question this class exists to answer is whether the host's ledger agrees - and "nothing here
/// could be compared" is not a yes.
/// </param>
public sealed record LedgerAgreementResult(
    string BundlePath,
    Guid? MissionId,
    bool Agrees,
    IReadOnlyList<LedgerAgreementCheck> Checks)
{
    public string Verdict => Agrees
        ? "The host's ledger holds exactly the entries this bundle carries, at the positions it claims."
        : Checks.FirstOrDefault(c => c.Passed == false)?.Detail
          ?? Checks.FirstOrDefault(c => c.Passed is null)?.Detail
          ?? "The bundle could not be checked.";
}

/// <summary>
/// Checks a run record bundle against the ledger it claims to have come out of.
///
/// Until this existed the bundle's own summary said so in as many words: tying the entries to the
/// host's ledger "means checking that its ledger verifies, under its key when it has one, and holds
/// these entry hashes. No command makes that comparison yet." Everything a bundle could prove, it
/// proved about itself. The Merkle root covers the rows the bundle carries and the signature covers
/// the files, so a bundle holding four of a mission's nine rows passes every check inside it while
/// reading as the whole mission. That is not tampering with evidence, it is choosing it, and no
/// amount of signing catches it.
///
/// This is the other end of that: the live chain, read now, held against what the bundle says it was.
/// </summary>
public sealed class RunRecordLedgerVerifier
{
    private readonly IAuditLedger _ledger;
    private readonly IMerkleProofEngine _merkle;
    private readonly IRunRecordSigner? _hostSigner;

    /// <param name="hostSigner">
    /// This host's own run record key, when it has one. A bundle carries the public key its signature
    /// verifies under, so the signature alone says only that one holder of one key produced these
    /// files - it cannot say whose. Comparing the key id with the host's is what turns that into a
    /// statement about this host.
    /// </param>
    public RunRecordLedgerVerifier(IAuditLedger ledger, IMerkleProofEngine merkle, IRunRecordSigner? hostSigner = null)
    {
        _ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));
        _merkle = merkle ?? throw new ArgumentNullException(nameof(merkle));
        _hostSigner = hostSigner;
    }

    public async Task<LedgerAgreementResult> VerifyAsync(string bundlePath, CancellationToken ct = default)
    {
        var checks = new List<LedgerAgreementCheck>();

        if (!File.Exists(bundlePath))
        {
            checks.Add(new("bundle-readable", false, $"There is no file at '{bundlePath}'."));
            return Result(bundlePath, null, checks);
        }

        Dictionary<string, byte[]> files;
        try
        {
            files = ReadBundle(bundlePath);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            checks.Add(new("bundle-readable", false, $"'{bundlePath}' does not open as a bundle: {ex.Message}"));
            return Result(bundlePath, null, checks);
        }

        MissionRunRecord? record = null;
        IReadOnlyList<AuditLogEntry>? entries = null;
        LedgerAnchor? anchor = null;
        try
        {
            record = Read<MissionRunRecord>(files, "mission_run_record.json");
            entries = Read<List<AuditLogEntry>>(files, "audit_chain.json");
            anchor = files.ContainsKey("ledger_anchor.json") ? Read<LedgerAnchor>(files, "ledger_anchor.json") : null;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException)
        {
            checks.Add(new("bundle-readable", false, $"'{bundlePath}' is missing or cannot parse a bundle file: {ex.Message}"));
            return Result(bundlePath, record?.MissionId, checks);
        }

        if (record is null || entries is null)
        {
            checks.Add(new("bundle-readable", false, "The bundle's record or audit chain is empty."));
            return Result(bundlePath, record?.MissionId, checks);
        }

        checks.Add(new("bundle-readable", true, $"{files.Count} files, {entries.Count} audit entries, mission {record.MissionId:D}."));

        checks.Add(CheckSignature(files, record.MissionId));
        checks.Add(CheckMerkleRoot(record, entries));

        // From here on, the host. Everything above would have passed inside the bundle too.
        bool ledgerVerifies = await _ledger.VerifyLedgerIntegrityAsync(ct);
        checks.Add(new("host-ledger-chain", ledgerVerifies,
            ledgerVerifies
                ? "The host's ledger recomputes end to end."
                : "The host's LEDGER does not verify. Nothing can be established against it, including this bundle - the disagreement may be the ledger's, not the bundle's."));

        var live = await _ledger.ReadAnchorAsync(record.MissionId, ct);
        checks.AddRange(CompareWithLedger(anchor, live, entries));

        return Result(bundlePath, record.MissionId, checks);
    }

    private static LedgerAgreementResult Result(string path, Guid? missionId, List<LedgerAgreementCheck> checks) =>
        new(path, missionId, checks.Count > 0 && checks.All(c => c.Passed == true), checks);

    /// <summary>
    /// The mission's rows as the ledger holds them now, against the rows the bundle carries and the
    /// anchor it was exported with. Three lists, and every way they can disagree is named rather than
    /// collapsed into one boolean: an auditor needs to know whether a row went missing from the
    /// bundle, from the ledger, or changed in one of them.
    /// </summary>
    private static IEnumerable<LedgerAgreementCheck> CompareWithLedger(
        LedgerAnchor? anchor,
        LedgerAnchor? live,
        IReadOnlyList<AuditLogEntry> bundleEntries)
    {
        if (anchor is null)
        {
            yield return new("bundle-anchored", null,
                "This bundle carries no ledger_anchor.json, so it does not say which chain it came from or how many rows that chain held. " +
                "It cannot be compared with any ledger - re-export it from a host that anchors.");
            yield break;
        }

        if (live is null)
        {
            yield return new("host-anchor-readable", null,
                "The host's ledger cannot report an anchor, so the bundle has nothing to be held against here.");
            yield break;
        }

        bool sameChain = string.Equals(anchor.GenesisEntryHash, live.GenesisEntryHash, StringComparison.OrdinalIgnoreCase);
        yield return new("same-chain", sameChain,
            sameChain
                ? $"Both name the chain beginning {Short(anchor.GenesisEntryHash)}."
                : $"The bundle came out of the chain beginning {Short(anchor.GenesisEntryHash)}; this host's chain begins {Short(live.GenesisEntryHash)}. They are different ledgers.");

        if (!sameChain)
        {
            yield break;
        }

        // A head that moved forward is a ledger still in use. One that moved BACK, or kept its id and
        // changed its hash, is a ledger that was rewritten under the bundle.
        if (live.HeadEntryId < anchor.HeadEntryId)
        {
            yield return new("head-not-rewound", false,
                $"The chain stood at row {anchor.HeadEntryId} when this bundle was exported and stands at row {live.HeadEntryId} now. Rows have been removed.");
        }
        else if (live.HeadEntryId == anchor.HeadEntryId && !string.Equals(live.HeadEntryHash, anchor.HeadEntryHash, StringComparison.OrdinalIgnoreCase))
        {
            yield return new("head-not-rewound", false,
                $"Row {anchor.HeadEntryId} is still the chain's last, but its hash changed since the export. That row was rewritten.");
        }
        else
        {
            yield return new("head-not-rewound", true,
                $"The chain was at row {anchor.HeadEntryId} at export and is at row {live.HeadEntryId} now.");
        }

        var liveById = live.MissionEntries.ToDictionary(e => e.Id);
        var bundleById = bundleEntries.ToDictionary(e => e.Id);

        var missingFromBundle = live.MissionEntries.Where(e => !bundleById.ContainsKey(e.Id)).ToList();
        var notInLedger = bundleEntries.Where(e => !liveById.ContainsKey(e.Id)).ToList();
        var changed = bundleEntries
            .Where(e => liveById.TryGetValue(e.Id, out var l) && !string.Equals(l.EntryHash, e.EntryHash, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (live.MissionEntries.Count == 0)
        {
            // Nothing to be missing from the bundle, because the ledger has nothing. Saying "all 0
            // rows are present" here would read as a pass on the one case where the host has never
            // heard of this mission.
            yield return new("bundle-holds-every-row", false,
                $"This ledger holds no rows at all for this mission, and the bundle carries {bundleEntries.Count}. Nothing in it came from here.");
        }
        else if (missingFromBundle.Count > 0)
        {
            // The one this whole class exists for. Everything inside the bundle passes; the mission
            // simply had more to it than the bundle shows.
            yield return new("bundle-holds-every-row", false,
                $"The ledger holds {live.MissionEntries.Count} rows for this mission and the bundle carries {bundleEntries.Count}. " +
                $"Missing: {string.Join(", ", missingFromBundle.Take(10).Select(e => $"row {e.Id} ({e.Action})"))}" +
                (missingFromBundle.Count > 10 ? $" and {missingFromBundle.Count - 10} more." : "."));
        }
        else
        {
            yield return new("bundle-holds-every-row", true,
                $"All {live.MissionEntries.Count} of the mission's rows are in the bundle.");
        }

        if (notInLedger.Count > 0)
        {
            yield return new("no-row-the-ledger-lacks", false,
                $"The bundle carries {notInLedger.Count} row(s) this ledger does not hold for this mission: " +
                string.Join(", ", notInLedger.Take(10).Select(e => $"row {e.Id} ({e.Action})")) + ".");
        }
        else
        {
            yield return new("no-row-the-ledger-lacks", true, "Every row in the bundle is in the ledger.");
        }

        if (changed.Count > 0)
        {
            yield return new("row-hashes-match", false,
                "The ledger's hash differs from the bundle's for " +
                string.Join(", ", changed.Take(10).Select(e => $"row {e.Id} ({e.Action})")) +
                ". One of the two was altered after the export.");
        }
        else
        {
            yield return new("row-hashes-match", true, $"All {bundleEntries.Count} entry hashes match the ledger's.");
        }

        // The anchor is inside the signature, so a short bundle cannot be repaired by trimming it.
        // Checking it against the live ledger as well catches the other order: a bundle exported with
        // an anchor that already understated the mission.
        bool anchorMatchesLive = anchor.MissionEntries.Count == live.MissionEntries.Count
            && anchor.MissionEntries.All(a => liveById.TryGetValue(a.Id, out var l)
                && string.Equals(l.EntryHash, a.EntryHash, StringComparison.OrdinalIgnoreCase));
        yield return new("anchor-matches-ledger", anchorMatchesLive,
            anchorMatchesLive
                ? $"The anchor lists the same {anchor.MissionEntries.Count} rows the ledger holds."
                : $"The anchor lists {anchor.MissionEntries.Count} rows for this mission; the ledger holds {live.MissionEntries.Count}. " +
                  "Either the ledger changed since the export, or the anchor never described it.");
    }

    /// <summary>
    /// The signature over the bundle, re-checked here rather than left to the scripts inside it: one
    /// command should be able to answer the whole question, and a verifier that trusts the artifact
    /// to check itself is not a verifier.
    /// </summary>
    private LedgerAgreementCheck CheckSignature(IReadOnlyDictionary<string, byte[]> files, Guid missionId)
    {
        if (!files.TryGetValue("signature.json", out var signatureBytes))
        {
            return new("bundle-signature", null,
                "This bundle is unsigned, so nothing says who produced it. Whoever can edit it can rebuild every file to agree.");
        }

        ComplianceArchiveExporter.RunRecordSignature? signature;
        try
        {
            signature = JsonSerializer.Deserialize<ComplianceArchiveExporter.RunRecordSignature>(
                StripPreamble(signatureBytes), ComplianceArchiveExporter.BundleJson);
        }
        catch (JsonException ex)
        {
            return new("bundle-signature", false, $"signature.json does not parse: {ex.Message}");
        }

        if (signature is null)
        {
            return new("bundle-signature", false, "signature.json is empty.");
        }

        if (!signature.Statement.StartsWith(ComplianceArchiveExporter.StatementHeader + "\n", StringComparison.Ordinal))
        {
            return new("bundle-signature", false, "The signed statement is not a run record statement.");
        }

        if (!signature.Statement.Contains($"mission {missionId:D}\n", StringComparison.Ordinal))
        {
            return new("bundle-signature", false, $"The signed statement does not name mission {missionId:D}.");
        }

        // Every file the statement names must be here with the hash it names, and nothing else may be
        // here at all. Checking only the listed files would let an unlisted one ride along signed.
        var named = new HashSet<string>(StringComparer.Ordinal);
        foreach (string line in signature.Statement.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!line.StartsWith("file ", StringComparison.Ordinal))
            {
                continue;
            }

            string[] parts = line.Split(' ');
            if (parts.Length != 4 || parts[2] != "sha256")
            {
                return new("bundle-signature", false, $"The signed statement has a line this build cannot read: '{line}'");
            }

            string name = parts[1];
            named.Add(name);
            if (!files.TryGetValue(name, out var content))
            {
                return new("bundle-signature", false, $"The statement names '{name}', which is not in the bundle.");
            }

            string actual = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
            if (!string.Equals(actual, parts[3], StringComparison.OrdinalIgnoreCase))
            {
                return new("bundle-signature", false, $"'{name}' has changed since it was signed.");
            }
        }

        var unsigned = files.Keys.Where(k => k != "signature.json" && !named.Contains(k)).ToList();
        if (unsigned.Count > 0)
        {
            return new("bundle-signature", false, $"The bundle carries files the signature does not cover: {string.Join(", ", unsigned)}.");
        }

        bool valid;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(Convert.FromBase64String(signature.PublicKey), out _);
            valid = rsa.VerifyData(
                Encoding.UTF8.GetBytes(signature.Statement),
                Convert.FromBase64String(signature.Signature),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return new("bundle-signature", false, $"The signature cannot be checked: {ex.Message}");
        }

        if (!valid)
        {
            return new("bundle-signature", false, "The signature does not verify over the statement.");
        }

        if (_hostSigner is null)
        {
            return new("bundle-signature", true,
                $"Signed by key {signature.KeyId}, and the files are unchanged. This host holds no run record key, so nothing here says that key is its own - compare the fingerprint with the one the operator published.");
        }

        bool sameKey = string.Equals(signature.KeyId, _hostSigner.KeyId, StringComparison.OrdinalIgnoreCase);
        return new("bundle-signature", sameKey,
            sameKey
                ? $"Signed by this host's own run record key {signature.KeyId}, and the files are unchanged."
                : $"The signature verifies, but under key {signature.KeyId}; this host signs with {_hostSigner.KeyId}. The bundle was not produced by this host's current key.");
    }

    private LedgerAgreementCheck CheckMerkleRoot(MissionRunRecord record, IReadOnlyList<AuditLogEntry> entries)
    {
        if (record.Integrity.MerkleRootHash is not { } claimed)
        {
            return new("merkle-root", null, "The record names no Merkle root.");
        }

        string rebuilt = _merkle.BuildTree(entries).RootHash;
        bool matches = string.Equals(rebuilt, claimed, StringComparison.OrdinalIgnoreCase);
        return new("merkle-root", matches,
            matches
                ? $"The {entries.Count} entries rebuild the root the record names."
                : $"The entries rebuild {Short(rebuilt)}; the record names {Short(claimed)}.");
    }

    private static Dictionary<string, byte[]> ReadBundle(string bundlePath)
    {
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        using var archive = ZipFile.OpenRead(bundlePath);
        foreach (var entry in archive.Entries)
        {
            using var stream = entry.Open();
            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);
            files[entry.FullName] = buffer.ToArray();
        }

        return files;
    }

    private static T? Read<T>(IReadOnlyDictionary<string, byte[]> files, string name) =>
        files.TryGetValue(name, out var bytes)
            ? JsonSerializer.Deserialize<T>(StripPreamble(bytes), ComplianceArchiveExporter.BundleJson)
            : throw new KeyNotFoundException($"the bundle has no {name}");

    // The exporter writes every text file with a BOM. System.Text.Json refuses one.
    private static ReadOnlySpan<byte> StripPreamble(byte[] bytes) =>
        bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF
            ? bytes.AsSpan(3)
            : bytes.AsSpan();

    private static string Short(string hash) => hash.Length <= 16 ? hash : hash[..16] + "...";
}
