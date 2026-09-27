using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Retention;

namespace SplatMcp;

/// <summary>
/// Runs the retention policy.
///
/// <see cref="DataRetentionService"/> was written, tested and then constructed by nothing but its own
/// tests. A retention policy no host applies is not a policy, it is a class - and "SPLAT erases raw
/// telemetry after seven days" was a sentence about code that had never run outside a test. This is
/// the host that runs it.
///
/// It is a command rather than a timer, deliberately. The sweep overwrites mission payloads and
/// cryptographically erases audit detail: there is no undo, and starting it on a schedule nobody
/// chose is how an operator loses evidence they were still using. Whoever wants it periodic points a
/// scheduled task at `splat-mcp retain --apply`, the same way the substrate re-proof is scheduled,
/// and the decision stays a person's.
/// </summary>
public static class RetentionSweep
{
    public static async Task<int> RunAsync(
        McpServerCommand.Retain retain,
        TextWriter output,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(retain);
        ArgumentNullException.ThrowIfNull(output);

        string dbPath = Environment.GetEnvironmentVariable("SPLAT_DB_PATH")
            ?? SplatDataRoot.Layout.LedgerDatabase;

        output.WriteLine(retain.Apply
            ? "SPLAT retention - erasing what the policy no longer keeps"
            : "SPLAT retention - what would be erased (nothing is changed; add --apply)");
        output.WriteLine();
        output.WriteLine($"  database   {dbPath}");

        if (!File.Exists(dbPath))
        {
            // Not an error. A host that has run no mission has nothing to sweep, and saying so is more
            // use than an exception about a file the operator never created.
            output.WriteLine();
            output.WriteLine("  No database at that path, so there is nothing to sweep.");
            return 0;
        }

        byte[]? ledgerKey;
        try
        {
            ledgerKey = retain.LedgerKeyPath is null ? null : LedgerKeyFile.Read(retain.LedgerKeyPath);
        }
        catch (InvalidOperationException ex)
        {
            output.WriteLine();
            output.WriteLine($"  {ex.Message}");
            return McpServerCommand.UsageExitCode;
        }

        // The same refusal the server makes, for the same reason: redacting detail out of a keyed chain
        // this process cannot verify would leave an operator unable to tell a retention sweep from
        // tampering. A chain is checked before it is rewritten.
        var chain = await SqliteChainedAuditLedger.InspectAsync(dbPath, ledgerKey);
        if (chain.Keyed && chain.KeyMatches != true)
        {
            output.WriteLine();
            output.WriteLine(ledgerKey is null
                ? $"  The audit ledger at {dbPath} is keyed. Re-run with --ledger-key <file>."
                : $"  The audit ledger at {dbPath} was not keyed by {retain.LedgerKeyPath}.");
            return McpServerCommand.UsageExitCode;
        }

        output.WriteLine(ledgerKey is null ? "  ledger     unkeyed" : $"  ledger     keyed by {retain.LedgerKeyPath}");

        var policy = new RetentionPolicy();
        output.WriteLine();
        output.WriteLine("  Windows, per data class:");
        output.WriteLine($"    raw sensor output      {Window(policy.RawOutputRetention)}");
        output.WriteLine($"    input parameters       {Window(policy.InputParameterRetention)}");
        output.WriteLine($"    model analysis         {Window(policy.AiAnalysisRetention)}");
        output.WriteLine($"    semantic index rows    {Window(policy.SemanticIndexRetention)}");
        output.WriteLine($"    audit detail           {Window(policy.AuditDetailRetention)}  (row kept, text erased)");

        var context = new SqliteStorageContext(dbPath);
        var ledger = new SqliteChainedAuditLedger(context, ledgerKey);
        var service = new DataRetentionService(context, ledger);

        // Vacuum is skipped on a preview by SweepAsync, and asking for it here would misreport the
        // plan; on an --apply run it is what returns the freed pages to the filesystem.
        var result = await service.SweepAsync(policy, nowUtc: null, cancellationToken: ct, apply: retain.Apply);

        output.WriteLine();
        output.WriteLine(retain.Apply ? "  Erased:" : "  Would erase:");
        output.WriteLine($"    raw outputs scrubbed       {result.RawOutputsScrubbed}");
        output.WriteLine($"    input parameters scrubbed  {result.InputParametersScrubbed}");
        output.WriteLine($"    analyses scrubbed          {result.AiAnalysesScrubbed}");
        output.WriteLine($"    semantic rows deleted      {result.SemanticRowsDeleted}");
        output.WriteLine($"    audit details erased       {result.AuditDetailsRedacted}");

        if (result.LegacyAuditEntriesSkipped > 0)
        {
            // Version 1 rows commit to the plaintext itself, so erasing the text breaks the chain that
            // proves the row. They are left, and named, because silently skipping them would let an
            // operator believe a window applied to entries it cannot reach.
            output.WriteLine($"    audit rows NOT erasable    {result.LegacyAuditEntriesSkipped}  " +
                "(version 1 chain commits to the plaintext, so erasing it would break the chain)");
        }

        if (policy.PurgeExpiredVaultSecrets)
        {
            output.WriteLine(retain.Apply
                ? $"    expired vault secrets      {result.VaultSecretsPurged}"
                : "    expired vault secrets      not counted - a preview cannot ask the vault what it " +
                  "would purge without purging it");
        }

        output.WriteLine();
        if (!retain.Apply)
        {
            output.WriteLine("  Nothing was changed. Re-run with --apply to erase. There is no undo:");
            output.WriteLine("  payload columns are overwritten and audit text is erased against a chain");
            output.WriteLine("  that keeps only its commitment to what the text was.");
            return 0;
        }

        // The WAL sidecar holds pre-purge page images until a checkpoint, so a sweep that reports
        // success without truncating it has not erased anything an attacker with the file cannot read.
        if (!result.WalTruncated)
        {
            output.WriteLine("  WARNING: the write-ahead log could not be truncated, because a reader held");
            output.WriteLine("  the database. The rows are scrubbed, but their pre-purge images may remain in");
            output.WriteLine("  the -wal sidecar until a checkpoint succeeds. Re-run with nothing else");
            output.WriteLine("  attached to the database.");
            return 1;
        }

        output.WriteLine(result.Vacuumed
            ? "  WAL truncated and the file vacuumed; the freed pages are back with the filesystem."
            : "  WAL truncated. The file was not vacuumed, so freed pages stay inside it.");
        return 0;
    }

    private static string Window(TimeSpan retention) =>
        retention == TimeSpan.MaxValue ? "never erased" : $"{retention.TotalDays:0.#} days";
}
