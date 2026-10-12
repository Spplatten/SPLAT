using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using MissionController.Core;
using MissionController.Host;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;

namespace SplatMcp;

/// <summary>
/// The half of the roadmap 2.4 gate the bridge probe cannot score. The admitted operator is denied the
/// service's ledger by design, so whether each admission row names the pipe's caller - and not an
/// identity the request claimed in its arguments - is read here, elevated, from the keyed chain itself.
/// </summary>
internal static class ManagedLedgerAudit
{
    internal sealed record Report(string At, string ServiceSid, string? CallerSid,
        IReadOnlyDictionary<string, bool> Checks, string Verdict);

    internal static async Task<int> RunAsync(string configurationPath, string probePath, string outputPath, CancellationToken ct)
    {
        var config = ManagedBridgeConfiguration.Load(configurationPath);
        using var probe = JsonDocument.Parse(await File.ReadAllTextAsync(probePath, ct));
        Report report = await AuditAsync(config.ServiceSid, config.OperatorSids, config.StateDirectory, probe.RootElement, ct);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }), ct);
        Console.WriteLine($"Managed ledger audit: {report.Verdict} ({outputPath})");
        return report.Verdict == "PASS" ? 0 : 1;
    }

    internal static async Task<Report> AuditAsync(string serviceSid, IReadOnlyCollection<string> operatorSids,
        string stateDirectory, JsonElement probe, CancellationToken ct)
    {
        var checks = new SortedDictionary<string, bool>(StringComparer.Ordinal);
        string? caller = Text(probe, "CallerSid");
        string? callerName = Text(probe, "CallerName");
        // The probe's own start and finish bound the rows it can claim; an earlier run sends the same
        // requests, so the same digests, and must not stand in for this one.
        bool hasWindow = DateTimeOffset.TryParse(Text(probe, "At"), CultureInfo.InvariantCulture, DateTimeStyles.None, out var started);
        hasWindow &= DateTimeOffset.TryParse(Text(probe, "FinishedAt"), CultureInfo.InvariantCulture, DateTimeStyles.None, out var finished);
        checks["ProbeIsAnAdmittedOwnerPass"] = Text(probe, "Verdict") == "PASS" && Text(probe, "ServiceSid") == serviceSid
            && caller is not null && callerName is not null && operatorSids.Contains(caller, StringComparer.Ordinal) && hasWindow;

        byte[] key = LedgerKeyFile.Read(Path.Combine(stateDirectory, "ledger.key"));
        string directory = Path.Combine(Path.GetTempPath(), "splat-ledger-audit-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(directory);
            string snapshot = Path.Combine(directory, "ledger.db");
            // SQLite's own backup from a read-only handle: the service may be writing, a file copy can
            // miss its write-ahead log, and nothing here may open the service's database for write.
            using (var source = Open(Path.Combine(stateDirectory, "ledger.db"), SqliteOpenMode.ReadOnly))
            using (var target = Open(snapshot, SqliteOpenMode.ReadWriteCreate))
            {
                source.Open();
                target.Open();
                source.BackupDatabase(target);
            }

            var state = await SqliteChainedAuditLedger.InspectAsync(snapshot, key, ct);
            checks["LedgerKeyedByTheServiceKey"] = state.Keyed && state.KeyMatches == true;
            var ledger = new SqliteChainedAuditLedger(new SqliteStorageContext(snapshot), key);
            checks["ChainVerifies"] = await ledger.VerifyLedgerIntegrityAsync(ct);

            var window = (await ledger.GetAuditLogsAsync(limit: 100_000, cancellationToken: ct))
                .Where(row => hasWindow && row.TimestampUtc >= started.UtcDateTime && row.TimestampUtc <= finished.UtcDateTime)
                .ToList();
            string expected = new OperatorIdentity(callerName ?? "", caller, OperatorAuthenticationMethod.WindowsAuthenticated,
                ManagedBridgeHost.Transport).ToLedgerIdentity();
            var claimed = new List<string>();
            int admissions = 0;
            if (probe.TryGetProperty("Admissions", out var list) && list.ValueKind == JsonValueKind.Array)
            {
                foreach (var admission in list.EnumerateArray())
                {
                    admissions++;
                    string? tool = Text(admission, "Tool");
                    string? digest = Text(admission, "RequestSha256");
                    if (Text(admission, "ClaimedPrincipal") is string principal) claimed.Add(principal);
                    // Exactly one: a request admitted twice, or never, is not this run's record of it.
                    var rows = window.Where(row => row.Action == ManagedBridgeHost.AdmissionAction && tool is not null
                        && digest is not null && row.Details == ManagedBridgeHost.AdmissionDetails(tool, digest)).ToList();
                    string label = admission.TryGetProperty("Id", out var id) ? id.ToString() : "?";
                    checks[$"Admitted:{label}:{tool}"] = rows.Count == 1 && rows[0].OperatorIdentity == expected;
                }
            }

            checks["ProbeListsItsAdmissions"] = admissions > 0;
            // The probe's run_command names another principal in its arguments; no row in its window may carry it.
            checks["ClaimedIdentityIgnored"] = claimed.Count > 0
                && window.All(row => claimed.All(principal => !row.OperatorIdentity.Contains($"[{principal}]", StringComparison.Ordinal)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            // The snapshot's pooled handles must close before its directory can go. Removal is best
            // effort: the copy sits in the elevated auditor's own temp directory, and a leftover file
            // must not turn a measured verdict into an exception.
            SqliteConnection.ClearAllPools();
            try { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }

        return new Report(DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture), serviceSid, caller, checks,
            checks.Values.All(passed => passed) ? "PASS" : "FAIL");
    }

    private static SqliteConnection Open(string path, SqliteOpenMode mode) =>
        new(new SqliteConnectionStringBuilder { DataSource = path, Mode = mode, Pooling = false }.ToString());

    private static string? Text(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
