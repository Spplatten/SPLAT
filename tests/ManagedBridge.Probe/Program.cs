using System.Text.Json;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;

// Run elevated after the standard-account probe. Reuse the actual ledger verifier rather than
// trusting a caller-produced claim of attribution or reproducing the chain algorithm in a script.
if (args.Length != 1 || !File.Exists(Path.Combine(args[0], "ledger.db")) || !File.Exists(Path.Combine(args[0], "ledger.key"))) return 2;
var ledger = new SqliteChainedAuditLedger(new SqliteStorageContext(Path.Combine(args[0], "ledger.db")),
    File.ReadAllBytes(Path.Combine(args[0], "ledger.key")));
bool valid = await ledger.VerifyLedgerIntegrityAsync();
var rows = await ledger.GetAuditLogsAsync(limit: 1000);
Console.WriteLine(JsonSerializer.Serialize(new { Verified = valid, Rows = rows }));
return valid && rows.Count > 0 ? 0 : 1;
