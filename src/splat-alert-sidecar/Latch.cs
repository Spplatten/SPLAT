using Microsoft.Data.Sqlite;

namespace Splat.AlertSidecar;

// The control action is monotone: many alerts can only request the SAME cancellation.
// A one-slot durable mailbox therefore suffices. There is no per-alert queue to overflow and
// no state in which dropping a redundant signal restores authority. This is not an audit log
// of every alert: the sensor/collector owns that history. No network call holds a DB lock.
internal sealed class Latch
{
    private readonly string _connection;
    private readonly string _fingerprint;
    internal Latch(string path, string fingerprint)
    {
        _fingerprint = fingerprint;
        _connection = new SqliteConnectionStringBuilder { DataSource = path, Pooling = false,
            DefaultTimeout = 1 }.ToString();
        using var db = Open();
        using var tx = db.BeginTransaction();
        using var cmd = db.CreateCommand(); cmd.Transaction = tx;
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS latch(slot INTEGER PRIMARY KEY CHECK(slot=1), binding TEXT NOT NULL,
              state TEXT NOT NULL, alert TEXT, observed INTEGER, received INTEGER, reported INTEGER NOT NULL DEFAULT 0);
            INSERT OR IGNORE INTO latch(slot,binding,state) VALUES(1,$binding,'idle');
            SELECT binding FROM latch WHERE slot=1;
            """;
        cmd.Parameters.AddWithValue("$binding", fingerprint);
        if ((string?)cmd.ExecuteScalar() != fingerprint) throw new InvalidDataException("Mailbox belongs to another binding.");
        tx.Commit();
    }
    private SqliteConnection Open()
    {
        var db = new SqliteConnection(_connection);
        try { db.Open(); using var c = db.CreateCommand(); c.CommandText = "PRAGMA synchronous=FULL"; c.ExecuteNonQuery(); return db; }
        catch { db.Dispose(); throw; }
    }
    internal bool Admit(string id, long observed, long received)
    {
        using var db = Open(); using var c = db.CreateCommand();
        // SQLite's autocommit completes before the client can receive HTTP 202. A process death
        // after commit but before the response is safe to retry; the first event is retained.
        c.CommandText = "UPDATE latch SET state='pending',alert=$id,observed=$o,received=$r WHERE slot=1 AND binding=$binding AND state='idle'";
        c.Parameters.AddWithValue("$id", id); c.Parameters.AddWithValue("$o", observed); c.Parameters.AddWithValue("$r", received);
        c.Parameters.AddWithValue("$binding", _fingerprint);
        if (c.ExecuteNonQuery() == 1) return true;
        // Zero updated rows means duplicate only if the durable, correctly bound row still exists.
        // A missing/corrupt row must not be acknowledged as an already-persisted cancellation.
        if (Read().State == "idle") throw new IOException("Mailbox admission was not persisted.");
        return false;
    }
    internal (string State, string? Alert, long Received, bool Reported) Read()
    {
        using var db = Open(); using var c = db.CreateCommand();
        c.CommandText = "SELECT state,alert,coalesce(received,0),reported,binding FROM latch WHERE slot=1";
        using var r = c.ExecuteReader();
        if (!r.Read() || r.GetString(4) != _fingerprint
            || r.GetString(0) is not ("idle" or "pending" or "cancel-request-recorded" or "host-reports-drain" or "terminal-without-drain-proof" or "expired-unresolved"))
            throw new IOException("Missing or invalid durable mailbox.");
        return (r.GetString(0), r.IsDBNull(1) ? null : r.GetString(1), r.GetInt64(2), r.GetInt32(3) != 0);
    }
    internal void Finish(string state)
    {
        if (state is not ("cancel-request-recorded" or "host-reports-drain" or "terminal-without-drain-proof" or "expired-unresolved"))
            throw new ArgumentException("Unknown control outcome");
        using var db = Open(); using var c = db.CreateCommand();
        c.CommandText = "UPDATE latch SET state=$s WHERE slot=1 AND state='pending'";
        c.Parameters.AddWithValue("$s", state); c.ExecuteNonQuery();
    }
    internal void MarkReported()
    {
        using var db = Open(); using var c = db.CreateCommand();
        c.CommandText = "UPDATE latch SET reported=1 WHERE slot=1 AND state NOT IN ('idle','pending')"; c.ExecuteNonQuery();
    }
}
