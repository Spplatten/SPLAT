using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace MissionController.Infrastructure.Data;

public sealed class SqliteStorageContext
{
    private readonly string _connectionString;
    private static readonly object Lock = new();

    public SqliteStorageContext(string? dbPath = null)
    {
        string path = dbPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "MissionController",
            "Data",
            "missioncontroller.db");

        string? dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        };

        _connectionString = builder.ToString();
        DatabasePath = path;
        InitializeDatabase();
    }

    /// <summary>
    /// On-disk location of the database. Exposed so the retention sweep can checkpoint the WAL and
    /// VACUUM the file - purged bytes survive in the -wal sidecar and in free pages until both happen.
    /// </summary>
    public string DatabasePath { get; }

    public SqliteConnection CreateConnection()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();

        // Enable WAL mode and NORMAL synchronous for maximum concurrency and durability.
        //
        // secure_delete is a RETENTION prerequisite, not a performance setting: without it SQLite
        // leaves deleted row bytes intact in free pages, so purged mission telemetry (event log
        // dumps, local account enumerations, registry reads) stays recoverable from the .db file
        // with a hex editor long after the retention job claims to have erased it. It is set per
        // connection because a pragma applied only at init would not cover the pooled connections
        // the retention sweep actually deletes through.
        using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;";
        cmd.ExecuteNonQuery();

        return conn;
    }

    private void InitializeDatabase()
    {
        lock (Lock)
        {
            using var conn = CreateConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS AuditLedger (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    TimestampUtc TEXT NOT NULL,
                    MissionId TEXT NOT NULL,
                    TemplateId TEXT NOT NULL,
                    Action TEXT NOT NULL,
                    Details TEXT NOT NULL,
                    OperatorIdentity TEXT NOT NULL,
                    PreviousHash TEXT NOT NULL,
                    EntryHash TEXT NOT NULL,
                    DetailsSalt TEXT,
                    DetailsCommitment TEXT,
                    HashVersion INTEGER NOT NULL DEFAULT 1,
                    RedactedAtUtc TEXT
                );

                CREATE TABLE IF NOT EXISTS Templates (
                    TemplateId TEXT PRIMARY KEY,
                    Name TEXT NOT NULL,
                    Category TEXT NOT NULL,
                    TemplateJson TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS Missions (
                    MissionId TEXT PRIMARY KEY,
                    TemplateId TEXT NOT NULL,
                    Status TEXT NOT NULL,
                    CreatedAtUtc TEXT NOT NULL,
                    StartedAtUtc TEXT,
                    CompletedAtUtc TEXT,
                    JailDirectory TEXT NOT NULL,
                    JobId TEXT,
                    InitiatedBy TEXT NOT NULL,
                    InputParametersJson TEXT NOT NULL,
                    RawOutput TEXT NOT NULL,
                    AiAnalysis TEXT NOT NULL,
                    ExitCode INTEGER,
                    ErrorMessage TEXT
                );

                CREATE TABLE IF NOT EXISTS ProjectTemplates (
                    ProjectId TEXT PRIMARY KEY,
                    Name TEXT NOT NULL,
                    Category TEXT NOT NULL,
                    ProjectJson TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS GovernedCrews (
                    CrewId TEXT PRIMARY KEY,
                    Name TEXT NOT NULL,
                    ProcessType TEXT NOT NULL,
                    CrewJson TEXT NOT NULL DEFAULT '{}'
                );
            ";
            cmd.ExecuteNonQuery();

            // Migration check: ensure TemplateJson column exists
            try
            {
                using var alterCmd = conn.CreateCommand();
                alterCmd.CommandText = "ALTER TABLE Templates ADD COLUMN TemplateJson TEXT NOT NULL DEFAULT '{}';";
                alterCmd.ExecuteNonQuery();
            }
            catch
            {
                // Column already exists
            }

            // Migration: redaction columns on the audit ledger. Existing rows stay HashVersion 1
            // (their EntryHash covers plaintext Details, so erasing Details would break the chain);
            // new rows are written as version 2 and are redactable. See SqliteChainedAuditLedger.
            foreach (var columnDdl in new[]
            {
                "ALTER TABLE AuditLedger ADD COLUMN DetailsSalt TEXT;",
                "ALTER TABLE AuditLedger ADD COLUMN DetailsCommitment TEXT;",
                "ALTER TABLE AuditLedger ADD COLUMN HashVersion INTEGER NOT NULL DEFAULT 1;",
                "ALTER TABLE AuditLedger ADD COLUMN RedactedAtUtc TEXT;"
            })
            {
                try
                {
                    using var alterCmd = conn.CreateCommand();
                    alterCmd.CommandText = columnDdl;
                    alterCmd.ExecuteNonQuery();
                }
                catch
                {
                    // Column already exists
                }
            }
        }
    }
}
