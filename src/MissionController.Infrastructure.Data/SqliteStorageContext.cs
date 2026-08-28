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
        InitializeDatabase();
    }

    public SqliteConnection CreateConnection()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();

        // Enable WAL mode and NORMAL synchronous for maximum concurrency and durability
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;";
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
                    EntryHash TEXT NOT NULL
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
        }
    }
}
