using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Data.Vector;

public sealed class SqliteSemanticMemoryIndex : ISemanticMemoryIndex
{
    private readonly SqliteStorageContext _context;
    private const int EmbeddingDimension = 128;

    public SqliteSemanticMemoryIndex(SqliteStorageContext context)
    {
        _context = context;
        InitializeVectorTable();
    }

    private void InitializeVectorTable()
    {
        using var conn = _context.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS MissionSemanticIndex (
                MissionId TEXT PRIMARY KEY,
                TemplateId TEXT NOT NULL,
                Content TEXT NOT NULL,
                VectorJson TEXT NOT NULL,
                TimestampUtc TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS IDX_Semantic_Template ON MissionSemanticIndex(TemplateId);
        ";
        cmd.ExecuteNonQuery();
    }

    public async Task IndexMissionDocumentAsync(
        Guid missionId,
        string templateId,
        string content,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(content))
            return;

        float[] embedding = GenerateEmbeddingVector(content);
        string vectorJson = JsonSerializer.Serialize(embedding);
        string timestampUtc = DateTime.UtcNow.ToString("O");

        await using var conn = _context.CreateConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO MissionSemanticIndex (MissionId, TemplateId, Content, VectorJson, TimestampUtc)
            VALUES ($mid, $tid, $cnt, $vec, $ts)
            ON CONFLICT(MissionId) DO UPDATE SET
                Content = excluded.Content,
                VectorJson = excluded.VectorJson,
                TimestampUtc = excluded.TimestampUtc;
        ";
        cmd.Parameters.AddWithValue("$mid", missionId.ToString("D"));
        cmd.Parameters.AddWithValue("$tid", templateId);
        cmd.Parameters.AddWithValue("$cnt", content);
        cmd.Parameters.AddWithValue("$vec", vectorJson);
        cmd.Parameters.AddWithValue("$ts", timestampUtc);

        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<SemanticSearchResult>> SearchSimilarMissionsAsync(
        string query,
        int topK = 5,
        double minScore = 0.1,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(query))
            return Array.Empty<SemanticSearchResult>();

        float[] queryEmbedding = GenerateEmbeddingVector(query);
        var scoredList = new List<SemanticSearchResult>();

        await using var conn = _context.CreateConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT MissionId, TemplateId, Content, VectorJson, TimestampUtc FROM MissionSemanticIndex ORDER BY TimestampUtc DESC LIMIT 500;";

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var missionId = Guid.Parse(reader.GetString(0));
            string templateId = reader.GetString(1);
            string content = reader.GetString(2);
            string vectorJson = reader.GetString(3);
            DateTime ts = DateTime.Parse(reader.GetString(4));

            float[] docEmbedding = JsonSerializer.Deserialize<float[]>(vectorJson) ?? Array.Empty<float>();
            double similarity = ComputeCosineSimilarity(queryEmbedding, docEmbedding);

            if (similarity >= minScore)
            {
                string snippet = content.Length > 240 ? content.Substring(0, 240) + "..." : content;
                scoredList.Add(new SemanticSearchResult(missionId, templateId, snippet, Math.Round(similarity, 4), ts));
            }
        }

        scoredList.Sort((a, b) => b.SimilarityScore.CompareTo(a.SimilarityScore));
        if (scoredList.Count > topK)
        {
            return scoredList.GetRange(0, topK);
        }

        return scoredList;
    }

    public static float[] GenerateEmbeddingVector(string text)
    {
        var vector = new float[EmbeddingDimension];
        if (string.IsNullOrWhiteSpace(text))
            return vector;

        // Tokenize into words and character trigrams
        var tokens = Regex.Matches(text.ToLowerInvariant(), @"[a-z0-9_\-\.]{2,}");
        foreach (Match match in tokens)
        {
            string token = match.Value;
            int hash = Math.Abs(GetStableHashCode(token)) % EmbeddingDimension;
            vector[hash] += 1.0f;

            // Character n-grams for typo-resilient semantic matching
            if (token.Length >= 3)
            {
                for (int i = 0; i <= token.Length - 3; i++)
                {
                    string tri = token.Substring(i, 3);
                    int triHash = Math.Abs(GetStableHashCode(tri)) % EmbeddingDimension;
                    vector[triHash] += 0.5f;
                }
            }
        }

        // Normalize vector to unit length (L2 norm)
        float sumSquares = 0f;
        for (int i = 0; i < EmbeddingDimension; i++)
        {
            sumSquares += vector[i] * vector[i];
        }

        if (sumSquares > 0)
        {
            float norm = MathF.Sqrt(sumSquares);
            for (int i = 0; i < EmbeddingDimension; i++)
            {
                vector[i] /= norm;
            }
        }

        return vector;
    }

    public static double ComputeCosineSimilarity(float[] a, float[] b)
    {
        if (a.Length != b.Length || a.Length == 0)
            return 0;

        double dotProduct = 0.0;
        double normA = 0.0;
        double normB = 0.0;

        for (int i = 0; i < a.Length; i++)
        {
            dotProduct += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }

        if (normA == 0 || normB == 0)
            return 0;

        return dotProduct / (Math.Sqrt(normA) * Math.Sqrt(normB));
    }

    private static int GetStableHashCode(string str)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(str));
        return BitConverter.ToInt32(hash, 0);
    }
}
