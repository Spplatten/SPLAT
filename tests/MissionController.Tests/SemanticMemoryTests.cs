using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Vector;
using Xunit;

namespace MissionController.Tests;

public class SemanticMemoryTests
{
    [Fact]
    public void GenerateEmbeddingVector_ReturnsNormalizedVector()
    {
        string text = "Failed logon EventID 4625 brute force credential stuffing attack";
        float[] vector = SqliteSemanticMemoryIndex.GenerateEmbeddingVector(text);

        Assert.Equal(128, vector.Length);

        // Verify unit length (L2 norm ~= 1)
        float sumSquares = 0f;
        for (int i = 0; i < vector.Length; i++)
        {
            sumSquares += vector[i] * vector[i];
        }
        Assert.InRange(sumSquares, 0.99f, 1.01f);
    }

    [Fact]
    public async Task SemanticMemoryIndex_IndexesAndRetrievesSimilarIncidents()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"semantic_test_{Guid.NewGuid():N}.db");
        try
        {
            var ctx = new SqliteStorageContext(dbPath);
            var index = new SqliteSemanticMemoryIndex(ctx);

            var mission1 = Guid.NewGuid();
            var mission2 = Guid.NewGuid();
            var mission3 = Guid.NewGuid();

            await index.IndexMissionDocumentAsync(
                mission1,
                "secops-logon-bruteforce",
                "Multiple Event 4625 failed logon attempts detected from source IP 192.168.1.100 targeting Administrator account.");

            await index.IndexMissionDocumentAsync(
                mission2,
                "net-dns-audit",
                "High latency packet loss detected on gateway ping 8.8.8.8 and unknown listening port 4444.");

            await index.IndexMissionDocumentAsync(
                mission3,
                "sysops-disk-space",
                "Drive C: has only 5% free space remaining. Temporary cache purge recommended.");

            // Query 1: Search for brute force authentication failures
            var results1 = await index.SearchSimilarMissionsAsync("failed logon attempts brute force", topK: 3);
            Assert.NotEmpty(results1);
            Assert.Equal(mission1, results1[0].MissionId);
            Assert.True(results1[0].SimilarityScore > 0.4);

            // Query 2: Search for network latency and packet loss
            var results2 = await index.SearchSimilarMissionsAsync("packet loss and network latency", topK: 3);
            Assert.NotEmpty(results2);
            Assert.Equal(mission2, results2[0].MissionId);
            Assert.True(results2[0].SimilarityScore > 0.4);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            GC.Collect();
            GC.WaitForPendingFinalizers();

            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }
}
