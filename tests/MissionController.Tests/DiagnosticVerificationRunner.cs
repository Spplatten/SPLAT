using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Templates;
using MissionController.Infrastructure.Network.Http;
using MissionController.Infrastructure.Network.Identity;
using MissionController.Infrastructure.Network.Vertex;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.JobObjects;
using MissionController.Infrastructure.Windows.Process;
using MissionController.Infrastructure.Windows.Security;
using MissionController.Infrastructure.Windows.Vault;

namespace MissionController.Tests;

public static class DiagnosticVerificationRunner
{
    public static async Task<bool> RunVerificationAsync()
    {
        // 1. Initialize Infrastructure Components
        var restrictedTokenProvider = new RestrictedTokenProvider();
        var jailManager = new NtAclJailManager();
        var processLauncher = new SuspendedProcessLauncher(restrictedTokenProvider);
        var vault = new DpapiCredentialVault();
        var tokenLifecycleManager = new TokenLifecycleManager(vault);
        var (httpClient, firewall) = HardenedHttpClientFactory.CreateHardenedClient();
        var vertexClient = new VertexAiStreamClient(httpClient, firewall, vault, tokenLifecycleManager);
        var storageContext = new SqliteStorageContext();
        var auditLedger = new SqliteChainedAuditLedger(storageContext);
        var templateRegistry = new SqliteTemplateRegistry(storageContext);
        var credentialSanitizer = new MissionController.Infrastructure.Network.Identity.PromptCredentialSanitizer();
        var revocationManager = new MissionController.Infrastructure.Network.Identity.IncidentRevocationManager(auditLedger);

        Func<string, IJobSandbox> jobSandboxFactory = name => new Win32JobSandbox(name);

        var engine = new MissionExecutionEngine(
            jailManager,
            processLauncher,
            vertexClient,
            auditLedger,
            jobSandboxFactory,
            semanticMemoryIndex: null,
            dlpSanitizer: null,
            credentialSanitizer: credentialSanitizer,
            revocationManager: revocationManager);


        // 2. Perform Startup Orphan Sweep
        int swept = await jailManager.SweepOrphanJailsAsync();

        // 3. Load Templates
        var templates = await templateRegistry.GetAllTemplatesAsync();

        const string SmokeTestTemplateId = "net-dns-audit";
        var template = await templateRegistry.GetTemplateByIdAsync(SmokeTestTemplateId);
        if (template is not null)
        {
            var stdoutList = new List<string>();
            var aiList = new List<string>();

            await foreach (var chunk in engine.ExecuteMissionAsync(template, new Dictionary<string, string>(), "Operator_SecOpsTier1"))
            {
                if (chunk.ChunkType == MissionChunkType.Stdout)
                    stdoutList.Add(chunk.Content);
                else if (chunk.ChunkType == MissionChunkType.AiToken)
                    aiList.Add(chunk.Content);
            }

            // 4. Verify Chained Audit Ledger
            bool isValid = await auditLedger.VerifyLedgerIntegrityAsync();
            var logs = await auditLedger.GetAuditLogsAsync();

            return isValid && logs.Count > 0;
        }

        return false;
    }
}
