using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Brain;
using MissionController.Core.Crew;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Data.Templates;
using MissionController.Infrastructure.Data.Vector;
using MissionController.Infrastructure.Linux;
using MissionController.Infrastructure.Network.Ai;
using MissionController.Infrastructure.Network.Dlp;
using MissionController.Infrastructure.Network.Http;
using MissionController.Infrastructure.Network.Identity;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.JobObjects;
using MissionController.Infrastructure.Windows.Process;
using MissionController.Infrastructure.Windows.Security;
using MissionController.Infrastructure.Windows.Vault;

namespace SplatMcp;

public static class Program
{
    public static async Task Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;

        // 1. Data & Storage Layer
        string dbPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SPLAT", "audit_ledger.db");
        var storageContext = new SqliteStorageContext(dbPath);
        var auditLedger = new SqliteChainedAuditLedger(storageContext);
        var templateRegistry = new SqliteTemplateRegistry(storageContext);
        var semanticMemory = new SqliteSemanticMemoryIndex(storageContext);

        // Seed template catalog into SQLite registry
        foreach (var template in GovernedTemplateCatalog.All)
        {
            await templateRegistry.RegisterTemplateAsync(template);
        }

        // 2. Sandboxing & Security Layer
        var tokenProvider = new RestrictedTokenProvider();
        var jailManager = new NtAclJailManager();
        var processLauncher = new SuspendedProcessLauncher(tokenProvider);
        var dlpSanitizer = new RegexDataLossPreventionSanitizer();
        var credSanitizer = new PromptCredentialSanitizer();
        var findingsExtractor = new JsonFindingsExtractor();
        var vault = new DpapiCredentialVault();

        // 3. AI Gateway & Model Client Layer
        var (httpClient, firewallHandler) = HardenedHttpClientFactory.CreateHardenedClient();
        var claudeClient = new ClaudeStreamClient(httpClient, firewallHandler, vault);
        var geminiClient = new GeminiStreamClient(httpClient, firewallHandler, vault);
        var modelRouter = new ModelClientRouter(claudeClient, geminiClient);

        // 4. Core Cognitive Engine
        var missionEngine = new MissionExecutionEngine(
            jailManager,
            processLauncher,
            modelRouter,
            auditLedger,
            name => new Win32JobSandbox(name),
            semanticMemory,
            dlpSanitizer,
            credSanitizer,
            null,
            findingsExtractor);

        var investigationLoop = new GovernedInvestigationLoop(
            missionEngine,
            templateRegistry,
            modelRouter,
            auditLedger,
            findingsExtractor);

        var agentBrain = new AgentBrainEngine(
            missionEngine,
            templateRegistry,
            auditLedger,
            new CognitiveGoalDecomposer(modelRouter, semanticMemory),
            semanticMemory,
            findingsExtractor,
            modelRouter);

        var crewEngine = new GovernedCrewEngine(
            missionEngine,
            templateRegistry,
            auditLedger,
            dlpSanitizer,
            semanticMemory,
            findingsExtractor,
            modelRouter);

        // 5. Linux / WSL2 Substrate
        var leasedExecutor = new WslLeasedExecutor();
        var policyCompiler = new TemplatePolicyCompiler();
        var healthChecker = new WslSubstrateHealthChecker();

        // 6. MCP Protocol Handler
        var handler = new McpServerHandler(
            leasedExecutor,
            policyCompiler,
            auditLedger,
            healthChecker,
            missionEngine,
            investigationLoop,
            templateRegistry,
            semanticMemory,
            modelRouter,
            agentBrain,
            crewEngine,
            // Ledger attribution. The Windows logon session this server runs under is the real
            // principal for a stdio transport; a configured SPLAT_MCP_CLIENT_CREDENTIAL overrides it
            // with a validated one and a bad credential refuses the call outright.
            identityProvider: new McpOperatorIdentityProvider(
                new WindowsOperatorIdentityProvider(),
                new JwtTokenValidator(),
                new ApiKeyValidator()));

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (s, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        using var reader = new StreamReader(Console.OpenStandardInput(), Encoding.UTF8);
        using var writer = new StreamWriter(Console.OpenStandardOutput(), Encoding.UTF8) { AutoFlush = true };

        while (!cts.Token.IsCancellationRequested)
        {
            string? line = await reader.ReadLineAsync(cts.Token);
            if (line == null) break;
            if (string.IsNullOrWhiteSpace(line)) continue;

            try
            {
                var message = JsonSerializer.Deserialize<McpJsonRpcMessage>(line);
                if (message != null)
                {
                    var response = await handler.ProcessMessageAsync(message, cts.Token);
                    string jsonResponse = JsonSerializer.Serialize(response);
                    await writer.WriteLineAsync(jsonResponse);
                }
            }
            catch (Exception ex)
            {
                var errResponse = new McpJsonRpcMessage
                {
                    JsonRpc = "2.0",
                    Error = new McpError
                    {
                        Code = -32700,
                        Message = $"Parse error: {ex.Message}"
                    }
                };
                await writer.WriteLineAsync(JsonSerializer.Serialize(errResponse));
            }
        }
    }
}
