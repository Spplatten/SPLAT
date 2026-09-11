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
    public static async Task<int> Main(string[] args)
    {
        // Decided before anything is built: a bad invocation must not create the ledger database,
        // seed the catalog or reach for the daemon. stdout is the JSON-RPC channel, so everything that
        // is not a protocol message - errors, and the startup note - goes to stderr.
        var command = McpServerCommand.Parse(args);
        if (command is McpServerCommand.ShowHelp)
        {
            Console.Out.Write(McpServerCommand.Usage);
            return 0;
        }

        if (command is McpServerCommand.UsageError error)
        {
            Console.Error.WriteLine($"splat-mcp: {error.Message}");
            Console.Error.WriteLine("Run 'splat-mcp --help' for usage.");
            return McpServerCommand.UsageExitCode;
        }

        // Configured only for serving. The help and usage paths need nothing from the console's code
        // page, and leaving it alone keeps them safe to call from a host - a test runner - that may
        // have no console to configure.
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;

        var serve = (McpServerCommand.Serve)command;
        string? workspaceRoot = serve.WorkspaceRoot;
        Console.Error.WriteLine(workspaceRoot is null
            ? $"splat-mcp: no --workspace given; fs_read and fs_write are confined to {McpServerHandler.DefaultWorkspaceRoot}"
            : $"splat-mcp: workspace {workspaceRoot}");
        Console.Error.WriteLine(serve.Egress.IsEmpty
            ? "splat-mcp: no --egress given; run_command and run_code get no network"
            : $"splat-mcp: run_command and run_code may connect only to {serve.Egress}");

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
                new ApiKeyValidator()),
            workspaceRoot: workspaceRoot,
            egressPolicy: serve.Egress);

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (s, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        using var reader = new StreamReader(Console.OpenStandardInput(), Encoding.UTF8);
        await ServeAsync(reader, Console.OpenStandardOutput(), handler, cts.Token);
        return 0;
    }

    /// <summary>
    /// The JSON-RPC loop: one message per line in, one response per line out, until end of input or
    /// cancellation. It takes its streams so the bytes a client actually receives can be asserted,
    /// rather than inferred from what the handler returned.
    /// </summary>
    public static async Task ServeAsync(TextReader reader, Stream output, McpServerHandler handler, CancellationToken ct)
    {
        // UTF-8 WITHOUT a byte order mark. With Encoding.UTF8, StreamWriter writes EF BB BF at its first
        // flush, so every client's first response - the answer to `initialize` - began with three bytes
        // a strict JSON parser rejects before it reaches the opening brace. WslLeasedExecutor fixed the
        // same defect on the daemon socket; stdout had it too, found 2026-09-11 by reading the bytes.
        using var writer = new StreamWriter(output, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), leaveOpen: true)
        {
            AutoFlush = true
        };

        while (!ct.IsCancellationRequested)
        {
            string? line = await reader.ReadLineAsync(ct);
            if (line == null) break;
            if (string.IsNullOrWhiteSpace(line)) continue;

            try
            {
                var message = JsonSerializer.Deserialize<McpJsonRpcMessage>(line);
                if (message != null)
                {
                    var response = await handler.ProcessMessageAsync(message, ct);
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
