using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Brain;
using MissionController.Core.Crew;
using MissionController.Core.Interfaces;
using MissionController.Core.Replay;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Data.Compliance;
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
        if (await ManagedBridgeCommand.TryRunAsync(args) is int managedExit) return managedExit;
        // Decided before anything is built: a bad invocation must not create the ledger database,
        // seed the catalog or reach for the daemon. stdout is the JSON-RPC channel, so everything that
        // is not a protocol message - errors, and the startup note - goes to stderr.
        var command = McpServerCommand.WithRunRecordKeyFromEnvironment(
            McpServerCommand.WithLedgerKeyFromEnvironment(McpServerCommand.Parse(args), Environment.GetEnvironmentVariable),
            Environment.GetEnvironmentVariable);
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

        if (command is McpServerCommand.Provision provision)
        {
            return await SubstrateProvisioner.RunAsync(provision, Console.Out);
        }

        if (command is McpServerCommand.Unmount unmount)
        {
            return await SubstrateUnmounter.RunAsync(unmount, Console.Out);
        }

        if (command is McpServerCommand.NewRunRecordKey newKey)
        {
            return MakeRunRecordKey(newKey.Path, Console.Out, Console.Error);
        }

        if (command is McpServerCommand.Doctor doctor)
        {
            return await SubstrateDoctor.RunAsync(doctor, Console.Out);
        }

        if (command is McpServerCommand.Retain retain)
        {
            return await RetentionSweep.RunAsync(retain, Console.Out);
        }

        return await RunServerAsync((McpServerCommand.Serve)command);
    }

    internal static async Task<int> RunServerAsync(
        McpServerCommand.Serve serve, ManagedBridgeConfiguration? managed = null, CancellationToken ct = default)
    {
        var pipeIdentity = managed is null ? null : new ManagedPipeIdentity();
        string? workspaceRoot = serve.WorkspaceRoot;
        Console.Error.WriteLine(workspaceRoot is null
            ? $"splat-mcp: no --workspace given; fs_read and fs_write are confined to {McpServerHandler.DefaultWorkspaceRoot}"
            : $"splat-mcp: workspace {workspaceRoot}");
        Console.Error.WriteLine(serve.Egress.IsEmpty
            ? "splat-mcp: no --egress given; run_command and run_code get no network"
            : $"splat-mcp: run_command and run_code may connect only to {serve.Egress}");

        // 1. Data & Storage Layer
        //
        // Adoption runs before the first open. This host shares the console's DPAPI vault, so a copy
        // that started here before the console did would otherwise find an empty vault at the new root
        // while the operator's key sat under the old one, and report a missing key rather than a moved
        // one. Idempotent, so whichever host starts first does the move and the other sees nothing.
        foreach (string adopted in SplatDataRoot.AdoptLegacyHostLayout(SplatDataRoot.Current))
        {
            Console.Error.WriteLine($"splat-mcp: data {adopted}");
        }

        Console.Error.WriteLine($"splat-mcp: data root {SplatDataRoot.Current}");

        string dbPath = Environment.GetEnvironmentVariable("SPLAT_DB_PATH")
            ?? SplatDataRoot.Layout.LedgerDatabase;
        byte[]? ledgerKey;
        SqliteChainedAuditLedger.ChainState chain;
        try
        {
            ledgerKey = serve.LedgerKeyPath is null ? null : LedgerKeyFile.Read(serve.LedgerKeyPath);
            chain = await SqliteChainedAuditLedger.InspectAsync(dbPath, ledgerKey);
        }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine($"splat-mcp: {ex.Message}");
            return McpServerCommand.UsageExitCode;
        }

        // Refused here, not on the first tool call: a keyed ledger would turn every call away, and the
        // client's log should say why before the agent meets a single refusal.
        if (chain.Keyed && chain.KeyMatches != true)
        {
            Console.Error.WriteLine(ledgerKey is null
                ? $"splat-mcp: the audit ledger at {dbPath} is keyed; start the server with --ledger-key <file>."
                : $"splat-mcp: the audit ledger at {dbPath} was not keyed by {serve.LedgerKeyPath}.");
            return McpServerCommand.UsageExitCode;
        }

        Console.Error.WriteLine(ledgerKey is null
            ? "splat-mcp: no --ledger-key given; the audit ledger chains unkeyed"
            : $"splat-mcp: the audit ledger is keyed by {serve.LedgerKeyPath}");
        // The signing key for run record bundles, if the operator configured one. A bundle exported
        // without it says it is unsigned rather than implying otherwise.
        RsaRunRecordSigner? runRecordSigner = null;
        try
        {
            runRecordSigner = serve.RunRecordKeyPath is null ? null : RunRecordKeyFile.Load(serve.RunRecordKeyPath);
        }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine($"splat-mcp: {ex.Message}");
            return McpServerCommand.UsageExitCode;
        }

        Console.Error.WriteLine(runRecordSigner is null
            ? "splat-mcp: no --run-record-key given; exported run records are unsigned"
            : $"splat-mcp: run records are signed by {runRecordSigner.KeyId}");

        var storageContext = new SqliteStorageContext(dbPath);
        var auditLedger = new SqliteChainedAuditLedger(storageContext, ledgerKey);
        var merkleEngine = new MerkleTreeEngine();
        var runRecords = new MissionRunRecordAssembler(
            auditLedger, merkleEngine, new ComplianceArchiveExporter(merkleEngine, runRecordSigner));
        var revocationStore = new SqliteRevocationStore(storageContext);
        var revocationManager = new IncidentRevocationManager(auditLedger, revocationStore);
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

        // The same switch the console reads: a directory named in the environment gets every
        // mission's replay fixture, and the client's log says so before the first one is written.
        var recorder = MissionFixtureDirectoryRecorder.FromEnvironment("splat-mcp");
        if (recorder is not null)
        {
            Console.Error.WriteLine($"splat-mcp: every mission's replay fixture is written to {recorder.DirectoryPath}");
        }

        // 3.5 Linux / WSL2 Substrate, built before the engine because the engine runs missions on it:
        // a catalog template whose tool names the Linux lease is handed to the daemon whole, with its
        // lease compiled from the template by the compiler that used to be constructed and never called.
        var guest = managed is null ? null : new ManagedGuest(managed.Distribution);
        var guestToken = guest is null ? null : new WslAgentToken(guest.ReadTokenAsync);
        var leasedExecutor = guest is null ? new WslLeasedExecutor()
            : new WslLeasedExecutor("127.0.0.1", managed!.Port, guestToken!, guest.StartDaemonAsync, guest.HoldAwake);
        var policyCompiler = new TemplatePolicyCompiler();
        var healthChecker = managed is null ? new WslSubstrateHealthChecker()
            : new WslSubstrateHealthChecker("127.0.0.1", managed.Port, guestToken);
        var leaseSubstrate = new LinuxLeaseSubstrate(leasedExecutor, policyCompiler);

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
            revocationManager,
            findingsExtractor,
            // Two different records of one mission: the recorder writes a replay fixture, and the
            // history store writes the Missions row the retention sweep erases.
            recorder: recorder,
            missionHistory: new SqliteMissionHistoryStore(storageContext),
            substrates: leaseSubstrate);

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

        // 5. MCP Protocol Handler
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
            identityProvider: (IOperatorIdentityProvider?)pipeIdentity ?? new McpOperatorIdentityProvider(
                new WindowsOperatorIdentityProvider(),
                new JwtTokenValidator(),
                new ApiKeyValidator()),
            workspaceRoot: workspaceRoot,
            egressPolicy: serve.Egress,
            runRecords: runRecords,
            revocationManager: revocationManager,
            // The host's own key, so verify_run_record can say a bundle was signed by THIS host and
            // not merely by a holder of the key the bundle carries with it.
            recordVerifier: new RunRecordLedgerVerifier(auditLedger, merkleEngine, runRecordSigner),
            credentialSanitizer: credSanitizer,
            dlpSanitizer: dlpSanitizer);

        using (runRecordSigner)
        {
            if (managed is not null)
            {
                await ManagedBridgeHost.RunAsync(managed, handler, auditLedger, pipeIdentity!, ct);
                return 0;
            }
            return await ServeAsync(handler);
        }
    }

    /// <summary>
    /// Writes a new signing key where only this account can read it, and prints its fingerprint. The
    /// key itself is never printed, and an existing file is never overwritten: a key nobody meant to
    /// replace would silently orphan every bundle already signed with it.
    /// </summary>
    private static int MakeRunRecordKey(string path, TextWriter output, TextWriter error)
    {
        if (File.Exists(path) || Directory.Exists(path))
        {
            error.WriteLine($"splat-mcp: '{path}' already exists; it will not be overwritten.");
            return McpServerCommand.UsageExitCode;
        }

        string pem = RunRecordKeyFile.NewKeyPem(out string keyId);
        try
        {
            var onlyThisAccount = new FileSecurity();
            var self = WindowsIdentity.GetCurrent().User
                ?? throw new InvalidOperationException("this process's token names no user to grant the key to.");
            onlyThisAccount.SetOwner(self);
            onlyThisAccount.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            onlyThisAccount.AddAccessRule(new FileSystemAccessRule(self, FileSystemRights.FullControl, AccessControlType.Allow));

            // Created WITH that security descriptor: a file made first and secured after is readable
            // for as long as the two calls are apart.
            using var stream = new FileInfo(path).Create(
                FileMode.CreateNew, FileSystemRights.WriteData, FileShare.None, 4096, FileOptions.None, onlyThisAccount);
            using var writer = new StreamWriter(stream, new UTF8Encoding(false));
            writer.Write(pem);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            error.WriteLine($"splat-mcp: could not write the key file '{path}': {ex.Message}");
            return McpServerCommand.UsageExitCode;
        }

        output.WriteLine($"Wrote a {RunRecordKeyFile.CreatedKeyBits}-bit run record signing key to {path}");
        output.WriteLine($"Its fingerprint is {keyId}");
        output.WriteLine("Publish that fingerprint. Anyone you hand a bundle to compares it with the one in the bundle,");
        output.WriteLine("which is how they tell your bundles from a forgery. Keep the file where only you can read it,");
        output.WriteLine($"and point the host at it with --run-record-key or {RunRecordKeyFile.EnvironmentVariable}.");
        return 0;
    }

    private static async Task<int> ServeAsync(McpServerHandler handler)
    {
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
    /// The largest request this server will hold in memory, in characters, not counting the newline.
    ///
    /// <c>ReadLineAsync</c> grows its buffer until it meets one, so a client that never sent a
    /// newline could make this process allocate without bound - the same defect the guest daemon
    /// carried on its socket. 1 MiB is far above any real call, including a <c>run_code</c> script.
    /// </summary>
    public const int MaxFrameChars = 1024 * 1024;

    /// <summary>
    /// Reads one line, refusing one that would grow past <see cref="MaxFrameChars"/>.
    /// </summary>
    /// <returns>
    /// The line, or null at end of input; <c>Oversized</c> is true when a frame was refused, in
    /// which case the rest of it has been discarded - read past, never buffered - so the reader is
    /// positioned at the start of the next one.
    /// </returns>
    internal static async Task<(string? Line, bool Oversized)> ReadBoundedLineAsync(TextReader reader, CancellationToken ct)
    {
        var frame = new StringBuilder();
        var one = new char[1];

        while (await reader.ReadAsync(one, ct) == 1)
        {
            if (one[0] == '\n')
            {
                return (frame.ToString().TrimEnd('\r'), false);
            }

            if (frame.Length >= MaxFrameChars)
            {
                while (await reader.ReadAsync(one, ct) == 1 && one[0] != '\n')
                {
                }

                return (null, true);
            }

            frame.Append(one[0]);
        }

        // End of input. A trailing frame without its newline is still a frame the client sent.
        return (frame.Length > 0 ? frame.ToString().TrimEnd('\r') : null, false);
    }

    /// <summary>
    /// The JSON-RPC loop: one message per line in, one response per line out, until end of input or
    /// cancellation. It takes its streams so the bytes a client actually receives can be asserted,
    /// rather than inferred from what the handler returned.
    /// </summary>
    public static async Task ServeAsync(TextReader reader, Stream output, McpServerHandler handler, CancellationToken ct,
        Func<McpJsonRpcMessage, CancellationToken, Task<McpJsonRpcMessage>>? dispatch = null)
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
            var (line, oversized) = await ReadBoundedLineAsync(reader, ct);
            if (oversized)
            {
                // The frame is gone, but the session is not: a stdio client has no second connection
                // to fall back on, so this resynchronises on the next newline and keeps serving.
                await writer.WriteLineAsync(JsonSerializer.Serialize(new McpJsonRpcMessage
                {
                    JsonRpc = "2.0",
                    Error = new McpError
                    {
                        Code = -32700,
                        Message = $"Parse error: a request may not exceed {MaxFrameChars} characters."
                    }
                }));
                continue;
            }

            if (line == null) break;
            if (string.IsNullOrWhiteSpace(line)) continue;

            try
            {
                var message = JsonSerializer.Deserialize<McpJsonRpcMessage>(line);
                if (message != null)
                {
                    var response = await (dispatch is null ? handler.ProcessMessageAsync(message, ct) : dispatch(message, ct));
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
