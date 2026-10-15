using System.Diagnostics;
using System.ServiceProcess;
using System.Text;
using MissionController.Core;
using MissionController.Host;

namespace SplatMcp;

internal static class ManagedBridgeCommand
{
    internal static async Task<int?> TryRunAsync(string[] args)
    {
        bool host = args.FirstOrDefault() == "bridge-service";
        bool bootstrap = args.FirstOrDefault() == "bridge-bootstrap";
        bool client = args.FirstOrDefault() == "managed";
        bool deployment = args.FirstOrDefault() is "provision" or "unmount" && args.Contains("--managed", StringComparer.Ordinal);
        bool audit = args.FirstOrDefault() == "audit" && args.Contains("--managed", StringComparer.Ordinal);
        if (!host && !bootstrap && !client && !deployment && !audit) return null;
        try
        {
            if (deployment) return await DeployAsync(args);
            if (audit) return await AuditAsync(args);
            if (args.Length != 3 || args[1] != "--configuration")
                throw new ArgumentException("Use managed --configuration <file> or bridge-service --configuration <file>.");
            var config = ManagedBridgeConfiguration.Load(args[2], serving: host || bootstrap);
            if (client)
            {
                using var input = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false, true));
                return await ManagedBridgeHost.ProxyAsync(config, input, Console.OpenStandardOutput(), CancellationToken.None);
            }
            // Configuration and policies come from administrator-owned storage, never client argv or
            // the operator's environment. All data and signing material belong to this service account.
            Environment.SetEnvironmentVariable(SplatDataRoot.EnvironmentVariable, config.StateDirectory);
            Environment.SetEnvironmentVariable("SPLAT_DB_PATH", Path.Combine(config.StateDirectory, "ledger.db"));
            Environment.SetEnvironmentVariable("SPLAT_AGENT_TOKEN", null);
            Environment.SetEnvironmentVariable("SPLAT_MCP_CLIENT_CREDENTIAL", null);
            Environment.SetEnvironmentVariable("SPLAT_REPLAY_DIR", null);
            if (bootstrap)
            {
                var guest = new ManagedGuest(config.Distribution);
                var token = new MissionController.Infrastructure.Linux.WslAgentToken(guest.ReadTokenAsync);
                return await SubstrateProvisioner.RunAsync(new ProvisionOptions(true,
                        string.IsNullOrEmpty(config.Egress) ? McpEgressPolicy.None : McpEgressPolicy.Parse(config.Egress)), Console.Out,
                    wsl: (arguments, ct) => SubstrateDoctor.RunWslAsync(new[] { "-d", config.Distribution }.Concat(arguments).ToArray(), ct),
                    health: new MissionController.Infrastructure.Linux.WslSubstrateHealthChecker("127.0.0.1", config.Port, token),
                    daemonPort: config.Port);
            }
            ServiceBase.Run(new BridgeService(config));
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("splat-mcp managed: " + ex.Message);
            return 2;
        }
    }

    internal sealed record DeploymentRequest(string Mode, string Instance, IReadOnlyDictionary<string, string> Options, bool Apply);

    // provision --managed installs, provision --managed --upgrade replaces a running instance's build
    // in place, and unmount --managed removes it. Parsed apart from running, so the combinations that
    // must be refused are testable without an elevated terminal.
    internal static DeploymentRequest ParseDeployment(string[] args)
    {
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        bool apply = false, upgrade = false;
        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--managed") continue;
            if (args[i] == "--apply") { if (apply) throw new ArgumentException("Duplicate --apply."); apply = true; continue; }
            if (args[i] == "--upgrade") { if (upgrade) throw new ArgumentException("Duplicate --upgrade."); upgrade = true; continue; }
            string option = args[i];
            if (option is not ("--rootfs" or "--rootfs-sha256" or "--operator-sid" or "--instance" or "--egress") || ++i == args.Length
                || args[i].StartsWith('-') || !options.TryAdd(option, args[i]))
                throw new ArgumentException("Managed deployment accepts --rootfs, --rootfs-sha256, --operator-sid, --instance, --egress, --upgrade and --apply.");
        }
        bool remove = args[0] == "unmount";
        if (remove && upgrade) throw new ArgumentException("--upgrade belongs to provision --managed, not unmount.");
        string instance = options.GetValueOrDefault("--instance", "SplatManaged");
        if (!System.Text.RegularExpressions.Regex.IsMatch(instance, @"\ASplat[A-Za-z0-9]{0,14}\z"))
            throw new ArgumentException("Managed instance names start with Splat and contain at most 19 letters/digits.");
        if ((remove || upgrade) && options.Keys.Any(key => key != "--instance"))
            throw new ArgumentException($"Managed {(remove ? "unmount" : "upgrade")} accepts only --instance and --apply.");
        if (!remove && !upgrade && (!options.ContainsKey("--rootfs") || !options.ContainsKey("--operator-sid")
            || !options.TryGetValue("--rootfs-sha256", out var rootfsHash)
            || !System.Text.RegularExpressions.Regex.IsMatch(rootfsHash, @"\A[0-9a-fA-F]{64}\z")))
            throw new ArgumentException("Managed provision requires --rootfs <clean archive>, --rootfs-sha256 <publisher hash> and --operator-sid <Windows SID>.");
        return new DeploymentRequest(remove ? "Remove" : upgrade ? "Upgrade" : "Install", instance, options, apply);
    }

    private static async Task<int> DeployAsync(string[] args)
    {
        var request = ParseDeployment(args);
        string? executable = Environment.ProcessPath;
        if (executable is null || !Path.GetFileName(executable).Equals("splat-mcp.exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Use the published self-contained splat-mcp.exe for managed deployment.");
        if (!request.Apply)
        {
            Console.WriteLine(request.Mode switch
            {
                "Remove" => $"Remove managed instance {request.Instance}: its service, account and WSL distro. The private ledger is kept and moved aside, administrators only.",
                "Upgrade" => $"Upgrade managed instance {request.Instance} to this build: stop its service, replace the executable, re-run the guest bootstrap as its account and restart, restoring the previous build if it does not stay running.",
                _ => $"Install managed instance {request.Instance}: dedicated non-admin account, WSL distro, Windows bridge service and private ledger.",
            } + " Use --apply from an elevated Windows terminal.");
            return 0;
        }
        using var script = typeof(Program).Assembly.GetManifestResourceStream("managed-deployment.ps1")
            ?? throw new InvalidOperationException("Managed deployment resource is missing.");
        string temporary = Path.Combine(Path.GetTempPath(), "splat-managed-" + Guid.NewGuid().ToString("N") + ".ps1");
        try
        {
            // Created by the elevated installer in its private temp directory, removed after use.
            await using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                await script.CopyToAsync(file);
            var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"))
                { UseShellExecute = false, CreateNoWindow = true };
            foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", temporary,
                "-Mode", request.Mode, "-Instance", request.Instance, "-Executable", executable }) start.ArgumentList.Add(arg);
            foreach (var pair in new[] { ("--rootfs", "-Rootfs"), ("--rootfs-sha256", "-RootfsSha256"), ("--operator-sid", "-OperatorSid"), ("--egress", "-Egress") })
                if (request.Options.TryGetValue(pair.Item1, out string? value)) { start.ArgumentList.Add(pair.Item2); start.ArgumentList.Add(value); }
            using var process = Process.Start(start) ?? throw new IOException("Managed installer did not start.");
            await process.WaitForExitAsync();
            return process.ExitCode;
        }
        finally { File.Delete(temporary); }
    }

    // Run elevated after probe-managed-bridge.ps1's owner run: the service's state admits only the
    // service account and administrators, which is the point of the deployment.
    private static Task<int> AuditAsync(string[] args)
    {
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--managed") continue;
            string option = args[i];
            if (option is not ("--configuration" or "--probe" or "--output") || ++i == args.Length
                || args[i].StartsWith('-') || !options.TryAdd(option, args[i]))
                throw new ArgumentException("Managed audit accepts --configuration, --probe and --output.");
        }
        if (options.Count != 3)
            throw new ArgumentException("Managed audit requires --configuration <bridge.json>, --probe <owner evidence> and --output <file>.");
        return ManagedLedgerAudit.RunAsync(options["--configuration"], options["--probe"], options["--output"], CancellationToken.None);
    }

    private sealed class BridgeService : ServiceBase
    {
        private readonly ManagedBridgeConfiguration _config;
        private readonly CancellationTokenSource _stop = new();
        private Task? _run;
        internal BridgeService(ManagedBridgeConfiguration config) { _config = config; ServiceName = config.ServiceName; AutoLog = false; }
        protected override void OnStart(string[] args)
        {
            var serve = new McpServerCommand.Serve(_config.WorkspaceDirectory,
                string.IsNullOrEmpty(_config.Egress) ? McpEgressPolicy.None : McpEgressPolicy.Parse(_config.Egress),
                Path.Combine(_config.StateDirectory, "ledger.key"),
                AgentId: _config.AgentId, AgentVersion: _config.AgentVersion);
            _run = Task.Run(async () =>
            {
                try
                {
                    int exit = await Program.RunServerAsync(serve, _config, _stop.Token);
                    if (exit != 0) throw new InvalidOperationException($"Managed host refused startup (exit {exit}).");
                }
                catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
                catch (Exception ex)
                {
                    File.AppendAllText(Path.Combine(_config.StateDirectory, "service-error.log"), $"{DateTimeOffset.UtcNow:o} {ex}\n");
                    ExitCode = 1064;
                    _ = Task.Run(Stop);
                }
            });
        }
        protected override void OnStop()
        {
            _stop.Cancel();
            _run?.Wait(TimeSpan.FromSeconds(20));
        }
        protected override void Dispose(bool disposing) { if (disposing) _stop.Dispose(); base.Dispose(disposing); }
    }
}
