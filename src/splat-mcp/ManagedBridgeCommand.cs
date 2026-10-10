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
        if (!host && !bootstrap && !client && !deployment) return null;
        try
        {
            if (deployment) return await DeployAsync(args);
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

    private static async Task<int> DeployAsync(string[] args)
    {
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        bool apply = false;
        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--managed") continue;
            if (args[i] == "--apply") { if (apply) throw new ArgumentException("Duplicate --apply."); apply = true; continue; }
            string option = args[i];
            if (option is not ("--rootfs" or "--rootfs-sha256" or "--operator-sid" or "--instance" or "--egress") || ++i == args.Length
                || args[i].StartsWith('-') || !options.TryAdd(option, args[i]))
                throw new ArgumentException("Managed deployment accepts --rootfs, --rootfs-sha256, --operator-sid, --instance, --egress and --apply.");
        }
        bool remove = args[0] == "unmount";
        string instance = options.GetValueOrDefault("--instance", "SplatManaged");
        if (!System.Text.RegularExpressions.Regex.IsMatch(instance, @"\ASplat[A-Za-z0-9]{0,14}\z"))
            throw new ArgumentException("Managed instance names start with Splat and contain at most 19 letters/digits.");
        if (remove && options.Keys.Any(key => key != "--instance")) throw new ArgumentException("Managed unmount accepts only --instance and --apply.");
        if (!remove && (!options.ContainsKey("--rootfs") || !options.ContainsKey("--operator-sid")
            || !options.TryGetValue("--rootfs-sha256", out var rootfsHash)
            || !System.Text.RegularExpressions.Regex.IsMatch(rootfsHash, @"\A[0-9a-fA-F]{64}\z")))
            throw new ArgumentException("Managed provision requires --rootfs <clean archive>, --rootfs-sha256 <publisher hash> and --operator-sid <Windows SID>.");
        string? executable = Environment.ProcessPath;
        if (executable is null || !Path.GetFileName(executable).Equals("splat-mcp.exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Use the published self-contained splat-mcp.exe for managed deployment.");
        if (!apply)
        {
            Console.WriteLine($"{(remove ? "Remove" : "Install")} managed instance {instance}: dedicated non-admin account, WSL distro, Windows bridge service and private ledger. Use --apply from an elevated Windows terminal.");
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
                "-Mode", remove ? "Remove" : "Install", "-Instance", instance, "-Executable", executable }) start.ArgumentList.Add(arg);
            foreach (var pair in new[] { ("--rootfs", "-Rootfs"), ("--rootfs-sha256", "-RootfsSha256"), ("--operator-sid", "-OperatorSid"), ("--egress", "-Egress") })
                if (options.TryGetValue(pair.Item1, out string? value)) { start.ArgumentList.Add(pair.Item2); start.ArgumentList.Add(value); }
            using var process = Process.Start(start) ?? throw new IOException("Managed installer did not start.");
            await process.WaitForExitAsync();
            return process.ExitCode;
        }
        finally { File.Delete(temporary); }
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
                Path.Combine(_config.StateDirectory, "ledger.key"));
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
