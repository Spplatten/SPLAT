using System.Diagnostics;

namespace SplatMcp;

internal sealed class ManagedGuest(string distribution)
{
    private ProcessStartInfo Start(params string[] args)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "wsl.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (string arg in new[] { "-d", distribution, "-u", "root", "-e" }.Concat(args)) start.ArgumentList.Add(arg);
        return start;
    }

    private async Task<(int Exit, string Output)> RunAsync(CancellationToken ct, params string[] args)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(TimeSpan.FromSeconds(30));
        using var process = Process.Start(Start(args)) ?? throw new IOException("WSL did not start.");
        process.StandardInput.Close();
        try
        {
            var output = process.StandardOutput.ReadToEndAsync(budget.Token);
            var error = process.StandardError.ReadToEndAsync(budget.Token);
            await process.WaitForExitAsync(budget.Token);
            await error;
            return (process.ExitCode, await output);
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
    }

    internal async Task<string?> ReadTokenAsync(CancellationToken ct)
    {
        var (exit, output) = await RunAsync(ct, "/bin/cat", "/etc/splat/agent.token");
        string token = output.Trim();
        // Never turn WSL error text into a token by filtering its hex-looking characters.
        return exit == 0 && token.Length == 64 && token.All(Uri.IsHexDigit) ? token : null;
    }

    internal async Task<int> StartDaemonAsync(CancellationToken ct) =>
        (await RunAsync(ct, "/bin/systemctl", "start", "splat-agent")).Exit;

    internal IDisposable HoldAwake() => new GuestSession(Process.Start(Start("/bin/cat"))
        ?? throw new IOException("Could not keep the managed guest awake."));

    private sealed class GuestSession(Process process) : IDisposable
    {
        public void Dispose()
        {
            process.StandardInput.Close();
            if (!process.WaitForExit(3000)) process.Kill(entireProcessTree: true);
            process.Dispose();
        }
    }
}
