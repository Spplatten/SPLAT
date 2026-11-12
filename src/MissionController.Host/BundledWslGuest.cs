using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MissionController.Infrastructure.Linux;

namespace MissionController.Host;

/// <summary>
/// An opt-in, per-data-root guest from the installer's verified Debian payload. Import is a
/// separate reviewed change. Every subsequent guest command is bound to its registration and
/// checks its ownership marker; a missing or replaced guest never selects the user's default.
/// </summary>
public sealed class BundledWslGuest
{
    internal sealed record ImportPlan(string Sha256, long Bytes);
    private sealed record Receipt(string Distribution, string Identity, string Phase);
    private readonly string _linuxDirectory;
    private readonly SubstrateDoctor.WslRunner _run;
    private string Archive => Path.Combine(_linuxDirectory, "rootfs.tar.xz");
    private string ReceiptPath => Path.Combine(StateDirectory, "import.json");
    public string StateDirectory { get; }
    public string StorageDirectory => Path.Combine(StateDirectory, "rootfs");
    public string ManifestPath => Path.Combine(StateDirectory, "mount-manifest.json");
    public string Distribution { get; }
    public WslLeasedExecutor Executor { get; }
    public WslSubstrateHealthChecker Health { get; }

    public BundledWslGuest(string linuxDirectory, string dataRoot, SubstrateDoctor.WslRunner? run = null)
        : this(linuxDirectory, dataRoot, run, 50051)
    {
    }

    // A loopback stand-in must use its own ephemeral port, never the operator's daemon.
    internal BundledWslGuest(string linuxDirectory, string dataRoot, SubstrateDoctor.WslRunner? run, int port)
    {
        _linuxDirectory = Path.GetFullPath(linuxDirectory);
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataRoot));
        StateDirectory = Path.Combine(root, "lite-guest");
        Distribution = "SPLAT-Lite-" + Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(root.ToUpperInvariant())))[..12].ToLowerInvariant();
        _run = run ?? RunProcessAsync;
        var token = new WslAgentToken(ReadTokenAsync);
        Executor = new WslLeasedExecutor("127.0.0.1", port, token, StartDaemonAsync, HoldAwake,
            validateGuest: RequireOwnedAsync);
        Health = new WslSubstrateHealthChecker("127.0.0.1", port, token,
            connect: Executor.ConnectToDaemonAsync);
    }

    public static BundledWslGuest? BesideApp(string appDirectory, string dataRoot)
    {
        string linux = Path.GetFullPath(Path.Combine(appDirectory, "..", "Linux"));
        // Legacy raw rootfs packages have no Guest records. They retain their existing setup path.
        return Directory.Exists(Path.Combine(linux, "Guest")) ||
            File.Exists(Path.Combine(dataRoot, "lite-guest", "import.json")) ? new(linux, dataRoot) : null;
    }

    internal async Task<ImportPlan?> PlanAsync(TextWriter output, CancellationToken ct)
    {
        bool registered = await IsRegisteredAsync(ct);
        if (File.Exists(ReceiptPath))
        {
            await RequireOwnedAsync(ct);
            if (!registered) throw new IOException($"Owned guest {Distribution} is no longer registered.");
            return null;
        }
        if (registered || Directory.Exists(StorageDirectory))
            throw new IOException($"Refusing to adopt {Distribution}: its name or storage already exists without an ownership receipt.");
        using FileStream archive = OpenArchive();
        ImportPlan plan = await ValidateArchiveAsync(archive, ct);
        output.WriteLine("SPLAT Lite import plan - nothing is changed");
        output.WriteLine($"Import {Archive}");
        output.WriteLine($"SHA-256: {plan.Sha256} ({plan.Bytes} bytes)");
        output.WriteLine($"Register WSL2 guest {Distribution} at {StorageDirectory}.");
        output.WriteLine("In this new guest, enable systemd and mount Windows drives with metadata and umask 077.");
        output.WriteLine("Write its ownership receipt and marker, then stop this new guest so its boot settings take effect.");
        output.WriteLine("The default WSL distribution is unchanged. Import does not install the daemon or establish enforcement.");
        output.WriteLine("Apply imports the guest only. Then plan a mount to review daemon and host boot-line changes.");
        output.WriteLine("Unmount removes the recorded daemon setup; it retains the guest and its data. Guest removal is manual.");
        return plan;
    }

    internal async Task<int> ImportAsync(ImportPlan plan, TextWriter output, CancellationToken ct)
    {
        // Hold the archive against replacement throughout import, and compare with the reviewed plan.
        using FileStream archive = OpenArchive();
        if (await ValidateArchiveAsync(archive, ct) != plan)
            throw new IOException("The guest archive changed after the plan. Plan the import again.");
        if (await IsRegisteredAsync(ct) || File.Exists(ReceiptPath) || Directory.Exists(StorageDirectory))
            throw new IOException("The guest name or storage changed after the plan. Nothing was imported.");
        RejectReparsePoints(StateDirectory);
        Directory.CreateDirectory(StateDirectory);
        var receipt = new Receipt(Distribution, Guid.NewGuid().ToString("N"), "importing");
        // CreateNew also prevents two consoles sharing this data root from both importing.
        using (var file = new FileStream(ReceiptPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            JsonSerializer.Serialize(file, receipt);
        output.WriteLine($"Importing {Distribution}. Recovery receipt: {ReceiptPath}");
        await RequireSuccessAsync(new[] { "--import", Distribution, StorageDirectory, Archive, "--version", "2" }, ct);
        // Only the newly imported guest gets this initializer. No shell text contains an external value;
        // the sole substitution is the generated 32-character hex identity.
        string initialize = "set -eu; umask 077; mkdir -p /etc/splat; " +
            $"printf '%s\\n' '{receipt.Identity}' > /etc/splat/guest.id; " +
            "printf '[boot]\\nsystemd=true\\n[automount]\\noptions=\"metadata,umask=077\"\\n' > /etc/wsl.conf";
        await RequireSuccessAsync(new[] { "-d", Distribution, "-u", "root", "-e", "/bin/sh", "-c", initialize }, ct);
        await RequireSuccessAsync(new[] { "--terminate", Distribution }, ct);
        string ready = ReceiptPath + ".ready";
        using (var file = new FileStream(ready, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            JsonSerializer.Serialize(file, receipt with { Phase = "ready" });
        File.Move(ready, ReceiptPath, overwrite: true);
        output.WriteLine("Guest imported. Plan a mount next; kernel enforcement has not been checked.");
        return 0;
    }

    private FileStream OpenArchive()
    {
        RejectReparsePoints(Archive);
        return new FileStream(Archive, FileMode.Open, FileAccess.Read, FileShare.Read);
    }

    private async Task<ImportPlan> ValidateArchiveAsync(FileStream archive, CancellationToken ct)
    {
        string buildPath = Path.Combine(_linuxDirectory, "Guest", "BUILD.json");
        RejectReparsePoints(buildPath);
        using JsonDocument build = JsonDocument.Parse(await File.ReadAllTextAsync(buildPath, ct));
        string? expected = build.RootElement.GetProperty("sha256").GetString();
        long length = build.RootElement.GetProperty("xzBytes").GetInt64();
        archive.Position = 0;
        string hash = Convert.ToHexString(await SHA256.HashDataAsync(archive, ct)).ToLowerInvariant();
        if (length <= 0 || archive.Length != length || !string.Equals(hash, expected, StringComparison.OrdinalIgnoreCase))
            throw new IOException("The bundled guest does not match Guest/BUILD.json. Import refused.");
        return new(hash, length);
    }

    private async Task<bool> IsRegisteredAsync(CancellationToken ct)
    {
        string names = await RequireSuccessAsync(new[] { "--list", "--quiet" }, ct);
        return names.Replace("\0", "").Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Any(name => string.Equals(name.Trim(), Distribution, StringComparison.OrdinalIgnoreCase));
    }

    private Receipt ReadReceipt()
    {
        RejectReparsePoints(ReceiptPath);
        if (!File.Exists(ReceiptPath)) throw new IOException("The bundled Lite guest is not imported. Plan a mount on the Kernel Lease page first.");
        Receipt? receipt = JsonSerializer.Deserialize<Receipt>(File.ReadAllText(ReceiptPath));
        if (receipt is null || receipt.Distribution != Distribution || receipt.Phase != "ready" ||
            string.IsNullOrEmpty(receipt.Identity) || receipt.Identity.Length != 32 || !receipt.Identity.All(Uri.IsHexDigit))
            throw new IOException($"The Lite guest import is incomplete or its receipt is invalid. Review {ReceiptPath} before recovery; no guest will be adopted or removed automatically.");
        return receipt;
    }

    internal async Task RequireOwnedAsync(CancellationToken ct)
    {
        Receipt receipt = ReadReceipt();
        string identity = await RequireSuccessAsync(new[] { "-d", Distribution, "-u", "root", "-e", "/bin/cat", "/etc/splat/guest.id" }, ct);
        if (identity.Trim() != receipt.Identity)
            throw new IOException($"The ownership marker of {Distribution} does not match its receipt. Nothing will be changed.");
    }

    public async Task<(int ExitCode, string Output)> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
    {
        await RequireOwnedAsync(ct);
        return await _run(new[] { "-d", Distribution }.Concat(args).ToArray(), ct);
    }

    private async Task<string?> ReadTokenAsync(CancellationToken ct)
    {
        var (code, token) = await RunAsync(new[] { "-u", "root", "-e", "/bin/cat", WslAgentToken.DefaultPath }, ct);
        token = token.Trim();
        return code == 0 && token.Length == 64 && token.All(Uri.IsHexDigit) ? token : null;
    }

    private async Task<int> StartDaemonAsync(CancellationToken ct) =>
        (await RunAsync(new[] { "-u", "root", "-e", "/bin/systemctl", "start", "splat-agent" }, ct)).ExitCode;

    private IDisposable HoldAwake()
    {
        Receipt receipt = ReadReceipt();
        // The shell checks ownership before holding stdin open. No default-distro idle session.
        var start = StartInfo(new[] { "-d", Distribution, "-u", "root", "-e", "/bin/sh", "-c",
            $"test \"$(cat /etc/splat/guest.id)\" = '{receipt.Identity}' && exec /bin/cat" });
        Process process = Process.Start(start) ?? throw new IOException("The Lite guest keep-alive did not start.");
        _ = process.StandardOutput.ReadToEndAsync();
        _ = process.StandardError.ReadToEndAsync();
        return new GuestSession(process);
    }

    private sealed class GuestSession(Process process) : IDisposable
    {
        public void Dispose()
        {
            try { process.StandardInput.Close(); if (!process.WaitForExit(3000)) process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            finally { process.Dispose(); }
        }
    }

    private async Task<string> RequireSuccessAsync(IReadOnlyList<string> args, CancellationToken ct)
    {
        var (code, output) = await _run(args, ct);
        if (code != 0) throw new IOException($"WSL {args[0]} failed ({code}): {output}");
        return output;
    }

    private static ProcessStartInfo StartInfo(IReadOnlyList<string> args)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "wsl.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        foreach (string arg in args) start.ArgumentList.Add(arg);
        return start;
    }

    private static async Task<(int, string)> RunProcessAsync(IReadOnlyList<string> args, CancellationToken ct)
    {
        bool importing = args[0] == "--import";
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(importing ? TimeSpan.FromMinutes(10) : TimeSpan.FromSeconds(30));
        using Process process = Process.Start(StartInfo(args)) ?? throw new IOException("wsl.exe did not start.");
        process.StandardInput.Close();
        try
        {
            Task<string> stdout = process.StandardOutput.ReadToEndAsync(budget.Token);
            Task<string> stderr = process.StandardError.ReadToEndAsync(budget.Token);
            await process.WaitForExitAsync(budget.Token);
            return (process.ExitCode, SubstrateDoctor.OutputOf(process.ExitCode, await stdout, await stderr));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new IOException($"WSL {args[0]} exceeded its {(importing ? "10-minute" : "30-second")} budget. A partial import requires inspection.");
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
    }

    private static void RejectReparsePoints(string path)
    {
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException($"Guest paths may not traverse a reparse point: {current}");
    }
}
