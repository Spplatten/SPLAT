using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace MissionController.Infrastructure.Linux;

/// <summary>
/// The daemon's shared secret, read out of the guest once and held for the life of the host process.
///
/// Every request to the daemon carries it — leases and health checks alike. It lives at
/// <c>/etc/splat/agent.token</c>, mode 0600 and root-owned, which stops an unprivileged process
/// INSIDE the guest from reading it - though not from being handed it: every caller presents it to
/// whatever answers on the daemon's port, and while the daemon is not listening, anything can. It
/// does not stop another Windows process running as this same user, and the daemon's own header
/// says so.
///
/// One class rather than one per caller, because the way it is fetched has already been a defect
/// twice, and a second copy is where a fix stops being applied.
/// </summary>
public sealed class WslAgentToken
{
    /// <summary>Where the daemon writes its secret on first run.</summary>
    public const string DefaultPath = "/etc/splat/agent.token";

    /// <summary>The token every caller on this host shares, fetched at most once.</summary>
    public static WslAgentToken Default { get; } = new();

    /// <summary>
    /// How long a caller gives <see cref="GetAsync"/>, apart from any budget of its own: long enough for a
    /// cold wsl.exe on a guest still booting, and bounded so a wedged WSL cannot hold the caller open.
    /// </summary>
    public static TimeSpan ReadBudget { get; } = TimeSpan.FromSeconds(15);

    private readonly SemaphoreSlim _lock = new(1, 1);
    private string? _cached;
    private readonly Func<CancellationToken, Task<string?>>? _fetch;

    /// <summary>Where this instance looks, named so a refusal can say what it could not read.</summary>
    public string Path { get; }

    /// <param name="authTokenPath">Where the daemon keeps its secret inside the guest.</param>
    /// <param name="authToken">
    /// An explicit token, for a host that already holds one — or a test driving the wire against a
    /// stand-in listener, which must never shell into WSL to learn something it was told.
    /// </param>
    public WslAgentToken(string authTokenPath = DefaultPath, string? authToken = null)
    {
        Path = authTokenPath;
        _cached = !string.IsNullOrWhiteSpace(authToken)
            ? authToken
            : Environment.GetEnvironmentVariable("SPLAT_AGENT_TOKEN");
    }

    /// <param name="fetch">
    /// How the secret is obtained, for a host that holds it somewhere other than the guest - or a test
    /// that needs the read to be slow, which is the case a health check's budget must not absorb. Asked
    /// again after an empty answer; a token it returns is kept for the life of the instance.
    /// </param>
    /// <param name="authTokenPath">Named in refusals, although this instance never reads it.</param>
    public WslAgentToken(Func<CancellationToken, Task<string?>> fetch, string authTokenPath = DefaultPath)
    {
        ArgumentNullException.ThrowIfNull(fetch);
        _fetch = fetch;
        Path = authTokenPath;
    }

    /// <summary>
    /// The token, or null when this host cannot read one.
    ///
    /// Callers that also start the daemon must do that FIRST: the file does not exist until the
    /// daemon has run once, so a read made before the start finds nothing to read.
    /// </summary>
    public async Task<string?> GetAsync(CancellationToken ct = default)
    {
        if (_cached is { Length: > 0 })
        {
            return _cached;
        }

        await _lock.WaitAsync(ct);
        try
        {
            if (_cached is { Length: > 0 })
            {
                return _cached;
            }

            string? token = _fetch is null ? await FetchFromGuestAsync(ct) : await _fetch(ct);
            _cached = token is { Length: > 0 } ? token : null;
            return _cached;
        }
        catch
        {
            return null;
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<string?> FetchFromGuestAsync(CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "wsl.exe",
            // -u root because the token is 0600 and root-owned. Reading it any other way would
            // mean the file was readable to an unprivileged guest process, which is the state
            // the daemon warns about at startup.
            Arguments = $"-u root -e /bin/cat {Path}",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            // And stdin, which this child has no use for. Without the redirect it INHERITS the
            // host's stdin - and in splat-mcp that is the JSON-RPC channel: wsl.exe pumps
            // whatever it finds there into the guest, eating bytes the client had already sent.
            // Recorded on 2026-09-11 by the last-hop probe, whose sixth request reached the
            // server as a lone "{" and came back as a parse error.
            RedirectStandardInput = true,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        if (proc is null)
        {
            return null;
        }

        proc.StandardInput.Close();

        string output = await proc.StandardOutput.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct);

        if (proc.ExitCode != 0)
        {
            return null;
        }

        // WSL hands back UTF-16-ish noise on some hosts; keep only the hex the daemon emits.
        return new string(output.Where(Uri.IsHexDigit).ToArray());
    }
}
