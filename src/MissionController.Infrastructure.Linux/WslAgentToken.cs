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
/// <c>/etc/splat/agent.token</c>, mode 0600 and root-owned, which is what stops an unprivileged
/// process INSIDE the guest from issuing itself a lease or reading the substrate's state. It does
/// not stop another Windows process running as this same user, and the daemon's own header says so.
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

    private readonly SemaphoreSlim _lock = new(1, 1);
    private string? _cached;

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

    /// <summary>
    /// The token, or null when this host cannot read one.
    ///
    /// Callers that also start the daemon must do that FIRST: the file does not exist until the
    /// daemon has run once, so fetching it on a clean machine would fail and cache the failure.
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
            string token = new string(output.Where(Uri.IsHexDigit).ToArray());
            _cached = token.Length > 0 ? token : null;
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
}
