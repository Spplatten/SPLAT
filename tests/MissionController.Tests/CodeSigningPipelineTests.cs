using System.Diagnostics;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// packaging/code-signing.ps1 decides which publisher a release names. Its refusals are the guarantee:
/// a configured identity that is ambiguous, missing or pointed at a host other than Artifact Signing
/// stops the build, and never falls through to an artifact that is quietly unsigned. Every case here is
/// judged before the helper looks for signtool, so the test needs no Windows SDK and no certificate.
/// </summary>
public sealed class CodeSigningPipelineTests
{
    private const string Probe = """
        param([string]$Helper, [string]$Work)
        $ErrorActionPreference = 'Stop'
        . $Helper
        function Probe([string]$name, [scriptblock]$body) {
            try { $r = & $body; if ($null -eq $r) { "${name}: <null>" } else { "${name}: $r" } }
            catch { "${name}: THROWS $($_.Exception.Message)" }
        }
        foreach ($n in 'SPLAT_SIGNING_METADATA', 'SPLAT_SIGNING_THUMBPRINT', 'SPLAT_SIGNING_DLIB', 'SPLAT_SIGNING_TIMESTAMP') {
            Remove-Item "env:$n" -ErrorAction SilentlyContinue
        }
        Probe 'neither' { Get-SplatSigningProfile }
        $env:SPLAT_SIGNING_METADATA = 'a.json'; $env:SPLAT_SIGNING_THUMBPRINT = 'b'
        Probe 'both' { Get-SplatSigningProfile }
        Remove-Item env:SPLAT_SIGNING_THUMBPRINT
        $env:SPLAT_SIGNING_METADATA = Join-Path $Work 'absent.json'
        Probe 'absent' { Get-SplatSigningProfile }
        $foreign = Join-Path $Work 'foreign.json'
        '{"Endpoint":"https://signing.example.com","CodeSigningAccountName":"a","CertificateProfileName":"b"}' | Set-Content -LiteralPath $foreign
        $env:SPLAT_SIGNING_METADATA = $foreign
        Probe 'foreign' { Get-SplatSigningProfile }
        $partial = Join-Path $Work 'partial.json'
        '{"Endpoint":"https://eus.codesigning.azure.net","CodeSigningAccountName":"a"}' | Set-Content -LiteralPath $partial
        $env:SPLAT_SIGNING_METADATA = $partial
        Probe 'partial' { Get-SplatSigningProfile }
        Remove-Item env:SPLAT_SIGNING_METADATA
        $env:SPLAT_SIGNING_THUMBPRINT = 'not-a-thumbprint'
        Probe 'thumbprint' { Get-SplatSigningProfile }
        Probe 'inno' { Get-SplatInnoSignCommand -Signing ([pscustomobject]@{ SignTool = 'C:\Kits\x64\signtool.exe'
            Timestamp = 'http://ts.test'; Arguments = @('/dlib', 'C:\a b\dlib.dll', '/dmdf', 'C:\m.json') }) }
        """;

    [Fact]
    public async Task ASigningIdentity_IsRefusedUnlessItIsUnambiguousAndWellFormed()
    {
        string work = Directory.CreateTempSubdirectory("splat-signing-").FullName;
        try
        {
            string script = Path.Combine(work, "probe.ps1");
            File.WriteAllText(script, Probe);
            var (exitCode, output) = await RunWindowsPowerShellAsync(
                script, Path.Combine(RepositoryRoot(), "packaging", "code-signing.ps1"), work);

            Assert.True(exitCode == 0, output);
            Assert.Contains("neither: <null>", output);
            Assert.Contains("both: THROWS Set SPLAT_SIGNING_METADATA or SPLAT_SIGNING_THUMBPRINT, not both.", output);
            Assert.Contains("absent: THROWS SPLAT_SIGNING_METADATA names no file:", output);
            Assert.Contains("not a regional codesigning.azure.net endpoint.", output);
            Assert.Contains("has no CertificateProfileName.", output);
            Assert.Contains("thumbprint: THROWS SPLAT_SIGNING_THUMBPRINT must be a certificate's 40-hex-digit SHA-1 thumbprint.", output);
            // Inno substitutes $q and $f itself; PowerShell must hand them over unexpanded, with every
            // path quoted so a space in one cannot split the command.
            Assert.Contains(
                @"inno: $qC:\Kits\x64\signtool.exe$q sign /fd SHA256 /tr http://ts.test /td SHA256 /dlib $qC:\a b\dlib.dll$q /dmdf $qC:\m.json$q $f",
                output);
        }
        finally
        {
            Directory.Delete(work, recursive: true);
        }
    }

    // Windows PowerShell 5.1, which the packaging scripts declare. PSModulePath is dropped because a
    // PowerShell 7 parent's value makes 5.1 load 7's modules and fail on core cmdlets.
    private static async Task<(int ExitCode, string Output)> RunWindowsPowerShellAsync(string script, string helper, string work)
    {
        var psi = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-Helper", helper, "-Work", work })
        {
            psi.ArgumentList.Add(arg);
        }
        psi.Environment.Remove("PSModulePath");

        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(1));
        try
        {
            await process.WaitForExitAsync(deadline.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("The code-signing probe did not finish within a minute.");
        }
        return (process.ExitCode, await stdout + await stderr);
    }

    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MissionController.sln")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
