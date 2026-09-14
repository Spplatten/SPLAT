using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Infrastructure.Linux;

namespace SplatMcp;

/// <summary>
/// Gets this host from "WSL2 is installed" to "a lease reaches the kernel", with no shell step.
///
/// <see cref="SubstrateDoctor"/> reports; this repairs. They read the same machine in the same order,
/// so a `provision` run and a `doctor` run agree by construction rather than by two authors
/// remembering the same facts.
///
/// Two rules shape it. Nothing changes without <c>--apply</c>, because the steps write to /etc inside
/// the guest and to the user's own .wslconfig, and a tool that edits those on sight of a typo is
/// worse than one that prints what it would do. And what it cannot do it names rather than
/// approximates: `wsl --install` needs administrator rights and a reboot, and `wsl --shutdown` ends
/// every session the user has open, so both stay theirs.
/// </summary>
public static class SubstrateProvisioner
{
    private const string AgentPath = "/opt/splat/splat-agent";
    private const string UnitPath = "/etc/systemd/system/splat-agent.service";

    /// <summary>
    /// Root, because loading a BPF-LSM program and writing the cgroup tree need it — the WORKLOAD is
    /// dropped to nobody by the daemon itself, which is the property the probe checks. Restart on
    /// failure but never on a clean exit: the daemon exits deliberately when it cannot enforce, and
    /// restarting that would turn a fail-closed refusal into a crash loop nobody reads.
    /// </summary>
    private const string UnitFile =
        "[Unit]\n" +
        "Description=SPLAT resident BPF-LSM lease daemon\n" +
        "After=network.target\n" +
        "\n" +
        "[Service]\n" +
        "Type=simple\n" +
        "ExecStart=" + AgentPath + " --listen 127.0.0.1:50051\n" +
        "Restart=on-failure\n" +
        "RestartSec=2\n" +
        "\n" +
        "[Install]\n" +
        "WantedBy=multi-user.target\n";

    public static async Task<int> RunAsync(
        McpServerCommand.Provision provision,
        TextWriter output,
        SubstrateDoctor.WslRunner? wsl = null,
        WslSubstrateHealthChecker? health = null,
        string? wslConfigPath = null,
        string? agentBinaryPath = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(provision);
        ArgumentNullException.ThrowIfNull(output);
        wsl ??= SubstrateDoctor.RunWslAsync;
        health ??= new WslSubstrateHealthChecker();
        bool apply = provision.Apply;

        output.WriteLine(apply
            ? "SPLAT provision - making this host enforce"
            : "SPLAT provision - what this host still needs (nothing is changed; add --apply)");
        output.WriteLine();

        // 1. The one step that is not ours: WSL2 itself.
        var (wslExit, wslOut) = await wsl(new[] { "-e", "sh", "-c", "echo ok" }, ct);
        if (wslExit != 0)
        {
            Line(output, "FAIL", "WSL",
                $"wsl.exe did not answer ({Short(wslOut)}). Run `wsl --install` yourself: it needs "
                + "administrator rights and a reboot, which this command will not take.");
            return Verdict(output, false, apply);
        }

        var (_, distro) = await wsl(new[] { "-e", "sh", "-c", ". /etc/os-release; echo $PRETTY_NAME" }, ct);
        Line(output, "ok", "WSL", distro.Trim());

        // 2. systemd, because the daemon has to come back after a restart without anyone typing.
        var (_, pid1) = await wsl(new[] { "-e", "ps", "-p", "1", "-o", "comm=" }, ct);
        if (pid1.Trim() != "systemd")
        {
            if (apply)
            {
                var (confExit, confOut) = await wsl(Root("printf '[boot]\\nsystemd=true\\n' >> /etc/wsl.conf"), ct);
                Line(output, confExit == 0 ? "todo" : "FAIL", "systemd",
                    confExit == 0
                        ? "wrote [boot] systemd=true to /etc/wsl.conf. `wsl --shutdown` is yours - it ends every WSL session you have open - then re-run this."
                        : $"could not write /etc/wsl.conf: {Short(confOut)}");
            }
            else
            {
                Line(output, "todo", "systemd",
                    $"pid 1 is '{pid1.Trim()}', so nothing would start the daemon at boot. --apply writes [boot] systemd=true to /etc/wsl.conf.");
            }

            return Verdict(output, false, apply);
        }

        Line(output, "ok", "systemd", "pid 1, so a unit can start the daemon at boot");

        // 3. The kernel's own LSM list, set on the Windows side and taking effect only on a restart.
        var (_, cmdline) = await wsl(new[] { "-e", "cat", "/proc/cmdline" }, ct);
        bool bpf = cmdline
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Where(token => token.StartsWith("lsm=", StringComparison.Ordinal))
            .SelectMany(token => token["lsm=".Length..].Split(','))
            .Any(lsm => lsm.Trim() == "bpf");

        if (!bpf)
        {
            Line(output, "todo", "BPF-LSM", WslConfigAdvice(apply, wslConfigPath));
            return Verdict(output, false, apply);
        }

        Line(output, "ok", "BPF-LSM", "bpf is on the boot command line, so the kernel initialised it");

        // 4. The daemon binary, at a path that survives a restart. /tmp does not: it is tmpfs, and the
        //    distro stops seconds after its last process exits, taking the build with it.
        //
        //    A published splat-mcp.exe carries the daemon inside it, so a stranger needs neither this
        //    repository nor a Rust toolchain. A developer checkout carries none, and builds it with cargo.
        (string Path, string Sha256)? extracted = agentBinaryPath is null ? ExtractShippedAgent() : null;
        (string Path, string Sha256)? shipped = agentBinaryPath is null ? extracted : (agentBinaryPath, Sha256Of(agentBinaryPath));
        AgentStep agent;
        try
        {
            agent = await AgentStepAsync(output, wsl, apply, shipped, ct);
        }
        finally
        {
            if (extracted is not null)
            {
                File.Delete(extracted.Value.Path);
            }
        }

        if (agent == AgentStep.Stop)
        {
            return Verdict(output, false, apply);
        }

        bool reinstalled = agent == AgentStep.Installed;

        // 5. The unit, rewritten on every --apply: a stale ExecStart pointing at a path that no longer
        //    exists fails at boot, quietly, and nobody reads a unit they did not write today.
        var (unitExit, _) = await wsl(Root($"test -f {UnitPath}"), ct);
        if (unitExit != 0 && !apply)
        {
            Line(output, "todo", "service", $"{UnitPath} is not there. --apply writes it and enables it.");
            return Verdict(output, false, apply);
        }

        if (apply)
        {
            var (writeExit, writeOut) = await wsl(Root(
                $"install -d /opt/splat && printf '%s' \"$SPLAT_UNIT\" > {UnitPath} && "
                + "systemctl daemon-reload && " + StartCommand(reinstalled), ("SPLAT_UNIT", UnitFile)), ct);
            if (writeExit != 0)
            {
                Line(output, "FAIL", "service", $"could not install the unit: {Short(writeOut)}");
                return Verdict(output, false, apply);
            }
        }

        var (activeExit, activeOut) = await wsl(
            Root("systemctl is-active splat-agent; systemctl is-enabled splat-agent"), ct);
        bool running = activeOut.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Any(line => line.Trim() == "active");
        Line(output, running, "service",
            running
                ? $"splat-agent is {activeOut.ReplaceLineEndings(" and ").Trim()} - it comes back on its own after a restart"
                : $"splat-agent is not running: {Short(activeOut)} (exit {activeExit})");

        // 6. The verdict is the doctor's question, answered through the same authenticated health
        //    check: reachable is not enforcing, and a daemon that will not talk to this host is not
        //    provisioned however many files are in place.
        var status = await health.CheckHealthAsync(ct);
        Line(output, status.Authenticated, "daemon token",
            status.Authenticated
                ? $"accepted: a request from this host authenticated against {WslAgentToken.DefaultPath}"
                : $"REFUSED: {status.Message}");
        Line(output, status.Enforcing, "enforcement",
            status.Enforcing
                ? $"live: a lease reaches the kernel ({status.ActiveLeaseCount} active)"
                : "not live: the daemon holds no BPF maps, so nothing it runs is contained");

        return Verdict(output, status.Enforcing, apply);
    }

    private const string ShippedAgentResource = "splat-agent";

    /// <summary>Where step 4 left the daemon: already right, freshly installed, or blocked.</summary>
    private enum AgentStep
    {
        InPlace,
        Installed,
        Stop,
    }

    private static async Task<AgentStep> AgentStepAsync(
        TextWriter output, SubstrateDoctor.WslRunner wsl, bool apply, (string Path, string Sha256)? shipped, CancellationToken ct)
    {
        var (agentExit, _) = await wsl(Root($"test -x {AgentPath}"), ct);
        bool installed = agentExit == 0;

        if (installed)
        {
            if (shipped is null)
            {
                Line(output, "ok", "daemon binary", AgentPath);
                return AgentStep.InPlace;
            }

            // Kept only when it is byte-for-byte the daemon this executable carries. A newer splat-mcp.exe
            // over an older daemon is two halves of a wire protocol from different builds. A checksum
            // that cannot be read counts as different, and the replacement is verified before it lands.
            var (_, sums) = await wsl(Root($"sha256sum {AgentPath}"), ct);
            if (sums.Trim().Split(' ', 2)[0].Equals(shipped.Value.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                Line(output, "ok", "daemon binary", $"{AgentPath}, byte-for-byte the daemon built into this executable");
                return AgentStep.InPlace;
            }
        }

        if (!apply)
        {
            Line(output, "todo", "daemon binary",
                shipped is null
                    ? $"{AgentPath} is not there. --apply builds it from this repo and installs it."
                    : installed
                        ? $"{AgentPath} is not the daemon built into this executable. --apply replaces it and restarts the service."
                        : $"{AgentPath} is not there. --apply installs the daemon built into this executable - no Rust toolchain needed.");
            return AgentStep.Stop;
        }

        bool done = shipped is null
            ? await InstallAgentAsync(output, wsl, ct)
            : await InstallShippedAgentAsync(output, wsl, shipped.Value, ct);
        return done ? AgentStep.Installed : AgentStep.Stop;
    }

    /// <summary>
    /// Installs the daemon this executable carries: staged beside the live binary, run once, and only then
    /// renamed over it. The run is the check that matters for a binary built on another machine - a guest
    /// whose glibc predates the build's, or that lacks a library, fails here with the loader naming what is
    /// missing, not at boot in a unit log nobody reads. Running the staged copy rather than the file on the
    /// Windows mount means a DrvFs mount without exec permission cannot pass for a binary that will not
    /// start, and the rename means the service never sees a half-written file. Before any of that the copy
    /// is hashed against the bytes this executable carries, because the file it was copied from is on the
    /// Windows mount, and every process in the guest can write there.
    /// </summary>
    private static async Task<bool> InstallShippedAgentAsync(
        TextWriter output, SubstrateDoctor.WslRunner wsl, (string Path, string Sha256) shipped, CancellationToken ct)
    {
        var (pathExit, guestPath) = await wsl(new[] { "-e", "wslpath", "-a", shipped.Path }, ct);
        if (pathExit != 0 || string.IsNullOrWhiteSpace(guestPath))
        {
            Line(output, "FAIL", "daemon binary", $"could not resolve {shipped.Path} inside the guest: {Short(guestPath)}");
            return false;
        }

        // The check's stderr is kept in a variable, not in /tmp. It went to a fixed file there, and the
        // guest's /tmp is world-writable: a file planted under that name made root's write fail, so the
        // check failed and `cat` gave the planter's text as the reason.
        string staged = AgentPath + ".new";
        var (installExit, installOut) = await wsl(Root(
            "install -D -m 0755 \"$SPLAT_AGENT\" " + staged
            + " && { [ \"$(sha256sum " + staged + " | cut -d ' ' -f 1)\" = \"$SPLAT_AGENT_SHA256\" ]"
            + " || { rm -f " + staged + "; exit 4; }; }"
            + " && { err=$(" + staged + " --help 2>&1 >/dev/null)"
            + @" || { printf '%s\n' ""$err""; rm -f " + staged + "; exit 3; }; }"
            + " && mv -f " + staged + " " + AgentPath,
            ("SPLAT_AGENT", guestPath.Trim()), ("SPLAT_AGENT_SHA256", shipped.Sha256)), ct);

        if (installExit == 4)
        {
            Line(output, "FAIL", "daemon binary",
                "the copy that reached the guest does not match the daemon built into this executable, so nothing "
                + "was replaced. It came through the Windows mount, which every process in the guest can write.");
            return false;
        }

        if (installExit == 3)
        {
            // Not shortened: this is the one line the reader has to act on, and the version the loader
            // names is exactly what Short() would cut off.
            Line(output, "FAIL", "daemon binary",
                "the daemon built into this executable will not start in this guest, so nothing was replaced: "
                + installOut.ReplaceLineEndings(" ").Trim());
            return false;
        }

        if (installExit != 0)
        {
            Line(output, "FAIL", "daemon binary", $"could not install the daemon built into this executable: {Short(installOut)}");
            return false;
        }

        Line(output, "ok", "daemon binary", $"installed the daemon built into this executable to {AgentPath} - no Rust toolchain involved");
        return true;
    }

    /// <summary>
    /// The daemon publish-splat-mcp.ps1 builds into this executable, written out to a temp file, with the hash
    /// of the bytes written; or null for a build that carries none - a developer checkout, where this
    /// repository and cargo are the way in.
    /// </summary>
    private static (string Path, string Sha256)? ExtractShippedAgent()
    {
        using Stream? resource = typeof(SubstrateProvisioner).Assembly.GetManifestResourceStream(ShippedAgentResource);
        if (resource is null)
        {
            return null;
        }

        // Hashed as it is written, never read back: the guest reaches the file through /mnt/c, so by the
        // time it was read again anything in the guest could have changed it.
        string path = Path.Combine(Path.GetTempPath(), $"splat-agent-{Environment.ProcessId}");
        using var sha256 = SHA256.Create();
        using (var file = File.Create(path))
        using (var hashing = new CryptoStream(file, sha256, CryptoStreamMode.Write))
        {
            resource.CopyTo(hashing);
        }

        return (path, Convert.ToHexString(sha256.Hash!).ToLowerInvariant());
    }

    private static string Sha256Of(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    /// <summary>
    /// Restarted, not merely enabled, when step 4 put a new binary in place: <c>enable --now</c> leaves a
    /// running service alone, so the old daemon would go on serving the old code until the next boot.
    /// When nothing changed it is only enabled, because a restart drops every lease the daemon holds.
    /// </summary>
    private static string StartCommand(bool reinstalled) => reinstalled
        ? "systemctl enable splat-agent && systemctl restart splat-agent"
        : "systemctl enable --now splat-agent";

    private static async Task<bool> InstallAgentAsync(TextWriter output, SubstrateDoctor.WslRunner wsl, CancellationToken ct)
    {
        // The crate as this host sees it. wslpath rather than string surgery on C:\ — a repo on
        // another drive, or under a junction, is not a /mnt/c path.
        string crate = Path.Combine(RepositoryRoot(), "native", "splat-agent");
        var (pathExit, guestCrate) = await wsl(new[] { "-e", "wslpath", "-a", crate }, ct);
        if (pathExit != 0 || string.IsNullOrWhiteSpace(guestCrate))
        {
            Line(output, "FAIL", "daemon binary", $"could not resolve {crate} inside the guest: {Short(guestCrate)}");
            return false;
        }

        // rustup puts cargo in ~/.cargo/bin and adds it to PATH from .bashrc, which a non-login shell
        // never reads — which is how preflight once reported a missing cargo on a machine that had it.
        // Look in both places before concluding anything.
        var (cargoExit, cargo) = await wsl(
            new[] { "-e", "sh", "-c", "command -v cargo || ls \"$HOME\"/.cargo/bin/cargo 2>/dev/null" }, ct);
        if (cargoExit != 0 || string.IsNullOrWhiteSpace(cargo))
        {
            Line(output, "FAIL", "daemon binary",
                "no cargo in the guest, so the daemon cannot be built here. Install Rust in WSL "
                + "(`curl https://sh.rustup.rs -sSf | sh`) and re-run.");
            return false;
        }

        // The building user's own cache, never /tmp. Root installs what this build leaves, and the guest's
        // /tmp is world-writable: whoever created /tmp/splat_agent_target before the first build owned every
        // file in it from then on. $HOME is read here because root's, below, is a different one.
        var (homeExit, home) = await wsl(new[] { "-e", "sh", "-c", "printf %s \"$HOME\"" }, ct);
        if (homeExit != 0 || !home.StartsWith('/'))
        {
            Line(output, "FAIL", "daemon binary", $"could not find the guest user's home directory: {Short(home)}");
            return false;
        }

        string target = home + "/.cache/splat-agent-target";
        Line(output, "...", "daemon binary", $"building from {guestCrate.Trim()} - about a minute the first time");
        var (buildExit, buildOut) = await wsl(new[]
        {
            "-e", "sh", "-c",
            // cargo's exit status, not tail's. Piped straight into tail, a failed build exited 0 - and with a
            // target directory that persists, root would then have installed whatever an earlier build left.
            $"out=$(cd '{guestCrate.Trim()}' && EXTRA_CFLAGS=-Wno-error CFLAGS=-Wno-error "
            + $"CARGO_TARGET_DIR='{target}' '{cargo.Trim()}' build --release 2>&1); status=$?; "
            + @"printf '%s\n' ""$out"" | tail -3; exit $status",
        }, ct);
        if (buildExit != 0)
        {
            Line(output, "FAIL", "daemon binary", $"the build failed: {Short(buildOut)}");
            return false;
        }

        var (installExit, installOut) = await wsl(
            Root("install -D -m 0755 \"$SPLAT_AGENT\" " + AgentPath, ("SPLAT_AGENT", target + "/release/splat-agent")), ct);
        if (installExit != 0)
        {
            Line(output, "FAIL", "daemon binary", $"built, but could not install to {AgentPath}: {Short(installOut)}");
            return false;
        }

        Line(output, "ok", "daemon binary", $"built and installed to {AgentPath}");
        return true;
    }

    /// <summary>
    /// The kernel command line is a Windows-side setting, and merging one that already exists is not
    /// something to guess at: an operator's boot line may carry options this tool has never heard of.
    /// So it appends the stanza only when the file has no [wsl2] section at all, and otherwise prints
    /// the one edit to make.
    ///
    /// "Already sets kernelCommandLine" is read the way WSL reads it: a live key under [wsl2]. The
    /// substring test this replaced also matched a commented-out line and the same key under any other
    /// section - both ignored by WSL - and told the user to add bpf to a line that could never take
    /// effect, so the restart they were sent to make came back with the same answer. Nor is a second
    /// [wsl2] appended beside an existing one: whether WSL honours a key in a repeated section is its
    /// parser's business, and this tool should not depend on an answer nobody here has observed.
    /// </summary>
    private static string WslConfigAdvice(bool apply, string? path)
    {
        path ??= Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".wslconfig");
        const string line = "kernelCommandLine = lsm=landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,apparmor,tomoyo,bpf";
        string existing = File.Exists(path) ? File.ReadAllText(path) : string.Empty;

        string[] lines = existing.ReplaceLineEndings("\n").Split('\n');
        int section = Array.FindIndex(lines, l => l.Trim().Equals("[wsl2]", StringComparison.OrdinalIgnoreCase));
        bool liveKey = section >= 0 && lines
            .Skip(section + 1)
            .TakeWhile(l => !l.TrimStart().StartsWith('['))
            .Select(l => l.Trim())
            .Where(l => !l.StartsWith('#') && !l.StartsWith(';'))
            .Any(l => l.Contains('=') && l[..l.IndexOf('=')].Trim().Equals("kernelCommandLine", StringComparison.OrdinalIgnoreCase));

        if (liveKey)
        {
            return $"bpf is NOT on the boot command line, and {path} already sets kernelCommandLine under [wsl2]. "
                + "Add `bpf` to the end of its lsm= list yourself, then run `wsl --shutdown`.";
        }

        if (section >= 0)
        {
            return $"bpf is NOT on the boot command line, and {path} has a [wsl2] section without a kernelCommandLine. "
                + $"Add this line under [wsl2] yourself, then run `wsl --shutdown`: {line}";
        }

        if (!apply)
        {
            return $"bpf is NOT on the boot command line. --apply appends a [wsl2] section to {path}, after which "
                + $"`wsl --shutdown` is yours: [wsl2] {line}";
        }

        File.AppendAllText(path, (existing.Length > 0 && !existing.EndsWith('\n') ? "\n" : string.Empty) + "[wsl2]\n" + line + "\n");
        return $"appended the lsm= stanza to {path}. `wsl --shutdown` is yours - it ends every WSL "
            + "session you have open - then re-run this.";
    }

    /// <summary>Everything that touches /etc or /opt in the guest, as root.</summary>
    private static string[] Root(string script, params (string Name, string Value)[] environment)
    {
        var args = new List<string> { "-u", "root", "-e", "env" };
        foreach (var (name, value) in environment)
        {
            // The unit file travels as an environment value rather than inside the script: a heredoc
            // would have to survive two levels of quoting, and this way nothing in the content can be
            // read as shell at all.
            args.Add($"{name}={value}");
        }

        args.Add("sh");
        args.Add("-c");
        args.Add(script);
        return args.ToArray();
    }

    private static int Verdict(TextWriter output, bool enforcing, bool apply)
    {
        output.WriteLine();
        output.WriteLine(enforcing
            ? "Verdict: provisioned. A lease on this host reaches the kernel, and `splat-mcp doctor` will say the same."
            : apply
                ? "Verdict: NOT provisioned yet. The first line above that is not `ok` is the step to take."
                : "Verdict: NOT provisioned. Nothing was changed - re-run with --apply to do the steps marked `todo`.");
        return enforcing ? 0 : 1;
    }

    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MissionController.sln")))
        {
            dir = dir.Parent;
        }

        // Published beside no repository: the build step then says it cannot find the crate, rather
        // than this guessing a path that happens to exist.
        return dir?.FullName ?? AppContext.BaseDirectory;
    }

    private static void Line(TextWriter output, string mark, string what, string detail) =>
        output.WriteLine($"  {mark,-6}{what,-18}{detail}");

    private static void Line(TextWriter output, bool ok, string what, string detail) =>
        Line(output, ok ? "ok" : "FAIL", what, detail);

    private static string Short(string text) =>
        text.Length <= 90 ? text.ReplaceLineEndings(" ") : text.ReplaceLineEndings(" ")[..90] + "...";
}
