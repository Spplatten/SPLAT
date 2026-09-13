using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
        var (agentExit, _) = await wsl(Root($"test -x {AgentPath}"), ct);
        if (agentExit != 0)
        {
            if (!apply)
            {
                Line(output, "todo", "daemon binary",
                    $"{AgentPath} is not there. --apply builds it from this repo and installs it.");
                return Verdict(output, false, apply);
            }

            if (!await InstallAgentAsync(output, wsl, ct))
            {
                return Verdict(output, false, apply);
            }
        }
        else
        {
            Line(output, "ok", "daemon binary", AgentPath);
        }

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
                + "systemctl daemon-reload && systemctl enable --now splat-agent", ("SPLAT_UNIT", UnitFile)), ct);
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

        Line(output, "...", "daemon binary", $"building from {guestCrate.Trim()} - about a minute the first time");
        var (buildExit, buildOut) = await wsl(new[]
        {
            "-e", "sh", "-c",
            $"cd '{guestCrate.Trim()}' && EXTRA_CFLAGS=-Wno-error CFLAGS=-Wno-error "
            + $"CARGO_TARGET_DIR=/tmp/splat_agent_target '{cargo.Trim()}' build --release 2>&1 | tail -3",
        }, ct);
        if (buildExit != 0)
        {
            Line(output, "FAIL", "daemon binary", $"the build failed: {Short(buildOut)}");
            return false;
        }

        var (installExit, installOut) = await wsl(
            Root($"install -D -m 0755 /tmp/splat_agent_target/release/splat-agent {AgentPath}"), ct);
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
