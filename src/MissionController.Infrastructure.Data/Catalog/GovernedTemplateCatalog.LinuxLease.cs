using MissionController.Core.Enums;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Catalog;

/// <summary>
/// The specialists that run under the Linux lease: their tool is a guest executable, named by its
/// absolute path, and the mission engine hands the whole mission to the WSL2 daemon, which runs the tool
/// as nobody in a cgroup the kernel polices, in a jail it makes for the mission and removes after it.
///
/// Until 2026-09-24 every template in this catalog ran on Windows, and the lease held only what an
/// outside agent sent through <c>run_command</c>. These four are read-only sensors on the guest itself,
/// chosen because each reads something a responder wants from a Linux host and none needs the
/// network, so each runs with every socket refused by the kernel. Their tools are the four the lease
/// ceiling admits by prefix on any provisioned guest.
/// </summary>
public static partial class GovernedTemplateCatalog
{
    private const string LinuxCat = "/bin/cat";
    private const string LinuxDf = "/bin/df";
    private const string LinuxPs = "/bin/ps";
    private const string LinuxSs = "/usr/bin/ss";

    private static SingleToolTemplate LeasedTemplate(
        string templateId,
        string name,
        string description,
        string model,
        string toolId,
        string toolName,
        string executable,
        string arguments,
        string systemPrompt,
        int timeoutSeconds = 30) =>
        Template(
            templateId,
            name,
            description,
            CatLinuxGuest,
            model,
            new SingleToolDefinition(
                toolId,
                toolName,
                executable,
                arguments,
                ExitOkOrPartial,
                TimeoutSeconds: timeoutSeconds,
                MaxMemoryBytes: Mb(128),
                MaxCpuPercent: 40,
                // The daemon drops the workload to nobody whatever this says; it is recorded as the
                // request the record can compare against the workload uid the daemon reports back.
                RequiresRestrictedToken: true,
                Substrate: ToolSubstrate.LinuxLease),
            systemPrompt,
            null);

    private static IEnumerable<SingleToolTemplate> LinuxLeaseTemplates() => new[]
    {
        LeasedTemplate(
            "linux-guest-identity",
            "Linux Guest Identity & Load",
            "Reads the WSL2 guest's release, kernel, uptime, load and memory from /etc and /proc, under the kernel lease with no network.",
            ModelFlash,
            "linux_guest_identity_tool",
            "Release, Kernel, Uptime, Load and Memory Reader",
            LinuxCat,
            "/etc/os-release /proc/version /proc/uptime /proc/loadavg /proc/meminfo",
            "You are a Linux systems engineer reading a host's identity sheet. Report the distribution and kernel release, the uptime in days, the three load averages against the CPU count if it can be inferred, and memory: MemTotal, MemAvailable and the share available. Mark WARNING when MemAvailable is under 10% of MemTotal or the one-minute load is more than twice the fifteen-minute load; mark CRITICAL only for MemAvailable under 3%. Quote the exact lines you used. This sensor runs as an unprivileged user in a read-only jail with no network; anything it could not read is reported as not visible from this sensor, never as absent."),

        LeasedTemplate(
            "linux-disk-usage",
            "Linux Filesystem Usage",
            "Reports every mounted filesystem the leased tool can see with its size, use and mount point, under the kernel lease with no network.",
            ModelFlash,
            "linux_disk_usage_tool",
            "Filesystem Usage Reader",
            LinuxDf,
            "-hP",
            "You are a Linux storage engineer reading df output. For each filesystem, quote the size, used, available and use percentage exactly as printed. Mark WARNING for any real filesystem at 85% or more and CRITICAL at 95% or more; tmpfs, devtmpfs and overlay mounts are memory-backed or layered and are reported but never escalated on their own. The tool runs inside a read-only jail, so the mounts it sees are the jail's bind mounts of the guest's system directories and its working directory; say so, and do not treat a mount you would expect on a full host as missing evidence."),

        LeasedTemplate(
            "linux-process-snapshot",
            "Linux Process Snapshot",
            "Lists every process the guest exposes with its owner, state, elapsed time, CPU and memory share and command, under the kernel lease with no network.",
            ModelPro,
            "linux_process_snapshot_tool",
            "Process Table Reader",
            LinuxPs,
            "-eo pid,ppid,user,stat,etime,pcpu,pmem,args --sort=-pcpu",
            "You are a Linux incident responder reading a process table taken as an unprivileged user. Mark CRITICAL for a process running from /tmp, /dev/shm, /var/tmp or a home directory, for a process whose command line carries a reverse shell, a base64 payload or a download-and-execute pipeline, and for a process in state Z or D that has held that state for hours. Mark WARNING for a process using more than 50% CPU or 20% memory, and for a shell owned by a service account. Quote the pid, user and full command for every finding. Processes of other users may show their command line; their environment and open files are out of this sensor's reach, and are reported as not visible, never as clean.",
            timeoutSeconds: 45),

        LeasedTemplate(
            "linux-listening-sockets",
            "Linux Listening Sockets",
            "Lists every TCP and UDP listener in the guest with its local address and, where visible, its owning process, under the kernel lease with no network.",
            ModelPro,
            "linux_listening_sockets_tool",
            "Socket Listener Reader",
            LinuxSs,
            "-tulnpH",
            "You are a Linux network security engineer reading ss output. For every listener quote the protocol, local address and port, and the process when one is shown. Mark CRITICAL for a listener on 0.0.0.0 or [::] for a service that has no business on the network (a shell, a database, a debugger, a proxy on an unusual port) and for any listener whose process name suggests a tunnel or a miner; mark WARNING for a listener on a high port with no process shown, because an unprivileged sensor cannot see other users' processes and the owner is unknown, not innocent. A listener bound to 127.0.0.1 is local-only and is reported, not escalated. This sensor's own socket is refused by the kernel lease before it opens, so a connect attempt in the output is the lease working."),
    };
}
