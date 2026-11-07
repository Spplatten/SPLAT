using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Splat.AlertSidecar;

// What the operator's wrapper made for this run, and nothing else: ports, certificate pins, the guest
// and its deployed observer, and the daemon key pinned before the run. Every other plan field is read
// while both tasks run, from SPLAT's GetTask and the guest's own cgroup and procfs, so no plan carries
// a hand-copied or stale identity. Checked before any workload starts.
internal sealed record PilotRequest(int Version, int A2aPort, string A2aCertificateSha256, int SidecarPort,
    string SidecarCertificateFile, string SidecarCertificateSha256, string Distribution, string GuestWitnessPath,
    string GuestWitnessSha256, string DaemonKeySha256, int TimeoutSeconds, string OperatorEvidenceReference)
{
    internal void Check()
    {
        if (Version != 1 || A2aPort is < 1024 or > 65535 || SidecarPort is < 1024 or > 65535 || A2aPort == SidecarPort
            || SidecarCertificateFile is not { Length: > 0 } || !Path.IsPathFullyQualified(SidecarCertificateFile)
            || !CancellationReceiptProof.IsHash(A2aCertificateSha256) || !CancellationReceiptProof.IsHash(SidecarCertificateSha256)
            || !CancellationReceiptProof.IsHash(GuestWitnessSha256) || !CancellationReceiptProof.IsHash(DaemonKeySha256)
            || !Binding.ValidIdentifier(Distribution) || Distribution.StartsWith('-')
            || GuestWitnessPath is not { Length: > 1 and <= 1024 } || GuestWitnessPath[0] != '/' || GuestWitnessPath.Any(char.IsControl)
            || TimeoutSeconds is < 5 or > 120 || !Binding.ValidIdentifier(OperatorEvidenceReference))
            throw new InvalidDataException("Pilot request is incomplete or unbounded.");
    }
}

// One task as SPLAT stated it while it ran, before any receipt existed: what the plan pins.
internal sealed record AdmittedTask(string TaskId, ulong Cgroup, string CgroupPath, string ExecutionContext,
    string ExecutionPolicySha256, string EffectivePolicySha256, string ContextIdentitySha256);

internal sealed record NativeRoot(int Pid, ulong StartTicks);

// Option B in one process: admit the pilot target and control through the operator's A2A host, pin what
// SPLAT and the guest state about them, start a Falcon-mode sidecar holding only the target's sensor
// credential, then hand the unchanged --check-falcon-pilot and --run-falcon-pilot the files they take.
// The runner, its witness and its receipt verification stay the judges; this only assembles inputs.
internal static class PilotOrchestrator
{
    internal const string Rule = "splat-synthetic-control";
    internal const string EventType = "SplatSyntheticControl";

    internal static async Task<int?> TryRunAsync(string[] args)
    {
        if (args.Length == 0 || args[0] != "--orchestrate-cancellation-pilot") return null;
        try
        {
            if (args.Length != 3) throw new ArgumentException("Use --orchestrate-cancellation-pilot request.json NEW-run-directory.");
            return await RunAsync(args[1], args[2]);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or InvalidOperationException
            or ArgumentException or UnauthorizedAccessException or HttpRequestException or OperationCanceledException
            or KeyNotFoundException or FormatException or System.ComponentModel.Win32Exception)
        {
            // These messages are this harness's and the local host's own; no credential reaches them.
            Console.Error.WriteLine($"Cancellation pilot orchestration refused: {ex.GetType().Name}: {ex.Message}");
            return 2;
        }
    }

    private static async Task<int> RunAsync(string requestPath, string run)
    {
        using var requestDocument = StrictJson.Parse(ConfigurationFiles.Read(requestPath));
        var request = requestDocument.RootElement.Deserialize<PilotRequest>(Binding.Json)
            ?? throw new InvalidDataException("Missing pilot request.");
        request.Check();
        string ownerToken = Credentials.Required("SPLAT_A2A_CALLER_TOKEN");
        // Absolute, because the plan's mailbox path must be fully qualified.
        run = Path.GetFullPath(run);
        if (Directory.Exists(run)) throw new IOException("Use a new run directory; a pilot run is never repeated in place.");
        Directory.CreateDirectory(run);
        string At(string name) => Path.Combine(run, name);
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        // The runner's own rule: the chain must validate AND be the pinned certificate.
        handler.ServerCertificateCustomValidationCallback = (message, certificate, _, errors) => errors == SslPolicyErrors.None
            && certificate != null && message.RequestUri is { Host: "127.0.0.1", Scheme: "https" } uri && uri.Port == request.A2aPort
            && CancellationReceiptProof.Hash(certificate.RawData) == request.A2aCertificateSha256;
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
        var a2a = new A2a(client, request.A2aPort, ownerToken);
        string stage = "admission";
        string? targetId = null, controlId = null;
        NativeRoot? targetRoot = null, controlRoot = null;
        Process? sidecar = null;
        int result = 2;
        string[] cancelledAtCleanup = [];
        try
        {
            using var preparation = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var ct = preparation.Token;
            controlId = await a2a.SendAsync("pilot_control", ct);
            targetId = await a2a.SendAsync("pilot_target", ct);
            var control = await a2a.WaitAdmittedAsync(controlId, ct);
            var target = await a2a.WaitAdmittedAsync(targetId, ct);

            stage = "native-identity";
            var boot = Guid.Parse(await GuestAsync(request.Distribution, ct, "/usr/bin/cat", "/proc/sys/kernel/random/boot_id"));
            targetRoot = await NativeRootAsync(request.Distribution, target, ct);
            controlRoot = await NativeRootAsync(request.Distribution, control, ct);

            stage = "sensor-registration";
            string sensorToken = await a2a.RegisterSensorAsync(targetId, ct);

            stage = "inputs";
            var (binding, profile, plan) = Inputs(request, target, control, boot, targetRoot, controlRoot, At("mailbox.sqlite"),
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            File.WriteAllBytes(At("profile.json"), profile);
            File.WriteAllBytes(At("binding.json"), JsonSerializer.SerializeToUtf8Bytes(binding, Binding.Json));
            File.WriteAllBytes(At("plan.json"), JsonSerializer.SerializeToUtf8Bytes(plan, Binding.Json));

            stage = "sidecar-start";
            string intakeToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            sidecar = StartSidecar(At("binding.json"), At("mailbox.sqlite"), request.SidecarCertificateFile,
                At("profile.json"), sensorToken, intakeToken);
            await WaitListeningAsync(sidecar, request.SidecarPort, ct);

            // Written last: the event must still be fresh when the runner delivers it.
            stage = "check";
            File.WriteAllBytes(At("event.json"), SyntheticEvent(binding, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
            Environment.SetEnvironmentVariable("SPLAT_ALERT_TOKEN", intakeToken);
            string[] inputs = [At("plan.json"), At("binding.json"), At("profile.json"), At("event.json")];
            if (await FalconPilot.TryRunAsync(["--check-falcon-pilot", .. inputs]) != 0)
                throw new InvalidDataException("The assembled pilot inputs did not validate.");
            stage = "run";
            result = await FalconPilot.TryRunAsync(["--run-falcon-pilot", .. inputs, At("evidence")]) ?? 2;
            stage = result == 0 ? "complete" : "run-refused";
            return result;
        }
        finally
        {
            Environment.SetEnvironmentVariable("SPLAT_ALERT_TOKEN", null);
            if (sidecar is { HasExited: false })
            {
                try { sidecar.Kill(); } catch (InvalidOperationException) when (sidecar.HasExited) { }
                sidecar.WaitForExit(5000);
            }
            sidecar?.Dispose();
            // A refused or partial run must not leave a fixture running out the rest of its lease. The
            // control a passing run proved alive ends here too, by an owner CancelTask the ledger records.
            try
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                cancelledAtCleanup = await a2a.CancelUnfinishedAsync([targetId, controlId], cleanup.Token);
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or InvalidOperationException
                or InvalidDataException or JsonException or KeyNotFoundException)
            {
                Console.Error.WriteLine($"Cleanup could not confirm both pilot tasks ended ({ex.GetType().Name}); each ends by its lease deadline.");
            }
            if (result != 0) Console.Error.WriteLine($"Cancellation pilot stopped at stage '{stage}'.");
            File.WriteAllBytes(At("orchestration.json"), JsonSerializer.SerializeToUtf8Bytes(new { version = 1, stage, result,
                targetTask = targetId, controlTask = controlId, targetRoot, controlRoot, cancelledAtCleanup,
                request.Distribution, request.A2aPort, request.SidecarPort, request.DaemonKeySha256, request.GuestWitnessSha256 }, Binding.Json));
        }
    }

    // Null while the guest has not yet installed the lease. Once it has, every fact the plan pins must
    // be present and agree with the cgroup SPLAT admitted the task to, or the run stops here.
    internal static AdmittedTask? Admitted(JsonElement task)
    {
        string id = task.GetProperty("id").GetString() ?? throw new InvalidDataException("Task without an id.");
        string? state = task.GetProperty("status").GetProperty("state").GetString();
        if (state is "TASK_STATE_COMPLETED" or "TASK_STATE_FAILED" or "TASK_STATE_CANCELED" or "TASK_STATE_REJECTED")
            throw new InvalidDataException($"Pilot task {id} ended ({state}) before the proof could pin it.");
        var metadata = task.GetProperty("metadata").GetProperty(Control.Extension);
        if (state != "TASK_STATE_WORKING" || !metadata.TryGetProperty("installedLease", out var lease)
            || lease.ValueKind != JsonValueKind.Object) return null;
        string mission = Guid.ParseExact(id, "N").ToString("D");
        string? effective = lease.TryGetProperty("effectivePolicySha256", out var stated) ? stated.GetString() : null;
        if (!CancellationReceiptProof.IsHash(effective))
            throw new InvalidDataException("The guest daemon did not state its installed policy at admission; install the daemon built from this tree.");
        string cgroupPath = lease.GetProperty("cgroupPath").GetString() ?? "";
        if (!lease.GetProperty("enforcing").GetBoolean() || cgroupPath != "/sys/fs/cgroup/splat_leases/mission_" + mission
            || metadata.GetProperty("leaseCgroup").GetString() != "/splat_leases/mission_" + mission)
            throw new InvalidDataException($"Pilot task {id} is not enforced in the cgroup SPLAT admitted it to.");
        return new AdmittedTask(id, lease.GetProperty("cgroupId").GetUInt64(), cgroupPath,
            metadata.GetProperty("executionContextJson").GetString() ?? throw new InvalidDataException("No execution context bytes."),
            metadata.GetProperty("executionPolicySha256").GetString() ?? throw new InvalidDataException("No execution policy digest."),
            effective!, CancellationReceiptProof.ContextIdentityHash(metadata.GetProperty("executionContext")));
    }

    // /proc/<pid>/stat is "pid (comm) state ppid ...", and comm may itself hold spaces and ')'. Fields are
    // read after the LAST ')': state first, ppid second, starttime (field 22 of the line) twentieth.
    internal static (int Pid, int Ppid, ulong StartTicks) ParseStat(string stat)
    {
        stat = stat.Trim();
        int open = stat.IndexOf(" (", StringComparison.Ordinal), close = stat.LastIndexOf(')');
        string[] fields = open > 0 && close > open ? stat[(close + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries) : [];
        if (fields.Length < 20 || !int.TryParse(stat.AsSpan(0, open), NumberStyles.None, CultureInfo.InvariantCulture, out int pid)
            || !int.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out int ppid)
            || !ulong.TryParse(fields[19], NumberStyles.None, CultureInfo.InvariantCulture, out ulong start) || pid <= 0 || start == 0)
            throw new InvalidDataException("Unreadable procfs stat line.");
        return (pid, ppid, start);
    }

    // The daemon's child joins the lease cgroup before it execs the tool, so the one member whose parent
    // is outside the cgroup is the workload root, whatever it has spawned since.
    internal static NativeRoot Root(IReadOnlyCollection<(int Pid, int Ppid, ulong StartTicks)> members)
    {
        var roots = members.Where(m => !members.Any(other => other.Pid == m.Ppid)).ToArray();
        if (roots.Length != 1) throw new InvalidDataException("A pilot lease cgroup must hold exactly one workload root.");
        return new NativeRoot(roots[0].Pid, roots[0].StartTicks);
    }

    internal static (Binding Binding, byte[] Profile, FalconPilotPlan Plan) Inputs(PilotRequest request, AdmittedTask target,
        AdmittedTask control, Guid boot, NativeRoot targetRoot, NativeRoot controlRoot, string mailbox, long now)
    {
        // Labelled synthetic by its own event type and tenant: B's contract experiment, never a vendor event.
        byte[] profile = JsonSerializer.SerializeToUtf8Bytes(new FalconProfile(1, EventType, "/event_simpleName", "/cid",
            "/aid", "/TargetProcessId", "/rule", "/id", "/timestamp", "unix-ms"), Binding.Json);
        var identity = new FalconIdentity("splat-synthetic-tenant", "splat-synthetic-agent",
            "splat-synthetic-process-" + Guid.NewGuid().ToString("N"), now, CancellationReceiptProof.Hash(profile));
        var binding = new Binding(target.TaskId, request.Distribution, boot, target.Cgroup, targetRoot.Pid,
            targetRoot.StartTicks, "falcon", Rule, now + 600_000, request.SidecarPort, request.A2aPort, identity);
        var plan = new FalconPilotPlan(1, new ReceiptExpectation(target.TaskId, Guid.ParseExact(target.TaskId, "N").ToString("D"),
                target.Cgroup, request.DaemonKeySha256, target.ExecutionContext, target.ExecutionPolicySha256,
                target.EffectivePolicySha256),
            control.TaskId, control.ContextIdentitySha256,
            new WitnessSpec(boot, new WitnessProcess(target.TaskId, target.Cgroup, targetRoot.Pid, targetRoot.StartTicks),
                new WitnessProcess(control.TaskId, control.Cgroup, controlRoot.Pid, controlRoot.StartTicks)),
            request.Distribution, request.GuestWitnessPath, request.GuestWitnessSha256, request.SidecarCertificateSha256,
            request.A2aCertificateSha256, request.TimeoutSeconds, "synthetic-control", request.OperatorEvidenceReference, mailbox);
        binding.Check(now);
        plan.Check(binding);
        return (binding, profile, plan);
    }

    internal static byte[] SyntheticEvent(Binding binding, long observedUnixMs) =>
        JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["splatSyntheticControl"] = true, ["event_simpleName"] = EventType, ["cid"] = binding.Falcon!.TenantId,
            ["aid"] = binding.Falcon.AgentId, ["TargetProcessId"] = binding.Falcon.ProcessInstanceId, ["rule"] = binding.Rule,
            ["id"] = "splat-synthetic-" + Guid.NewGuid().ToString("N"), ["timestamp"] = observedUnixMs
        });

    private static async Task<NativeRoot> NativeRootAsync(string distribution, AdmittedTask task, CancellationToken ct)
    {
        // The guest's own view of the cgroup SPLAT named: its inode must be the id the daemon reported,
        // or this read is looking at another guest's tree and the plan would pin the wrong processes.
        if (ulong.Parse(await GuestAsync(distribution, ct, "/usr/bin/stat", "-c", "%i", task.CgroupPath),
                NumberStyles.None, CultureInfo.InvariantCulture) != task.Cgroup)
            throw new InvalidDataException($"The guest's cgroup for task {task.TaskId} is not the one SPLAT reported; check -Distro.");
        var members = new List<(int Pid, int Ppid, ulong StartTicks)>();
        foreach (string line in (await GuestAsync(distribution, ct, "/usr/bin/cat", task.CgroupPath + "/cgroup.procs"))
                     .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            members.Add(ParseStat(await GuestAsync(distribution, ct, "/usr/bin/cat",
                $"/proc/{int.Parse(line, NumberStyles.None, CultureInfo.InvariantCulture)}/stat")));
        return Root(members);
    }

    // Reads only, as the guest's default user, with no shell between the argument and the program.
    private static async Task<string> GuestAsync(string distribution, CancellationToken ct, params string[] argv)
    {
        var start = new ProcessStartInfo("wsl.exe") { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string arg in (string[])["-d", distribution, "-e", .. argv]) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new IOException("Cannot start wsl.exe.");
        var output = process.StandardOutput.ReadToEndAsync(ct);
        var errors = process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);
        if (process.ExitCode != 0) throw new IOException($"Guest read failed: {string.Join(' ', argv)}: {(await errors).Trim()}");
        return (await output).Trim();
    }

    private static Process StartSidecar(string binding, string mailbox, string certificate, string profile,
        string sensorToken, string intakeToken)
    {
        // This same build, started the way an operator starts it: through dotnet, or as its own apphost.
        string self = Environment.ProcessPath ?? throw new IOException("Cannot locate this sidecar build.");
        var start = new ProcessStartInfo(self) { UseShellExecute = false };
        if (Path.GetFileNameWithoutExtension(self).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(typeof(PilotOrchestrator).Assembly.Location);
        foreach (string arg in new[] { binding, mailbox, certificate, profile }) start.ArgumentList.Add(arg);
        // The sensor credential reads and cancels the target alone; the owner's never reaches the sidecar.
        start.Environment["SPLAT_A2A_CALLER_TOKEN"] = sensorToken;
        start.Environment["SPLAT_ALERT_TOKEN"] = intakeToken;
        return Process.Start(start) ?? throw new IOException("Cannot start the alert sidecar.");
    }

    private static async Task WaitListeningAsync(Process sidecar, int port, CancellationToken ct)
    {
        while (true)
        {
            if (sidecar.HasExited) throw new IOException($"The alert sidecar exited ({sidecar.ExitCode}) before it listened.");
            try { using var probe = new TcpClient(); await probe.ConnectAsync(IPAddress.Loopback, port, ct); return; }
            catch (SocketException) { await Task.Delay(200, ct); }
        }
    }

    private sealed class A2a(HttpClient client, int port, string token)
    {
        private async Task<JsonElement> CallAsync(string method, object parameters, CancellationToken ct)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, $"https://127.0.0.1:{port}/a2a");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Add("A2A-Version", "1.0"); request.Headers.Add("A2A-Extensions", Control.Extension);
            string rpcId = Guid.NewGuid().ToString("N");
            request.Content = new StringContent(JsonSerializer.Serialize(new { jsonrpc = "2.0", id = rpcId, method,
                @params = parameters }), Encoding.UTF8, "application/json");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            byte[] body = await FalconPilot.ReadBounded(response, ct);
            if (body.Length == 0) throw new HttpRequestException($"A2A {method} answered HTTP {(int)response.StatusCode} with no body.");
            using var document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 32 });
            var root = document.RootElement;
            if (root.TryGetProperty("error", out var error))
                throw new InvalidOperationException($"A2A {method} refused: {error.GetProperty("message").GetString()}");
            if (!response.IsSuccessStatusCode || root.GetProperty("id").GetString() != rpcId)
                throw new InvalidDataException($"A2A {method} answer was not this request's.");
            return root.GetProperty("result").Clone();
        }

        internal async Task<string> SendAsync(string skill, CancellationToken ct) =>
            (await CallAsync("SendMessage", new
            {
                message = new { messageId = Guid.NewGuid().ToString("N"), role = "ROLE_USER",
                    parts = new[] { new { data = new { skill, parameters = new { } } } } },
                configuration = new { returnImmediately = true, historyLength = 0 }
            }, ct)).GetProperty("task").GetProperty("id").GetString() ?? throw new InvalidDataException("SendMessage returned no task.");

        private Task<JsonElement> GetAsync(string id, CancellationToken ct) => CallAsync("GetTask", new { id, historyLength = 0 }, ct);

        internal async Task<AdmittedTask> WaitAdmittedAsync(string id, CancellationToken ct)
        {
            while (true)
            {
                if (Admitted(await GetAsync(id, ct)) is { } admitted) return admitted;
                await Task.Delay(250, ct);
            }
        }

        internal async Task<string> RegisterSensorAsync(string id, CancellationToken ct) =>
            (await CallAsync("splat/RegisterSensor", new { id }, ct)).GetProperty("token").GetString()
                ?? throw new InvalidDataException("RegisterSensor returned no credential.");

        internal async Task<string[]> CancelUnfinishedAsync(string?[] ids, CancellationToken ct)
        {
            var cancelled = new List<string>();
            foreach (string id in ids.OfType<string>())
            {
                if (Control.Outcome(await GetAsync(id, ct)) != null) continue;
                await CallAsync("CancelTask", new { id, historyLength = 0 }, ct);
                cancelled.Add(id);
                while (Control.Outcome(await GetAsync(id, ct)) == null) await Task.Delay(250, ct);
            }
            return cancelled.ToArray();
        }
    }
}
