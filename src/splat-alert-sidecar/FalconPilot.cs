using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;

namespace Splat.AlertSidecar;

internal sealed record WitnessProcess(string TaskId, ulong Cgroup, int Pid, ulong StartTicks);
internal sealed record WitnessSpec(Guid Boot, WitnessProcess Target, WitnessProcess Control);
internal sealed record FalconPilotPlan(int Version, ReceiptExpectation Target, string ControlTaskId,
    string ControlExecutionContextSha256, WitnessSpec Witness, string Distribution,
    string GuestWitnessPath, string GuestWitnessSha256, string SidecarCertificateSha256,
    string A2aCertificateSha256, int TimeoutSeconds, string EventOrigin, string OperatorEvidenceReference, string MailboxPath)
{
    internal void Check(Binding binding)
    {
        if (Target is null || Witness is null || Witness.Target is null || Witness.Control is null)
            throw new InvalidDataException("Missing pinned target/witness identity.");
        Target.Check();
        bool Valid(WitnessProcess p) => Guid.TryParseExact(p.TaskId, "N", out var id) && id != Guid.Empty
            && p.Cgroup > 0 && p.Pid > 0 && p.StartTicks > 0;
        if (Version != 1 || Target.TaskId != binding.TaskId || Target.Cgroup != binding.Cgroup
            || !Valid(Witness.Target) || !Valid(Witness.Control) || Witness.Boot != binding.Boot
            || Witness.Target.TaskId != Target.TaskId || Witness.Target.Cgroup != Target.Cgroup
            || Witness.Target.Pid != binding.Pid || Witness.Target.StartTicks != binding.StartTicks
            || Witness.Control.TaskId != ControlTaskId || ControlTaskId == Target.TaskId
            || Witness.Control.Cgroup == Target.Cgroup || Witness.Control.Pid == Witness.Target.Pid
            || !CancellationReceiptProof.IsHash(ControlExecutionContextSha256)
            || !CancellationReceiptProof.IsHash(GuestWitnessSha256)
            || !CancellationReceiptProof.IsHash(SidecarCertificateSha256)
            || !CancellationReceiptProof.IsHash(A2aCertificateSha256)
            || !Binding.ValidIdentifier(Distribution) || Distribution.StartsWith('-')
            || GuestWitnessPath is not { Length: > 1 and <= 1024 }
            || !GuestWitnessPath.StartsWith("/", StringComparison.Ordinal) || GuestWitnessPath.Any(char.IsControl)
            || TimeoutSeconds is < 5 or > 120 || EventOrigin is not ("synthetic-control" or "operator-captured-falcon")
            || !Binding.ValidIdentifier(OperatorEvidenceReference) || MailboxPath is not { Length: > 0 }
            || !Path.IsPathFullyQualified(MailboxPath))
            throw new InvalidDataException("Pilot plan is incomplete, unbounded or targets overlap.");
    }
}

internal static class FalconPilot
{
    internal sealed record Inputs(FalconPilotPlan Plan, Binding Binding, FalconProfile Profile,
        Alert OriginalAlert, byte[] PlanBytes, byte[] BindingBytes, byte[] ProfileBytes, byte[] EventBytes);
    internal static Inputs LoadInputs(string planPath, string bindingPath, string profilePath, string eventPath)
    {
        byte[] planBytes = ConfigurationFiles.Read(planPath), bindingBytes = ConfigurationFiles.Read(bindingPath);
        byte[] profileBytes = ConfigurationFiles.Read(profilePath), eventBytes = ConfigurationFiles.Read(eventPath);
        using var planDoc = StrictJson.Parse(planBytes); using var bindingDoc = StrictJson.Parse(bindingBytes);
        using var profileDoc = StrictJson.Parse(profileBytes); using var eventDoc = StrictJson.Parse(eventBytes);
        var plan = planDoc.RootElement.Deserialize<FalconPilotPlan>(Binding.Json) ?? throw new InvalidDataException("Missing plan.");
        var binding = bindingDoc.RootElement.Deserialize<Binding>(Binding.Json) ?? throw new InvalidDataException("Missing binding.");
        var profile = profileDoc.RootElement.Deserialize<FalconProfile>(Binding.Json) ?? throw new InvalidDataException("Missing profile.");
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); binding.Check(now); plan.Check(binding);
        var alert = new FalconAdapter(binding, profileBytes).Normalize(eventDoc.RootElement, now);
        return new(plan, binding, profile, alert, planBytes, bindingBytes, profileBytes, eventBytes);
    }
    internal static async Task<int?> TryRunAsync(string[] args)
    {
        if (args.Length == 0 || args[0] is not ("--verify-cancellation" or "--run-falcon-pilot" or "--check-falcon-pilot" or "--inspect-pilot-context")) return null;
        try
        {
            if (args[0] == "--check-falcon-pilot" && args.Length == 5)
            {
                var input = LoadInputs(args[1], args[2], args[3], args[4]);
                Console.WriteLine(JsonSerializer.Serialize(new { status = "VALIDATED_INPUTS_ONLY",
                    input.Plan.Target.TaskId, input.Plan.ControlTaskId, input.Plan.EventOrigin,
                    eventSha256 = CancellationReceiptProof.Hash(input.EventBytes), networkRequests = 0,
                    nativePrerequisitesChecked = false, vendorOriginIndependentlyVerified = false }, Binding.Json));
                return 0;
            }
            if (args[0] == "--inspect-pilot-context" && args.Length == 2)
            {
                using var context = StrictJson.Parse(ConfigurationFiles.Read(args[1]));
                Console.WriteLine(CancellationReceiptProof.ContextIdentityHash(context.RootElement));
                return 0;
            }
            if (args[0] == "--verify-cancellation" && args.Length == 3)
            {
                using var expectedDoc = StrictJson.Parse(ConfigurationFiles.Read(args[1]));
                var expected = expectedDoc.RootElement.Deserialize<ReceiptExpectation>(Binding.Json)
                    ?? throw new InvalidDataException("Missing receipt expectation.");
                using var task = StrictJson.Parse(ConfigurationFiles.Read(args[2], 1_048_576));
                Console.WriteLine(JsonSerializer.Serialize(CancellationReceiptProof.VerifyTask(task.RootElement, expected), Binding.Json));
                return 0;
            }
            if (args[0] == "--run-falcon-pilot" && args.Length == 6)
                return await RunAsync(args[1], args[2], args[3], args[4], args[5]);
            throw new ArgumentException("Use --verify-cancellation expectation.json task.json, or --run-falcon-pilot plan.json binding.json profile.json event.json NEW-output-directory.");
        }
        // InvalidDataException is not an IOException, and it is how most refusals here are raised.
        catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or InvalidOperationException or ArgumentException
            or UnauthorizedAccessException or HttpRequestException or OperationCanceledException or System.Security.Cryptography.CryptographicException
            or System.ComponentModel.Win32Exception or KeyNotFoundException or FormatException or SqliteException)
        {
            Console.Error.WriteLine("Cancellation proof/pilot refused: " + ex.GetType().Name);
            return 2;
        }
    }

    private static async Task<int> RunAsync(string planPath, string bindingPath, string profilePath, string eventPath, string output)
    {
        var input = LoadInputs(planPath, bindingPath, profilePath, eventPath);
        var (plan, binding, profile, originalAlert, planBytes, bindingBytes, profileBytes, eventBytes) = input;
        string intakeToken = Credentials.Required("SPLAT_ALERT_TOKEN");
        if (Convert.FromBase64String(intakeToken).Length != 32) throw new InvalidDataException("Intake token must encode 32 bytes.");
        string controlToken = Credentials.Required("SPLAT_A2A_CALLER_TOKEN");
        if (Directory.Exists(output)) throw new IOException("Use a new output directory; evidence is never overwritten.");
        Directory.CreateDirectory(output);
        using var ownership = new FileStream(Path.Combine(output, "run.owner"), FileMode.CreateNew, FileAccess.Write, FileShare.None);
        var hashes = new Dictionary<string, string>();
        void Save(string name, ReadOnlySpan<byte> bytes)
        {
            using var file = new FileStream(Path.Combine(output, name), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            file.Write(bytes); file.Flush(true); hashes.Add(name, CancellationReceiptProof.Hash(bytes));
        }
        void SaveJson(string name, object value) => Save(name, JsonSerializer.SerializeToUtf8Bytes(value, Binding.Json));
        string status = "INCOMPLETE", stage = "inputs";
        VerifiedCancellation? verified = null;
        try
        {
            Save("plan.json", planBytes); Save("binding.json", bindingBytes);
            Save("profile.json", profileBytes); Save("event-original.json", eventBytes);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(plan.TimeoutSeconds));
            var ct = timeout.Token;
            using var handler = new HttpClientHandler { AllowAutoRedirect = false };
            handler.ServerCertificateCustomValidationCallback = (request, certificate, _, errors) =>
                errors == SslPolicyErrors.None && certificate != null && request.RequestUri is { Host: "127.0.0.1", Scheme: "https" } uri
                && CancellationReceiptProof.Hash(certificate.RawData) == (uri.Port == binding.A2aPort ? plan.A2aCertificateSha256
                    : uri.Port == binding.ListenPort ? plan.SidecarCertificateSha256 : "invalid-port");
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
            async Task<JsonElement> GetTask(string id)
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, $"https://127.0.0.1:{binding.A2aPort}/a2a");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", controlToken);
                request.Headers.Add("A2A-Version", "1.0"); request.Headers.Add("A2A-Extensions", Control.Extension);
                string rpcId = Guid.NewGuid().ToString("N");
                request.Content = new StringContent(JsonSerializer.Serialize(new { jsonrpc = "2.0", id = rpcId,
                    method = "GetTask", @params = new { id, historyLength = 0 } }), Encoding.UTF8, "application/json");
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
                response.EnsureSuccessStatusCode();
                using var document = StrictJson.Parse(await ReadBounded(response, ct));
                var root = document.RootElement;
                if (root.TryGetProperty("error", out _) || root.GetProperty("jsonrpc").GetString() != "2.0"
                    || root.GetProperty("id").GetString() != rpcId || root.GetProperty("result").GetProperty("id").GetString() != id)
                    throw new InvalidDataException("A2A response correlation failed.");
                return root.GetProperty("result").Clone();
            }
            async Task<int> Deliver(byte[] body, bool discardBody = false)
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, $"https://127.0.0.1:{binding.ListenPort}/v1/falcon/alerts");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", intakeToken);
                request.Content = new ByteArrayContent(body); request.Content.Headers.ContentType = new("application/json");
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
                if (!discardBody) _ = await ReadBounded(response, ct);
                return (int)response.StatusCode;
            }
            stage = "pre-delivery-task-checks";
            var beforeMailbox = ReadMailbox(plan.MailboxPath, binding.Fingerprint);
            if (beforeMailbox.State != "idle") throw new InvalidDataException("Pilot requires a fresh idle task mailbox.");
            SaveJson("mailbox-before.json", beforeMailbox);
            var targetBefore = await GetTask(binding.TaskId); var controlBefore = await GetTask(plan.ControlTaskId);
            using var targetContext = StrictJson.Parse(Encoding.UTF8.GetBytes(plan.Target.ExecutionContext));
            RequireWorking(targetBefore, plan.Target.TaskId, CancellationReceiptProof.ContextIdentityHash(targetContext.RootElement));
            RequireWorking(controlBefore, plan.ControlTaskId, plan.ControlExecutionContextSha256);
            SaveJson("target-before.json", targetBefore); SaveJson("control-before.json", controlBefore);

            // The witness is a separate, read-only guest process. It holds both original pidfds
            // and cgroup directory descriptors across delivery; post-event PID lookup is not proof.
            stage = "native-witness-start";
            await using var witness = await NativeWitness.StartAsync(plan, ct);
            SaveJson("native-before.json", witness.Before);
            stage = "negative-controls";
            foreach (var (name, pointer) in new[] { ("wrong-tenant", profile.TenantPointer), ("wrong-process", profile.ProcessInstancePointer) })
            {
                byte[] negative = Mutate(eventBytes, pointer);
                int result = await Deliver(negative);
                SaveJson(name + "-result.json", new { httpStatus = result, payloadSha256 = CancellationReceiptProof.Hash(negative) });
                if (result != 409) throw new InvalidDataException("Identity negative control did not fail closed.");
                var afterNegative = ReadMailbox(plan.MailboxPath, binding.Fingerprint);
                SaveJson(name + "-mailbox.json", afterNegative);
                if (afterNegative.State != "idle") throw new InvalidDataException("Negative control changed durable cancellation state.");
            }
            SaveJson("native-after-negatives.json", await witness.SampleAsync("check", ct));
            stage = "delivery";
            // Exercise loss of the intake RESPONSE BODY, then replay the identical bytes. This
            // does not simulate loss of CancelTask's response or a sidecar process crash.
            int first = await Deliver(eventBytes, discardBody: true);
            int replay = await Deliver(eventBytes);
            SaveJson("delivery.json", new { firstHttpStatus = first, replayHttpStatus = replay, intakeResponseBodyDiscarded = true });
            if (first != 202 || replay != 202) throw new InvalidDataException("Intake/replay did not acknowledge persistence.");
            var persisted = ReadMailbox(plan.MailboxPath, binding.Fingerprint);
            SaveJson("mailbox-after-delivery.json", persisted);
            if (persisted.State == "idle" || persisted.Alert != originalAlert.AlertId || persisted.Observed != originalAlert.ObservedUnixMs)
                throw new InvalidDataException("Acknowledged intake lacks the expected durable mailbox record.");
            stage = "signed-cancellation-receipt";
            int poll = 0;
            while (true)
            {
                var target = await GetTask(binding.TaskId);
                SaveJson($"target-poll-{poll++:D4}.json", target);
                string? state = target.GetProperty("status").GetProperty("state").GetString();
                if (state == "TASK_STATE_CANCELED" && target.TryGetProperty("artifacts", out var artifacts)
                    && artifacts.ValueKind == JsonValueKind.Array && artifacts.GetArrayLength() > 0)
                {
                    verified = CancellationReceiptProof.VerifyTask(target, plan.Target);
                    SaveJson("verified-receipt.json", verified); break;
                }
                if (state is "TASK_STATE_COMPLETED" or "TASK_STATE_FAILED" or "TASK_STATE_REJECTED")
                    throw new InvalidDataException("Target terminated without the required cancellation proof.");
                await Task.Delay(250, ct);
            }
            stage = "native-drain-and-control-survival";
            SaveJson("native-after.json", await witness.SampleAsync("after", ct));
            var controlAfter = await GetTask(plan.ControlTaskId);
            RequireWorking(controlAfter, plan.ControlTaskId, plan.ControlExecutionContextSha256);
            SaveJson("control-after.json", controlAfter);
            await witness.DisposeAsync();
            status = "PASS_CANCELLATION_CHAIN"; stage = "complete";
            return 0;
        }
        finally
        {
            // Failure never becomes PASS due to a missing artifact. The manifest is unsigned;
            // its hashes establish local consistency, not independent off-host audit anchoring.
            SaveJson("manifest.json", new { version = 1, status, stage, recordedUtc = DateTimeOffset.UtcNow,
                targetTask = plan.Target.TaskId, controlTask = plan.ControlTaskId, plan.EventOrigin,
                plan.OperatorEvidenceReference, vendorOriginIndependentlyVerified = false,
                signatureVerified = verified?.SignatureVerified ?? false,
                sourceAssemblySha256 = CancellationReceiptProof.Hash(File.ReadAllBytes(typeof(FalconPilot).Assembly.Location)),
                files = hashes.ToDictionary(k => k.Key, v => v.Value) });
            Console.WriteLine($"{status}: {stage}. Vendor origin requires the operator's tenant evidence.");
        }
    }

    internal static void RequireWorking(JsonElement task, string id, string contextHash)
    {
        var metadata = task.GetProperty("metadata").GetProperty(Control.Extension);
        if (task.GetProperty("id").GetString() != id || task.GetProperty("status").GetProperty("state").GetString() != "TASK_STATE_WORKING"
            || !metadata.GetProperty("dispatched").GetBoolean() || metadata.GetProperty("cancellationRequested").GetBoolean()
            || metadata.GetProperty("executionContext").GetProperty("taskId").GetString() != id
            || CancellationReceiptProof.ContextIdentityHash(metadata.GetProperty("executionContext")) != contextHash)
            throw new InvalidDataException("Expected the independently pinned, dispatched working task.");
    }
    internal sealed record MailboxObservation(string State, string? Alert, long? Observed, long? Received);
    internal static MailboxObservation ReadMailbox(string path, string fingerprint)
    {
        // Inspection must not create a database or an idle row. A missing/mismatched mailbox
        // is a failed prerequisite, not evidence of an empty queue. No writer credential needed.
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path,
            Mode = SqliteOpenMode.ReadOnly, Pooling = false, DefaultTimeout = 1 }.ToString());
        db.Open(); using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT binding,state,alert,observed,received FROM latch WHERE slot=1";
        using var row = cmd.ExecuteReader();
        if (!row.Read() || row.GetString(0) != fingerprint) throw new InvalidDataException("Wrong or missing mailbox binding.");
        string state = row.GetString(1);
        if (state is not ("idle" or "pending" or "cancel-request-recorded" or "host-reports-drain"
            or "terminal-without-drain-proof" or "expired-unresolved")) throw new InvalidDataException("Unknown mailbox state.");
        return new(state, row.IsDBNull(2) ? null : row.GetString(2), row.IsDBNull(3) ? null : row.GetInt64(3), row.IsDBNull(4) ? null : row.GetInt64(4));
    }
    internal static byte[] Mutate(byte[] original, string pointer)
    {
        JsonPointer.Check(pointer);
        var node = JsonNode.Parse(original) ?? throw new InvalidDataException("Missing event.");
        var cursor = node;
        string[] segments = pointer.Split('/').Skip(1).Select(s => s.Replace("~1", "/").Replace("~0", "~")).ToArray();
        foreach (string segment in segments.SkipLast(1)) cursor = cursor[segment] ?? throw new InvalidDataException("Missing event field.");
        if (cursor is not JsonObject obj || !obj.ContainsKey(segments[^1])) throw new InvalidDataException("Missing event field.");
        obj[segments[^1]] = "splat-negative-control-" + Guid.NewGuid().ToString("N");
        return JsonSerializer.SerializeToUtf8Bytes(node);
    }
    internal static async Task<byte[]> ReadBounded(HttpResponseMessage response, CancellationToken ct)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var memory = new MemoryStream(); byte[] buffer = new byte[8192]; int count;
        while ((count = await stream.ReadAsync(buffer, ct)) > 0)
        {
            if (memory.Length + count > 1_048_576) throw new InvalidDataException("Response budget exceeded.");
            memory.Write(buffer, 0, count);
        }
        return memory.ToArray();
    }
}

internal sealed class NativeWitness : IAsyncDisposable
{
    private readonly Process _process;
    private readonly FalconPilotPlan _plan;
    private int _disposed;
    private ulong _controlCpuBefore;
    private readonly CancellationTokenSource _stderrStop = new();
    private readonly Task _stderrDrain;
    internal JsonElement Before { get; private set; }
    private NativeWitness(Process process, FalconPilotPlan plan)
    {
        _process = process; _plan = plan;
        _stderrDrain = WitnessWire.DrainAsync(process.StandardError.BaseStream, _stderrStop.Token);
    }
    internal static async Task<NativeWitness> StartAsync(FalconPilotPlan plan, CancellationToken ct)
    {
        var start = new ProcessStartInfo("wsl.exe") { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string arg in new[] { "-d", plan.Distribution, "-u", "root", "-e", "/usr/bin/python3", "-I", plan.GuestWitnessPath })
            start.ArgumentList.Add(arg);
        var process = Process.Start(start) ?? throw new IOException("Cannot start read-only guest witness.");
        var witness = new NativeWitness(process, plan);
        try
        {
            await WitnessWire.WriteAsync(process.StandardInput.BaseStream, JsonSerializer.Serialize(new { version = 1, plan.Witness.Boot,
                plan.Witness.Target, plan.Witness.Control, sourceSha256 = plan.GuestWitnessSha256 }, Binding.Json), ct);
            witness.Before = await witness.ReadAsync("before", ct); return witness;
        }
        catch { await witness.DisposeAsync(); throw; }
    }
    internal async Task<JsonElement> SampleAsync(string phase, CancellationToken ct)
    {
        await WitnessWire.WriteAsync(_process.StandardInput.BaseStream, phase, ct);
        return await ReadAsync(phase, ct);
    }
    private async Task<JsonElement> ReadAsync(string phase, CancellationToken ct)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct); budget.CancelAfter(TimeSpan.FromSeconds(8));
        using var doc = StrictJson.Parse(await WitnessWire.ReadAsync(_process.StandardOutput.BaseStream, budget.Token));
        var root = doc.RootElement;
        ValidateSample(root, _plan, phase, _controlCpuBefore);
        if (phase == "before") _controlCpuBefore = root.GetProperty("control").GetProperty("cpuTicks").GetUInt64();
        return root.Clone();
    }
    internal static void ValidateSample(JsonElement root, FalconPilotPlan plan, string phase, ulong controlCpuBefore)
    {
        bool Identity(JsonElement sample, WitnessProcess p) => sample.GetProperty("taskId").GetString() == p.TaskId
            && sample.GetProperty("pid").GetInt32() == p.Pid && sample.GetProperty("startTicks").GetUInt64() == p.StartTicks
            && sample.GetProperty("cgroup").GetUInt64() == p.Cgroup && sample.GetProperty("originalPidfdAlive").GetBoolean()
            && sample.GetProperty("cgroupPopulated").GetBoolean();
        if (root.GetProperty("version").GetInt32() != 1 || root.GetProperty("phase").GetString() != phase
            || !root.GetProperty("ok").GetBoolean() || root.GetProperty("sourceSha256").GetString() != plan.GuestWitnessSha256
            || root.GetProperty("boot").GetGuid() != plan.Witness.Boot || root.GetProperty("targetTask").GetString() != plan.Target.TaskId
            || root.GetProperty("controlTask").GetString() != plan.ControlTaskId
            || !Identity(root.GetProperty("control"), plan.Witness.Control))
            throw new InvalidDataException("Independent native witness refused the expected identities/outcome.");
        if (phase is "before" or "check")
        {
            if (!Identity(root.GetProperty("target"), plan.Witness.Target)) throw new InvalidDataException("Wrong native target.");
        }
        else if (phase != "after" || !root.GetProperty("originalTargetExited").GetBoolean()
            || !root.GetProperty("targetCgroupDrained").GetBoolean() || !root.GetProperty("controlAdvanced").GetBoolean()
            || root.GetProperty("controlCpuAtAfterStart").GetUInt64() < controlCpuBefore
            || root.GetProperty("control").GetProperty("cpuTicks").GetUInt64() <= root.GetProperty("controlCpuAtAfterStart").GetUInt64())
            throw new InvalidDataException("Native target drain and control progress were not both demonstrated.");
    }
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try
        {
            _process.StandardInput.Dispose();
            // Give the read-only guest observer EOF first. Only this relay is terminated if
            // cleanup stalls; never use Kill(entireProcessTree) or enumerate workload PIDs.
            using var grace = new CancellationTokenSource(TimeSpan.FromSeconds(1));
            try { await _process.WaitForExitAsync(grace.Token); }
            catch (OperationCanceledException)
            {
                try { _process.Kill(); }
                catch (InvalidOperationException) when (_process.HasExited) { }
                using var stopped = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await _process.WaitForExitAsync(stopped.Token);
            }
        }
        finally
        {
            await _stderrStop.CancelAsync();
            try { await _stderrDrain; }
            catch (OperationCanceledException) when (_stderrStop.IsCancellationRequested) { }
            finally { _stderrStop.Dispose(); _process.Dispose(); }
        }
    }
}
