using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Splat.AlertSidecar;

internal static class PilotProofChecks
{
    internal static void Run(string directory, Action<bool> check)
    {
        // Real RSA operations with test-generated keys. These are format/verification negative
        // controls, not daemon receipts and not evidence that a native workload was terminated.
        int checks = 0;
        void Verify(bool value, string name) { check(value); checks++; Console.WriteLine("PASS proof: " + name); }
        void Refuse(Action action, string name)
        {
            bool refused = false;
            try { action(); }
            catch (Exception ex) when (ex is InvalidDataException or JsonException or InvalidOperationException
                or KeyNotFoundException or CryptographicException or FormatException) { refused = true; }
            Verify(refused, name);
        }
        using var key = RSA.Create(2048);
        byte[] publicKey = key.ExportRSAPublicKey();
        string keyId = CancellationReceiptProof.Hash(publicKey);
        Guid task = Guid.NewGuid();
        string context = JsonSerializer.Serialize(new { agentId = "splat", contractSha256 = new string('a', 64),
            tenantId = "tenant", callerId = "caller", taskId = task.ToString("N") });
        var expected = new ReceiptExpectation(task.ToString("N"), task.ToString("D"), 123, keyId,
            context, "none", new string('b', 64));
        string Escape(string value) => value.Replace("\\", "\\\\").Replace("|", "\\p").Replace("\n", "\\n");
        string Canonical(string? field = null, string? value = null)
        {
            var fields = new Dictionary<string, string> {
                ["mission"] = expected.MissionId, ["cgroup"] = "123", ["enforcing"] = "true", ["uid"] = "200000",
                ["exit"] = "-1", ["counted"] = "0", ["reported"] = "0", ["dropped"] = "0",
                ["workspace"] = "/test/pipe|and\\backslash\nnewline", ["workspaceRemoved"] = "true",
                ["executionPolicySha256"] = "none", ["executionContext"] = context,
                ["effectivePolicySha256"] = expected.EffectivePolicySha256, ["workloadDrained"] = "true", ["cancellationAccepted"] = "true" };
            if (field != null) fields[field] = value!;
            return "splat-lease-outcome/2|" + string.Join('|', fields.Select(f => f.Key + "=" + Escape(f.Value)));
        }
        JsonElement Receipt(string? canonical = null, RSA? signer = null, bool corrupt = false)
        {
            canonical ??= Canonical(); signer ??= key;
            byte[] bytes = signer.ExportRSAPublicKey();
            var signature = signer.SignData(Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            if (corrupt) signature[0] ^= 1;
            return JsonSerializer.SerializeToElement(new { SignedOutcome = canonical,
                OutcomeSignature = Convert.ToBase64String(signature), OutcomePublicKey = Convert.ToBase64String(bytes),
                OutcomeKeyId = CancellationReceiptProof.Hash(bytes) });
        }
        JsonElement TaskArtifact(JsonElement receipt, string state = "TASK_STATE_CANCELED", bool requested = true,
            bool dispatched = true, bool duplicate = false, string? id = null)
        {
            string line = JsonSerializer.Serialize(new { agentLease = receipt });
            return JsonSerializer.SerializeToElement(new { id = id ?? expected.TaskId, status = new { state },
                artifacts = new[] { new { parts = new[] { new { text = "[Output]\n" + line + (duplicate ? "\n" + line : "") } } } },
                metadata = new Dictionary<string, object> { [Control.Extension] = new {
                    cancellationRequested = requested, dispatched, workloadTerminationConfirmed = true } } });
        }
        var validReceipt = Receipt();
        var result = CancellationReceiptProof.VerifyReceipt(validReceipt, expected);
        Verify(result.SignatureVerified && result.DaemonAttestsCancellation && result.DaemonAttestsDrain,
            "real RSA signature plus exact invocation accepted");
        Verify(result.SignedOutcomeSha256 == CancellationReceiptProof.Hash(Encoding.UTF8.GetBytes(Canonical())),
            "signed bytes retained without canonical reconstruction");
        Verify(CancellationReceiptProof.VerifyTask(TaskArtifact(validReceipt), expected).TaskId == expected.TaskId,
            "shipping A2A text-artifact shape extracted and verified");
        Refuse(() => CancellationReceiptProof.VerifyReceipt(Receipt(corrupt: true), expected), "signature tampering refused");
        using var otherKey = RSA.Create(2048);
        Refuse(() => CancellationReceiptProof.VerifyReceipt(Receipt(signer: otherKey), expected), "valid attacker signature cannot replace pinned daemon key");
        foreach (var (field, value) in new[] { ("mission", Guid.NewGuid().ToString()), ("cgroup", "124"),
            ("enforcing", "false"), ("executionContext", "{\"taskId\":\"other\"}"),
            ("executionPolicySha256", new string('c', 64)), ("effectivePolicySha256", new string('d', 64)),
            ("workloadDrained", "false"), ("cancellationAccepted", "false") })
            Refuse(() => CancellationReceiptProof.VerifyReceipt(Receipt(Canonical(field, value)), expected), "signed wrong " + field + " refused");
        Refuse(() => CancellationReceiptProof.VerifyReceipt(Receipt(Canonical().Replace("splat-lease-outcome/2", "splat-lease-outcome/1")), expected), "legacy unbound receipt refused");
        Refuse(() => CancellationReceiptProof.VerifyReceipt(Receipt(Canonical() + "|extra=value"), expected), "extra canonical field refused");
        Refuse(() => CancellationReceiptProof.VerifyReceipt(Receipt(Canonical().Replace("uid=200000", "mission=duplicate")), expected), "duplicate canonical field refused");
        Refuse(() => CancellationReceiptProof.VerifyReceipt(Receipt(Canonical().Replace("uid=200000", "uid=\\q")), expected), "unknown canonical escape refused");
        Refuse(() => CancellationReceiptProof.VerifyReceipt(Receipt(Canonical().Replace("|uid=200000", "")), expected), "missing canonical field refused");
        Refuse(() => CancellationReceiptProof.VerifyTask(TaskArtifact(validReceipt, state: "TASK_STATE_COMPLETED"), expected), "natural completion is not cancellation proof");
        Refuse(() => CancellationReceiptProof.VerifyTask(TaskArtifact(validReceipt, requested: false), expected), "missing cancellation request refused");
        Refuse(() => CancellationReceiptProof.VerifyTask(TaskArtifact(validReceipt, dispatched: false), expected), "never-started task cannot prove a kill");
        Refuse(() => CancellationReceiptProof.VerifyTask(TaskArtifact(validReceipt, duplicate: true), expected), "ambiguous artifacts refused");
        Refuse(() => CancellationReceiptProof.VerifyTask(TaskArtifact(validReceipt, id: Guid.NewGuid().ToString("N")), expected), "wrong A2A task refused");
        Refuse(() => CancellationReceiptProof.VerifyReceipt(validReceipt, expected with { TaskId = Guid.NewGuid().ToString("N") }), "expected context/task mismatch refused");
        Refuse(() => CancellationReceiptProof.VerifyReceipt(JsonSerializer.SerializeToElement(new { WorkloadDrained = true }), expected), "unsigned host drain flag is insufficient");
        var altered = JsonSerializer.SerializeToElement(new { SignedOutcome = Canonical() + " ",
            OutcomeSignature = validReceipt.GetProperty("OutcomeSignature").GetString(),
            OutcomePublicKey = validReceipt.GetProperty("OutcomePublicKey").GetString(), OutcomeKeyId = keyId });
        Refuse(() => CancellationReceiptProof.VerifyReceipt(altered, expected), "one changed signed byte refused");

        byte[] original = Encoding.UTF8.GetBytes("{\"a/b\":{\"~field\":18446744073709551615},\"other\":\"untouched\"}");
        byte[] copy = (byte[])original.Clone();
        using var mutation = StrictJson.Parse(FalconPilot.Mutate(original, "/a~1b/~0field"));
        Verify(original.SequenceEqual(copy), "pilot negative-control construction preserves original event bytes");
        Verify(mutation.RootElement.GetProperty("other").GetString() == "untouched"
            && mutation.RootElement.GetProperty("a/b").GetProperty("~field").ValueKind == JsonValueKind.String,
            "reviewed escaped JSON pointer selects only negative-control field");
        Refuse(() => FalconPilot.Mutate(original, "/absent"), "missing mutation field refused");
        JsonElement Working(bool cancel = false, string state = "TASK_STATE_WORKING") => JsonSerializer.SerializeToElement(new {
            id = expected.TaskId, status = new { state }, metadata = new Dictionary<string, object> {
                [Control.Extension] = new { dispatched = true, cancellationRequested = cancel,
                    executionContext = JsonSerializer.Deserialize<JsonElement>(context) } } });
        using var contextDocument = JsonDocument.Parse(context);
        string contextHash = CancellationReceiptProof.ContextIdentityHash(contextDocument.RootElement);
        using var withNull = JsonDocument.Parse(context[..^1] + ",\"parentTaskId\":null}");
        Verify(CancellationReceiptProof.ContextIdentityHash(withNull.RootElement) == contextHash,
            "A2A omitted nulls match native context identity without rewriting signed bytes");
        FalconPilot.RequireWorking(Working(), expected.TaskId, contextHash);
        Verify(true, "working control requires exact context and task");
        Refuse(() => FalconPilot.RequireWorking(Working(true), expected.TaskId, contextHash), "already-canceling control refused");
        Refuse(() => FalconPilot.RequireWorking(Working(), expected.TaskId, new string('e', 64)), "control context substitution refused");
        Refuse(() => FalconPilot.RequireWorking(Working(state: "TASK_STATE_COMPLETED"), expected.TaskId, contextHash), "finished control cannot establish survival");

        var binding = new Binding(expected.TaskId, "node", Guid.NewGuid(), 123, 77, 9000, "falcon", "rule",
            DateTimeOffset.UtcNow.AddMinutes(2).ToUnixTimeMilliseconds(), 19443, 19444,
            new FalconIdentity("tenant", "agent", "opaque", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), new string('a', 64)));
        string otherTask = Guid.NewGuid().ToString("N");
        var witness = new WitnessSpec(binding.Boot, new(expected.TaskId, 123, 77, 9000), new(otherTask, 456, 78, 9001));
        var plan = new FalconPilotPlan(1, expected, otherTask, contextHash, witness, "SplatProof", "/opt/splat/witness.py",
            new string('a', 64), new string('b', 64), new string('c', 64), 60, "synthetic-control", "unit-test-only",
            Path.Combine(directory, "pilot-mailbox.sqlite"));
        plan.Check(binding); Verify(true, "disjoint pinned pilot identities accepted");
        Refuse(() => (plan with { Witness = witness with { Control = witness.Target } }).Check(binding), "target/control identity overlap refused");
        Refuse(() => (plan with { TimeoutSeconds = 121 }).Check(binding), "unbounded pilot timeout refused");
        Refuse(() => (plan with { SidecarCertificateSha256 = "" }).Check(binding), "missing HTTPS pin refused");
        Refuse(() => (plan with { EventOrigin = "live-verified" }).Check(binding), "unsupported vendor-origin claim refused");
        JsonElement Sample(bool drain = true, bool advance = true, ulong cpu = 12, int? pid = null) => JsonSerializer.SerializeToElement(new {
            version = 1, phase = "after", ok = true, sourceSha256 = plan.GuestWitnessSha256, boot = witness.Boot,
            targetTask = expected.TaskId, controlTask = otherTask, originalTargetExited = true,
            targetCgroupDrained = drain, controlAdvanced = advance, controlCpuAtAfterStart = 11, control = new {
                taskId = otherTask, cgroup = witness.Control.Cgroup, pid = pid ?? witness.Control.Pid,
                startTicks = witness.Control.StartTicks, originalPidfdAlive = true, cgroupPopulated = true, cpuTicks = cpu } });
        NativeWitness.ValidateSample(Sample(), plan, "after", 10); Verify(true, "native evidence schema requires identity and progress");
        Refuse(() => NativeWitness.ValidateSample(Sample(drain: false), plan, "after", 10), "surviving target descendants refuse proof");
        Refuse(() => NativeWitness.ValidateSample(Sample(advance: false), plan, "after", 10), "missing control progress refuses proof");
        Refuse(() => NativeWitness.ValidateSample(Sample(cpu: 10), plan, "after", 10), "claimed progress with unchanged CPU ticks refused");
        Refuse(() => NativeWitness.ValidateSample(Sample(cpu: 11), plan, "after", 10), "only pre-cancellation control progress is insufficient");
        Refuse(() => NativeWitness.ValidateSample(Sample(pid: 999), plan, "after", 10), "witness recycled/wrong control PID refused");
        var mailbox = new Latch(plan.MailboxPath, binding.Fingerprint);
        Verify(FalconPilot.ReadMailbox(plan.MailboxPath, binding.Fingerprint).State == "idle", "read-only mailbox inspection sees real idle SQLite row");
        Refuse(() => FalconPilot.ReadMailbox(plan.MailboxPath, "wrong"), "read-only mailbox identity mismatch refused");
        mailbox.Admit("proof-alert", 100, 200);
        var persisted = FalconPilot.ReadMailbox(plan.MailboxPath, binding.Fingerprint);
        Verify(persisted.State == "pending" && persisted.Alert == "proof-alert" && persisted.Observed == 100,
            "separate SQLite reader sees durably admitted alert");
        string missingPath = Path.Combine(directory, "does-not-exist.sqlite");
        bool missingRefused = false;
        try { FalconPilot.ReadMailbox(missingPath, binding.Fingerprint); }
        catch (Microsoft.Data.Sqlite.SqliteException) { missingRefused = true; }
        Verify(missingRefused && !File.Exists(missingPath), "read-only inspection never creates absent mailbox");
        var pilotProfile = new FalconProfile(1, "pilot-test", "/type", "/tenant", "/agent", "/process", "/rule", "/id", "/time", "unix-ms");
        byte[] pilotProfileBytes = JsonSerializer.SerializeToUtf8Bytes(pilotProfile, Binding.Json);
        var pilotBinding = binding with { Falcon = binding.Falcon! with { ProfileSha256 = CancellationReceiptProof.Hash(pilotProfileBytes) } };
        string planFile = Path.Combine(directory, "pilot-plan.json"), bindingFile = Path.Combine(directory, "pilot-binding.json"),
            profileFile = Path.Combine(directory, "pilot-profile.json"), eventFile = Path.Combine(directory, "pilot-event.json");
        File.WriteAllBytes(planFile, JsonSerializer.SerializeToUtf8Bytes(plan, Binding.Json));
        File.WriteAllBytes(bindingFile, JsonSerializer.SerializeToUtf8Bytes(pilotBinding, Binding.Json));
        File.WriteAllBytes(profileFile, pilotProfileBytes);
        File.WriteAllBytes(eventFile, JsonSerializer.SerializeToUtf8Bytes(new { type = "pilot-test", tenant = "tenant", agent = "agent",
            process = "opaque", rule = "rule", id = "offline-fixture", time = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }));
        Verify(FalconPilot.TryRunAsync(["--check-falcon-pilot", planFile, bindingFile, profileFile, eventFile]).GetAwaiter().GetResult() == 0,
            "offline CLI validates actual files without network or observer credentials");
        File.WriteAllBytes(profileFile, pilotProfileBytes.Concat(new byte[] { 32 }).ToArray());
        Refuse(() => FalconPilot.LoadInputs(planFile, bindingFile, profileFile, eventFile), "offline and live paths share profile pin validation");
        Console.WriteLine($"PASS {checks} cancellation-proof/pilot checks; synthetic receipts, no native or vendor success claimed.");
    }
}
