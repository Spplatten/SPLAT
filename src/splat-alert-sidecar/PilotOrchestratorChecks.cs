using System.Text.Json;

namespace Splat.AlertSidecar;

internal static class PilotOrchestratorChecks
{
    internal static void Run(string directory, Action<bool> check)
    {
        // Derivations only: no A2A host and no guest. They prove the orchestrator pins what SPLAT and the
        // guest state, and hands the runner inputs its own validation accepts, not that any lease ran.
        void Verify(bool value, string name) { check(value); Console.WriteLine("PASS orchestrator: " + name); }
        void Refuse(Action action, string name)
        {
            bool refused = false;
            try { action(); }
            catch (Exception ex) when (ex is InvalidDataException or JsonException or FormatException) { refused = true; }
            Verify(refused, name);
        }

        string[] after = Enumerable.Repeat("0", 50).ToArray();
        after[0] = "S"; after[1] = "4100"; after[19] = "987654";
        string stat = "4242 (py thon) x) " + string.Join(' ', after) + "\n";
        Verify(PilotOrchestrator.ParseStat(stat) == (4242, 4100, 987654UL), "procfs stat read past a comm holding ' ' and ')'");
        Refuse(() => PilotOrchestrator.ParseStat(""), "empty stat refused");
        Refuse(() => PilotOrchestrator.ParseStat("4242 (short) S 4100"), "truncated stat refused");
        after[19] = "0";
        Refuse(() => PilotOrchestrator.ParseStat("4242 (py) " + string.Join(' ', after)), "zero start time refused");

        Verify(PilotOrchestrator.Root([(10, 1, 5UL), (11, 10, 6UL), (12, 11, 7UL)]) == new NativeRoot(10, 5),
            "workload root found among its descendants");
        Refuse(() => PilotOrchestrator.Root([(10, 1, 5UL), (20, 2, 6UL)]), "two roots in one lease cgroup refused");
        Refuse(() => PilotOrchestrator.Root([]), "empty lease cgroup refused");

        JsonElement Snapshot(Guid task, string state, ulong cgroup, Action<Dictionary<string, object>>? lease)
        {
            string id = task.ToString("N"), mission = task.ToString("D");
            // Exact wire bytes, deliberately not in sorted field order, so a re-serialization would show.
            string context = "{\"taskId\":\"" + id + "\",\"agentId\":\"cancellation-pilot\",\"contractSha256\":\""
                + new string('f', 64) + "\",\"tenantId\":\"pilot\",\"callerId\":\"operator\",\"parentTaskId\":null}";
            var installed = new Dictionary<string, object> { ["cgroupId"] = cgroup,
                ["cgroupPath"] = "/sys/fs/cgroup/splat_leases/mission_" + mission, ["enforcing"] = true,
                ["effectivePolicySha256"] = new string('e', 64) };
            lease?.Invoke(installed);
            var metadata = new Dictionary<string, object> { ["dispatched"] = true, ["cancellationRequested"] = false,
                ["leaseCgroup"] = "/splat_leases/mission_" + mission, ["executionContextJson"] = context,
                ["executionContext"] = JsonSerializer.Deserialize<JsonElement>(context), ["executionPolicySha256"] = "none" };
            if (lease != null) metadata["installedLease"] = installed;
            return JsonSerializer.SerializeToElement(new { id, status = new { state },
                metadata = new Dictionary<string, object> { [Control.Extension] = metadata } });
        }
        Guid targetTask = Guid.NewGuid(), controlTask = Guid.NewGuid();
        var target = PilotOrchestrator.Admitted(Snapshot(targetTask, "TASK_STATE_WORKING", 4242, _ => { }));
        Verify(target is { Cgroup: 4242, ExecutionPolicySha256: "none" } && target.ExecutionContext.StartsWith("{\"taskId\"")
            && target.ContextIdentitySha256 == CancellationReceiptProof.ContextIdentityHash(
                Snapshot(targetTask, "TASK_STATE_WORKING", 4242, null).GetProperty("metadata").GetProperty(Control.Extension)
                    .GetProperty("executionContext")), "admission facts pinned byte for byte while the task runs");
        Verify(PilotOrchestrator.Admitted(Snapshot(targetTask, "TASK_STATE_WORKING", 4242, null)) is null,
            "no installed lease yet means wait, not guess");
        Verify(PilotOrchestrator.Admitted(Snapshot(targetTask, "TASK_STATE_SUBMITTED", 4242, _ => { })) is null,
            "a task not yet working is waited for");
        Refuse(() => PilotOrchestrator.Admitted(Snapshot(targetTask, "TASK_STATE_WORKING", 4242, l => l.Remove("effectivePolicySha256"))),
            "a daemon that stated no installed policy is refused");
        Refuse(() => PilotOrchestrator.Admitted(Snapshot(targetTask, "TASK_STATE_WORKING", 4242, l => l["enforcing"] = false)),
            "an unenforced lease is refused");
        Refuse(() => PilotOrchestrator.Admitted(Snapshot(targetTask, "TASK_STATE_WORKING", 4242,
            l => l["cgroupPath"] = "/sys/fs/cgroup/splat_leases/mission_" + Guid.NewGuid().ToString("D"))),
            "an installed cgroup for another mission is refused");
        Refuse(() => PilotOrchestrator.Admitted(Snapshot(targetTask, "TASK_STATE_COMPLETED", 4242, _ => { })),
            "a task that ended before pinning is refused");

        string Hash(char c) => new(c, 64);
        var request = new PilotRequest(1, 19444, Hash('a'), 19443, Path.Combine(directory, "pilot.pfx"), Hash('b'),
            "SPLAT-Guest", "/usr/local/lib/splat/pilot/witness.py", Hash('c'), Hash('d'), 60, "b-synthetic-control-check");
        request.Check();
        Refuse(() => (request with { SidecarPort = request.A2aPort }).Check(), "a request reusing one port for both endpoints is refused");
        var control = PilotOrchestrator.Admitted(Snapshot(controlTask, "TASK_STATE_WORKING", 5151, _ => { }))!;
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var (binding, profile, plan) = PilotOrchestrator.Inputs(request, target!, control, Guid.NewGuid(),
            new NativeRoot(4242, 987654), new NativeRoot(5151, 987700), Path.Combine(directory, "pilot-mailbox.sqlite"), now);
        string At(string name) => Path.Combine(directory, "pilot-" + name);
        File.WriteAllBytes(At("plan.json"), JsonSerializer.SerializeToUtf8Bytes(plan, Binding.Json));
        File.WriteAllBytes(At("binding.json"), JsonSerializer.SerializeToUtf8Bytes(binding, Binding.Json));
        File.WriteAllBytes(At("profile.json"), profile);
        byte[] synthetic = PilotOrchestrator.SyntheticEvent(binding, now);
        File.WriteAllBytes(At("event.json"), synthetic);
        var loaded = FalconPilot.LoadInputs(At("plan.json"), At("binding.json"), At("profile.json"), At("event.json"));
        Verify(loaded.OriginalAlert.Pid == 4242 && loaded.OriginalAlert.Cgroup == 4242 && loaded.Plan.ControlTaskId == control.TaskId
            && loaded.Plan.Target.ExecutionContext == target!.ExecutionContext && loaded.Plan.EventOrigin == "synthetic-control",
            "assembled inputs pass the runner's own validation");
        using (var mutated = JsonDocument.Parse(FalconPilot.Mutate(synthetic, "/cid")))
            Refuse(() => new FalconAdapter(binding, profile).Normalize(mutated.RootElement, now), "the synthetic event's tenant is load-bearing");
        File.WriteAllBytes(At("plan-v2.json"), JsonSerializer.SerializeToUtf8Bytes(plan with { Version = 2 }, Binding.Json));
        Verify(FalconPilot.TryRunAsync(["--check-falcon-pilot", At("plan-v2.json"), At("binding.json"), At("profile.json"),
            At("event.json")]).GetAwaiter().GetResult() == 2, "a refused plan exits 2 rather than escaping as an exception");
    }
}
