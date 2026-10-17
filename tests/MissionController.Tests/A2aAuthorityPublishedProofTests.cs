using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Linux;
using MissionController.Infrastructure.Network.Identity;
using SplatMcp;

namespace MissionController.Tests;

public sealed class TemporaryAuthorityProofAttribute : FactAttribute
{
    public TemporaryAuthorityProofAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SPLAT_A2A_TEMPORARY_DAEMON_PID")))
            Skip = "Run probe-a2a-authority.py with the explicitly selected published host and daemon.";
    }
}

public sealed partial class A2aPublishedProofTests
{
    [TemporaryAuthorityProof]
    public async Task TwoPublishedAgentsNarrowAuthorityAndRareSensorsRunUnderSignedLeases()
    {
        string root = RepositoryRoot(), exe = Environment.GetEnvironmentVariable("SPLAT_A2A_PROOF_EXE")!;
        string directory = Environment.GetEnvironmentVariable("SPLAT_A2A_PROOF_DIRECTORY")!;
        Directory.CreateDirectory(directory);
        var checks = new Dictionary<string, bool>();
        var observations = new Dictionary<string, object>();
        var children = new List<Child>();
        var clients = new List<HttpClient>();
        bool passed = false;
        void Check(string name, bool value) { checks.Add(name, value); Assert.True(value, name + "; " + directory); }
        using var certificate = A2aBridgeTests.Certificate();
        using var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string certFile = Path.Combine(directory, "server.pfx"), keyFile = Path.Combine(directory, "delegation.pem");
        await File.WriteAllBytesAsync(certFile, certificate.Export(X509ContentType.Pkcs12));
        await File.WriteAllTextAsync(keyFile, signing.ExportECPrivateKeyPem());
        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        var health = new WslSubstrateHealthChecker(timeout: TimeSpan.FromSeconds(10));
        Dictionary<string, string> EnvironmentFor(string name) => new()
        {
            ["SPLAT_AGENT_TOKEN"] = Environment.GetEnvironmentVariable("SPLAT_AGENT_TOKEN")!,
            ["SPLAT_DB_PATH"] = Path.Combine(directory, name + ".db"),
            ["SPLAT_DATA_DIR"] = Path.Combine(directory, name + "-state")
        };
        async Task<(string Id, string Version)> Import(JsonNode manifest, string name)
        {
            manifest["agentId"] = "authority-proof-" + name;
            string path = Path.Combine(directory, name + ".contract.json");
            await File.WriteAllTextAsync(path, manifest.ToJsonString());
            var result = await Run(exe, EnvironmentFor(name), "import-agent", path);
            await File.WriteAllTextAsync(Path.Combine(directory, name + ".import.stderr.txt"), result.Error);
            Check(name + "_imported", result.ExitCode == 0);
            using var approval = JsonDocument.Parse(result.Output);
            return (approval.RootElement.GetProperty("agentId").GetString()!, approval.RootElement.GetProperty("contractSha256").GetString()!);
        }
        async Task<(HttpClient Client, Child Host)> Start(A2aConfiguration config, string name)
        {
            string path = Path.Combine(directory, name + ".configuration.json");
            await SaveConfiguration(path, config);
            var client = A2aBridgeTests.Client(config.Port, certificate);
            client.Timeout = TimeSpan.FromMinutes(5);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add("A2A-Version", "1.0");
            client.DefaultRequestHeaders.Add("A2A-Extensions", A2aConfiguration.Extension);
            var child = Child.Start(exe, EnvironmentFor(name), "a2a", "--configuration", path);
            children.Add(child); clients.Add(client);
            await Ready(client, child);
            return (client, child);
        }
        static object Send(string id, string skill, string? grant = null, bool immediately = false) => new
        {
            message = new { messageId = id, role = "ROLE_USER", parts = new[] { new { data = new
            { skill, parameters = skill is "reviews" or "offers" ? new Dictionary<string, string> { ["AppId"] = "570060128" } : new(), delegationToken = grant } } } },
            configuration = new { returnImmediately = immediately }
        };
        static JsonElement TaskOf(JsonElement reply) => reply.GetProperty("result").GetProperty("task");
        static string Id(JsonElement task) => task.GetProperty("id").GetString()!;
        static string State(JsonElement task) => task.GetProperty("status").GetProperty("state").GetString()!;
        JsonElement Receipt(JsonElement task, string name) => ReceiptText(Text(task), name);
        JsonElement ReceiptText(string text, string name)
        {
            using var document = JsonDocument.Parse(text.Split('\n').Single(l => l.StartsWith("{\"agentLease\":")));
            var lease = document.RootElement.GetProperty("agentLease").Clone();
            Check(name + "_signed_drain", lease.GetProperty("WorkloadDrained").GetBoolean()
                && lease.GetProperty("Enforcing").GetBoolean() && lease.GetProperty("Jailed").GetBoolean()
                && lease.GetProperty("WorkspaceRemoved").GetBoolean()
                && lease.GetProperty("EffectivePolicySha256").GetString()!.Length == 64);
            observations[name + "Lease"] = lease;
            return lease;
        }
        async Task WaitForLease()
        {
            for (int i = 0; i < 100; i++)
            {
                if ((await health.CheckHealthAsync()).ActiveLeaseCount > 0) return;
                await Task.Delay(100);
            }
            throw new TimeoutException("No active lease observed before cancellation.");
        }
        try
        {
            using var build = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(Path.GetDirectoryName(exe)!, "MCP-BUILD-MANIFEST.json")));
            // Generated receipts cannot be inputs to the binary they prove. Use the same compiled
            // input set as the resident-daemon proof, retaining the complete package manifest below.
            var inputs = build.RootElement.GetProperty("sourceInputs").EnumerateArray().Where(i =>
                new[] { ".cs", ".csproj", ".py", ".rs", ".c", ".h", ".toml", ".lock", ".props", ".targets" }
                    .Contains(Path.GetExtension(i.GetProperty("path").GetString()), StringComparer.OrdinalIgnoreCase)).Select(i => i.Clone()).ToArray();
            bool SourcesMatch() => inputs.Length > 0 && inputs.All(i =>
            {
                string path = Path.GetFullPath(Path.Combine(root, i.GetProperty("path").GetString()!));
                return path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                    && FileHash(path) == i.GetProperty("sha256").GetString();
            });
            Check("source_inventory_before", SourcesMatch());
            Check("published_host_hash", FileHash(exe) == build.RootElement.GetProperty("sha256").GetString());
            string pid = Environment.GetEnvironmentVariable("SPLAT_A2A_TEMPORARY_DAEMON_PID")!;
            Check("temporary_pid_valid", int.TryParse(pid, out int nativePid) && nativePid > 0);
            Check("temporary_daemon_hash", (await Guest("sha256sum", $"/proc/{nativePid}/exe")).StartsWith(build.RootElement.GetProperty("daemonSha256").GetString()!, StringComparison.Ordinal));
            Check("installed_service_stopped_by_runner", (await Guest("systemctl", "show", "splat-agent", "--property=MainPID", "--value")).Trim() == "0");
            observations["buildManifest"] = build.RootElement.Clone();
            observations["compiledSourceCount"] = inputs.Length;
            observations["probeSha256"] = FileHash(Path.Combine(root, "tests", "MissionController.Tests", "A2aAuthorityPublishedProofTests.cs"));
            observations["testAssemblySha256"] = FileHash(typeof(A2aPublishedProofTests).Assembly.Location);
            Check("enforcing_before", (await health.CheckHealthAsync()) is { Enforcing: true, FramesProven: true, ActiveLeaseCount: 0 });
            var original = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(root, "examples", "agent-manifests", "guest-identity.contract.json")))!;
            var parent = await Import(original.DeepClone(), "parent");
            var workerManifest = original.DeepClone();
            var restricted = workerManifest["tools"]![0]!.DeepClone();
            restricted["name"] = "narrow_read";
            var grants = restricted["executionPolicy"]!["fileGrants"]!.AsArray();
            grants.Remove(grants.Single(g => g!["path"]!.GetValue<string>() == "/proc/meminfo"));
            workerManifest["tools"]![0]!.AsObject().Remove("executionPolicy");
            workerManifest["tools"]!.AsArray().Add(restricted);
            workerManifest["tools"]!.AsArray().Add(JsonSerializer.SerializeToNode(new { name = "reviews", templateId = "source-consumer-reviews", allowNetwork = true }));
            var worker = await Import(workerManifest, "worker");
            var caller = new A2aCaller("proof-tenant", "operator", Hash(token), ["read_guest_identity"], DateTimeOffset.UtcNow.AddHours(1));
            var parentConfig = new A2aConfiguration(1, parent.Id, parent.Version, A2aBridgeTests.FreePort(), certFile, [caller], DelegationKeyFile: keyFile);
            var workerConfig = new A2aConfiguration(1, worker.Id, worker.Version, A2aBridgeTests.FreePort(), certFile,
                [caller with { Skills = ["read_guest_identity", "narrow_read", "reviews"], RequireDelegation = true }],
                DelegationIssuers: [new(parent.Id, parent.Version, Convert.ToBase64String(signing.ExportSubjectPublicKeyInfo()))]);
            var p = await Start(parentConfig, "parent"); var w = await Start(workerConfig, "worker");
            async Task<string> Grant(string skill)
            {
                var task = TaskOf(await Rpc(p.Client, "SendMessage", Send(Guid.NewGuid().ToString("N"), "read_guest_identity")));
                Check("parent_completed_" + skill, State(task) == "TASK_STATE_COMPLETED");
                var reply = await Rpc(p.Client, "splat/DelegateTask", new { parentTaskId = Id(task), audience = worker.Id,
                    audienceVersion = worker.Version, callerId = caller.CallerId, skill });
                return reply.GetProperty("result").GetProperty("delegationToken").GetString()!;
            }
            Check("missing_delegation_refused", Error(await Rpc(w.Client, "SendMessage", Send("missing", "read_guest_identity"))) == -32000);
            string grant = await Grant("read_guest_identity");
            Check("tampered_delegation_refused", Error(await Rpc(w.Client, "SendMessage", Send("forged", "read_guest_identity", "A" + grant[1..]))) == -32000);
            var childTask = TaskOf(await Rpc(w.Client, "SendMessage", Send("delegated", "read_guest_identity", grant)));
            Check("delegated_task_completed", State(childTask) == "TASK_STATE_COMPLETED");
            var receipt = Receipt(childTask, "delegated");
            string canonical = receipt.GetProperty("SignedOutcome").GetString()!;
            Check("signature_binds_both_agents_and_token", canonical.Contains(parent.Id) && canonical.Contains(worker.Id)
                && canonical.Contains(parent.Version) && canonical.Contains(worker.Version) && canonical.Contains(Hash(grant)));
            await w.Host.DisposeAsync();
            w = await Start(workerConfig, "worker");
            Check("retry_after_restart_is_same_task", Id(TaskOf(await Rpc(w.Client, "SendMessage", Send("delegated", "read_guest_identity", grant)))) == Id(childTask));
            Check("replay_after_restart_refused", Error(await Rpc(w.Client, "SendMessage", Send("replay", "read_guest_identity", grant))) == -32000);
            var denied = TaskOf(await Rpc(w.Client, "SendMessage", Send("narrow", "narrow_read", await Grant("narrow_read"))));
            Check("intersected_file_grants_deny_read", State(denied) == "TASK_STATE_FAILED" && Text(denied).Contains("Permission denied"));
            Receipt(denied, "narrow");
            Check("parent_cannot_lend_network_or_python", Error(await Rpc(w.Client, "SendMessage", Send("borrow-network", "reviews", await Grant("reviews")))) == -32000);

            var rareManifest = original.DeepClone();
            rareManifest["tools"] = JsonSerializer.SerializeToNode(new[] { new { name = "catalog", templateId = "source-consumer-catalog", allowNetwork = true },
                new { name = "reviews", templateId = "source-consumer-reviews", allowNetwork = true }, new { name = "offers", templateId = "source-consumer-offers", allowNetwork = true } });
            var rare = await Import(rareManifest, "rare");
            string otherCallerToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
            string otherTenantToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
            var rareConfig = new A2aConfiguration(1, rare.Id, rare.Version, A2aBridgeTests.FreePort(), certFile,
                [caller with { Skills = ["catalog", "reviews", "offers"], MaxConcurrentTasks = 1 },
                 caller with { CallerId = "other-caller", TokenSha256 = Hash(otherCallerToken), Skills = ["reviews"] },
                 caller with { TenantId = "other-tenant", TokenSha256 = Hash(otherTenantToken), Skills = ["reviews"] }]);
            var r = await Start(rareConfig, "rare");
            // Exercise the published receiver with hostile requests before any authorized Apple read.
            // These are synthetic attacker inputs, never claims about a model resisting injection.
            foreach (string skill in new[] { "run_command", "run_code", "fs_read", "fs_write" })
                Check("rare_generic_" + skill + "_refused", Error(await Rpc(r.Client, "SendMessage", Send("attack-" + skill, skill))) == -32000);
            foreach (var field in new Dictionary<string, object>
            {
                ["command"] = "/bin/sh", ["executionPolicy"] = new { syscalls = new[] { "socket" } },
                ["allowedEgressIps"] = new[] { "127.0.0.1" }, ["callerId"] = "other-caller", ["tenantId"] = "other-tenant"
            })
            {
                var attack = JsonSerializer.SerializeToNode(Send("attack-" + field.Key, "reviews"), A2aConfiguration.Json)!;
                attack["message"]!["parts"]![0]!["data"]![field.Key] = JsonSerializer.SerializeToNode(field.Value);
                Check("rare_forged_" + field.Key + "_refused", Error(await Rpc(r.Client, "SendMessage", attack)) == -32602);
            }
            var poisoned = JsonSerializer.SerializeToNode(Send("attack-parameter", "reviews"), A2aConfiguration.Json)!;
            poisoned["message"]!["parts"]![0]!["data"]!["parameters"]!["AppId"] = "570060128; /bin/sh -c 'exit 0'";
            var refusedParameter = TaskOf(await Rpc(r.Client, "SendMessage", poisoned));
            Check("rare_poisoned_parameter_refused_before_execution", State(refusedParameter) == "TASK_STATE_FAILED"
                && Text(refusedParameter).Contains("[SPLAT POLICY]") && !Text(refusedParameter).Contains("\"agentLease\""));
            using (var duplicate = JsonDocument.Parse("{\"message\":{\"messageId\":\"attack-duplicate\",\"role\":\"ROLE_USER\",\"parts\":[{\"data\":{\"skill\":\"reviews\",\"parameters\":{\"AppId\":\"570060128\",\"AppId\":\"0\"}}}]}}"))
                Check("rare_duplicate_parameter_refused", Error(await Rpc(r.Client, "SendMessage", duplicate.RootElement)) == -32602);
            var forgedParent = JsonSerializer.SerializeToNode(Send("attack-parent", "reviews"), A2aConfiguration.Json)!;
            forgedParent["message"]!["parts"]![0]!["data"]!["parentTaskId"] = Id(childTask);
            Check("rare_parent_id_is_not_authority", Error(await Rpc(r.Client, "SendMessage", forgedParent)) == -32000);
            Check("rare_attack_batch_leaves_no_active_lease", (await health.CheckHealthAsync()).ActiveLeaseCount == 0);
            observations["externalNetworkAttempted"] = true;
            var running = TaskOf(await Rpc(r.Client, "SendMessage", Send("cancel-catalog", "catalog", immediately: true)));
            await WaitForLease();
            Check("caller_running_quota_refused", Error(await Rpc(r.Client, "SendMessage", Send("over-quota", "reviews"))) == -32000);
            var canceled = (await Rpc(r.Client, "CancelTask", new { id = Id(running) })).GetProperty("result");
            Check("cancel_confirms_native_drain", State(canceled) == "TASK_STATE_CANCELED"
                && canceled.GetProperty("metadata").GetProperty(A2aConfiguration.Extension).GetProperty("workloadTerminationConfirmed").GetBoolean());
            observations["cancellation"] = canceled.Clone();
            Receipt(canceled, "canceled");
            Check("idle_after_cancellation", (await health.CheckHealthAsync()).ActiveLeaseCount == 0);
            foreach (string skill in new[] { "reviews", "offers", "catalog" })
            {
                var task = TaskOf(await Rpc(r.Client, "SendMessage", Send("public-" + skill, skill)));
                string output = Text(task);
                await File.WriteAllTextAsync(Path.Combine(directory, "rare-" + skill + ".txt"), output);
                Check(skill + "_public_evidence", State(task) == "TASK_STATE_COMPLETED" && !output.Contains("PROBE_FAILED:")
                    && output.Contains(skill == "catalog" ? "\"cohorts\"" : "\"kind\""));
                Receipt(task, skill);
                Check("rare_" + skill + "_retry_returns_same_task", Id(TaskOf(await Rpc(r.Client, "SendMessage", Send("public-" + skill, skill)))) == Id(task));
                if (skill == "reviews")
                {
                    foreach (var outsider in new[] { (Name: "caller", Token: otherCallerToken), (Name: "tenant", Token: otherTenantToken) })
                    {
                        r.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", outsider.Token);
                        try
                        {
                            foreach (string operation in new[] { "GetTask", "CancelTask" })
                                Check("rare_cross_" + outsider.Name + "_" + operation + "_refused",
                                    Error(await Rpc(r.Client, operation, new { id = Id(task) })) == -32001);
                            var listing = await Rpc(r.Client, "ListTasks", new { includeArtifacts = true });
                            Check("rare_cross_" + outsider.Name + "_artifacts_hidden", listing.GetProperty("result").GetProperty("tasks").GetArrayLength() == 0);
                        }
                        finally { r.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token); }
                    }
                }
            }
            // Deliberately substitute a hostile Python body below the A2A layer, using the exact
            // RARE reviews template's lease. This measures containment after hypothetical runtime
            // compromise; the published endpoint above never accepts a caller-supplied body.
            var compromiseMission = Guid.NewGuid();
            var compromiseTemplate = GovernedTemplateCatalog.All.Single(t => t.TemplateId == "source-consumer-reviews");
            var compromiseLease = new TemplatePolicyCompiler().CompileTemplatePolicy(compromiseTemplate,
                compromiseMission, $"{LinuxLeaseSubstrate.DefaultMissionsRoot}/{compromiseMission:N}", 30)
                with { RequireEnforcing = true };
            const string hostilePython = """
                import errno,json,socket,subprocess
                results = {}
                try:
                    subprocess.run(['/bin/sh','-c','exit 0'], check=True)
                    results['shell'] = 'ESCAPED'
                except OSError as error:
                    results['shell'] = error.errno
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                    connection.settimeout(2)
                    try:
                        connection.connect(('127.0.0.1', 9))
                        results['egress'] = 'ESCAPED'
                    except OSError as error:
                        results['egress'] = error.errno
                print(json.dumps(results))
                """;
            var compromise = await new WslLeasedExecutor().ExecuteLeasedAsync(compromiseLease,
                compromiseTemplate.Tool.ExecutablePath, ["-I", "-B", "-c", hostilePython]);
            Check("rare_hostile_runtime_executed_in_enforcing_jail", compromise.ExitCode == 0
                && compromise.Lease is { Enforcing: true, Jailed: true, WorkspaceRemoved: true });
            using (var attempts = JsonDocument.Parse(compromise.StandardOutput))
            {
                // EPERM distinguishes policy denial from a missing binary or absent TCP listener.
                Check("rare_hostile_runtime_shell_denied_by_kernel", attempts.RootElement.GetProperty("shell").GetInt32() == 1);
                Check("rare_hostile_runtime_loopback_egress_denied_by_kernel", attempts.RootElement.GetProperty("egress").GetInt32() == 1);
            }
            observations["compromisedRuntimeLease"] = compromise.Lease!;
            var revokeTask = TaskOf(await Rpc(r.Client, "SendMessage", Send("revoke-catalog", "catalog", immediately: true)));
            await WaitForLease();
            var db = new SqliteStorageContext(EnvironmentFor("rare")["SPLAT_DB_PATH"]);
            await new IncidentRevocationManager(new SqliteChainedAuditLedger(db), new SqliteRevocationStore(db))
                .RevokeAsync(caller.Identity.ToLedgerIdentity(), "API_KEY", "Synthetic live revocation", "proof");
            for (int i = 0; i < 100 && (await health.CheckHealthAsync()).ActiveLeaseCount != 0; i++) await Task.Delay(100);
            Check("revocation_drains_active_workload", (await health.CheckHealthAsync()).ActiveLeaseCount == 0);
            // The revoked caller must remain locked out. Read the operator's durable task record
            // instead of borrowing another caller's API authority to retrieve the final receipt.
            var taskStore = new A2aTaskStore(db, rare.Id, rare.Version);
            A2aTaskRecord revokedRecord = taskStore.Load(rareConfig.MaxTasks).Single(t => t.Id == Id(revokeTask));
            for (int i = 0; i < 100 && revokedRecord.State == "TASK_STATE_WORKING"; i++)
            {
                await Task.Delay(100);
                revokedRecord = taskStore.Load(rareConfig.MaxTasks).Single(t => t.Id == Id(revokeTask));
            }
            Check("revocation_persisted_confirmed_drain", revokedRecord is
                { State: "TASK_STATE_CANCELED", WorkloadTerminationConfirmed: true, Result: not null });
            ReceiptText(string.Join("\n", revokedRecord.Result!.Value.GetProperty("content").EnumerateArray()
                .Select(part => part.GetProperty("text").GetString())), "revoked");
            Check("revocation_loaded_without_restart", Error(await Rpc(r.Client, "SendMessage", Send("revoked", "reviews"))) == -32000);
            Check("source_inventory_after", SourcesMatch());
            Check("enforcing_after", (await health.CheckHealthAsync()) is { Enforcing: true, FramesProven: true, ActiveLeaseCount: 0 });
            passed = true;
        }
        finally
        {
            foreach (var child in children) await child.DisposeAsync();
            foreach (var client in clients) client.Dispose();
            File.Delete(certFile); File.Delete(keyFile);
            await File.WriteAllTextAsync(Path.Combine(directory, "a2a-authority-proof.json"), JsonSerializer.Serialize(new
            {
                schema = 1, timestampUtc = DateTimeOffset.UtcNow, result = passed ? "PASS" : "FAIL", checks, observations,
                scope = "Published local HTTPS agents and real enforcing daemon; public Apple data; no model API. Temporary service restoration is verified separately by the root runner."
            }, new JsonSerializerOptions(A2aConfiguration.Json) { WriteIndented = true }));
        }
    }
}
