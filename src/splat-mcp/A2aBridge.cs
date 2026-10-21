using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Core.Models;
using MissionController.Infrastructure.Linux;

namespace SplatMcp;

internal sealed partial class A2aBridge : IAsyncDisposable
{
    private sealed class Work(A2aTaskRecord record)
    {
        internal volatile A2aTaskRecord Record = record;
        internal readonly SemaphoreSlim Gate = new(1);
        internal readonly CancellationTokenSource Cancellation = new();
        internal Task Execution = Task.CompletedTask;
        internal bool Drained;
    }

    private readonly A2aConfiguration _config;
    private readonly A2aTaskStore _store;
    private readonly IAuditLedger _ledger;
    private readonly SqliteChainedAuditLedger _admissionLedger;
    private readonly Func<A2aCaller, McpServerHandler> _handler;
    private readonly IIncidentRevocationManager? _revocations;
    // Only admission and archival share a lock: quota and replay decisions must remain atomic.
    // Execution, cancellation, delegation, polling and compilation do not hold it.
    private readonly SemaphoreSlim _admissionGate = new(1);
    private readonly ConcurrentDictionary<string, Work> _tasks = new(StringComparer.Ordinal);
    private readonly ILeaseReceiptLookup? _receiptLookup;
    private readonly SemaphoreSlim _receiptSlots = new(4);
    private readonly SemaphoreSlim[] _receiptGates = Enumerable.Range(0, 32).Select(_ => new SemaphoreSlim(1)).ToArray();
    private readonly HashSet<string> _skills;
    private readonly AgentManifestApproval _approval;
    private readonly A2aDelegation _delegation;
    private readonly ITemplatePolicyCompiler _compiler;
    private volatile int _running;
    private bool _stopping;
    private volatile bool _faulted;
    private int _disposed;

    internal A2aBridge(A2aConfiguration config, AgentManifestApproval approval, SqliteStorageContext context,
        IAuditLedger ledger, Func<A2aCaller, McpServerHandler> handler, IIncidentRevocationManager? revocations = null,
        ITemplatePolicyCompiler? compiler = null, ILeaseReceiptLookup? receiptLookup = null)
    {
        // Copy the authority snapshot: a caller holding the original arrays cannot widen this server.
        _config = JsonSerializer.Deserialize<A2aConfiguration>(JsonSerializer.Serialize(config, A2aConfiguration.Json), A2aConfiguration.Json)!;
        _config.Validate();
        if (approval.AgentId != config.AgentId || approval.Sha256 != config.AgentVersion
            || AgentManifestApproval.Hash(approval.Manifest) != config.AgentVersion)
            throw new InvalidOperationException("A2A configuration does not match the approved agent.");
        _skills = approval.Manifest.Project.Stages.Select(s => s.StageId).ToHashSet(StringComparer.Ordinal);
        if (_config.Callers.Any(c => c.Skills.Any(s => !_skills.Contains(s))))
            throw new InvalidOperationException("A caller's skill grant exceeds the approved manifest.");
        // Admission commits the task and its authorization row together, so both must live in one
        // database. A ledger elsewhere could only be written before or after the task, never with it.
        _admissionLedger = ledger as SqliteChainedAuditLedger is { } chained
            && string.Equals(Path.GetFullPath(chained.DatabasePath), Path.GetFullPath(context.DatabasePath),
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)
            ? chained
            : throw new InvalidOperationException(
                "A2A admission needs the chained audit ledger in the task database, so a task and its authorization commit together.");
        _store = new A2aTaskStore(context, config.AgentId, config.AgentVersion);
        _approval = approval;
        _delegation = new A2aDelegation(_config);
        _compiler = compiler ?? new TemplatePolicyCompiler();
        _ledger = ledger; _handler = handler; _revocations = revocations; _receiptLookup = receiptLookup;
        foreach (var saved in _store.Load(config.MaxTasks))
        {
            var record = saved;
            if (!Terminal(record.State))
            {
                // Never replay an external effect after a crash. A lease receipt, not a restart,
                // would be needed to establish what happened before the connection disappeared.
                // Dispatch was saved before the executor was reached, so an undispatched task provably
                // never started; a dispatched one stays unresolved until a receipt says otherwise.
                record = record with { State = "TASK_STATE_FAILED", UpdatedUtc = DateTimeOffset.UtcNow,
                    CancellationEvidence = record.Dispatched == false ? "not-started" : "unresolved",
                    Failure = record.Dispatched != false
                        ? "Server restarted; previous execution outcome is unconfirmed. No automatic replay."
                        : "Server restarted before dispatch; no workload was started. No automatic replay." };
                _store.Save(record);
            }
            _tasks.TryAdd(record.Id, new Work(record));
        }
    }

    internal A2aCaller? Authenticate(string authorization) => _config.Authenticate(authorization);

    internal async Task CheckCallerAsync(A2aCaller caller, CancellationToken ct)
    {
        if (!_config.Callers.Any(c => ReferenceEquals(c, caller)) || caller.ExpiresUtc <= DateTimeOffset.UtcNow)
            throw new A2aException(-32000, "Authentication required.", 401);
        if (_revocations is not null && (await _revocations.CheckRevocationAsync(caller.Identity.ToLedgerIdentity(), ct)).IsRevoked)
            throw new A2aException(-32000, "Caller access has been revoked.", 403);
    }

    internal object Card(A2aCaller caller) => new
    {
        name = _config.AgentId, description = "Approved SPLAT template execution with task-scoped results.",
        version = _config.AgentVersion,
        supportedInterfaces = new[] { new { url = $"https://127.0.0.1:{_config.Port}/a2a", protocolBinding = "JSONRPC", protocolVersion = "1.0" } },
        capabilities = new { streaming = false, pushNotifications = false, extendedAgentCard = false,
            extensions = new[] { new { uri = A2aConfiguration.Extension, required = true,
                description = "One structured data part selects an approved skill and its declared string parameters. One message creates one task." } } },
        defaultInputModes = new[] { "application/json" }, defaultOutputModes = new[] { "text/plain" },
        securitySchemes = new { splat = new { httpAuthSecurityScheme = new { scheme = "Bearer", bearerFormat = "Opaque" } } },
        securityRequirements = new[] { new { schemes = new { splat = new { list = Array.Empty<string>() } } } },
        skills = caller.Skills.Select(s => new { id = s, name = s,
            description = "Runs the operator-approved template for this skill.", tags = new[] { "splat", "governed" } }).ToArray()
    };

    internal async Task<object> DispatchAsync(A2aCaller caller, string method, JsonElement parameters, CancellationToken ct)
    {
        // The HTTP boundary supplies this exact configuration object. Never accept an equivalent
        // caller record constructed from message fields, including a client-supplied tenant.
        await CheckCallerAsync(caller, ct);
        if (method == "splat/DelegateTask") return await DelegateAsync(caller, parameters, ct);
        if (method == "SendMessage") return new { task = await SendAsync(caller, parameters, ct) };
        if (method == "GetTask" || method == "CancelTask")
        {
            A2aJson.Fields(parameters, "id", "historyLength");
            ValidateHistory(parameters);
            var id = A2aJson.Text(parameters, "id");
            if (method == "GetTask") return await ReadAsync(caller, id, ct);
            if (!_tasks.ContainsKey(id) && _store.ReadArchived(id, caller.TenantId, caller.CallerId) is { } archived
                && Owns(caller, archived)) throw new A2aException(-32002, "Task is no longer cancelable.");
            Work work = Owned(caller, id);
            await work.Gate.WaitAsync(ct);
            try
            {
                if (Terminal(work.Record.State)) throw new A2aException(-32002, "Task is no longer cancelable.");
                await Audit(caller, work.Record, "A2A_CANCEL_REQUESTED", CancellationToken.None);
                work.Record = work.Record with { CancellationRequested = true };
                _store.Save(work.Record);
                work.Cancellation.Cancel();
            }
            finally { work.Gate.Release(); }
            await work.Execution.WaitAsync(ct);
            return await ReadAsync(caller, id, ct);
        }
        if (method == "ListTasks")
        {
            A2aJson.Fields(parameters, "contextId", "status", "pageSize", "pageToken", "historyLength", "includeArtifacts", "statusTimestampAfter");
            ValidateHistory(parameters);
            int size = 50;
            if (parameters.TryGetProperty("pageSize", out var pageSize)
                && (pageSize.ValueKind != JsonValueKind.Number || !pageSize.TryGetInt32(out size)))
                throw new A2aException(-32602, "Invalid pageSize.");
            if (size is < 1 or > 100 || parameters.TryGetProperty("pageToken", out var token)
                && token.ValueKind != JsonValueKind.String) throw new A2aException(-32602, "Invalid pagination.");
            string cursor = parameters.TryGetProperty("pageToken", out token) ? token.GetString()! : "";
            string? context = parameters.TryGetProperty("contextId", out _) ? A2aJson.Text(parameters, "contextId") : null;
            string? state = parameters.TryGetProperty("status", out _) ? A2aJson.Text(parameters, "status") : null;
            if (state is not null && !Terminal(state)
                && state is not ("TASK_STATE_SUBMITTED" or "TASK_STATE_WORKING" or "TASK_STATE_INPUT_REQUIRED" or "TASK_STATE_AUTH_REQUIRED"))
                throw new A2aException(-32602, "Invalid task status.");
            bool includeArtifacts = false;
            if (parameters.TryGetProperty("includeArtifacts", out var include))
            {
                if (include.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                    throw new A2aException(-32602, "Invalid includeArtifacts.");
                includeArtifacts = include.GetBoolean();
            }
            DateTimeOffset after = DateTimeOffset.MinValue;
            if (parameters.TryGetProperty("statusTimestampAfter", out var timestamp)
                && (timestamp.ValueKind != JsonValueKind.String || !timestamp.TryGetDateTimeOffset(out after)))
                throw new A2aException(-32602, "Invalid statusTimestampAfter.");
            var owned = _tasks.Values.Select(w => w.Record).Where(r => Owns(caller, r)
                && (context is null || r.ContextId == context) && (state is null || r.State == state)
                && r.UpdatedUtc >= after)
                .OrderByDescending(r => r.UpdatedUtc).ThenBy(r => r.Id, StringComparer.Ordinal).ToArray();
            if (cursor.Length > 0 && !owned.Any(r => r.Id == cursor)) throw new A2aException(-32602, "Invalid pagination.");
            var page = (cursor.Length == 0 ? owned : owned.SkipWhile(r => r.Id != cursor).Skip(1)).Take(size + 1).ToArray();
            return new { tasks = page.Take(size).Select(r => Snapshot(r, includeArtifacts)).ToArray(), pageSize = size,
                nextPageToken = page.Length > size ? page[size - 1].Id : "", totalSize = owned.Length };
        }
        if (method is "SendStreamingMessage" or "SubscribeToTask" or "GetExtendedAgentCard")
            throw new A2aException(-32004, "This endpoint supports one-shot tasks and polling.");
        if (method.Contains("PushNotification", StringComparison.Ordinal))
            throw new A2aException(-32003, "Push notifications are not supported.");
        throw new A2aException(-32601, "Method not found.");
    }

    private async Task<object> SendAsync(A2aCaller caller, JsonElement parameters, CancellationToken ct)
    {
        A2aJson.Fields(parameters, "message", "configuration");
        if (!parameters.TryGetProperty("message", out var message)) throw new A2aException(-32602, "message is required.");
        A2aJson.Fields(message, "messageId", "role", "parts", "extensions");
        var messageId = A2aJson.Text(message, "messageId");
        if (!A2aJson.Identifier(messageId) || A2aJson.Text(message, "role") != "ROLE_USER")
            throw new A2aException(-32602, "A user message with a bounded messageId is required.");
        if (message.TryGetProperty("extensions", out var extensions)
            && (extensions.ValueKind != JsonValueKind.Array || extensions.EnumerateArray().Any(e =>
                e.ValueKind != JsonValueKind.String || e.GetString() != A2aConfiguration.Extension)))
            throw new A2aException(-32602, "Unsupported message extension.");
        if (!message.TryGetProperty("parts", out var parts) || parts.ValueKind != JsonValueKind.Array || parts.GetArrayLength() != 1)
            throw new A2aException(-32602, "Exactly one structured data part is required.");
        A2aJson.Fields(parts[0], "data", "mediaType");
        if (parts[0].TryGetProperty("mediaType", out var mediaType)
            && (mediaType.ValueKind != JsonValueKind.String || mediaType.GetString() != "application/json"))
            throw new A2aException(-32005, "The skill request must be application/json.");
        if (!parts[0].TryGetProperty("data", out var data)) throw new A2aException(-32005, "A structured skill request is required.");
        A2aJson.Fields(data, "skill", "parameters", "parentTaskId", "delegationToken");
        string skill = A2aJson.Text(data, "skill");
        if (!caller.Skills.Contains(skill, StringComparer.Ordinal))
        {
            await _ledger.AppendLogAsync(Guid.NewGuid(), "a2a", "A2A_SKILL_REFUSED",
                "The requested skill is outside this caller's configured grant.", caller.Identity.ToLedgerIdentity(), ct);
            throw new A2aException(-32000, "Skill is not authorized.", 403);
        }
        JsonElement arguments = data.TryGetProperty("parameters", out var supplied) ? supplied.Clone() : JsonSerializer.SerializeToElement(new { });
        if (arguments.ValueKind != JsonValueKind.Object || arguments.EnumerateObject().Any(p => p.Value.ValueKind != JsonValueKind.String))
            throw new A2aException(-32602, "Skill parameters must be declared string values.");
        string? parent = data.TryGetProperty("parentTaskId", out _) ? A2aJson.Text(data, "parentTaskId") : null;
        if (parent is not null && !A2aJson.Identifier(parent)) throw new A2aException(-32602, "Invalid parentTaskId.");
        string? token = data.TryGetProperty("delegationToken", out _) ? A2aJson.Text(data, "delegationToken") : null;
        if ((parent is not null || caller.RequireDelegation) && token is null)
            throw new A2aException(-32000, "A signed delegation is required; parentTaskId is not authority.", 403);
        bool immediate = false;
        if (parameters.TryGetProperty("configuration", out var configuration))
        {
            A2aJson.Fields(configuration, "returnImmediately", "historyLength", "acceptedOutputModes");
            ValidateHistory(configuration);
            if (configuration.TryGetProperty("returnImmediately", out var flag))
            {
                if (flag.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new A2aException(-32602, "Invalid returnImmediately.");
                immediate = flag.GetBoolean();
            }
            if (configuration.TryGetProperty("acceptedOutputModes", out var modes)
                && (modes.ValueKind != JsonValueKind.Array || !modes.EnumerateArray().Any(m =>
                    m.ValueKind == JsonValueKind.String && m.GetString() == "text/plain")))
                throw new A2aException(-32005, "This endpoint returns text/plain artifacts.");
        }
        string fingerprint = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(message.GetRawText())));
        Work work;
        // DNS resolution and signature validation may be slow. Perform them outside admission,
        // then recheck replay/capacity/expiry while committing the one authoritative decision.
        var existing = _tasks.Values.FirstOrDefault(w => Owns(caller, w.Record) && w.Record.MessageId == messageId);
        var archivedMessage = _store.FindArchived(caller.TenantId, caller.CallerId, messageId);
        if (existing is not null || archivedMessage is not null)
        {
            string previous = existing?.Record.RequestSha256 ?? archivedMessage!.Value.RequestSha256;
            if (previous != fingerprint) throw new A2aException(-32602, "messageId already names a different request.");
            if (!immediate && existing is not null) await existing.Execution.WaitAsync(ct);
            return await ReadAsync(caller, existing?.Record.Id ?? archivedMessage!.Value.TaskId, ct);
        }
        var grant = token is null ? null : _delegation.Verify(token, caller, skill);
        if (grant is not null && parent is not null && parent != grant.ParentTaskId)
            throw new A2aException(-32000, "parentTaskId does not match the signed delegation.", 403);
        if (grant is not null) await CheckIssuerAsync(grant.Issuer, grant.IssuerVersion, ct);
        var stage = _approval.Manifest.Project.Stages.Single(s => s.StageId == skill);
        var template = _approval.Manifest.Templates.Single(t => t.TemplateId == stage.TemplateId);
        var taskId = Guid.NewGuid();
        var lease = _compiler.CompileTemplatePolicy(template, taskId,
            $"{LinuxLeaseSubstrate.DefaultMissionsRoot}/{taskId:N}", (uint)template.Tool.TimeoutSeconds);
        await CheckCallerAsync(caller, ct);
        await _admissionGate.WaitAsync(ct);
        try
        {
            work = _tasks.Values.FirstOrDefault(w => Owns(caller, w.Record) && w.Record.MessageId == messageId)!;
            // An archived messageId is answered from the archive, never executed again.
            if (work is null && _store.FindArchived(caller.TenantId, caller.CallerId, messageId) is { } kept)
            {
                if (kept.RequestSha256 != fingerprint) throw new A2aException(-32602, "messageId already names a different request.");
                return Snapshot(_store.ReadArchived(kept.TaskId, caller.TenantId, caller.CallerId)
                    ?? throw new A2aException(-32001, "Task not found."));
            }
            if (work is not null)
            {
                if (work.Record.RequestSha256 != fingerprint) throw new A2aException(-32602, "messageId already names a different request.");
            }
            else
            {
                if (_stopping || _faulted) throw new A2aException(-32603, "Task execution is unavailable.", 503);
                if (_running >= _config.MaxConcurrentTasks)
                    throw new A2aException(-32000, "Task capacity is exhausted; no execution was started.", 429);
                // Finished tasks give their slots back: archive the oldest before refusing. Only
                // unfinished work can hold capacity now (the stress run's six-slot host stayed full
                // forever once its tasks had completed).
                if (_tasks.Count >= _config.MaxTasks) await ArchiveOldestAsync(_ => true, ct);
                if (_tasks.Count >= _config.MaxTasks)
                    throw new A2aException(-32000, "Task capacity is exhausted; no execution was started.", 429);
                bool Mine(A2aTaskRecord r) => r.TenantId == caller.TenantId && r.CallerId == caller.CallerId;
                int runningLimit = caller.MaxConcurrentTasks ?? Math.Max(1, _config.MaxConcurrentTasks / _config.Callers.Length);
                int retainedLimit = caller.MaxRetainedTasks ?? Math.Max(1, _config.MaxTasks / _config.Callers.Length);
                if (_tasks.Values.Count(w => Mine(w.Record)) >= retainedLimit) await ArchiveOldestAsync(Mine, ct);
                var owned = _tasks.Values.Where(w => Mine(w.Record)).ToArray();
                if (owned.Length >= retainedLimit || owned.Count(w => !Terminal(w.Record.State)) >= runningLimit)
                    throw new A2aException(-32000, "This caller's task capacity is exhausted.", 429);
                var expires = DateTimeOffset.UtcNow.AddSeconds(lease.LeaseDurationSeconds);
                if (expires > caller.ExpiresUtc) expires = caller.ExpiresUtc;
                if (grant is not null && expires > grant.ExpiresUtc) expires = grant.ExpiresUtc;
                try
                {
                    lease = (grant?.Authority ?? LeaseAuthority.From(lease)).Narrow(lease, template.Tool.ExecutablePath, expires);
                }
                catch (InvalidOperationException) { throw new A2aException(-32000, "Delegation cannot authorize the requested lease.", 403); }
                lease = lease with { RequireEnforcing = true, ExecutionContext = new(_config.AgentId,
                    _config.AgentVersion, caller.TenantId, caller.CallerId, taskId.ToString("N"),
                    grant?.ParentTaskId, token is null ? null : A2aDelegation.Digest(token), grant?.Issuer, grant?.IssuerVersion) };
                var record = new A2aTaskRecord(taskId.ToString("N"), Guid.NewGuid().ToString("N"),
                    caller.TenantId, caller.CallerId, messageId, fingerprint, skill, parent,
                    "TASK_STATE_WORKING", DateTimeOffset.UtcNow, AdmittedLease: lease, AuthorityExpiresUtc: expires,
                    DelegationNonce: grant?.Nonce, DelegationDepth: grant?.Depth ?? 0, Dispatched: false);
                // One transaction: nonce, task and authorization row commit together or not at all, and
                // nothing executes until they have.
                await _store.AdmitAsync(record, grant is null ? null : grant.Issuer + "@" + grant.IssuerVersion,
                    (connection, transaction) => _admissionLedger.AppendWithinAsync(connection, transaction,
                        Guid.ParseExact(record.Id, "N"), "a2a:" + _config.AgentId, "A2A_TASK_AUTHORIZED",
                        AuditDetails(caller, record), caller.Identity.ToLedgerIdentity(), ct), ct);
                work = new Work(record);
                work.Cancellation.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(0, (expires - DateTimeOffset.UtcNow).TotalMilliseconds)));
                Interlocked.Increment(ref _running);
                work.Execution = Task.Run(() => ExecuteAsync(work, caller, arguments));
                _tasks.TryAdd(record.Id, work);
            }
        }
        finally { _admissionGate.Release(); }
        // HTTP disconnect does not cancel an accepted asynchronous task. Its owner uses CancelTask;
        // retrying the same messageId returns this task rather than executing the effect twice.
        if (!immediate) await work.Execution.WaitAsync(ct);
        return await ReadAsync(caller, work.Record.Id, ct);
    }

    private async Task ExecuteAsync(Work work, A2aCaller caller, JsonElement parameters)
    {
        JsonElement? result = null;
        string state = "TASK_STATE_FAILED";
        string? failure = null;
        using var monitoring = new CancellationTokenSource();
        Task monitor = MonitorAuthorityAsync(work, caller, monitoring.Token);
        try
        {
            work.Cancellation.Token.ThrowIfCancellationRequested();
            await CheckCallerAsync(caller, work.Cancellation.Token);
            // Dispatch is recorded durably, under the lock CancelTask takes, before anything reaches the
            // executor: a cancellation that wins this race provably started nothing.
            await work.Gate.WaitAsync(work.Cancellation.Token);
            try
            {
                work.Cancellation.Token.ThrowIfCancellationRequested();
                work.Record = work.Record with { Dispatched = true };
                _store.Save(work.Record);
            }
            finally { work.Gate.Release(); }
            var handler = _handler(caller);
            handler.BindAgentInvocation(work.Record.AdmittedLease!, result =>
                work.Drained = result.Lease?.WorkloadDrained == true);
            var response = await handler.ProcessMessageAsync(new McpJsonRpcMessage
            {
                Id = JsonSerializer.SerializeToElement(work.Record.Id), Method = "tools/call",
                Params = JsonSerializer.SerializeToElement(new { name = work.Record.Skill,
                    arguments = new { parameters, traceId = work.Record.Id, clientName = "a2a:" + caller.CallerId } })
            }, work.Cancellation.Token);
            if (response.Error is null && response.Result is { } reply)
            {
                if (Encoding.UTF8.GetByteCount(reply.GetRawText()) > 512 * 1024)
                    failure = "Result exceeds the artifact limit; consult the operator's run record.";
                else
                {
                    result = reply.Clone();
                    state = reply.GetProperty("isError").GetBoolean() ? "TASK_STATE_FAILED" : "TASK_STATE_COMPLETED";
                }
            }
            else failure = "The governed execution endpoint refused the request.";
        }
        catch (OperationCanceledException) { failure = "Task cancellation requested; workload termination is unconfirmed."; }
        catch (Exception) { failure = "Execution failed; consult the operator's audit ledger."; }
        await monitoring.CancelAsync();
        await monitor;
        await work.Gate.WaitAsync();
        try
        {
            work.Record = work.Record with { WorkloadTerminationConfirmed = work.Drained };
            if (work.Record.CancellationRequested && state != "TASK_STATE_COMPLETED")
            {
                state = "TASK_STATE_CANCELED";
                string evidence = work.Record.Dispatched == false ? "not-started"
                    : work.Record.WorkloadTerminationConfirmed ? "termination-verified" : "unresolved";
                work.Record = work.Record with { CancellationEvidence = evidence };
                failure = evidence switch
                {
                    "not-started" => "A2A task canceled before dispatch; no workload was started.",
                    "termination-verified" => "A2A task canceled; signed receipt confirms the workload drained.",
                    _ => "A2A task canceled; workload termination is unconfirmed."
                };
                // Keep the signed EXIT artifact when available so the caller can verify the drain.
                if (!work.Record.WorkloadTerminationConfirmed) result = null;
            }
            work.Record = work.Record with { State = state, Result = result, Failure = failure, UpdatedUtc = DateTimeOffset.UtcNow };
            try
            {
                await Audit(caller, work.Record, "A2A_TASK_FINISHED", CancellationToken.None);
                _store.Save(work.Record);
            }
            catch (Exception)
            {
                _faulted = true;
                work.Record = work.Record with { State = "TASK_STATE_FAILED", Result = null,
                    Failure = "Task evidence could not be persisted; execution outcome is unconfirmed." };
            }
        }
        finally { Interlocked.Decrement(ref _running); work.Gate.Release(); }
    }

    private Task Audit(A2aCaller caller, A2aTaskRecord record, string action, CancellationToken ct) =>
        _ledger.AppendLogAsync(Guid.ParseExact(record.Id, "N"), "a2a:" + _config.AgentId, action,
            AuditDetails(caller, record), caller.Identity.ToLedgerIdentity(), ct);

    private string AuditDetails(A2aCaller caller, A2aTaskRecord record) =>
        JsonSerializer.Serialize(new { taskId = record.Id, contextId = record.ContextId, caller.TenantId,
            caller.CallerId, receiverAgentId = _config.AgentId, contractSha256 = _config.AgentVersion,
            record.Skill, record.CallerSuppliedParentTaskId, record.State, record.CancellationRequested,
            executionContext = record.AdmittedLease?.ExecutionContext, record.WorkloadTerminationConfirmed });

    private bool Owns(A2aCaller caller, A2aTaskRecord task) => task.TenantId == caller.TenantId
        && task.CallerId == caller.CallerId && caller.Skills.Contains(task.Skill, StringComparer.Ordinal);
    private Work Owned(A2aCaller caller, string id) => _tasks.TryGetValue(id, out var work) && Owns(caller, work.Record)
        ? work : throw new A2aException(-32001, "Task not found.");
    private async Task<object> ReadAsync(A2aCaller caller, string id, CancellationToken ct)
    {
        await CheckCallerAsync(caller, ct);
        var record = ReadOwned(caller, id);
        record = await RecoverAsync(caller, record, ct);
        await CheckCallerAsync(caller, ct);
        return Snapshot(record);
    }

    /// <summary>
    /// Archives the oldest finished task matching <paramref name="belongs"/>, with its archival entry, in
    /// one transaction. Only a terminal task whose execution has returned is eligible. Runs under admission.
    /// </summary>
    private async Task ArchiveOldestAsync(Func<A2aTaskRecord, bool> belongs, CancellationToken ct)
    {
        var oldest = _tasks.Values.Where(w => belongs(w.Record) && Terminal(w.Record.State) && w.Execution.IsCompleted)
            .OrderBy(w => w.Record.UpdatedUtc).ThenBy(w => w.Record.Id, StringComparer.Ordinal).FirstOrDefault();
        if (oldest is null) return;
        await oldest.Gate.WaitAsync(ct);
        try
        {
            var record = oldest.Record;
            await _store.ArchiveAsync(record, (connection, transaction) => _admissionLedger.AppendWithinAsync(
                connection, transaction, Guid.ParseExact(record.Id, "N"), "a2a:" + _config.AgentId, "A2A_TASK_ARCHIVED",
                JsonSerializer.Serialize(new { taskId = record.Id, record.TenantId, record.CallerId, record.MessageId,
                    record.State, receiverAgentId = _config.AgentId, contractSha256 = _config.AgentVersion }),
                $"a2a-host:{_config.AgentId}", ct), ct);
            _tasks.TryRemove(record.Id, out _);
            oldest.Cancellation.Dispose();
        }
        finally { oldest.Gate.Release(); }
    }
    private object Snapshot(A2aTaskRecord record, bool includeArtifacts = true) => new
    {
        id = record.Id, contextId = record.ContextId,
        status = new { state = record.State, timestamp = record.UpdatedUtc },
        artifacts = includeArtifacts && record.Result is { } result ? new[] { new { artifactId = record.Id + "-result", name = "Governed result",
            parts = result.GetProperty("content").EnumerateArray().Select(c => new { text = c.GetProperty("text").GetString() }).ToArray() } } : null,
        metadata = new Dictionary<string, object> { [A2aConfiguration.Extension] = new
        {
            receiverAgentId = _config.AgentId, contractSha256 = _config.AgentVersion, record.TenantId,
            record.CallerId, record.Skill, record.CallerSuppliedParentTaskId, record.CancellationRequested,
            workloadTerminationConfirmed = record.CancellationRequested || record.ReceiptRecovered
                ? (bool?)record.WorkloadTerminationConfirmed : null,
            record.Dispatched, record.CancellationEvidence, record.ReceiptRecovered,
            executionContext = record.AdmittedLease?.ExecutionContext, failure = record.Failure
        } }
    };
    private static bool Terminal(string state) => state is "TASK_STATE_COMPLETED" or "TASK_STATE_FAILED" or "TASK_STATE_CANCELED" or "TASK_STATE_REJECTED";
    private static void ValidateHistory(JsonElement value)
    {
        if (value.TryGetProperty("historyLength", out var history)
            && (history.ValueKind != JsonValueKind.Number || !history.TryGetInt32(out int count) || count < 0))
            throw new A2aException(-32602, "Invalid historyLength.");
    }
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        Work[] active;
        await _admissionGate.WaitAsync();
        try
        {
            _stopping = true;
            active = _tasks.Values.ToArray();
        }
        finally { _admissionGate.Release(); }
        foreach (var work in active)
        {
            await work.Gate.WaitAsync();
            try
            {
                if (Terminal(work.Record.State)) continue;
                work.Record = work.Record with { CancellationRequested = true };
                work.Cancellation.Cancel();
            }
            finally { work.Gate.Release(); }
        }
        await Task.WhenAll(active.Select(w => w.Execution));
        foreach (var work in _tasks.Values) work.Cancellation.Dispose();
        _delegation.Dispose();
        _admissionGate.Dispose();
    }

    private async Task CheckIssuerAsync(string agent, string version, CancellationToken ct)
    {
        if (_revocations is not null && (await _revocations.CheckRevocationAsync("a2a-agent:" + agent + "@" + version, ct)).IsRevoked)
            throw new A2aException(-32000, "Delegating agent has been revoked.", 403);
    }

    private async Task MonitorAuthorityAsync(Work work, A2aCaller caller, CancellationToken stop)
    {
        try
        {
            while (true)
            {
                await Task.Delay(500, stop);
                try
                {
                    await CheckCallerAsync(caller, stop);
                    if (work.Record.AdmittedLease?.ExecutionContext is { RequestingAgentId: { } issuer,
                        RequestingContractSha256: { } version }) await CheckIssuerAsync(issuer, version, stop);
                    if (work.Record.AuthorityExpiresUtc <= DateTimeOffset.UtcNow)
                        throw new A2aException(-32000, "Task authority expired.", 403);
                }
                catch (OperationCanceledException) when (stop.IsCancellationRequested) { return; }
                catch (Exception)
                {
                    await work.Gate.WaitAsync(stop);
                    try
                    {
                        work.Record = work.Record with { CancellationRequested = true };
                        work.Cancellation.Cancel();
                        try { _store.Save(work.Record); }
                        catch { _faulted = true; }
                    }
                    finally { work.Gate.Release(); }
                    return;
                }
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
    }

    private async Task<object> DelegateAsync(A2aCaller caller, JsonElement parameters, CancellationToken ct)
    {
        A2aJson.Fields(parameters, "parentTaskId", "audience", "audienceVersion", "callerId", "skill");
        string parent = A2aJson.Text(parameters, "parentTaskId"), audience = A2aJson.Text(parameters, "audience"),
            version = A2aJson.Text(parameters, "audienceVersion"), recipient = A2aJson.Text(parameters, "callerId"),
            skill = A2aJson.Text(parameters, "skill");
        if (!A2aJson.Identifier(audience) || !A2aDelegation.Hash(version) || !A2aJson.Identifier(recipient) || !A2aJson.Identifier(skill))
            throw new A2aException(-32602, "Invalid delegation audience or skill.");
        var work = Owned(caller, parent);
        await work.Gate.WaitAsync(ct);
        try
        {
            var record = work.Record;
            if (record.AdmittedLease is not { } lease || record.AuthorityExpiresUtc is not { } expiry
                || expiry <= DateTimeOffset.UtcNow.AddSeconds(5) || record.DelegationDepth >= 4 || record.CancellationRequested
                || record.State is "TASK_STATE_FAILED" or "TASK_STATE_CANCELED")
                throw new A2aException(-32000, "Parent task has no live delegable authority.", 403);
            var grant = new A2aDelegationGrant(1, _config.AgentId, _config.AgentVersion, audience, version,
                caller.TenantId, recipient, skill, record.Id, Guid.NewGuid().ToString("N"), expiry,
                record.DelegationDepth + 1, LeaseAuthority.From(lease));
            string token = _delegation.Issue(grant);
            await _ledger.AppendLogAsync(Guid.ParseExact(record.Id, "N"), "a2a:" + _config.AgentId,
                "A2A_DELEGATION_ISSUED", JsonSerializer.Serialize(new { parentTaskId = record.Id,
                    issuer = _config.AgentId, issuerVersion = _config.AgentVersion, audience, audienceVersion = version,
                    caller.TenantId, recipient, skill, grant.ExpiresUtc, grant.Depth, delegationSha256 = A2aDelegation.Digest(token) }),
                caller.Identity.ToLedgerIdentity(), ct);
            return new { delegationToken = token, expiresUtc = expiry };
        }
        finally { work.Gate.Release(); }
    }
}
