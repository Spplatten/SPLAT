using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Catalog;

namespace SplatMcp;

internal sealed class A2aBridge : IAsyncDisposable
{
    private sealed class Work(A2aTaskRecord record)
    {
        internal A2aTaskRecord Record = record;
        internal readonly CancellationTokenSource Cancellation = new();
        internal Task Execution = Task.CompletedTask;
    }

    private readonly A2aConfiguration _config;
    private readonly A2aTaskStore _store;
    private readonly IAuditLedger _ledger;
    private readonly Func<A2aCaller, McpServerHandler> _handler;
    private readonly IIncidentRevocationManager? _revocations;
    private readonly SemaphoreSlim _gate = new(1);
    private readonly Dictionary<string, Work> _tasks = new(StringComparer.Ordinal);
    private readonly HashSet<string> _skills;
    private int _running;
    private bool _stopping;
    private bool _faulted;
    private int _disposed;

    internal A2aBridge(A2aConfiguration config, AgentManifestApproval approval, SqliteStorageContext context,
        IAuditLedger ledger, Func<A2aCaller, McpServerHandler> handler, IIncidentRevocationManager? revocations = null)
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
        _store = new A2aTaskStore(context, config.AgentId, config.AgentVersion);
        _ledger = ledger; _handler = handler; _revocations = revocations;
        foreach (var saved in _store.Load(config.MaxTasks))
        {
            var record = saved;
            if (!Terminal(record.State))
            {
                // Never replay an external effect after a crash. A lease receipt, not a restart,
                // would be needed to establish what happened before the connection disappeared.
                record = record with { State = "TASK_STATE_FAILED", UpdatedUtc = DateTimeOffset.UtcNow,
                    Failure = "Server restarted; previous execution outcome is unconfirmed. No automatic replay." };
                _store.Save(record);
            }
            _tasks.Add(record.Id, new Work(record));
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
        if (method == "SendMessage") return new { task = await SendAsync(caller, parameters, ct) };
        if (method == "GetTask" || method == "CancelTask")
        {
            A2aJson.Fields(parameters, "id", "historyLength");
            ValidateHistory(parameters);
            var id = A2aJson.Text(parameters, "id");
            Work work;
            await _gate.WaitAsync(ct);
            try
            {
                work = Owned(caller, id);
                if (method == "GetTask") return Snapshot(work.Record);
                if (Terminal(work.Record.State)) throw new A2aException(-32002, "Task is no longer cancelable.");
                await Audit(caller, work.Record, "A2A_CANCEL_REQUESTED", CancellationToken.None);
                work.Record = work.Record with { CancellationRequested = true };
                _store.Save(work.Record);
                work.Cancellation.Cancel();
            }
            finally { _gate.Release(); }
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
            await _gate.WaitAsync(ct);
            try
            {
                var owned = _tasks.Values.Select(w => w.Record).Where(r => Owns(caller, r)
                    && (context is null || r.ContextId == context) && (state is null || r.State == state)
                    && r.UpdatedUtc >= after)
                    .OrderByDescending(r => r.UpdatedUtc).ThenBy(r => r.Id, StringComparer.Ordinal).ToArray();
                if (cursor.Length > 0 && !owned.Any(r => r.Id == cursor)) throw new A2aException(-32602, "Invalid pagination.");
                var page = (cursor.Length == 0 ? owned : owned.SkipWhile(r => r.Id != cursor).Skip(1)).Take(size + 1).ToArray();
                return new { tasks = page.Take(size).Select(r => Snapshot(r, includeArtifacts)).ToArray(), pageSize = size,
                    nextPageToken = page.Length > size ? page[size - 1].Id : "", totalSize = owned.Length };
            }
            finally { _gate.Release(); }
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
        A2aJson.Fields(data, "skill", "parameters", "parentTaskId");
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
        await _gate.WaitAsync(ct);
        try
        {
            work = _tasks.Values.FirstOrDefault(w => Owns(caller, w.Record) && w.Record.MessageId == messageId)!;
            if (work is not null)
            {
                if (work.Record.RequestSha256 != fingerprint) throw new A2aException(-32602, "messageId already names a different request.");
            }
            else
            {
                if (_stopping || _faulted) throw new A2aException(-32603, "Task execution is unavailable.", 503);
                if (_running >= _config.MaxConcurrentTasks || _tasks.Count >= _config.MaxTasks)
                    throw new A2aException(-32000, "Task capacity is exhausted; no execution was started.", 429);
                var record = new A2aTaskRecord(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
                    caller.TenantId, caller.CallerId, messageId, fingerprint, skill, parent,
                    "TASK_STATE_WORKING", DateTimeOffset.UtcNow);
                await Audit(caller, record, "A2A_TASK_AUTHORIZED", ct);
                _store.Save(record, insert: true);
                work = new Work(record);
                _tasks.Add(record.Id, work);
                _running++;
                work.Execution = Task.Run(() => ExecuteAsync(work, caller, arguments));
            }
        }
        finally { _gate.Release(); }
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
        try
        {
            work.Cancellation.Token.ThrowIfCancellationRequested();
            await CheckCallerAsync(caller, work.Cancellation.Token);
            var response = await _handler(caller).ProcessMessageAsync(new McpJsonRpcMessage
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
        await _gate.WaitAsync();
        try
        {
            if (work.Record.CancellationRequested && state != "TASK_STATE_COMPLETED")
            {
                state = "TASK_STATE_CANCELED";
                failure = "A2A task canceled; workload termination is unconfirmed.";
                result = null;
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
        finally { _running--; _gate.Release(); }
    }

    private Task Audit(A2aCaller caller, A2aTaskRecord record, string action, CancellationToken ct) =>
        _ledger.AppendLogAsync(Guid.ParseExact(record.Id, "N"), "a2a:" + _config.AgentId, action,
            JsonSerializer.Serialize(new { taskId = record.Id, contextId = record.ContextId, caller.TenantId,
                caller.CallerId, receiverAgentId = _config.AgentId, contractSha256 = _config.AgentVersion,
                record.Skill, record.CallerSuppliedParentTaskId, record.State, record.CancellationRequested }),
            caller.Identity.ToLedgerIdentity(), ct);

    private bool Owns(A2aCaller caller, A2aTaskRecord task) => task.TenantId == caller.TenantId
        && task.CallerId == caller.CallerId && caller.Skills.Contains(task.Skill, StringComparer.Ordinal);
    private Work Owned(A2aCaller caller, string id) => _tasks.TryGetValue(id, out var work) && Owns(caller, work.Record)
        ? work : throw new A2aException(-32001, "Task not found.");
    private async Task<object> ReadAsync(A2aCaller caller, string id, CancellationToken ct)
    {
        await CheckCallerAsync(caller, ct);
        await _gate.WaitAsync(ct);
        try { return Snapshot(Owned(caller, id).Record); }
        finally { _gate.Release(); }
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
            workloadTerminationConfirmed = record.CancellationRequested ? (bool?)false : null, failure = record.Failure
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
        Task[] executions;
        await _gate.WaitAsync();
        try
        {
            _stopping = true;
            executions = _tasks.Values.Select(w => w.Execution).ToArray();
            foreach (var work in _tasks.Values.Where(w => !Terminal(w.Record.State)))
            {
                work.Record = work.Record with { CancellationRequested = true };
                work.Cancellation.Cancel();
            }
        }
        finally { _gate.Release(); }
        await Task.WhenAll(executions);
        foreach (var work in _tasks.Values) work.Cancellation.Dispose();
        _gate.Dispose();
    }
}
