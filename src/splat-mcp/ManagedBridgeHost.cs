using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Host;
using MissionController.Infrastructure.Linux;

namespace SplatMcp;

internal sealed class ManagedPipeIdentity : IOperatorIdentityProvider
{
    private readonly AsyncLocal<OperatorIdentity?> _current = new();
    internal void Set(OperatorIdentity identity) => _current.Value = identity;
    public ValueTask<OperatorIdentity> ResolveAsync(CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(_current.Value ?? throw new McpAuthenticationException("No authenticated pipe caller.", "NO_PIPE_IDENTITY"));
}

internal static class ManagedBridgeHost
{
    // This mode exposes the Linux lease boundary. Host filesystem/model/admin tools are not proxies
    // into a more privileged Windows account and must earn their own service-side authorization.
    internal static readonly HashSet<string> AllowedTools = new(StringComparer.Ordinal)
        { "run_command", "run_code", "get_substrate_health" };
    internal const PipeAccessRights ClientRights = ManagedBridgeClient.ClientRights;

    // The admission row's exact shape. ManagedLedgerAudit finds a probe's rows by these strings, so
    // the writer and the reader share them rather than each spelling the row its own way.
    internal const string Transport = "mcp-managed-pipe";
    internal const string AdmissionAction = "MANAGED_CALL_ADMITTED";
    internal static string AdmissionDetails(string tool, string requestSha256) => $"Tool={tool}; request_sha256={requestSha256}";
    internal static string RequestSha256(JsonElement? parameters) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(parameters?.GetRawText() ?? "null"))).ToLowerInvariant();

    internal static PipeSecurity Security(ManagedBridgeConfiguration config)
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(new SecurityIdentifier(config.ServiceSid));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(config.ServiceSid), PipeAccessRights.FullControl, AccessControlType.Allow));
        foreach (string sid in config.OperatorSids)
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(sid), ClientRights, AccessControlType.Allow));
        // GENERIC_WRITE also grants CreateNewInstance. Clients receive the individual rights above
        // so an admitted operator cannot add a counterfeit server instance to this pipe.
        return security;
    }

    internal static async Task RunAsync(ManagedBridgeConfiguration config, McpServerHandler handler,
        IAuditLedger ledger, ManagedPipeIdentity identity, CancellationToken ct)
    {
        var security = Security(config);
        NamedPipeServerStream Create(bool first) => NamedPipeServerStreamAcl.Create(config.PipeName,
            PipeDirection.InOut, 9, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None),
            65536, 65536, security);
        // Keep the first handle alive for the entire lifetime, including between client sessions.
        using var anchor = Create(true);
        using var keeper = new NamedPipeClientStream(".", config.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        var anchored = anchor.WaitForConnectionAsync(ct);
        await keeper.ConnectAsync(10000, ct);
        await anchored;
        using var slots = new SemaphoreSlim(8);
        var active = new List<Task>();
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await slots.WaitAsync(ct);
                NamedPipeServerStream? pipe = null;
                try
                {
                    pipe = Create(false);
                    await pipe.WaitForConnectionAsync(ct);
                    var connected = pipe;
                    active.RemoveAll(t => t.IsCompleted);
                    active.Add(Task.Run(async () =>
                    {
                        try { await ServeConnectionAsync(connected, config, handler, ledger, identity, ct); }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OperationCanceledException or DecoderFallbackException) { }
                        finally { connected.Dispose(); slots.Release(); }
                    }, CancellationToken.None));
                    pipe = null;
                }
                finally
                {
                    if (pipe is not null) { pipe.Dispose(); slots.Release(); }
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        finally { await Task.WhenAll(active); }
    }

    private static async Task ServeConnectionAsync(NamedPipeServerStream pipe, ManagedBridgeConfiguration config,
        McpServerHandler handler, IAuditLedger ledger, ManagedPipeIdentity identity, CancellationToken ct)
    {
        using var handshake = CancellationTokenSource.CreateLinkedTokenSource(ct);
        handshake.CancelAfter(TimeSpan.FromSeconds(10));
        var hello = new byte[1];
        if (await pipe.ReadAsync(hello, handshake.Token) != 1 || hello[0] != 1) return;
        identity.Set(IdentifyCaller(pipe, config));
        await pipe.WriteAsync(new byte[] { 1 }, handshake.Token);
        using var reader = new StreamReader(pipe, new UTF8Encoding(false, true), leaveOpen: true);
        // Bound a connection independently of the caller. Lease expiry is also enforced by the guest.
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lifetime.CancelAfter(TimeSpan.FromMinutes(30));
        await Program.ServeAsync(reader, pipe, handler, lifetime.Token,
            (request, token) => DispatchAsync(request, handler, ledger, identity, token,
                cancellation => CheckManagedAsync(config, cancellation)));
    }

    /// <summary>
    /// The caller, read from its own token. The client supplies Identification-level impersonation,
    /// which names a principal but can open nothing, and the service impersonates only for this read.
    /// </summary>
    internal static OperatorIdentity IdentifyCaller(NamedPipeServerStream pipe, ManagedBridgeConfiguration config)
    {
        OperatorIdentity? caller = null;
        // Run in a copy of the context, because without one the client's token outlived the call.
        // WindowsIdentity.Name goes through RunImpersonated, which keeps the thread's current token, here
        // the client's, in an AsyncLocal of the caller's ExecutionContext. Every await after it then
        // resumed impersonating that token, so while it served a call the service could not open a file:
        // SQLite, the error log and the runtime's own assembly loader all failed (2026-10-20).
        ExecutionContext.Run(ExecutionContext.Capture() ?? throw new InvalidOperationException("Execution context flow is suppressed."),
            _ => pipe.RunAsClient(() =>
            {
                using var token = WindowsIdentity.GetCurrent(true) ?? throw new UnauthorizedAccessException("Missing client token.");
                string sid = token.User?.Value ?? throw new UnauthorizedAccessException("Missing client SID.");
                if (!config.OperatorSids.Contains(sid, StringComparer.Ordinal)) throw new UnauthorizedAccessException("Caller is not admitted.");
                caller = new OperatorIdentity(token.Name, sid, OperatorAuthenticationMethod.WindowsAuthenticated, Transport);
            }), null);
        return caller ?? throw new UnauthorizedAccessException("Missing pipe identity.");
    }

    private static async Task<SubstrateReport> CheckManagedAsync(ManagedBridgeConfiguration config, CancellationToken ct)
    {
        var guest = new ManagedGuest(config.Distribution);
        var token = new WslAgentToken(guest.ReadTokenAsync);
        using var output = new StringWriter();
        output.WriteLine($"Managed guest: {config.Distribution}; service: {config.ServiceName}");
        int exit = await SubstrateDoctor.RunAsync(new DoctorOptions(config.WorkspaceDirectory,
                string.IsNullOrEmpty(config.Egress) ? McpEgressPolicy.None : McpEgressPolicy.Parse(config.Egress),
                Path.Combine(config.StateDirectory, "ledger.key")) { LeasedWork = "managed Linux leases" }, output,
            wsl: (args, cancellation) => SubstrateDoctor.RunWslAsync(new[] { "-d", config.Distribution }.Concat(args).ToArray(), cancellation),
            health: new WslSubstrateHealthChecker("127.0.0.1", config.Port, token),
            ledgerPath: Path.Combine(config.StateDirectory, "ledger.db"), ct: ct);
        return new SubstrateReport(exit, output.ToString());
    }

    internal static async Task<McpJsonRpcMessage> DispatchAsync(McpJsonRpcMessage request,
        McpServerHandler handler, IAuditLedger ledger, IOperatorIdentityProvider identity, CancellationToken ct,
        Func<CancellationToken, Task<SubstrateReport>>? checkManaged = null)
    {
        bool executeLease = request.Method == ManagedLeaseRequest.ExecuteMethod;
        bool checkSubstrate = request.Method == ManagedLeaseRequest.CheckMethod;
        if (request.Method == "tools/call" || executeLease || checkSubstrate)
        {
            string? tool = executeLease ? "execute_lease" : checkSubstrate ? "check_substrate" :
                request.Params is { } parameters && parameters.TryGetProperty("name", out var name)
                && name.ValueKind == JsonValueKind.String ? name.GetString() : null;
            if (tool is null || (!executeLease && !checkSubstrate && !AllowedTools.Contains(tool)))
                return new McpJsonRpcMessage { JsonRpc = "2.0", Id = request.Id,
                    Error = new McpError { Code = -32601, Message = "This managed service exposes Linux lease tools and substrate health only." } };
            var actor = await identity.ResolveAsync(ct);
            if (!actor.IsAttributable || actor.Transport != Transport) throw new UnauthorizedAccessException("Untrusted service caller.");
            string digest = RequestSha256(request.Params);
            // Commit intent before calling any handler. A failed ledger write means no execution;
            // cancellation after execution still leaves a durable, SID-attributed admission record.
            try
            {
                await ledger.AppendLogAsync(Guid.NewGuid(), "mcp-tool-" + tool, AdmissionAction,
                    AdmissionDetails(tool, digest), actor.ToLedgerIdentity(), ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                // The reply says what failed and where, never the message, which can name a private path; the
                // service keeps the rest. The refusal used to drop both, and a gate run had nothing to act on (2026-10-19).
                return new McpJsonRpcMessage { JsonRpc = "2.0", Id = request.Id,
                    Error = new McpError { Code = -32001, Message = $"The managed audit admission could not be committed ({handler.RecordInternalError(ex)}); no tool was run." } };
            }
            if (executeLease)
                return await handler.ExecuteManagedLeaseAsync(request, actor.ToLedgerIdentity(), ct);
            if (checkSubstrate)
                return checkManaged is null
                    ? new McpJsonRpcMessage { JsonRpc = "2.0", Id = request.Id,
                        Error = new McpError { Code = -32601, Message = "The managed substrate report is unavailable." } }
                    : new McpJsonRpcMessage { JsonRpc = "2.0", Id = request.Id,
                        Result = JsonSerializer.SerializeToElement(await checkManaged(ct)) };
        }
        var response = await handler.ProcessMessageAsync(request, ct);
        if (request.Method == "tools/list" && response.Result is { } result)
        {
            var tools = result.GetProperty("tools").EnumerateArray()
                .Where(tool => AllowedTools.Contains(tool.GetProperty("name").GetString() ?? "")).Select(tool => tool.Clone()).ToArray();
            response.Result = JsonSerializer.SerializeToElement(new { tools });
        }
        return response;
    }

    internal static Task<NamedPipeClientStream> ConnectAsync(string name, string expectedSid, CancellationToken ct) =>
        ManagedBridgeClient.ConnectAsync(name, expectedSid, ct);

    internal static async Task<int> ProxyAsync(ManagedBridgeConfiguration config, TextReader input, Stream output, CancellationToken ct)
    {
        using var pipe = await ConnectAsync(config.PipeName, config.ServiceSid, ct);
        using var reader = new StreamReader(pipe, new UTF8Encoding(false, true), leaveOpen: true);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
        using var destination = new StreamWriter(output, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
        // One request/response at a time preserves the existing stdio contract, including EOF.
        while (true)
        {
            var (line, oversized) = await Program.ReadBoundedLineAsync(input, ct);
            if (oversized) throw new InvalidDataException("MCP request exceeds the frame limit.");
            if (line is null) break;
            if (string.IsNullOrWhiteSpace(line)) continue;
            await writer.WriteLineAsync(line.AsMemory(), ct);
            var (reply, responseOversized) = await Program.ReadBoundedLineAsync(reader, ct);
            if (responseOversized || reply is null) throw new InvalidDataException("Invalid response from the managed bridge.");
            await destination.WriteLineAsync(reply.AsMemory(), ct);
        }
        return 0;
    }
}
