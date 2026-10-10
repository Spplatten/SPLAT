using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using MissionController.Core.Interfaces;

namespace MissionController.Host;

[SupportedOSPlatform("windows")]
public sealed class ManagedBridgeClient(ManagedBridgeConfiguration configuration) : ILeasedExecutor
{
    public const string ConfigurationEnvironmentVariable = "SPLAT_MANAGED_CONFIGURATION";
    public const PipeAccessRights ClientRights = PipeAccessRights.ReadData | PipeAccessRights.WriteData |
        PipeAccessRights.ReadPermissions | PipeAccessRights.Synchronize;
    private const int MaxRequestChars = 1024 * 1024;
    // Two bounded process captures may expand sixfold when JSON escapes control characters.
    private const int MaxResponseBytes = 64 * 1024 * 1024;

    public static ManagedBridgeClient? FromEnvironment()
    {
        string? path = Environment.GetEnvironmentVariable(ConfigurationEnvironmentVariable);
        if (path is null)
        {
            path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "SplatManaged", "bridge.json");
            if (!File.Exists(path)) return null;
        }
        // A configured but unavailable service must fail closed, never use the operator's guest.
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return new(ManagedBridgeConfiguration.Load(path));
    }

    public static async Task<NamedPipeClientStream> ConnectAsync(string name, string expectedSid, CancellationToken ct)
    {
        var pipe = new NamedPipeClientStream(".", name, ClientRights, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification, HandleInheritability.None);
        try
        {
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
            budget.CancelAfter(TimeSpan.FromSeconds(10));
            await pipe.ConnectAsync(10000, budget.Token);
            string owner = pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier))!.Value;
            if (owner != expectedSid)
                throw new UnauthorizedAccessException("The pipe server is not the configured service principal.");
            // Even the identity bootstrap waits for the owner check; a counterfeit receives no bytes.
            await pipe.WriteAsync(new byte[] { 1 }, budget.Token);
            var response = new byte[1];
            if (await pipe.ReadAsync(response, budget.Token) != 1 || response[0] != 1)
                throw new UnauthorizedAccessException("The managed bridge refused this client.");
            return pipe;
        }
        catch { pipe.Dispose(); throw; }
    }

    public Task<SubstrateReport> CheckAsync(CancellationToken ct = default) =>
        CallAsync<SubstrateReport>(ManagedLeaseRequest.CheckMethod, new { }, TimeSpan.FromMinutes(2), ct);

    public async Task<ProcessExecutionResult> ExecuteLeasedAsync(LeaseSpec lease, string command,
        IReadOnlyList<string> argv, IProgress<string>? stdout = null, IProgress<string>? stderr = null,
        IProgress<LeaseViolationEvent>? violations = null, CancellationToken ct = default)
    {
        var request = new ManagedLeaseRequest(lease, command, argv);
        request.Validate(string.IsNullOrEmpty(configuration.Egress) ? McpEgressPolicy.None : McpEgressPolicy.Parse(configuration.Egress));
        var result = await CallAsync<ManagedLeaseResult>(ManagedLeaseRequest.ExecuteMethod, request,
            TimeSpan.FromSeconds(lease.LeaseDurationSeconds + 60), ct);
        if (result.Process is null || result.Violations is null)
            throw new InvalidDataException("The managed bridge returned an incomplete lease result.");
        // Preserve the guest's measured controls and signed outcome instead of reconstructing them
        // from an MCP prose transcript. The mission engine applies its normal scrub before egress.
        stdout?.Report(result.Process.StandardOutput);
        stderr?.Report(result.Process.StandardError);
        foreach (var violation in result.Violations) violations?.Report(violation);
        return result.Process;
    }

    private async Task<T> CallAsync<T>(string method, object parameters, TimeSpan timeout, CancellationToken ct)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(timeout);
        string id = Guid.NewGuid().ToString("N");
        string request = JsonSerializer.Serialize(new { jsonrpc = "2.0", id, method, @params = parameters });
        if (request.Length > MaxRequestChars) throw new InvalidDataException("Managed request exceeds the frame limit.");
        using var pipe = await ConnectAsync(configuration.PipeName, configuration.ServiceSid, budget.Token);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
        await writer.WriteLineAsync(request.AsMemory(), budget.Token);
        using var reply = JsonDocument.Parse(await ReadResponseAsync(pipe, budget.Token));
        var root = reply.RootElement;
        if (!root.TryGetProperty("jsonrpc", out var version) || version.GetString() != "2.0"
            || !root.TryGetProperty("id", out var replyId) || replyId.ValueKind != JsonValueKind.String || replyId.GetString() != id)
            throw new InvalidDataException("The managed response did not match this request.");
        if (root.TryGetProperty("error", out var error) && error.ValueKind != JsonValueKind.Null)
            throw new InvalidOperationException(error.GetProperty("message").GetString() ?? "The managed service refused the request.");
        return root.GetProperty("result").Deserialize<T>()
            ?? throw new InvalidDataException("The managed service returned no result.");
    }

    private static async Task<string> ReadResponseAsync(Stream stream, CancellationToken ct)
    {
        using var text = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            // Read the pipe directly: a text reader can wait to fill its character buffer while
            // the server is already waiting for our next request after a complete response.
            int read = await stream.ReadAsync(buffer.AsMemory(), ct);
            if (read == 0) throw new EndOfStreamException("The managed bridge closed before completing its response.");
            int newline = Array.IndexOf(buffer, (byte)'\n', 0, read);
            int count = newline < 0 ? read : newline;
            if (text.Length + count > MaxResponseBytes) throw new InvalidDataException("Managed response exceeds the frame limit.");
            text.Write(buffer, 0, count);
            if (newline >= 0) return new UTF8Encoding(false, true).GetString(text.GetBuffer(), 0, (int)text.Length);
        }
    }
}
