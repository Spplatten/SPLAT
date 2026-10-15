using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using MissionController.Core;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Data.Compliance;
using MissionController.Infrastructure.Linux;
using MissionController.Infrastructure.Network.Identity;

namespace SplatMcp;

internal static class A2aServer
{
    internal const int MaximumBodyBytes = 64 * 1024;

    internal static async Task<int?> TryRunAsync(string[] args)
    {
        if (args.Length == 0 || args[0] != "a2a") return null;
        if (args.Length != 3 || args[1] != "--configuration")
        {
            Console.Error.WriteLine("Usage: splat-mcp a2a --configuration <approved-a2a.json>");
            return 2;
        }
        try
        {
            var config = A2aConfiguration.Load(Path.GetFullPath(args[2]));
            using var certificate = LoadCertificate(config.CertificateFile,
                Environment.GetEnvironmentVariable("SPLAT_A2A_CERT_PASSWORD"));
            if (!certificate.HasPrivateKey || certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow
                || certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow)
                throw new InvalidOperationException("A current HTTPS certificate with a private key is required.");
            string db = Environment.GetEnvironmentVariable("SPLAT_DB_PATH") ?? SplatDataRoot.Layout.LedgerDatabase;
            // Prevent a second host from declaring a live peer's working tasks interrupted.
            string lockPath = Path.GetFullPath(db) + ".a2a-" + config.AgentId + ".lock";
            Directory.CreateDirectory(Path.GetDirectoryName(lockPath)!);
            using var instance = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            byte[]? key = Environment.GetEnvironmentVariable(LedgerKeyFile.EnvironmentVariable) is { Length: > 0 } keyFile
                ? LedgerKeyFile.Read(keyFile) : null;
            var chain = await SqliteChainedAuditLedger.InspectAsync(db, key);
            if (chain.Keyed && chain.KeyMatches != true) throw new InvalidOperationException("The configured audit ledger key is required.");
            var context = new SqliteStorageContext(db);
            var approval = await new AgentManifestImporter(context).LoadApprovedAsync(config.AgentId, config.AgentVersion);
            var ledger = new SqliteChainedAuditLedger(context, key);
            var revocations = new IncidentRevocationManager(ledger, new SqliteRevocationStore(context));
            using var signer = Environment.GetEnvironmentVariable(RunRecordKeyFile.EnvironmentVariable) is { Length: > 0 } signingFile
                ? RunRecordKeyFile.Load(signingFile) : null;
            var merkle = new MerkleTreeEngine();
            var records = new MissionRunRecordAssembler(ledger, merkle, new ComplianceArchiveExporter(merkle, signer));
            var executor = new WslLeasedExecutor();
            var compiler = new TemplatePolicyCompiler();
            await using var bridge = new A2aBridge(config, approval, context, ledger, caller =>
                new McpServerHandler(executor, compiler, ledger, agent: approval, runRecords: records,
                    revocationManager: revocations, identityProvider: new StaticOperatorIdentityProvider(caller.Identity)), revocations);
            await using var app = CreateApplication(config, bridge, certificate);
            Console.Error.WriteLine($"splat-mcp: A2A 1.0 on https://127.0.0.1:{config.Port}/a2a; approved agent {config.AgentId}@{config.AgentVersion}");
            await app.RunAsync();
            return 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException
            or ArgumentException or JsonException or CryptographicException or A2aException)
        {
            Console.Error.WriteLine("splat-mcp: A2A startup refused: " + ex.Message);
            return 2;
        }
    }

    internal static X509Certificate2 LoadCertificate(string path, string? password) =>
        // Windows Schannel needs a named private key. Omitting PersistKeySet lets disposal remove
        // the temporary user-key container; no machine trust store is modified.
        X509CertificateLoader.LoadPkcs12FromFile(path, password, OperatingSystem.IsWindows()
            ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.EphemeralKeySet);

    internal static WebApplication CreateApplication(A2aConfiguration config, A2aBridge bridge, X509Certificate2 certificate)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
        {
            Args = Array.Empty<string>(), ApplicationName = typeof(A2aServer).Assembly.FullName,
            EnvironmentName = "Production", ContentRootPath = AppContext.BaseDirectory
        });
        // Ambient ASPNETCORE_URLS/appsettings must not widen this first, local-only endpoint.
        builder.Configuration.Sources.Clear();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.AddServerHeader = false;
            options.Limits.MaxRequestBodySize = MaximumBodyBytes;
            options.Limits.MaxConcurrentConnections = 64;
            options.Limits.MaxRequestHeadersTotalSize = 8192;
            options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
            options.Listen(IPAddress.Loopback, config.Port, endpoint => endpoint.UseHttps(certificate));
        });
        var app = builder.Build();
        app.Run(context => HandleAsync(context, config, bridge));
        return app;
    }

    private static async Task HandleAsync(HttpContext http, A2aConfiguration config, A2aBridge bridge)
    {
        JsonElement? id = null;
        http.Response.Headers.CacheControl = "no-store";
        http.Response.Headers["A2A-Version"] = "1.0";
        try
        {
            if (http.Request.Host.Host != "127.0.0.1" || http.Request.Host.Port != config.Port
                || http.Request.Headers.ContainsKey("Origin"))
                throw new A2aException(-32000, "This endpoint accepts authenticated local agents.", 403);
            if (http.Request.Headers.Authorization.Count != 1
                || bridge.Authenticate(http.Request.Headers.Authorization.ToString()) is not { } caller)
            {
                http.Response.Headers.WWWAuthenticate = "Bearer realm=\"splat-a2a\"";
                throw new A2aException(-32000, "Authentication required.", 401);
            }
            await bridge.CheckCallerAsync(caller, http.RequestAborted);
            if (http.Request.Method == "GET" && http.Request.Path == "/.well-known/agent-card.json")
            {
                await http.Response.WriteAsJsonAsync(bridge.Card(caller), A2aConfiguration.Json, http.RequestAborted);
                return;
            }
            if (http.Request.Method != "POST" || http.Request.Path != "/a2a")
                throw new A2aException(-32601, "Endpoint not found.", 404);
            if (http.Request.ContentType?.Split(';')[0].Trim() != "application/json")
                throw new A2aException(-32005, "application/json is required.", 415);
            if (http.Request.Headers["A2A-Version"].ToString() != "1.0")
                throw new A2aException(-32009, "A2A-Version 1.0 is required.");
            if (!http.Request.Headers["A2A-Extensions"].ToString().Split(',').Select(s => s.Trim())
                .Contains(A2aConfiguration.Extension, StringComparer.Ordinal))
                throw new A2aException(-32008, "The SPLAT template-lease extension is required.");
            using var body = new MemoryStream();
            var buffer = new byte[8192];
            using var readBudget = CancellationTokenSource.CreateLinkedTokenSource(http.RequestAborted);
            readBudget.CancelAfter(TimeSpan.FromSeconds(15));
            int count;
            while ((count = await http.Request.Body.ReadAsync(buffer, readBudget.Token)) != 0)
            {
                if (body.Length + count > MaximumBodyBytes) throw new A2aException(-32600, "Request exceeds 64 KiB.", 413);
                body.Write(buffer, 0, count);
            }
            using var document = JsonDocument.Parse(body.ToArray(), new JsonDocumentOptions { MaxDepth = 24 });
            var request = document.RootElement;
            A2aJson.Fields(request, "jsonrpc", "id", "method", "params");
            if (A2aJson.Text(request, "jsonrpc") != "2.0" || !request.TryGetProperty("id", out var requestId)
                || requestId.ValueKind is not (JsonValueKind.String or JsonValueKind.Number)
                || requestId.GetRawText().Length > 256)
                throw new A2aException(-32600, "A bounded JSON-RPC request ID is required.");
            id = requestId.Clone();
            string method = A2aJson.Text(request, "method");
            if (!request.TryGetProperty("params", out var parameters)) parameters = JsonSerializer.SerializeToElement(new { });
            var result = await bridge.DispatchAsync(caller, method, parameters, http.RequestAborted);
            await http.Response.WriteAsJsonAsync(new { jsonrpc = "2.0", id, result }, A2aConfiguration.Json, http.RequestAborted);
        }
        catch (A2aException ex) { await Error(http, id, ex.Code, ex.Message, ex.HttpStatus); }
        catch (JsonException) { await Error(http, id, -32700, "Invalid JSON.", 400); }
        catch (BadHttpRequestException ex) { await Error(http, id, -32600, "Invalid HTTP request.", ex.StatusCode); }
        catch (OperationCanceledException) when (!http.RequestAborted.IsCancellationRequested)
        { await Error(http, id, -32600, "Request body deadline exceeded.", 408); }
        catch (OperationCanceledException) { }
        catch (Exception) { await Error(http, id, -32603, "Request failed; consult the operator's audit ledger.", 500); }
    }

    private static Task Error(HttpContext http, JsonElement? id, int code, string message, int status)
    {
        if (http.Response.HasStarted || http.RequestAborted.IsCancellationRequested) return Task.CompletedTask;
        http.Response.StatusCode = status;
        // JSON-RPC requires id:null on a request that could not be identified; global null omission
        // is appropriate for ProtoJSON objects, but not for this envelope.
        return http.Response.WriteAsJsonAsync(new { jsonrpc = "2.0", id, error = new { code, message } },
            new JsonSerializerOptions(A2aConfiguration.Json) { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never }, http.RequestAborted);
    }
}
