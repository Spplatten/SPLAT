using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Linux;
using MissionController.Infrastructure.Network.Identity;
using MissionController.Infrastructure.Windows.Security;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Every ledger row this product wrote used to be attributed to a string literal chosen at the call
/// site - "Operator_AuntMaryTier1", "Operator_1Click", "mcp-client" - while the README mapped the
/// ledger to NIST AU.2.041-042 non-repudiation. A hash chain over an actor nobody established
/// proves the row was not edited; it says nothing about who acted.
///
/// These tests pin the replacement: an identity is always resolved, always carries its provenance,
/// and an unestablished one is labelled as such rather than given a plausible name.
/// </summary>
public class OperatorAttributionTests
{
    // ---------------------------------------------------------------- the ledger string

    [Fact]
    public void WindowsIdentity_CarriesItsProvenanceAndStableSid()
    {
        var identity = new OperatorIdentity(
            @"CONTOSO\jsmith", "S-1-5-21-1-2-3-1001",
            OperatorAuthenticationMethod.WindowsAuthenticated, "winui-console");

        Assert.Equal(@"windows:CONTOSO\jsmith [S-1-5-21-1-2-3-1001] via winui-console",
            identity.ToLedgerIdentity());
        Assert.True(identity.IsAttributable);
    }

    /// <summary>
    /// The decisive property. An unresolved principal must be self-evidently unresolved in the
    /// ledger - never a name that reads like a person, which is exactly how "Operator_AuntMaryTier1"
    /// passed for attribution for so long.
    /// </summary>
    [Fact]
    public void AnUnresolvedPrincipal_IsLabelledUnauthenticated_NotGivenAName()
    {
        var identity = OperatorIdentity.Unknown("mcp-stdio");

        Assert.False(identity.IsAttributable);
        Assert.StartsWith("unauthenticated:", identity.ToLedgerIdentity());
        Assert.Contains("unresolved-principal", identity.ToLedgerIdentity());
    }

    [Theory]
    [InlineData(OperatorAuthenticationMethod.WindowsAuthenticated, "windows:")]
    [InlineData(OperatorAuthenticationMethod.ApiKey, "apikey:")]
    [InlineData(OperatorAuthenticationMethod.BearerToken, "bearer:")]
    [InlineData(OperatorAuthenticationMethod.Unauthenticated, "unauthenticated:")]
    public void EveryMethod_IsDistinguishableInTheLedgerColumn(OperatorAuthenticationMethod method, string prefix)
    {
        var identity = new OperatorIdentity("actor", null, method);

        Assert.StartsWith(prefix, identity.ToLedgerIdentity());
    }

    // ---------------------------------------------------------------- the Windows console

    /// <summary>
    /// The operator console resolves the real logon session. This is a stronger claim than a
    /// self-issued token would be: the OS authenticated this principal against the SAM or a domain
    /// controller, and the app has no separate authority it could add.
    /// </summary>
    [Fact]
    public async Task WindowsProvider_ResolvesTheRealLogonSession()
    {
        var provider = new WindowsOperatorIdentityProvider("winui-console");

        var identity = await provider.ResolveAsync();

        Assert.Equal(OperatorAuthenticationMethod.WindowsAuthenticated, identity.Method);
        Assert.True(identity.IsAttributable);
        Assert.False(string.IsNullOrWhiteSpace(identity.DisplayName));

        // A real SID, not a placeholder - display names are renameable and SIDs are not.
        Assert.NotNull(identity.PrincipalId);
        Assert.StartsWith("S-1-", identity.PrincipalId);
        Assert.Equal(System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value, identity.PrincipalId);
    }

    // ---------------------------------------------------------------- the MCP server

    private static SecurityIdentityContext Context(string name, DateTimeOffset? expiry = null) => new(
        name, "tenant-a", new HashSet<string> { "*" }, new Dictionary<string, string>(),
        DateTimeOffset.UtcNow.AddMinutes(-1), expiry ?? DateTimeOffset.UtcNow.AddHours(1), "test");

    /// <summary>
    /// With no credential configured, a stdio MCP server is spawned by its client and runs in that
    /// user's own session - so the honest actor is the host principal, tagged with the transport. A
    /// mandatory token here would be a ceremony, not a control; what matters is that the transport
    /// name never again occupies the column reserved for who acted.
    /// </summary>
    [Fact]
    public async Task McpWithoutACredential_AttributesToTheHostPrincipal_TaggedWithTransport()
    {
        var provider = new McpOperatorIdentityProvider(
            new StaticOperatorIdentityProvider(new OperatorIdentity(
                @"CONTOSO\svc", "S-1-5-21-9", OperatorAuthenticationMethod.WindowsAuthenticated)));

        var identity = await provider.ResolveAsync();

        Assert.Equal(OperatorAuthenticationMethod.WindowsAuthenticated, identity.Method);
        Assert.Equal("mcp-stdio", identity.Transport);
        Assert.Contains("via mcp-stdio", identity.ToLedgerIdentity());
        Assert.DoesNotContain("mcp-client", identity.ToLedgerIdentity());
    }

    /// <summary>
    /// A configured credential makes IApiKeyValidator load-bearing. It has existed and been tested
    /// since the first commit while gating nothing at all.
    /// </summary>
    [Fact]
    public async Task McpWithAValidApiKey_AttributesToTheValidatedIdentity()
    {
        var validator = new ApiKeyValidator();
        validator.RegisterApiKey("k-live-9f2c", Context("ci-runner"));

        var provider = new McpOperatorIdentityProvider(
            new StaticOperatorIdentityProvider(OperatorIdentity.Unknown()),
            apiKeyValidator: validator,
            presentedCredential: "k-live-9f2c");

        var identity = await provider.ResolveAsync();

        Assert.Equal(OperatorAuthenticationMethod.ApiKey, identity.Method);
        Assert.Equal("ci-runner", identity.DisplayName);
        Assert.StartsWith("apikey:ci-runner", identity.ToLedgerIdentity());
    }

    /// <summary>
    /// FAIL CLOSED. Falling back to an anonymous row on a bad credential would let a caller
    /// downgrade their own attribution just by sending a token that does not validate.
    /// </summary>
    [Fact]
    public async Task McpWithAnInvalidCredential_RefusesRatherThanFallingBackToAnonymous()
    {
        var provider = new McpOperatorIdentityProvider(
            new StaticOperatorIdentityProvider(new OperatorIdentity(
                @"CONTOSO\svc", "S-1-5-21-9", OperatorAuthenticationMethod.WindowsAuthenticated)),
            apiKeyValidator: new ApiKeyValidator(),
            presentedCredential: "k-not-registered");

        var ex = await Assert.ThrowsAsync<McpAuthenticationException>(
            () => provider.ResolveAsync().AsTask());

        Assert.Equal("INVALID_API_KEY", ex.ErrorCode);
    }

    [Fact]
    public async Task McpWithACredentialAndNoValidator_RefusesInsteadOfTrustingTheAssertion()
    {
        var provider = new McpOperatorIdentityProvider(
            new StaticOperatorIdentityProvider(OperatorIdentity.Unknown()),
            presentedCredential: "some-token");

        var ex = await Assert.ThrowsAsync<McpAuthenticationException>(
            () => provider.ResolveAsync().AsTask());

        Assert.Equal("NO_VALIDATOR_CONFIGURED", ex.ErrorCode);
    }

    [Fact]
    public async Task McpWithAValidBearerToken_AttributesToTheTokenSubject()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var validator = new JwtTokenValidator();
        validator.RegisterHmacSecret("default", secret);

        var provider = new McpOperatorIdentityProvider(
            new StaticOperatorIdentityProvider(OperatorIdentity.Unknown()),
            tokenValidator: validator,
            presentedCredential: BuildHs256Jwt(secret));

        var identity = await provider.ResolveAsync();

        Assert.Equal(OperatorAuthenticationMethod.BearerToken, identity.Method);
        Assert.StartsWith("bearer:", identity.ToLedgerIdentity());
    }

    private static string BuildHs256Jwt(byte[] secret)
    {
        static string B64(byte[] b) =>
            Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        string header = B64(Encoding.UTF8.GetBytes("""{"alg":"HS256","typ":"JWT","kid":"default"}"""));
        string payload = B64(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            sub = "agent-7",
            exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
        })));

        using var hmac = new HMACSHA256(secret);
        string signature = B64(hmac.ComputeHash(Encoding.UTF8.GetBytes($"{header}.{payload}")));
        return $"{header}.{payload}.{signature}";
    }

    // ---------------------------------------------------------------- end to end through the ledger

    private sealed class RecordingLedger : IAuditLedger
    {
        public readonly List<string> Actors = new();

        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details,
            string operatorIdentity, CancellationToken cancellationToken = default)
        {
            lock (Actors) Actors.Add(operatorIdentity);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }

    private sealed class StubLeasedExecutor : ILeasedExecutor
    {
        public Task<ProcessExecutionResult> ExecuteLeasedAsync(
            LeaseSpec lease, string command, IReadOnlyList<string> argv,
            IProgress<string>? stdout = null, IProgress<string>? stderr = null,
            IProgress<LeaseViolationEvent>? violations = null, CancellationToken ct = default) =>
            Task.FromResult(new ProcessExecutionResult(0, "ok", "", false, JobResourceMetrics.Unavailable));
    }

    /// <summary>
    /// The whole point, asserted where it lands: the ledger row itself. This is the assertion that
    /// would have failed for the entire life of the product before this change.
    /// </summary>
    [Fact]
    public async Task McpToolCall_WritesAnAttributedActorToTheLedger_NotTheTransportName()
    {
        var ledger = new RecordingLedger();
        var handler = new McpServerHandler(
            new StubLeasedExecutor(),
            new TemplatePolicyCompiler(),
            ledger,
            identityProvider: new McpOperatorIdentityProvider(
                new StaticOperatorIdentityProvider(new OperatorIdentity(
                    @"CONTOSO\sean", "S-1-5-21-42", OperatorAuthenticationMethod.WindowsAuthenticated))));

        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(1),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "run_command",
                arguments = new { command = "/bin/true" }
            })
        };

        await handler.ProcessMessageAsync(request);

        string actor = Assert.Single(ledger.Actors);
        Assert.Equal(@"windows:CONTOSO\sean [S-1-5-21-42] via mcp-stdio", actor);
        Assert.DoesNotContain("mcp-client", actor);
    }

    /// <summary>A refused credential must reach the client as an error, not a silent anonymous run.</summary>
    [Fact]
    public async Task McpToolCall_WithABadCredential_ReturnsAnErrorAndWritesNothing()
    {
        var ledger = new RecordingLedger();
        var handler = new McpServerHandler(
            new StubLeasedExecutor(),
            new TemplatePolicyCompiler(),
            ledger,
            identityProvider: new McpOperatorIdentityProvider(
                new StaticOperatorIdentityProvider(OperatorIdentity.Unknown()),
                apiKeyValidator: new ApiKeyValidator(),
                presentedCredential: "k-forged"));

        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(2),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "run_command",
                arguments = new { command = "/bin/true" }
            })
        };

        var response = await handler.ProcessMessageAsync(request);

        Assert.NotNull(response.Error);
        Assert.Contains("Authentication failed", response.Error!.Message);
        Assert.Empty(ledger.Actors);
    }

    // ---------------------------------------------------------------- no literals left

    /// <summary>
    /// A grep guard. The literals are gone from the dispatch paths; this fails if one comes back,
    /// which is cheaper than rediscovering it in an audit.
    /// </summary>
    [Fact]
    public void NoDispatchPathStillPassesAHardcodedOperatorLiteral()
    {
        string root = FindRepositoryRoot();
        var offenders = new List<string>();

        foreach (string file in System.IO.Directory.EnumerateFiles(
                     System.IO.Path.Combine(root, "src"), "*.cs", System.IO.SearchOption.AllDirectories))
        {
            if (file.Contains($"{System.IO.Path.DirectorySeparatorChar}bin{System.IO.Path.DirectorySeparatorChar}") ||
                file.Contains($"{System.IO.Path.DirectorySeparatorChar}obj{System.IO.Path.DirectorySeparatorChar}"))
            {
                continue;
            }

            foreach (var (line, number) in System.IO.File.ReadLines(file).Select((l, i) => (l, i + 1)))
            {
                string trimmed = line.TrimStart();
                // Comments describing the old behaviour are the point of the record, not a relapse.
                if (trimmed.StartsWith("//") || trimmed.StartsWith("///") || trimmed.StartsWith("*"))
                {
                    continue;
                }

                if (line.Contains("\"Operator_") || line.Contains("\"mcp-client\""))
                {
                    offenders.Add($"{System.IO.Path.GetFileName(file)}:{number}");
                }
            }
        }

        Assert.Empty(offenders);
    }

    private static string FindRepositoryRoot()
    {
        var dir = new System.IO.DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !System.IO.File.Exists(System.IO.Path.Combine(dir.FullName, "MissionController.sln")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
