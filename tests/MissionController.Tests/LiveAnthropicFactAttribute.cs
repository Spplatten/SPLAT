namespace MissionController.Tests;

public enum LiveAnthropicScope { Synthetic, HostTelemetry, Corpus }

public sealed class LiveAnthropicFactAttribute : FactAttribute
{
    internal const string RequestsConsent = "SPLAT_ALLOW_ANTHROPIC_TEST_REQUESTS";
    internal const string TelemetryConsent = "SPLAT_ALLOW_HOST_TELEMETRY_TO_ANTHROPIC";
    internal const string CorpusConsent = "SPLAT_RECORD_CORPUS";

    public LiveAnthropicScope Scope { get; }

    public LiveAnthropicFactAttribute(LiveAnthropicScope scope)
    {
        Scope = scope;
        // Discovery must skip before a test can read the vault or collect host telemetry.
        Skip = GetSkipReason(scope, Environment.GetEnvironmentVariable);
    }

    internal static string? GetSkipReason(LiveAnthropicScope scope, Func<string, string?> readEnvironment)
    {
        if (!Enum.IsDefined(scope))
            return "Unknown Anthropic test payload scope; external requests are disabled.";
        if (readEnvironment(RequestsConsent) != "1")
            return $"External requests to api.anthropic.com require explicit opt-in: {RequestsConsent}=1.";
        if (scope != LiveAnthropicScope.Synthetic && readEnvironment(TelemetryConsent) != "1")
            return $"Sending filtered host telemetry to api.anthropic.com requires separate opt-in: {TelemetryConsent}=1.";
        if (scope == LiveAnthropicScope.Corpus && readEnvironment(CorpusConsent) != "1")
            return $"Recording the live corpus requires an additional opt-in: {CorpusConsent}=1.";
        return null;
    }

    internal static void RequireConsent(LiveAnthropicScope scope, Func<string, string?>? readEnvironment = null)
    {
        // Recheck at execution: direct invocation and discovery in another process must not bypass consent.
        if (GetSkipReason(scope, readEnvironment ?? Environment.GetEnvironmentVariable) is { } reason)
            throw new InvalidOperationException(reason);
    }
}
