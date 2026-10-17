using System.Reflection;

namespace MissionController.Tests;

public sealed class LiveAnthropicConsentTests
{
    [Theory]
    [InlineData(LiveAnthropicScope.Synthetic, null, null, null, LiveAnthropicFactAttribute.RequestsConsent)]
    [InlineData(LiveAnthropicScope.Synthetic, "true", null, null, LiveAnthropicFactAttribute.RequestsConsent)]
    [InlineData(LiveAnthropicScope.Synthetic, "1 ", null, null, LiveAnthropicFactAttribute.RequestsConsent)]
    [InlineData(LiveAnthropicScope.Synthetic, "1", null, null, null)]
    [InlineData(LiveAnthropicScope.HostTelemetry, null, "1", "1", LiveAnthropicFactAttribute.RequestsConsent)]
    [InlineData(LiveAnthropicScope.HostTelemetry, "1", null, null, LiveAnthropicFactAttribute.TelemetryConsent)]
    [InlineData(LiveAnthropicScope.HostTelemetry, "1", "true", "1", LiveAnthropicFactAttribute.TelemetryConsent)]
    [InlineData(LiveAnthropicScope.HostTelemetry, "1", "1", null, null)]
    [InlineData(LiveAnthropicScope.Corpus, null, "1", "1", LiveAnthropicFactAttribute.RequestsConsent)]
    [InlineData(LiveAnthropicScope.Corpus, "1", null, "1", LiveAnthropicFactAttribute.TelemetryConsent)]
    [InlineData(LiveAnthropicScope.Corpus, "1", "1", null, LiveAnthropicFactAttribute.CorpusConsent)]
    [InlineData(LiveAnthropicScope.Corpus, "1", "1", "1", null)]
    public void ConsentIsSpecificToThePayload_AndNeverInferredFromAKey(
        LiveAnthropicScope scope, string? requests, string? telemetry, string? corpus, string? missingConsent)
    {
        // A supplied key or unrelated recording switch must not grant permission to transmit data.
        var environment = new Dictionary<string, string?>
        {
            [LiveAnthropicFactAttribute.RequestsConsent] = requests,
            [LiveAnthropicFactAttribute.TelemetryConsent] = telemetry,
            [LiveAnthropicFactAttribute.CorpusConsent] = corpus,
            ["ANTHROPIC_API_KEY"] = "synthetic-test-key",
            ["SPLAT_RECORD_MISSIONS_DIR"] = "synthetic-output-directory"
        };
        string? Read(string name) => environment.GetValueOrDefault(name);
        string? skip = LiveAnthropicFactAttribute.GetSkipReason(scope, Read);
        if (missingConsent is null)
        {
            Assert.Null(skip);
            LiveAnthropicFactAttribute.RequireConsent(scope, Read);
        }
        else
        {
            Assert.Contains(missingConsent, skip);
            var refusal = Assert.Throws<InvalidOperationException>(() => LiveAnthropicFactAttribute.RequireConsent(scope, Read));
            Assert.Equal(skip, refusal.Message);
        }
    }

    [Fact]
    public void UnknownPayloadScopeCannotOptIn()
    {
        Assert.Throws<InvalidOperationException>(() =>
            LiveAnthropicFactAttribute.RequireConsent((LiveAnthropicScope)999, _ => "1"));
    }

    [Fact]
    public void CorpusSelectionCollectsOnlyExplicitlyNamedTemplates()
    {
        Assert.Equal(new[] { "source-price-index-probe", "sysops-time-sync" },
            LiveMissionTests.SelectCorpusTemplates(" sysops-time-sync,source-price-index-probe ")
                .Select(t => t.TemplateId));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("sysops-time-sync,")]
    [InlineData("sysops-time-sync,sysops-time-sync")]
    [InlineData("sysops-time-sync,unknown-template")]
    public void InvalidCorpusSelectionCannotExpandConsent(string selection)
    {
        Assert.Throws<InvalidOperationException>(() => LiveMissionTests.SelectCorpusTemplates(selection));
    }

    [Fact]
    public void EveryLiveMissionTestDeclaresItsPayloadScope()
    {
        var expected = new Dictionary<string, LiveAnthropicScope>
        {
            [nameof(LiveMissionTests.TheKeyReachesTheModel_AndTheFirstBytesArriveInsideTheStallWindow)] = LiveAnthropicScope.Synthetic,
            [nameof(LiveMissionTests.AWholeMission_RunsLive_AndItsSignedBundleVerifiesFromTheBundleAlone)] = LiveAnthropicScope.HostTelemetry,
            [nameof(LiveMissionTests.TheCanary_ALargeTemplateRunsLive_AndItsRecordingReplaysToTheSameVerdict)] = LiveAnthropicScope.HostTelemetry,
            [nameof(LiveMissionTests.TheCorpus_RecordsCurrentTemplatesSequentially_AndReplaysEveryLiveAnswer)] = LiveAnthropicScope.Corpus
        };
        var methods = typeof(LiveMissionTests).GetMethods().Where(m => m.GetCustomAttribute<FactAttribute>() is not null).ToArray();
        Assert.Equal(expected.Count, methods.Length);
        foreach (var method in methods)
        {
            var attribute = Assert.IsType<LiveAnthropicFactAttribute>(method.GetCustomAttribute<FactAttribute>());
            Assert.Equal(expected[method.Name], attribute.Scope);
        }
    }

    [Theory]
    [InlineData("{\"source-consumer-reviews\":{\"AppId\":\"570060128\"}}", true)]
    [InlineData("{\"net-dns-audit\":{}}", false)]
    [InlineData("{\"source-consumer-reviews\":{\"AppId\":123}}", false)]
    [InlineData("{\"source-consumer-reviews\":{\"AppId\":\"1\",\"AppId\":\"2\"}}", false)]
    [InlineData("{\"source-consumer-reviews\":{},\"source-consumer-reviews\":{}}", false)]
    public void RecordingParametersCannotExpandTemplateSelection(string json, bool valid)
    {
        var templates = LiveMissionTests.SelectCorpusTemplates("source-consumer-reviews");
        if (valid)
            Assert.Equal("570060128", LiveMissionTests.SelectCorpusParameters(json, templates)["source-consumer-reviews"]["AppId"]);
        else
            Assert.Throws<InvalidOperationException>(() => LiveMissionTests.SelectCorpusParameters(json, templates));
    }
}
