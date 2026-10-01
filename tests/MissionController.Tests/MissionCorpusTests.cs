using System;
using System.Collections.Generic;
using System.Linq;
using MissionController.Core;
using MissionController.Core.Models;
using MissionController.Core.Replay;
using MissionController.Infrastructure.Data.Catalog;
using Xunit;

namespace MissionController.Tests;

public sealed class MissionCorpusTests
{
    [Fact]
    public void EveryShippedTemplate_HasALiveRecordingOfItsCurrentDefinition()
    {
        var catalog = GovernedTemplateCatalog.All;
        var fixtures = MissionReplayHarness.FixtureFiles(MissionReplayHarness.FixtureDirectory)
            .Select(MissionFixture.Load).ToList();
        var problems = CoverageProblems(catalog, fixtures);

        // No exemption list: a missing key, unavailable sensor or absent Linux guest is an
        // unfinished recording, not evidence that the shipped template has been exercised.
        Assert.True(problems.Count == 0,
            $"Live corpus coverage is incomplete for {CapabilityManifest.CensusOf(catalog).Templates} shipped templates:\n" +
            string.Join("\n", problems) + "\nRecord real missions, review/redact both sensor and answer, then promote the fixtures. " +
            "Blessing replay expectations cannot renew a recording's template hash.");
    }

    [Fact]
    public void Coverage_RejectsMissingSimulatedEmptyAndStaleRecordings()
    {
        var fixture = MissionFixture.Load(MissionReplayHarness.FixtureFiles(MissionReplayHarness.FixtureDirectory).First());
        var template = MissionReplayHarness.TemplateFor(fixture);
        // This is a control for the gate, never a promoted or purported live recording.
        fixture.TemplateSha256 = MissionRunFacts.HashTemplate(template);
        Assert.Empty(CoverageProblems(new[] { template }, new[] { fixture }));
        Assert.Single(CoverageProblems(new[] { template }, Array.Empty<MissionFixture>()));

        fixture.TemplateSha256 = "sha256:stale";
        Assert.Contains("stale", Assert.Single(CoverageProblems(new[] { template }, new[] { fixture })));
        fixture.TemplateSha256 = MissionRunFacts.HashTemplate(template);
        fixture.Model = "none: a local simulation (provider/model unavailable)";
        Assert.Single(CoverageProblems(new[] { template }, new[] { fixture }));
        fixture.Model = "Anthropic/claude-haiku-4-5";
        fixture.Expected.Accepted = false;
        Assert.Single(CoverageProblems(new[] { template }, new[] { fixture }));
        fixture.Expected.Accepted = true;
        fixture.Attempts[0].Response = string.Empty;
        Assert.Single(CoverageProblems(new[] { template }, new[] { fixture }));
        fixture.Attempts.Clear();
        Assert.Single(CoverageProblems(new[] { template }, new[] { fixture }));
    }

    internal static IReadOnlyList<string> CoverageProblems(
        IEnumerable<SingleToolTemplate> catalog, IReadOnlyList<MissionFixture> fixtures)
    {
        var problems = new List<string>();
        foreach (var template in catalog.OrderBy(t => t.TemplateId, StringComparer.Ordinal))
        {
            // These are consistency checks on reviewed recordings, not a signature or a claim
            // that every recorded diagnosis is correct. The replay holds the recorded verdict.
            var recorded = fixtures.Where(f => f.TemplateId == template.TemplateId &&
                f.MissionId != Guid.Empty && DateTimeOffset.TryParse(f.RecordedAtUtc, out _) &&
                MissionFixtureExporter.IsLiveModelIdentity(f.Model) &&
                f.Expected.Accepted && !f.Sensor.TimedOut && !string.IsNullOrWhiteSpace(f.SanitizedPayload()) &&
                f.Attempts.Count > 0 && f.Attempts.All(a => !string.IsNullOrWhiteSpace(a.Model) &&
                    !string.IsNullOrWhiteSpace(a.Response))).ToList();
            if (recorded.Count == 0)
                problems.Add($"{template.TemplateId}: missing accepted live-model fixture");
            else if (!recorded.Any(f => f.TemplateSha256 == MissionRunFacts.HashTemplate(template)))
                problems.Add($"{template.TemplateId}: stale recording; the shipped template changed");
        }
        return problems;
    }
}
