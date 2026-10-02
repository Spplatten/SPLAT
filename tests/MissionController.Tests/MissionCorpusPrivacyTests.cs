using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// A promoted fixture must not carry the recording machine's identity.
///
/// This exists because the README already says so and prose does not scale. Six fixtures were
/// redacted by hand on 2026-09-30 after an audit ranked "host recon in the mission fixtures" the
/// top exposure in a repository that has been public since the day it was created; the corpus gate
/// now asks for a recording of every shipped template, so the same mistake is about to be available
/// fifty-eight times instead of six. A sensor that lists services, scheduled tasks or firewall rules
/// prints the host name, the local account names and the machine's SID, and together those are an
/// attack-surface profile of whoever did the recording.
///
/// The check is deliberately keyed to <em>this</em> machine rather than to a list of forbidden
/// strings. Whoever records is the one who would leak, so reading the identity out of the
/// environment catches the next operator as well as the last one, and keeps the test itself free of
/// the names it is protecting.
/// </summary>
public sealed class MissionCorpusPrivacyTests
{
    /// <summary>
    /// A real Windows account SID: three large sub-authorities and a RID. The synthetic stand-in the
    /// README prescribes keeps the width and uses one repeated digit per field, so
    /// <c>S-1-5-21-1111111111-2222222222-333333333-1002</c> must pass and a machine's own SID must
    /// not. Distinct-digit counting is what separates them; a length rule cannot.
    /// </summary>
    private static readonly Regex AccountSid =
        new(@"S-1-5-21-(?<a>\d{4,})-(?<b>\d{4,})-(?<c>\d{4,})-\d+", RegexOptions.Compiled);

    [Fact]
    public void NoPromotedFixture_CarriesTheRecordingMachinesIdentity()
    {
        var problems = new List<string>();
        foreach (string file in MissionReplayHarness.FixtureFiles(MissionReplayHarness.FixtureDirectory))
        {
            problems.AddRange(IdentityLeaks(Path.GetFileName(file), File.ReadAllText(file)));
        }

        Assert.True(problems.Count == 0,
            "A promoted fixture carries identifying details of the machine it was recorded on. This repository is " +
            "public, so a merge publishes them. Replace each with a synthetic value of the same width in BOTH the " +
            "telemetry and the model's answer, re-derive with SPLAT_BLESS_MISSION_FIXTURES=1, and say in the Note " +
            "what was replaced - the recording guide beside the fixtures has the pattern:\n" +
            string.Join("\n", problems));
    }

    /// <summary>
    /// The control. A guard nobody has watched reject anything is a guard in name only, and this one
    /// passes trivially on a corpus that happens to be clean.
    /// </summary>
    [Fact]
    public void TheGuard_RejectsARealSidAndThisHostsOwnNames_AndAcceptsTheSyntheticStandIn()
    {
        Assert.NotEmpty(IdentityLeaks("planted.json", "owner S-1-5-21-2721853200-1390957683-193656296-1002"));
        Assert.NotEmpty(IdentityLeaks("planted.json", $"ComputerName : {Environment.MachineName}"));
        Assert.NotEmpty(IdentityLeaks("planted.json", $"Owner: {Environment.UserName}"));
        Assert.NotEmpty(IdentityLeaks("planted.json", $@"path C:\Users\{Environment.UserName}\AppData\Local\Temp"));

        // What a correctly redacted fixture looks like, taken from the ones redacted on 2026-09-30.
        Assert.Empty(IdentityLeaks("clean.json", "owner S-1-5-21-1111111111-2222222222-333333333-1002"));

        // A profile path naming some other account is a stand-in or someone else's machine. This
        // guard is about the one doing the recording and does not guess at every possible alias.
        Assert.Empty(IdentityLeaks("clean.json", @"path C:\Users\userx\Documents"));
    }

    internal static IReadOnlyList<string> IdentityLeaks(string name, string text)
    {
        var found = new List<string>();

        foreach (Match m in AccountSid.Matches(text))
        {
            // One repeated digit per sub-authority is the synthetic shape; anything else is a real
            // domain or machine identifier, which names the host as surely as its hostname does.
            bool synthetic = new[] { "a", "b", "c" }
                .All(g => m.Groups[g].Value.Distinct().Count() == 1);
            if (!synthetic)
            {
                found.Add($"  {name}: a real-shaped account SID, {m.Value}");
            }
        }

        // A profile path is not checked on its own. Every one of them names an account, and nothing
        // here can tell a stand-in like C:\Users\userx from a real owner - the first attempt flagged
        // exactly that and called a correctly redacted fixture a leak. A path naming THIS machine's
        // account is caught below with every other mention of it, which is the case that matters.
        //
        // Read from the environment, never written down here: the test must not itself contain the
        // names it exists to keep out of the repository.
        foreach (var (what, value) in new[]
                 {
                     ("the recording machine's name", Environment.MachineName),
                     ("the recording account's name", Environment.UserName),
                     ("the recording account's domain", Environment.UserDomainName),
                 })
        {
            if (value.Length >= 4 && text.Contains(value, StringComparison.OrdinalIgnoreCase))
            {
                found.Add($"  {name}: contains {what}");
            }
        }

        return found;
    }
}
