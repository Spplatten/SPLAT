using MissionController.Core.Models;

namespace MissionController.Core;

/// <summary>
/// The outbound half of structured diagnosis. <see cref="JsonFindingsExtractor"/> can already READ a
/// schema-shaped response, but nothing previously ASKED the model for one - so live providers
/// returned free prose and every mission silently degraded into regex bullet-scraping. This is the
/// contract that closes that loop.
///
/// Held as one constant, appended by <see cref="MissionExecutionEngine"/> for every provider, so the
/// wire format and the parser can never drift apart per-vendor: Claude and Gemini are handed
/// identical instructions and the extractor has exactly one shape to expect.
/// </summary>
public static class StructuredDiagnosisContract
{
    /// <summary>
    /// Field names here are load-bearing - they must stay in sync with the keys
    /// <see cref="JsonFindingsExtractor"/> reads (status / headline / findings / recommendedActions).
    ///
    /// Prose-then-JSON (rather than JSON-only) is deliberate: the live token stream is rendered
    /// verbatim in the mission monitor's reasoning pane, and a raw JSON blob there would be
    /// unreadable to the operator. The extractor's fenced-block path takes priority over its raw
    /// object scan, so the trailing block is what gets parsed while the prose stays human-facing.
    ///
    /// The grounding clause is not boilerplate: this product's honesty invariant is that findings
    /// trace to real sandboxed telemetry. A model that invents a plausible-sounding finding would
    /// defeat the DLP/audit chain that makes the rest of the pipeline trustworthy.
    /// </summary>
    public const string SystemPromptSuffix = """


[REQUIRED RESPONSE FORMAT]
First write a plain-English analysis for the operator: 2-4 sentences, or the labelled parts your
role instructions ask for when they ask for a structured analysis.
Then close your response with exactly one fenced JSON block in this schema, and nothing after it:

```json
{
  "status": "Healthy | Warning | Critical",
  "headline": "One short executive sentence naming the specific condition found",
  "findings": [
    "A concrete observation quoting the actual values seen in the tool output"
  ],
  "recommendedActions": [
    "A specific next step, or omit this array entirely when no action is warranted"
  ]
}
```

Rules:
- Ground every finding in the tool output supplied above. Never invent hosts, counts, versions, or
  timings that are not present in it. If the output is empty or unreadable, say so and set status
  to "Warning" rather than reporting a healthy system.
- "status" reflects the worst condition found: Critical for active compromise, failure, or
  exhaustion; Warning for degradation or something needing attention; Healthy only when the
  evidence genuinely supports it.
- Write findings for a non-expert operator: state what was measured and what it means.
- What you know from outside the tool output - framework mappings, known end-of-life dates, what a
  vendor's agent normally looks like, the value a setting is expected to hold - belongs in the
  analysis and in recommendedActions, labelled as knowledge. A finding quotes only what the output
  contains; a finding that names a value the output does not contain is reported as unsupported.
""";

    private const string SchemaTail = """
    "A specific next step, or omit this array entirely when no action is warranted"
  ]
}
""";

    /// <summary>
    /// The suffix for one template: <see cref="SystemPromptSuffix"/> with the template's own
    /// <see cref="TemplateOutputContract.ResponseFields"/> written into the same schema block, so the
    /// model is shown one shape to produce rather than two that compete for "nothing after it".
    /// </summary>
    public static string For(TemplateOutputContract contract)
    {
        ArgumentNullException.ThrowIfNull(contract);
        if (contract.ResponseFields is not { Count: > 0 } fields)
            return SystemPromptSuffix;

        // A checkout's line endings reach these raw literals; work in \n so the splice always matches.
        string suffix = SystemPromptSuffix.ReplaceLineEndings("\n");
        string tail = SchemaTail.ReplaceLineEndings("\n");
        string extra = string.Concat(fields.Select(f => $",\n  \"{f.Name}\": {f.ExampleJson}"));
        string schema = tail.Replace("  ]\n}", "  ]" + extra + "\n}", StringComparison.Ordinal);
        if (!suffix.Contains(tail, StringComparison.Ordinal))
            throw new InvalidOperationException("The response schema no longer ends where template fields are spliced in.");
        string rule = "\n- This template also requires "
            + string.Join(", ", fields.Select(f => $"\"{f.Name}\" ({f.Meaning})"))
            + " in that same block. They are part of SPLAT's format, not a second object; an answer without them is rejected.\n";
        return suffix.Replace(tail, schema, StringComparison.Ordinal).TrimEnd('\n') + rule;
    }
}
