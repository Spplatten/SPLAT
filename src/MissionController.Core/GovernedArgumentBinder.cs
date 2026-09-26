using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using MissionController.Core.Enums;
using MissionController.Core.Models;

namespace MissionController.Core;

/// <summary>
/// Raised when a parameter value cannot be safely placed into a sensor tool's command line.
/// The mission must not run: a rejected value is a refused mission, never a sanitised one.
/// </summary>
public sealed class TemplateParameterRejectedException : Exception
{
    public string ParameterKey { get; }

    public TemplateParameterRejectedException(string parameterKey, string reason)
        : base($"Parameter '{parameterKey}' was refused by the governed argument binder: {reason}")
    {
        ParameterKey = parameterKey;
    }
}

/// <summary>
/// Binds parameter values into a template's <c>ArgumentsTemplate</c>.
///
/// This exists because the engine used to build sensor command lines with a bare
/// <c>string.Replace</c> per parameter, no quoting and no validation, over ~35 placeholders that
/// land inside <c>cmd.exe /c</c> and <c>powershell.exe -Command</c> strings. Any caller who could
/// name a template could therefore choose what the machine executed - and the MCP server exposes
/// exactly that to an unauthenticated agent. <c>ValidateStrictRules()</c> checked template SHAPE
/// and never looked at a value.
///
/// Two properties do the work here:
///
/// 1. SINGLE PASS. Substitution happens in one <see cref="Regex.Replace"/> over the original
///    template, so a value can never be re-scanned and a value that itself contains
///    <c>{OtherKey}</c> is inert. The old sequential-Replace loop re-scanned its own output, which
///    made second-order injection possible without any single value looking dangerous.
///
/// 2. CONTEXT-AWARE ALLOW-LISTS, never escaping. Escaping correctly for cmd.exe is close to
///    impossible (<c>^</c>, <c>%VAR%</c> expansion, delayed <c>!</c> expansion all bite), and the
///    binder cannot re-quote a value whose placeholder already sits inside a quoted region without
///    breaking the template. So values are REFUSED rather than repaired, against the strictest
///    character set that the placeholder's actual position permits.
/// </summary>
public static class GovernedArgumentBinder
{
    private static readonly TimeSpan PatternTimeout = TimeSpan.FromMilliseconds(250);

    private static readonly Regex PlaceholderPattern =
        new(@"\{(?<key>[A-Za-z_][A-Za-z0-9_]*)\}", RegexOptions.Compiled, PatternTimeout);

    /// <summary>
    /// Values landing in a bare (unquoted) command-line position. Everything the shipped catalogue
    /// puts in such a position is a number, an IPv4 address, a hostname, a URL or a bare token, so
    /// this costs the product nothing. No spaces (they split tokens), no shell metacharacters, and
    /// the value must OPEN with an alphanumeric so it can never be parsed as a switch.
    /// </summary>
    private static readonly Regex BarePolicy =
        new(@"^[A-Za-z0-9][A-Za-z0-9._:/\\@-]{0,252}$", RegexOptions.Compiled, PatternTimeout);

    /// <summary>Numbers, when a field declares <see cref="TemplateParameterType.Number"/>.</summary>
    private static readonly Regex NumberPolicy =
        new(@"^-?\d{1,18}(\.\d{1,6})?$", RegexOptions.Compiled, PatternTimeout);

    /// <summary>Hostnames, IPv4/IPv6 literals and bracketed IPv6, for <see cref="TemplateParameterType.Host"/>.</summary>
    private static readonly Regex HostPolicy =
        new(@"^(?:[A-Za-z0-9][A-Za-z0-9._-]{0,252}|\[[0-9A-Fa-f:]{2,45}\])$", RegexOptions.Compiled, PatternTimeout);

    private const int QuotedMaxLength = 512;

    /// <summary>
    /// Characters that stay lethal even inside a PowerShell single-quoted literal.
    /// <c>'</c> closes the literal. <c>"</c> closes the outer <c>-Command "…"</c> region that
    /// <c>GovernedTemplateCatalog.Ps()</c> wraps every script in. The backtick is PowerShell's
    /// escape character and is refused as defence in depth.
    /// </summary>
    private static readonly char[] QuotedForbidden = { '\'', '"', '`' };

    /// <summary>
    /// Resolves <paramref name="template"/>'s argument string against caller-supplied parameters.
    /// </summary>
    /// <exception cref="TemplateParameterRejectedException">
    /// A value cannot be placed safely. The caller must abandon the mission rather than continue
    /// with a repaired string.
    /// </exception>
    public static string Bind(SingleToolTemplate template, IReadOnlyDictionary<string, string> parameters) =>
        RefusedOnTimeout(() => BindCore(template, parameters));

    /// <summary>
    /// A check that did not finish is a check that did not pass. As a refusal, the mission and workflow
    /// engines record it as a refused mission; as a timeout it got past both of their catches. On
    /// 2026-09-19 a loaded test run saw this binder throw something other than a refusal for input it
    /// refuses at once, and a match timeout is the only other thing these paths throw.
    /// </summary>
    private static string RefusedOnTimeout(Func<string> bind)
    {
        try
        {
            return bind();
        }
        catch (RegexMatchTimeoutException)
        {
            throw new TemplateParameterRejectedException(
                "*", $"a check did not finish within its {PatternTimeout.TotalMilliseconds:0} ms limit, so nothing was bound.");
        }
    }

    private static string BindCore(SingleToolTemplate template, IReadOnlyDictionary<string, string> parameters)
    {
        ArgumentNullException.ThrowIfNull(template);
        ArgumentNullException.ThrowIfNull(parameters);

        string argumentsTemplate = template.Tool.ArgumentsTemplate ?? string.Empty;
        if (argumentsTemplate.Length == 0)
        {
            return string.Empty;
        }

        var defaults = template.GetEffectiveDefaults();
        var declaredFields = BuildFieldLookup(template);
        bool isPowerShell = IsPowerShell(template.Tool.ExecutablePath);

        return PlaceholderPattern.Replace(argumentsTemplate, match =>
        {
            string key = match.Groups["key"].Value;

            // Caller value wins over the template default, matching the previous behaviour where a
            // blank override fell through to the default rather than blanking the argument.
            string? value =
                parameters.TryGetValue(key, out var supplied) && !string.IsNullOrWhiteSpace(supplied)
                    ? supplied
                    : defaults.TryGetValue(key, out var fallback) ? fallback : null;

            // An unresolved placeholder is left exactly as the template author wrote it. Silently
            // blanking it would change the tool's command shape; that is a template authoring
            // concern, not a security one.
            if (value is null)
            {
                return match.Value;
            }

            // match.Index is an offset into the ORIGINAL template, so the quoting context is read
            // from author-controlled text and can never be influenced by an earlier substitution.
            bool insideQuotedLiteral = isPowerShell && IsInsideSingleQuotedLiteral(argumentsTemplate, match.Index);

            declaredFields.TryGetValue(key, out var field);
            Validate(key, value, insideQuotedLiteral, field);
            return value;
        });
    }

    /// <summary>
    /// The outcome of screening values a MODEL proposed for a template's parameters.
    /// </summary>
    /// <param name="Accepted">
    /// The proposals that may be bound. Every one was validated against the same policy
    /// <see cref="Bind"/> applies, in the quoting context its placeholder actually sits in.
    /// </param>
    /// <param name="Rejections">
    /// One operator-readable line per discarded proposal, in the order they were screened. These are
    /// recorded in the audit ledger rather than swallowed: a model repeatedly reaching for a value it
    /// is not allowed to set is a signal about the model, not noise about the parameter.
    /// </param>
    public sealed record ProposedParameterScreening(
        IReadOnlyDictionary<string, string> Accepted,
        IReadOnlyList<string> Rejections);

    /// <summary>
    /// Upper bound on proposals considered in one screening pass. The declared-field filter already
    /// bounds the useful count to a template's own field list; this stops a runaway or adversarial
    /// answer from turning one decision into thousands of regex evaluations.
    /// </summary>
    private const int MaxProposalsScreened = 32;

    /// <summary>
    /// Screens model-proposed parameter values for <paramref name="template"/>, returning only those
    /// that may be bound.
    ///
    /// This exists so a chained investigation can TARGET its next step - "check Kerberos on DC02",
    /// not "run the default" - without the model ever composing a command. Three gates, in order,
    /// and a value must clear all three:
    ///
    ///  1. DECLARED. The key must be one of the template author's own
    ///     <see cref="SingleToolTemplate.ParameterFields"/>. A proposal for anything else is dropped;
    ///     the model cannot invent a parameter any more than it can invent a template id.
    ///
    ///  2. NOT ALREADY THE OPERATOR'S. <paramref name="operatorSupplied"/> wins outright. The binder
    ///     makes a value SAFE to place in argv; it says nothing about whether the operator meant to
    ///     point this mission at that target. So a value a person typed is never overridden by a
    ///     model reading sensor output that an attacker may have written - which is exactly how a
    ///     prompt injection would otherwise redirect a scan at a host of its choosing.
    ///
    ///  3. SAFE IN POSITION. The value runs <see cref="Validate"/> against the field's declared type
    ///     and the real quoting context of its placeholder in the author's original argument string.
    ///     A refusal DROPS THE PROPOSAL rather than failing the mission: the step then runs on its
    ///     template default, which is the behaviour before this method existed. Refusing the whole
    ///     investigation because a model guessed a bad hostname would trade a bounded loss of
    ///     precision for an unbounded loss of the investigation.
    ///
    /// A declared key with no placeholder in the argument string is accepted here and simply never
    /// reaches argv; it may still be read by callers that surface parameters elsewhere, and gating it
    /// on argv presence would make this method lie about what it screened.
    /// </summary>
    public static ProposedParameterScreening ScreenProposedValues(
        SingleToolTemplate template,
        IReadOnlyDictionary<string, string>? proposed,
        IReadOnlyDictionary<string, string>? operatorSupplied)
    {
        ArgumentNullException.ThrowIfNull(template);

        var accepted = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var rejections = new List<string>();

        if (proposed is null || proposed.Count == 0)
        {
            return new ProposedParameterScreening(accepted, rejections);
        }

        var declaredFields = BuildFieldLookup(template);
        string argumentsTemplate = template.Tool.ArgumentsTemplate ?? string.Empty;
        bool isPowerShell = IsPowerShell(template.Tool.ExecutablePath);
        var placeholderOffsets = MapPlaceholderOffsets(argumentsTemplate);

        int screened = 0;
        foreach (var pair in proposed)
        {
            if (screened >= MaxProposalsScreened)
            {
                rejections.Add(
                    $"'{pair.Key}': more than {MaxProposalsScreened} values were proposed for one step; the rest were not screened.");
                break;
            }

            screened++;
            string key = pair.Key ?? string.Empty;
            string? value = pair.Value;

            if (!declaredFields.TryGetValue(key, out var field))
            {
                rejections.Add($"'{key}': not a parameter this template declares.");
                continue;
            }

            if (string.IsNullOrWhiteSpace(value))
            {
                rejections.Add($"'{key}': proposed value was empty, so the template default stands.");
                continue;
            }

            if (operatorSupplied is not null &&
                operatorSupplied.TryGetValue(key, out var operatorValue) &&
                !string.IsNullOrWhiteSpace(operatorValue))
            {
                rejections.Add($"'{key}': the operator supplied this value, which a model may not change.");
                continue;
            }

            // The quoting context is read at the placeholder's offset in the AUTHOR's original
            // string, never at an offset into partially substituted text, so it cannot be moved by
            // any value screened earlier in this loop.
            bool insideQuotedLiteral = isPowerShell &&
                placeholderOffsets.TryGetValue(key, out int offset) &&
                IsInsideSingleQuotedLiteral(argumentsTemplate, offset);

            try
            {
                Validate(key, value, insideQuotedLiteral, field);
            }
            catch (TemplateParameterRejectedException ex)
            {
                rejections.Add($"'{key}': {ex.Message}");
                continue;
            }
            catch (RegexMatchTimeoutException)
            {
                rejections.Add($"'{key}': a check did not finish within its time limit, so the value was not accepted.");
                continue;
            }

            accepted[key] = value;
        }

        return new ProposedParameterScreening(accepted, rejections);
    }

    /// <summary>
    /// First offset of each placeholder in the author's argument string. A key repeated in the
    /// template is screened against its FIRST position; <see cref="Bind"/> then validates every
    /// occurrence in its own context and refuses there if a later one is stricter, so a value that
    /// passes screening but cannot be placed everywhere still fails closed at bind time.
    /// </summary>
    private static Dictionary<string, int> MapPlaceholderOffsets(string argumentsTemplate)
    {
        var offsets = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (argumentsTemplate.Length == 0)
        {
            return offsets;
        }

        foreach (Match match in PlaceholderPattern.Matches(argumentsTemplate))
        {
            string key = match.Groups["key"].Value;
            if (!offsets.ContainsKey(key))
            {
                offsets[key] = match.Index;
            }
        }

        return offsets;
    }

    /// <summary>
    /// Placeholder shape for workflow node references. Node IDs are author-chosen slugs
    /// (<c>recall-memory</c>), so the hyphen is admitted here rather than by widening
    /// <see cref="PlaceholderPattern"/>, which would change how the shipped mission templates parse.
    /// </summary>
    private static readonly Regex WorkflowPlaceholderPattern =
        new(@"\{(?<key>[A-Za-z_][A-Za-z0-9_-]*)\}", RegexOptions.Compiled, PatternTimeout);

    /// <summary>
    /// Binds upstream node outputs and node configuration into a workflow node's script command.
    ///
    /// A workflow's values are strictly less trustworthy than a mission's declared parameters: they
    /// arrive as an unauthenticated webhook body, as a previous node's raw stdout, or as whatever a
    /// model emitted. They therefore get the same treatment - one pass over the author's original
    /// template, refusal rather than repair - instead of the sequential <c>string.Replace</c> loop
    /// this class was written to retire.
    /// </summary>
    /// <exception cref="TemplateParameterRejectedException">
    /// A value cannot be placed safely. The node must fail; a repaired command is not an option.
    /// </exception>
    public static string BindWorkflowCommand(
        string? commandTemplate,
        IReadOnlyDictionary<string, string> values,
        bool isPowerShell = true) =>
        RefusedOnTimeout(() => BindWorkflowCommandCore(commandTemplate, values, isPowerShell));

    private static string BindWorkflowCommandCore(
        string? commandTemplate,
        IReadOnlyDictionary<string, string> values,
        bool isPowerShell)
    {
        ArgumentNullException.ThrowIfNull(values);

        if (string.IsNullOrEmpty(commandTemplate))
        {
            return string.Empty;
        }

        return WorkflowPlaceholderPattern.Replace(commandTemplate, match =>
        {
            string key = match.Groups["key"].Value;

            // An unresolved placeholder is left as the author wrote it, matching Bind().
            if (!values.TryGetValue(key, out var value) || value is null)
            {
                return match.Value;
            }

            // An upstream node that produced nothing is a normal outcome, and the empty string
            // cannot inject. Dropping the token changes the command's shape, but that is the
            // template author's problem, not a boundary the binder should refuse at.
            if (value.Length == 0)
            {
                return string.Empty;
            }

            bool insideQuotedLiteral = isPowerShell && IsInsideSingleQuotedLiteral(commandTemplate, match.Index);
            Validate(key, value, insideQuotedLiteral, field: null);
            return value;
        });
    }

    private static void Validate(string key, string value, bool insideQuotedLiteral, TemplateParameterField? field)
    {
        // A control character is a statement separator or a terminal escape in every shell involved,
        // so it is refused before any other policy is consulted, in both contexts.
        foreach (char c in value)
        {
            if (char.IsControl(c))
            {
                throw new TemplateParameterRejectedException(
                    key, "the value contains a control character or line break, which would terminate the command.");
            }
        }

        // The declared type, where a template bothers to declare one, narrows the policy further.
        // TemplateParameterType has existed since the first commit and has never been enforced.
        if (field is not null)
        {
            switch (field.ValueType)
            {
                case TemplateParameterType.Number when !NumberPolicy.IsMatch(value):
                    throw new TemplateParameterRejectedException(
                        key, $"the field is declared Number but '{Preview(value)}' is not numeric.");

                case TemplateParameterType.Host when !HostPolicy.IsMatch(value):
                    throw new TemplateParameterRejectedException(
                        key, $"the field is declared Host but '{Preview(value)}' is not a hostname or IP literal.");

                case TemplateParameterType.Multiline:
                    // Free-form multi-line text belongs in a prompt, never in argv.
                    throw new TemplateParameterRejectedException(
                        key, "a Multiline field cannot be bound into a command line; move it into the system prompt.");
            }
        }

        if (insideQuotedLiteral)
        {
            if (value.Length > QuotedMaxLength)
            {
                throw new TemplateParameterRejectedException(
                    key, $"the value is {value.Length} characters; the limit inside a quoted literal is {QuotedMaxLength}.");
            }

            int bad = value.IndexOfAny(QuotedForbidden);
            if (bad >= 0)
            {
                throw new TemplateParameterRejectedException(
                    key, $"the value contains {Describe(value[bad])}, which would break out of the quoted literal it sits in.");
            }

            return;
        }

        if (!BarePolicy.IsMatch(value))
        {
            throw new TemplateParameterRejectedException(
                key,
                $"'{Preview(value)}' is not permitted in an unquoted command-line position. " +
                "Such values must start with a letter or digit and may contain only letters, digits and . _ - : / \\ @");
        }
    }

    /// <summary>
    /// True when the offset sits inside a PowerShell single-quoted literal.
    ///
    /// PowerShell escapes a quote inside such a literal by doubling it (<c>''</c>), so a naive
    /// quote count would flip the state on every escaped quote and mis-report the context. Being
    /// wrong in the permissive direction is the dangerous failure, which is why the caller only
    /// consults this for PowerShell tools and falls back to the bare policy everywhere else.
    /// </summary>
    private static bool IsInsideSingleQuotedLiteral(string template, int offset)
    {
        bool inside = false;
        int i = 0;

        while (i < offset)
        {
            if (template[i] == '\'')
            {
                if (inside && i + 1 < template.Length && template[i + 1] == '\'')
                {
                    i += 2; // Escaped quote: the literal continues.
                    continue;
                }

                inside = !inside;
            }

            i++;
        }

        return inside;
    }

    private static bool IsPowerShell(string? executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            return false;
        }

        string file = System.IO.Path.GetFileName(executablePath);
        return file.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)
            || file.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase);
    }

    private static Dictionary<string, TemplateParameterField> BuildFieldLookup(SingleToolTemplate template)
    {
        var lookup = new Dictionary<string, TemplateParameterField>(StringComparer.OrdinalIgnoreCase);
        var fields = template.ParameterFields;
        if (fields is null)
        {
            return lookup;
        }

        foreach (var field in fields)
        {
            if (!string.IsNullOrWhiteSpace(field.Key))
            {
                lookup[field.Key] = field;
            }
        }

        return lookup;
    }

    /// <summary>
    /// Truncates a rejected value for the operator-facing message. The value is echoed because an
    /// operator fixing a typo needs to see it, but it is bounded so a long payload cannot flood the
    /// mission log or the audit ledger.
    /// </summary>
    private static string Preview(string value) =>
        value.Length <= 48 ? value : value.Substring(0, 48) + "…";

    private static string Describe(char c) => c switch
    {
        '\'' => "a single quote",
        '"' => "a double quote",
        '`' => "a backtick",
        _ => $"the character '{c}'"
    };
}
