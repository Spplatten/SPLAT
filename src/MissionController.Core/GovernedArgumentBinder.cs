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
    public static string Bind(SingleToolTemplate template, IReadOnlyDictionary<string, string> parameters)
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
