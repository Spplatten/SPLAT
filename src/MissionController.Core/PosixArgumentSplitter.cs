using System;
using System.Collections.Generic;
using System.Text;

namespace MissionController.Core;

/// <summary>
/// Splits a shell-style argument string into an argument vector.
///
/// This exists because the guest daemon used to do the job with
/// <c>arguments.split_whitespace()</c>, which is not a parse but a guess. MCP's <c>run_code</c>
/// shipped <c>-c '&lt;code&gt;'</c> and the split handed python the literal <c>'print(123)'</c> - a
/// string expression that evaluates, prints nothing and exits 0, so a caller asking to print a
/// number got a successful run with no output. Any argument containing a space tore in half:
/// <c>print(1, 2)</c> arrived as <c>'print(1,</c> and died on an unterminated string literal.
///
/// Splitting belongs on this side of the wire, where the original text is still intact and the
/// result can be sent as an explicit argv array. It is deliberately NOT a shell: no variable
/// expansion, no globbing, no command substitution, no operators. Those would be new capabilities
/// smuggled in through a parser, and a caller that wants a shell can name one as its command.
/// </summary>
public static class PosixArgumentSplitter
{
    /// <summary>
    /// Tokenises <paramref name="arguments"/> the way a POSIX shell splits a simple command.
    ///
    /// Handles single quotes (fully literal), double quotes (backslash escapes only before
    /// <c>" \ $ `</c>), and backslash escapes outside quotes. An unterminated quote is an error
    /// rather than a best guess: the caller's intent is genuinely unknown at that point, and
    /// guessing is what produced the defect this replaces.
    /// </summary>
    /// <exception cref="FormatException">The string ends inside a quote or on a trailing backslash.</exception>
    public static IReadOnlyList<string> Split(string? arguments)
    {
        var argv = new List<string>();
        if (string.IsNullOrEmpty(arguments))
        {
            return argv;
        }

        var current = new StringBuilder();
        bool inArgument = false;
        char quote = '\0';

        for (int i = 0; i < arguments.Length; i++)
        {
            char c = arguments[i];

            if (quote == '\'')
            {
                // Single quotes are fully literal - not even a backslash escapes inside them.
                if (c == '\'')
                {
                    quote = '\0';
                }
                else
                {
                    current.Append(c);
                }
                continue;
            }

            if (quote == '"')
            {
                if (c == '\\' && i + 1 < arguments.Length && IsDoubleQuoteEscapable(arguments[i + 1]))
                {
                    current.Append(arguments[++i]);
                }
                else if (c == '"')
                {
                    quote = '\0';
                }
                else
                {
                    current.Append(c);
                }
                continue;
            }

            switch (c)
            {
                case '\'':
                case '"':
                    quote = c;
                    // An opening quote starts an argument even if it turns out to be empty, so
                    // `''` is one empty argument rather than none.
                    inArgument = true;
                    break;

                case '\\':
                    if (i + 1 >= arguments.Length)
                    {
                        throw new FormatException(
                            "Argument string ends with a trailing backslash; the intended argument is ambiguous.");
                    }
                    current.Append(arguments[++i]);
                    inArgument = true;
                    break;

                case ' ':
                case '\t':
                case '\n':
                case '\r':
                    if (inArgument)
                    {
                        argv.Add(current.ToString());
                        current.Clear();
                        inArgument = false;
                    }
                    break;

                default:
                    current.Append(c);
                    inArgument = true;
                    break;
            }
        }

        if (quote != '\0')
        {
            throw new FormatException(
                $"Argument string ends inside a {(quote == '\'' ? "single" : "double")}-quoted section.");
        }

        if (inArgument)
        {
            argv.Add(current.ToString());
        }

        return argv;
    }

    /// <summary>
    /// Inside double quotes a backslash only escapes these; before anything else it is literal.
    /// That is the POSIX rule, and getting it wrong would silently eat backslashes out of a
    /// Windows path or a regex.
    /// </summary>
    private static bool IsDoubleQuoteEscapable(char c) =>
        c is '"' or '\\' or '$' or '`';
}
