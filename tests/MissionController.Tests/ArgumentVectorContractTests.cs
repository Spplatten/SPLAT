using System;
using System.Collections.Generic;
using MissionController.Core;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// F11's argument half. The guest daemon used to receive a single `arguments` string and split it
/// with <c>split_whitespace()</c>, which is not a parse but a guess - and the information needed to
/// split correctly had already been destroyed by the caller that quoted it.
///
/// Measured on this host before the fix, through the real daemon:
///   `-c 'print(123)'`   -> exit 0, NO OUTPUT. python received the literal `'print(123)'`, a string
///                          expression that evaluates and is discarded.
///   `-c 'print(1, 2)'`  -> SyntaxError: unterminated string literal, on the fragment `'print(1,`.
///
/// Splitting now happens here, where the original text is intact, and travels as an argv array.
/// </summary>
public class ArgumentVectorContractTests
{
    [Theory]
    // The two cases the daemon got wrong, stated as the vectors they should always have been.
    [InlineData("-c 'print(123)'", new[] { "-c", "print(123)" })]
    [InlineData("-c 'print(1, 2)'", new[] { "-c", "print(1, 2)" })]
    // Ordinary flags keep working.
    [InlineData("--max-time 3", new[] { "--max-time", "3" })]
    [InlineData("", new string[0])]
    [InlineData("   ", new string[0])]
    // Quoting a value with spaces is the entire point.
    [InlineData("--name \"two words\"", new[] { "--name", "two words" })]
    [InlineData("'a b' 'c d'", new[] { "a b", "c d" })]
    // Adjacent quoted and unquoted fragments are ONE argument, as a shell would join them.
    [InlineData("pre'mid'post", new[] { "premidpost" })]
    [InlineData("\"a\"'b'c", new[] { "abc" })]
    // An explicitly empty argument is an argument.
    [InlineData("x '' y", new[] { "x", "", "y" })]
    // Inside single quotes nothing escapes, not even a backslash.
    [InlineData(@"'a\b'", new[] { @"a\b" })]
    // Inside double quotes a backslash escapes only " \ $ ` - everything else stays literal, so a
    // Windows path or a regex survives intact.
    [InlineData("\"a\\\"b\"", new[] { "a\"b" })]
    [InlineData("\"C:\\temp\\x\"", new[] { "C:\\temp\\x" })]
    [InlineData("\"a\\$b\"", new[] { "a$b" })]
    // Tabs and newlines separate arguments the same way spaces do.
    [InlineData("a\tb\nc", new[] { "a", "b", "c" })]
    public void SplittingProducesTheArgumentVectorAShellWouldPass(string input, string[] expected)
    {
        Assert.Equal(expected, PosixArgumentSplitter.Split(input));
    }

    [Fact]
    public void UnicodeSurvivesUntouched()
    {
        // The audit asks for spaces, quotes, newlines and Unicode. Nothing here is special to the
        // splitter, which is the point - it must not normalise or re-encode anything.
        var argv = PosixArgumentSplitter.Split("-c 'print(\"héllo → 世界\")'");

        Assert.Equal(new[] { "-c", "print(\"héllo → 世界\")" }, argv);
    }

    [Theory]
    [InlineData("'unterminated")]
    [InlineData("\"unterminated")]
    [InlineData("trailing\\")]
    public void AnAmbiguousArgumentStringIsRefusedRatherThanGuessed(string input)
    {
        // Guessing is exactly what produced the defect. At this point the caller's intent genuinely
        // is unknown, and a wrong vector runs the wrong command with a successful exit code.
        Assert.Throws<FormatException>(() => PosixArgumentSplitter.Split(input));
    }

    [Fact]
    public void TheSplitterIsNotAShell()
    {
        // No expansion, no globbing, no substitution, no operators. A parser that grew these would
        // be handing the caller capabilities the lease never granted.
        Assert.Equal(new[] { "$HOME", "*.txt", "`id`", "a&&b", "x|y", ";" },
            PosixArgumentSplitter.Split("$HOME *.txt `id` a&&b x|y ;"));
    }
}
