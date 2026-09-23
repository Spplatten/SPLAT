using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;

namespace MissionController.UI;

/// <summary>
/// <c>MissionController.UI.exe --self-test [--self-test-report &lt;path&gt;]</c>: the console opens every
/// page its navigation offers, in order, waits for each to load, writes a report, and exits with a
/// code instead of staying open.
///
/// This exists because the packaging gate could only prove that a window opened. The XAML compiler
/// does not check resource keys, and no test project can reference a WinUI application, so two pages
/// that threw <c>XamlParseException</c> the moment they were opened shipped through a green build and a
/// green smoke test. Opening every page is the check the build was missing, and a process exit code is
/// the only channel a windowed executable has back to a script.
///
/// Exit codes: <see cref="PassedExitCode"/> when every page opened and loaded and nothing went unhandled;
/// <see cref="StartupFailedExitCode"/> when the console failed before its window existed, the same code
/// a normal start gives; <see cref="PageFailedExitCode"/> when at least one page failed; and
/// <see cref="IncompleteExitCode"/> when the self-test itself could not finish. The report says which.
/// </summary>
internal sealed class ConsoleSelfTest
{
    public const string Switch = "--self-test";
    public const string ReportSwitch = "--self-test-report";

    public const int PassedExitCode = 0;
    public const int StartupFailedExitCode = 1;
    public const int PageFailedExitCode = 2;
    public const int IncompleteExitCode = 3;

    /// <summary>How long one page gets to raise Loaded after navigation.</summary>
    private static readonly TimeSpan LoadBudget = TimeSpan.FromSeconds(20);

    /// <summary>
    /// Time given after each page loads for its Loaded handlers to run their first awaits - the view
    /// model's first read of the registry, the ledger or the vault - because the exceptions those raise
    /// arrive through the application's unhandled-exception path, not through navigation.
    /// </summary>
    private static readonly TimeSpan Settle = TimeSpan.FromMilliseconds(1500);

    /// <summary>The whole run, start-up check included. A hung page must still produce a report and a code.</summary>
    private static readonly TimeSpan Overall = TimeSpan.FromSeconds(150);

    private readonly object _gate = new();
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly DateTime _startedUtc = DateTime.UtcNow;
    private readonly List<PageReport> _pages = new();
    private readonly List<UnhandledReport> _unhandled = new();
    private string[] _statusBar = Array.Empty<string>();
    private string _windowTitle = string.Empty;
    private string _currentPage = "startup";
    private bool _finished;

    private ConsoleSelfTest(string reportPath) => ReportPath = reportPath;

    public string ReportPath { get; }

    public static string DefaultReportPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SPLAT", "self-test.json");

    /// <summary>The self-test the command line asks for, or null for a normal start.</summary>
    public static ConsoleSelfTest? FromCommandLine(string[] args)
    {
        if (!args.Any(a => string.Equals(a, Switch, StringComparison.OrdinalIgnoreCase)))
        {
            return null;
        }

        string report = DefaultReportPath;
        for (int i = 0; i < args.Length; i++)
        {
            if (string.Equals(args[i], ReportSwitch, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                report = args[i + 1];
            }
            else if (args[i].StartsWith(ReportSwitch + "=", StringComparison.OrdinalIgnoreCase))
            {
                report = args[i][(ReportSwitch.Length + 1)..];
            }
        }

        return new ConsoleSelfTest(report);
    }

    /// <summary>Runs the whole self-test against the window and exits the process with the result.</summary>
    public async Task RunAsync(MainWindow window)
    {
        try
        {
            var run = RunPagesAsync(window);
            var watchdog = Task.Delay(Overall);
            if (await Task.WhenAny(run, watchdog) == watchdog)
            {
                Finish(IncompleteExitCode, $"the self-test did not finish within {Overall.TotalSeconds:F0} s; it was on {_currentPage}");
                return;
            }

            await run;

            int failedPages;
            int unhandled;
            lock (_gate)
            {
                failedPages = _pages.Count(p => !p.Ok);
                unhandled = _unhandled.Count;
            }

            Finish(
                failedPages == 0 && unhandled == 0 ? PassedExitCode : PageFailedExitCode,
                failedPages == 0 && unhandled == 0
                    ? $"{_pages.Count} of {_pages.Count} pages opened and loaded"
                    : $"{failedPages} of {_pages.Count} pages failed, {unhandled} unhandled exception(s)");
        }
        catch (Exception ex)
        {
            Finish(IncompleteExitCode, $"the self-test threw {ex.GetType().Name}: {ex.Message}");
        }
    }

    private async Task RunPagesAsync(MainWindow window)
    {
        _windowTitle = window.AppWindow.Title;
        _statusBar = await window.ReadStatusBarAsync(TimeSpan.FromSeconds(30));

        foreach (Type page in MainWindow.EveryPage)
        {
            lock (_gate) _currentPage = page.Name;

            PageProbe probe = await window.ProbePageAsync(page, LoadBudget);
            await Task.Delay(Settle);

            lock (_gate)
            {
                int raised = _unhandled.Count(u => u.Page == page.Name);
                _pages.Add(new PageReport(
                    page.Name,
                    probe.Ok && raised == 0,
                    probe.ElapsedMs,
                    raised == 0 ? probe.Detail : $"{probe.Detail}; {raised} unhandled exception(s) while it loaded"));
            }
        }

        lock (_gate) _currentPage = "finished";
    }

    /// <summary>An unhandled exception with the window up: recorded against the page that was open, and the run goes on.</summary>
    public void RecordUnhandled(Exception exception)
    {
        lock (_gate)
        {
            if (_finished)
            {
                return;
            }

            _unhandled.Add(new UnhandledReport(_currentPage, $"{exception.GetType().Name}: {exception.Message}"));
        }
    }

    /// <summary>A failure before the window existed: the console did not start, which is the same verdict a normal start gives.</summary>
    public void AbortForStartupFailure(Exception exception)
    {
        lock (_gate) _unhandled.Add(new UnhandledReport("startup", $"{exception.GetType().Name}: {exception.Message}"));
        Finish(StartupFailedExitCode, $"the console failed before its window existed: {exception.GetType().Name}: {exception.Message}");
    }

    /// <summary>Best effort from a dying process: the report says how far the run got, and the exit code is the crash's own.</summary>
    public void NoteFatal(object? detail)
    {
        lock (_gate) _unhandled.Add(new UnhandledReport(_currentPage, $"fatal: {detail}"));
        TryWriteReport(IncompleteExitCode, $"the process died on {_currentPage}");
    }

    private void Finish(int exitCode, string summary)
    {
        lock (_gate)
        {
            if (_finished)
            {
                return;
            }

            _finished = true;
        }

        TryWriteReport(exitCode, summary);
        Environment.Exit(exitCode);
    }

    // camelCase and relaxed escaping: the report is read by build-client-dist.ps1 and by a person,
    // and the page names carry nothing that needs escaping from either.
    private static readonly JsonSerializerOptions ReportOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private void TryWriteReport(int exitCode, string summary)
    {
        try
        {
            Report report;
            lock (_gate)
            {
                report = new Report(
                    _startedUtc.ToString("O"),
                    DateTime.UtcNow.ToString("O"),
                    _clock.ElapsedMilliseconds,
                    exitCode,
                    summary,
                    _windowTitle,
                    _statusBar,
                    _pages.ToArray(),
                    _unhandled.ToArray());
            }

            string? directory = Path.GetDirectoryName(ReportPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(ReportPath, JsonSerializer.Serialize(report, ReportOptions), new UTF8Encoding(false));
        }
        catch
        {
            // The exit code still carries the verdict; a report that cannot be written must not
            // replace it with a crash.
        }
    }

    private sealed record Report(
        string StartedUtc,
        string FinishedUtc,
        long ElapsedMs,
        int ExitCode,
        string Summary,
        string WindowTitle,
        string[] StatusBar,
        PageReport[] Pages,
        UnhandledReport[] Unhandled);

    private sealed record PageReport(string Page, bool Ok, long Ms, string Detail);

    private sealed record UnhandledReport(string Page, string Error);
}

/// <summary>What opening one page found: whether it opened and loaded, how, and how long it took.</summary>
internal sealed record PageProbe(bool Ok, string Detail, long ElapsedMs);
