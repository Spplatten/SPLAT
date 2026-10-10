using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Reads the console's XAML for layout mistakes that WinUI accepts in silence.
///
/// The suite opens all ten pages through the console's own self-test, and every page opened. That
/// proves a page does not throw; it cannot see that six fields are stacked on top of one another.
/// Project Studio shipped that way: its project-definition grid declared two columns and no rows,
/// so <c>Grid.Row="1"</c> and <c>Grid.Row="2"</c> both resolved to row 0 and the operator read
/// "Description" printed over "Project ID". WinUI places a child in an undeclared row without a
/// warning, at build time or at run time, so nothing anywhere failed.
///
/// This is the cheapest check that would have caught it: the XAML is XML, the rule is arithmetic.
/// </summary>
public class XamlLayoutTests
{
    [Fact]
    public void NoGridPlacesAChildInARowOrColumnItNeverDeclared()
    {
        var offenders = new List<string>();

        foreach (string file in ProjectXamlFiles())
        {
            XElement root;
            try
            {
                root = XElement.Load(file, LoadOptions.SetLineInfo);
            }
            catch (System.Xml.XmlException ex)
            {
                offenders.Add($"{Relative(file)} is not well-formed XML: {ex.Message}");
                continue;
            }

            foreach (var grid in root.DescendantsAndSelf().Where(e => e.Name.LocalName == "Grid"))
            {
                // A grid with no definitions still has one row and one column, which is what makes
                // this defect silent: the child lands somewhere, just not where it says.
                int rows = Math.Max(1, Defined(grid, "RowDefinitions"));
                int columns = Math.Max(1, Defined(grid, "ColumnDefinitions"));

                foreach (var child in grid.Elements().Where(e => !e.Name.LocalName.Contains('.')))
                {
                    Check(offenders, file, child, "Row", rows);
                    Check(offenders, file, child, "Column", columns);
                }
            }
        }

        Assert.True(
            offenders.Count == 0,
            "These grids place a child outside the rows or columns they declare, so the children " +
            "overlap and nothing says so:" + Environment.NewLine + string.Join(Environment.NewLine, offenders));
    }

    /// <summary>
    /// Guards the reading above. If the scan stopped finding files - a moved project, a renamed
    /// folder - it would pass by finding nothing, which is the failure mode every file-scanning test
    /// has and the reason this one states its floor.
    /// </summary>
    [Fact]
    public void TheScanActuallyReachesTheConsolesPages()
    {
        var files = ProjectXamlFiles().ToList();

        Assert.True(files.Count >= 10, $"only {files.Count} XAML files were found under the console project");
        Assert.Contains(files, f => Path.GetFileName(f) == "ProjectStudioView.xaml");
    }

    private static void Check(List<string> offenders, string file, XElement child, string axis, int defined)
    {
        var attribute = child.Attribute("Grid." + axis);
        if (attribute is null || !int.TryParse(attribute.Value, out int index))
        {
            return;
        }

        var span = child.Attribute("Grid." + axis + "Span");
        int last = span is not null && int.TryParse(span.Value, out int width) ? index + width - 1 : index;

        if (last >= defined)
        {
            offenders.Add(
                $"{Relative(file)}: <{child.Name.LocalName}> uses Grid.{axis}={index}" +
                (span is null ? string.Empty : $" spanning {span.Value}") +
                $" but its grid declares {defined}");
        }
    }

    private static int Defined(XElement grid, string collection) =>
        grid.Elements().FirstOrDefault(e => e.Name.LocalName == "Grid." + collection)?.Elements().Count() ?? 0;

    private static IEnumerable<string> ProjectXamlFiles() =>
        Directory.EnumerateFiles(Path.Combine(RepositoryRoot(), "src", "MissionController.UI"), "*.xaml", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .OrderBy(f => f, StringComparer.Ordinal);

    private static string Relative(string file) => Path.GetRelativePath(RepositoryRoot(), file);

    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MissionController.sln")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
