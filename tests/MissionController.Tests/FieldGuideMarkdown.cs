using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Xml.Linq;

namespace MissionController.Tests;

/// <summary>
/// Turns <c>docs/SPLAT-Field-Guide.html</c> into <c>docs/TUTORIAL.md</c>.
///
/// The two were hand-synced for a month, which is exactly as reliable as it sounds: they once
/// advertised 297, 342 and 340 automated tests while the branch they described ran 192, and the
/// census had to be bound by a test in both copies, pattern by pattern, because a correction landed
/// in one and not the other. A second copy of a document is a second set of claims to keep true.
///
/// So the markdown is derived now, and <see cref="FieldGuideTutorialTests"/> fails if the committed
/// file is not what this produces. The HTML stays the source because it is also the published page.
///
/// Deliberately not a general HTML converter: it knows this one document's vocabulary and throws on
/// anything else, because a silently dropped element would quietly shorten the guide rather than
/// fail. Parsing is XML over the body with the four entities the file uses substituted first - a
/// fifth one, or an unclosed tag, fails the parse, which is the right way to find out.
/// </summary>
internal static class FieldGuideMarkdown
{
    private const string BodyOpen = "<div class=\"wrap\">";

    public static string Convert(string html)
    {
        var body = XElement.Parse(ExtractBody(html), LoadOptions.PreserveWhitespace);

        var markdown = new StringBuilder();
        markdown.Append("<!-- DERIVED FILE - do not edit. Generated from docs/SPLAT-Field-Guide.html,\n");
        markdown.Append("     which is the source of truth and the page published to readers. To change this file,\n");
        markdown.Append("     edit that one and run:  SPLAT_SYNC_TUTORIAL=1 dotnet test --filter TheTutorial_IsTheFieldGuideAsMarkdown -->\n\n");

        foreach (XElement child in body.Elements())
        {
            switch (ClassOf(child), child.Name.LocalName)
            {
                case ("hero", "header"):
                    Hero(markdown, child);
                    break;
                case (_, "section"):
                    Section(markdown, child);
                    break;
                case (_, "footer"):
                    Paragraph(markdown, "*" + string.Join(" - ", child.Elements("span").Select(Inline)) + "*");
                    break;
                default:
                    throw new InvalidOperationException(
                        $"The Field Guide grew a <{child.Name.LocalName} class=\"{ClassOf(child)}\"> at the top level " +
                        "that this converter does not know. Teach it that element rather than letting the markdown " +
                        "copy silently lose a section.");
            }
        }

        return markdown.ToString().TrimEnd() + "\n";
    }

    private static string ExtractBody(string html)
    {
        int start = html.IndexOf(BodyOpen, StringComparison.Ordinal);
        int end = html.LastIndexOf("</div>", StringComparison.Ordinal);
        if (start < 0 || end <= start)
        {
            throw new InvalidOperationException(
                "docs/SPLAT-Field-Guide.html no longer opens with " + BodyOpen + " and close with </div>, " +
                "which is how both this converter and packaging/build-field-guide-artifact.ps1 find the body.");
        }

        return html[start..(end + "</div>".Length)]
            .Replace("&mdash;", "—", StringComparison.Ordinal)
            .Replace("&ldquo;", "“", StringComparison.Ordinal)
            .Replace("&rdquo;", "”", StringComparison.Ordinal)
            .Replace("<br>", "<br/>", StringComparison.Ordinal);
    }

    private static void Hero(StringBuilder markdown, XElement hero)
    {
        markdown.Append("# ").Append(Inline(Find(hero, "h1"))).Append("\n\n");
        Paragraph(markdown, "*" + Inline(FindByClass(hero, "expansion")) + " - " + Inline(FindByClass(hero, "eyebrow")) + ".*");
        Paragraph(markdown, Inline(FindByClass(hero, "stand")));
        Paragraph(markdown, "*" + Inline(FindByClass(hero, "hero-meta")) + "*");
        markdown.Append("---\n\n");
    }

    private static void Section(StringBuilder markdown, XElement section)
    {
        string part = Inline(FindByClass(section, "part"));

        // "Part 4 - The mission" over "What actually happens when you press the button" is two lines on
        // a page and one heading in a document. The label's own subtitle is dropped rather than
        // repeated, because the h2 beneath it always says the same thing at more length.
        string label = part.Split('—')[0].Trim();
        markdown.Append("## ").Append(label).Append(" — ").Append(Inline(Find(section, "h2"))).Append("\n\n");

        foreach (XElement element in section.Elements())
        {
            string css = ClassOf(element);
            if (css is "part" || element.Name.LocalName == "h2")
            {
                continue;
            }

            switch (element.Name.LocalName)
            {
                case "p":
                    Paragraph(markdown, Inline(element));
                    break;
                case "h3":
                    markdown.Append("### ").Append(Inline(element)).Append("\n\n");
                    break;
                case "ol":
                    Pipeline(markdown, element);
                    break;
                case "dl":
                    Glossary(markdown, element);
                    break;
                case "div" when css == "pull":
                    Paragraph(markdown, "> " + string.Join(" ", element.Elements("p").Select(Inline)));
                    break;
                case "div" when css == "rings":
                    Rings(markdown, element);
                    break;
                case "div" when css == "squad":
                    Squad(markdown, element);
                    break;
                case "div" when css == "status":
                    Status(markdown, element);
                    break;
                case "div" when css == "table-scroll":
                    Table(markdown, Find(element, "table"));
                    break;
                default:
                    throw new InvalidOperationException(
                        $"Unknown <{element.Name.LocalName} class=\"{css}\"> inside section \"{label}\".");
            }
        }
    }

    /// <summary>
    /// The containment rings, as nested boxes. Widths are computed from the innermost outwards so the
    /// drawing cannot come out ragged: each box is wide enough for its own label and for the box it
    /// contains, and never wider.
    /// </summary>
    private static void Rings(StringBuilder markdown, XElement rings)
    {
        var labels = new List<string>();
        XElement ring = Find(rings, "div");
        XElement? core = null;
        while (true)
        {
            labels.Add(Inline(FindByClass(ring, "ring-label")));
            XElement? inner = ring.Elements("div").FirstOrDefault(e => ClassOf(e) == "ring");
            if (inner is null)
            {
                core = ring.Elements("div").First(e => ClassOf(e) == "ring-core");
                break;
            }

            ring = inner;
        }

        var coreLines = new List<string>
        {
            core.Nodes().OfType<XText>().Select(t => t.Value.Trim()).First(t => t.Length > 0),
            "(" + Inline(Find(core, "small")) + ")",
        };

        int width = coreLines.Max(line => line.Length);
        var block = coreLines.Select(line => line.PadRight(width)).ToList();
        foreach (string label in Enumerable.Reverse(labels))
        {
            // The top line is "|- " + label + " " + at least one rule + "|", so a box narrower than
            // label + 6 would have to cut its own label - which it did, and shipped a ring reading
            // "hard caps on memory & CP" into the markdown copy.
            int inner = width;
            width = Math.Max(label.Length + 6, inner + 4);
            string top = "┌─ " + label + " " + new string('─', width - label.Length - 5) + "┐";
            var wrapped = new List<string> { top };
            wrapped.AddRange(block.Select(line => "│ " + line.PadRight(width - 4) + " │"));
            wrapped.Add("└" + new string('─', width - 2) + "┘");
            block = wrapped;
        }

        markdown.Append("```\n").Append(string.Join("\n", block)).Append("\n```\n\n");
        Paragraph(markdown, "*" + Inline(FindByClass(rings, "rings-caption")) + "*");
    }

    private static void Squad(StringBuilder markdown, XElement squad)
    {
        foreach (XElement agent in squad.Elements("div"))
        {
            XElement head = Find(agent, "div");
            string name = Inline(head.Elements("span").First(s => ClassOf(s) == "agent-name"));
            string chip = Inline(head.Elements("span").First(s => ClassOf(s).StartsWith("chip", StringComparison.Ordinal)));
            markdown.Append("- **").Append(name).Append("** (").Append(chip).Append(") — ")
                .Append(Inline(Find(agent, "p"))).Append('\n');
        }

        markdown.Append('\n');
    }

    private static void Pipeline(StringBuilder markdown, XElement pipeline)
    {
        int step = 0;
        foreach (XElement item in pipeline.Elements("li"))
        {
            step++;
            string title = Inline(item.Elements("span").First(s => ClassOf(s) == "step-title"));
            markdown.Append(step.ToString(CultureInfo.InvariantCulture)).Append(". **").Append(title)
                .Append("** — ").Append(Inline(Find(item, "p"))).Append('\n');
        }

        markdown.Append('\n');
    }

    private static void Status(StringBuilder markdown, XElement status)
    {
        foreach (XElement card in status.Elements("div"))
        {
            string chip = Inline(Find(card, "span"));
            markdown.Append("- **").Append(chip).Append("** — ").Append(Inline(Find(card, "p"))).Append('\n');
        }

        markdown.Append('\n');
    }

    private static void Glossary(StringBuilder markdown, XElement list)
    {
        foreach (XElement term in list.Elements("div"))
        {
            markdown.Append("- **").Append(Inline(Find(term, "dt"))).Append("** — ")
                .Append(Inline(Find(term, "dd"))).Append('\n');
        }

        markdown.Append('\n');
    }

    private static void Table(StringBuilder markdown, XElement table)
    {
        var header = Find(table, "thead").Descendants("th").Select(Inline).ToList();
        markdown.Append("| ").Append(string.Join(" | ", header)).Append(" |\n");
        markdown.Append("| ").Append(string.Join(" | ", header.Select(_ => "---"))).Append(" |\n");

        foreach (XElement row in Find(table, "tbody").Elements("tr"))
        {
            markdown.Append("| ").Append(string.Join(" | ", row.Elements("td").Select(Inline))).Append(" |\n");
        }

        markdown.Append('\n');
    }

    private static void Paragraph(StringBuilder markdown, string text) => markdown.Append(text).Append("\n\n");

    /// <summary>
    /// One element's text as markdown. Whitespace is collapsed, because the HTML is indented for a
    /// person reading the source and a markdown paragraph that kept those newlines would reflow
    /// differently every time someone re-indented the page.
    /// </summary>
    private static string Inline(XElement element)
    {
        var text = new StringBuilder();
        foreach (XNode node in element.Nodes())
        {
            switch (node)
            {
                case XText value:
                    text.Append(value.Value);
                    break;
                case XElement child:
                    string inner = Inline(child);
                    text.Append(child.Name.LocalName switch
                    {
                        "strong" => "**" + inner + "**",
                        "em" => "*" + inner + "*",
                        "code" => "`" + inner + "`",
                        "br" => " ",
                        "a" => "[" + inner + "](" + child.Attribute("href")?.Value + ")",
                        "span" or "small" => inner,
                        _ => throw new InvalidOperationException(
                            $"The Field Guide uses an inline <{child.Name.LocalName}> this converter does not render."),
                    });
                    break;
            }
        }

        return string.Join(" ", text.ToString().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
    }

    private static string ClassOf(XElement element) => element.Attribute("class")?.Value ?? string.Empty;

    private static XElement Find(XElement parent, string name) =>
        parent.Descendants(name).FirstOrDefault()
        ?? throw new InvalidOperationException($"Expected a <{name}> inside <{parent.Name.LocalName}>.");

    private static XElement FindByClass(XElement parent, string css) =>
        parent.Descendants().FirstOrDefault(e => ClassOf(e) == css)
        ?? throw new InvalidOperationException($"Expected class=\"{css}\" inside <{parent.Name.LocalName}>.");
}
