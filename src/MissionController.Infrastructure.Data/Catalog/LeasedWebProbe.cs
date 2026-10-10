using System.Text.Json;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Catalog;

internal static class LeasedWebProbe
{
    private static readonly string Source = ReadSource();

    internal static SingleToolTemplate MoveToLease(SingleToolTemplate template)
    {
        string? mode = template.TemplateId switch
        {
            "source-price-index-probe" => "index",
            "source-average-price-probe" => "price",
            "source-public-interest-probe" => "attention",
            "source-credential-gate-probe" => "gate",
            "source-published-artifact-check" => "artifact",
            "source-dataset-catalog-search" => "catalog",
            "trends-brief-composer" => "brief",
            "grants-opportunity-ingestion" => "grants",
            _ => null
        };
        if (mode is null) return template;
        string[] keys = template.GetEffectiveDefaults().Keys.Order(StringComparer.Ordinal).ToArray();
        string script = "BASE = " + JsonSerializer.Serialize("https://" + template.EgressRule.AllowedFqdn + "/")
            + "\nMODE = " + JsonSerializer.Serialize(mode)
            + "\nKEYS = " + JsonSerializer.Serialize(keys) + "\n" + Source;
        string arguments = "-I -B -c " + Quote(script) + " "
            + string.Join(" ", keys.Select(key => "'{" + key + "}'"));
        return template with { Tool = template.Tool with
        {
            ExecutablePath = "/usr/bin/python3", ArgumentsTemplate = arguments,
            Substrate = ToolSubstrate.LinuxLease, PassLeaseEgressAsArguments = true
        } };
    }

    private static string Quote(string value) => "'" + value.Replace("'", "'\"'\"'", StringComparison.Ordinal) + "'";

    private static string ReadSource()
    {
        using var stream = typeof(LeasedWebProbe).Assembly.GetManifestResourceStream("LeasedWebProbe.py")
            ?? throw new InvalidOperationException("The leased web sensor was not packaged.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Replace("\r\n", "\n", StringComparison.Ordinal);
    }
}
