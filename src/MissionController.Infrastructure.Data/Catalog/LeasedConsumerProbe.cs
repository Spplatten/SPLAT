using System.Text.Json;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Catalog;

internal static class LeasedConsumerProbe
{
    private static readonly string Source = ReadSource();

    internal static SingleToolDefinition Tool(string id, string name, string mode, int seconds) => new(
        id, name, "/usr/bin/python3", "-I -B -c " + Quote("MODE = " + JsonSerializer.Serialize(mode)
            + "\nORIGIN = " + JsonSerializer.Serialize("https://" + (mode == "offers" ? "apps.apple.com/" : "itunes.apple.com/")) + "\n" + Source)
            + (mode == "catalog" ? "" : " '{AppId}'"), new[] { 0 }, TimeoutSeconds: seconds,
        MaxMemoryBytes: 256 * 1024 * 1024, MaxCpuPercent: 50,
        Substrate: ToolSubstrate.LinuxLease, PassLeaseHostPinsAsArguments: true);

    private static string Quote(string text) => "'" + text.Replace("'", "'\"'\"'", StringComparison.Ordinal) + "'";

    private static string ReadSource()
    {
        using var stream = typeof(LeasedConsumerProbe).Assembly.GetManifestResourceStream("LeasedConsumerProbe.py")
            ?? throw new InvalidOperationException("The RARE leased sensor was not packaged.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Replace("\r\n", "\n", StringComparison.Ordinal);
    }
}
