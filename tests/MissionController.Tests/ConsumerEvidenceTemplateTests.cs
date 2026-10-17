using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Linux;
using Xunit;

namespace MissionController.Tests;

public class ConsumerEvidenceTemplateTests
{
    private const string AppId = "123456";
    private const string FeedUrl = "https://itunes.apple.com/us/rss/customerreviews/page=1/id=123456/sortby=mostrecent/json";

    private static object Review(string rating = "2", string id = "98") => new Dictionary<string, object>
    {
        ["id"] = new { label = id }, ["updated"] = new { label = "2026-08-01T00:00:00Z" },
        ["im:rating"] = new { label = rating }, ["im:version"] = new { label = "1.0" },
        ["title"] = new { label = "Missing sync" }, ["content"] = new { label = "I enjoy this but need sync." },
        ["author"] = new { name = new { label = "PRIVATE_REVIEWER" } }
    };

    private static string ReviewPage(object[] entries, string identity = FeedUrl) =>
        JsonSerializer.Serialize(new { feed = new { id = new { label = identity }, entry = entries } });

    private static string OfferPage(string id = AppId, string price = "$9.99", bool includeOffers = true)
    {
        // The shape apps.apple.com served on 2026-10-12: an Annotation whose pairs sit under "items".
        var section = new { title = "In-App Purchases", items = new[] {
            new Dictionary<string, object> { ["$kind"] = "textPair", ["leadingText"] = "Monthly Premium", ["trailingText"] = price } } };
        var data = new { title = "Fixture App", titleOfferDisplayProperties = new { adamId = id },
            shelfMapping = new { information = new { items = includeOffers ? new[] { section } : Array.Empty<object>() } } };
        return "<script id=\"serialized-server-data\" type=\"application/json\">" +
            JsonSerializer.Serialize(new { data = new[] { new { data } } }) + "</script>";
    }

    private static async Task<string> Run(string kind, string page, string appId = AppId, string? redirect = null)
    {
        var template = GovernedTemplateCatalog.All.Single(t => t.TemplateId == "source-consumer-" + kind);
        string arguments = GovernedArgumentBinder.Bind(template, new Dictionary<string, string> { ["AppId"] = appId });
        // Replace transport only in the isolated test process; production has no fixture switch.
        var argv = PosixArgumentSplitter.Split(arguments).ToArray();
        string fixture = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new { text = page, redirect }));
        argv[3] = argv[3].Replace("if __name__ == '__main__':",
            "import base64\ndef read_page(url, limit):\n    return json.loads(base64.b64decode('" + fixture + "'))\n\nif __name__ == '__main__':");
        var start = new ProcessStartInfo(OperatingSystem.IsWindows() ? "python" : "python3")
        {
            RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true,
            UseShellExecute = false, CreateNoWindow = true
        };
        // stdin avoids Windows' command-line limit for deliberately oversized feed fixtures.
        foreach (string argument in argv.Take(2)) start.ArgumentList.Add(argument);
        start.ArgumentList.Add("-");
        foreach (string argument in argv.Skip(4)) start.ArgumentList.Add(argument);
        start.ArgumentList.Add(JsonSerializer.Serialize(new Dictionary<string, string[]> {
            [kind == "offers" ? "apps.apple.com" : "itunes.apple.com"] = ["8.8.8.8"] }));
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        await process.StandardInput.WriteAsync(argv[3]);
        process.StandardInput.Close();
        try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20)); }
        catch { process.Kill(entireProcessTree: true); throw; }
        Assert.Equal(0, process.ExitCode);
        Assert.True(string.IsNullOrWhiteSpace(await stderr), await stderr);
        return (await stdout).Trim();
    }

    [Fact]
    public async Task ReviewSensor_ProjectsPrivateEvidence_AndRefusesBrokenInputs()
    {
        var good = await Run("reviews", ReviewPage(new[] { Review() }));
        using var capture = JsonDocument.Parse(good);
        Assert.Equal("reviews", capture.RootElement.GetProperty("kind").GetString());
        Assert.Single(capture.RootElement.GetProperty("feed").GetProperty("entry").EnumerateArray());
        Assert.DoesNotContain("PRIVATE_REVIEWER", good);
        foreach (string broken in new[] {
            "{}", ReviewPage(new[] { Review() }, FeedUrl.Replace("123456", "999")),
            ReviewPage(new[] { Review("0") }), ReviewPage(new[] { Review(), Review() }),
            ReviewPage(Enumerable.Range(1, 51).Select(n => Review(id: n.ToString())).ToArray()) })
        {
            Assert.StartsWith("PROBE_FAILED:", await Run("reviews", broken));
        }
        Assert.StartsWith("PROBE_FAILED:", await Run("reviews", ReviewPage(new[] { Review() }), redirect: "https://other.invalid/"));
    }

    [Fact]
    public async Task OfferSensor_EmitsOnlyObservedLabelsAndPrices_AndRefusesMissingEvidence()
    {
        using var good = JsonDocument.Parse(await Run("offers", OfferPage()));
        Assert.Equal("$9.99", good.RootElement.GetProperty("offers")[0].GetProperty("price_display").GetString());
        foreach (string broken in new[] { "<html>changed</html>", OfferPage(id: "999"),
            OfferPage(price: "unavailable"), OfferPage(includeOffers: false) })
        {
            Assert.StartsWith("PROBE_FAILED:", await Run("offers", broken));
        }
        foreach (string redirect in new[] { "https://other.invalid/", "https://apps.apple.com/us/app/x/id999",
            "https://apps.apple.com/us/app/x/id123456?secret=value", "https://apps.apple.com@other.invalid/us/app/x/id123456" })
        {
            Assert.Contains("redirect_refused", await Run("offers", OfferPage(), redirect: redirect));
        }
        Assert.Contains("redirect_limit", await Run("offers", OfferPage(), redirect: "https://apps.apple.com/us/app/x/id123456"));
    }

    [Fact]
    public async Task AppIdCannotBindCodeOrChooseADestination()
    {
        foreach (string kind in new[] { "reviews", "offers" })
        {
            var template = GovernedTemplateCatalog.All.Single(t => t.TemplateId == "source-consumer-" + kind);
            Assert.Throws<TemplateParameterRejectedException>(() => GovernedArgumentBinder.Bind(template,
                new Dictionary<string, string> { ["AppId"] = "123'; exit 0; '" }));
            foreach (string invalid in new[] { "0", "abc", "1/../../elsewhere", "https://other.invalid" })
                Assert.Contains("invalid_app_id", await Run(kind, "{}", invalid));
        }
    }
}
