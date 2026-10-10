using System.Security.Cryptography;
using System.Text.Json;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Host;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Linux;

// This probe never constructs a model client or reads a credential vault. Its only external
// requests are the catalog's eight public, read-only source requests with their default inputs.
if (args.Length != 2 || args[0] is not ("--plan" or "--execute"))
{
    Console.Error.WriteLine("Usage: MissionController.SubstrateProbe --plan|--execute <output-directory>");
    return 2;
}
string output = Path.GetFullPath(args[1]);
Directory.CreateDirectory(output);
var templates = GovernedTemplateCatalog.All.Where(t => t.Tool.PassLeaseEgressAsArguments).ToArray();
var json = new JsonSerializerOptions { WriteIndented = true };
if (args[0] == "--plan")
{
    foreach (var template in templates)
        Console.WriteLine(JsonSerializer.Serialize(new { template.TemplateId, template.EgressRule,
            Parameters = template.GetEffectiveDefaults(), TemplateSha256 = MissionRunFacts.HashTemplate(template) }, json));
    return 0;
}

ManagedBridgeClient? managed = ManagedBridgeClient.FromEnvironment();
var lifecycle = new SubstrateLifecycle(managedCheck: managed is null ? null : managed.CheckAsync);
SubstrateReport report = await lifecycle.CheckAsync();
await File.WriteAllTextAsync(Path.Combine(output, "doctor.txt"), report.Text);
if (!report.Succeeded)
{
    Console.Error.WriteLine("The substrate check failed. See doctor.txt; no source tool was run.");
    return 1;
}
ILeasedExecutor executor = managed is not null ? managed : new WslLeasedExecutor();
var selector = new LinuxLeaseSubstrate(executor, new TemplatePolicyCompiler());
int failed = 0;
foreach (var template in templates)
{
    Guid mission = Guid.NewGuid();
    try
    {
        var substrate = selector.For(template, mission)!;
        string workspace = await substrate.Jails.ProvisionJailAsync(mission);
        using var job = substrate.Jobs("source-probe-" + mission.ToString("N"));
        job.ConfigureExtendedLimits(template.Tool.MaxMemoryBytes, template.Tool.MaxCpuPercent);
        ProcessExecutionResult result = await substrate.Launcher.LaunchSuspendedInJobAsync(template.Tool.ExecutablePath,
            GovernedArgumentBinder.Bind(template, new Dictionary<string, string>()), workspace, job, true, template.Tool.TimeoutSeconds);
        bool passed = result.ExitCode == 0 && !result.TimedOut && result.Lease is { Enforcing: true, Installed: true,
            WorkspaceRemoved: true, WorkloadUid: 65534, ViolationsComplete: true }
            && !string.IsNullOrWhiteSpace(result.Lease.SignedOutcome)
            && !result.StandardOutput.Contains("PROBE_FAILED", StringComparison.Ordinal)
            && !result.StandardOutput.Contains("INGESTION_FAILED", StringComparison.Ordinal);
        string path = Path.Combine(output, template.TemplateId + ".json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
        {
            RecordedAtUtc = DateTimeOffset.UtcNow, template.TemplateId, MissionId = mission,
            TemplateSha256 = MissionRunFacts.HashTemplate(template), Parameters = template.GetEffectiveDefaults(),
            Passed = passed, Result = result
        }, json));
        Console.WriteLine($"{(passed ? "PASS" : "FAIL")} {template.TemplateId}; receipt_sha256={Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path))).ToLowerInvariant()}");
        if (!passed) failed++;
    }
    catch (Exception ex)
    {
        failed++;
        Console.Error.WriteLine($"FAIL {template.TemplateId}: {ex.Message}");
    }
}
return failed == 0 ? 0 : 1;
