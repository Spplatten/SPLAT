using System.Security.Cryptography;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using MissionController.Host;

namespace MissionController.Tests;

/// <summary>Import consent and guest ownership, against recorded WSL commands, without importing a distro.</summary>
public sealed class BundledWslGuestTests
{
    private sealed class Fixture : IDisposable
    {
        public const string Token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "splat-lite-test-" + Guid.NewGuid().ToString("N"));
        public string Linux => Path.Combine(Root, "Linux");
        public BundledWslGuest Guest { get; }
        public SubstrateLifecycle Lifecycle { get; }
        public List<string[]> Commands { get; } = new();
        public string Registered = "";
        public string Identity = "";
        public bool FailImport;
        public bool FailInitialize;
        public int TokenReads;

        public Fixture(int port = 50051)
        {
            WriteArchive("synthetic test bytes, not a bootable image");
            Guest = new BundledWslGuest(Linux, Path.Combine(Root, "data"), Run, port);
            Lifecycle = new SubstrateLifecycle(bundledGuest: Guest, ledgerPath: Path.Combine(Root, "ledger.db"));
        }

        public void WriteArchive(string content)
        {
            Directory.CreateDirectory(Path.Combine(Linux, "Guest"));
            string archive = Path.Combine(Linux, "rootfs.tar.xz");
            File.WriteAllText(archive, content);
            File.WriteAllText(Path.Combine(Linux, "Guest", "BUILD.json"), JsonSerializer.Serialize(new
            {
                sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(archive))).ToLowerInvariant(),
                xzBytes = new FileInfo(archive).Length,
            }));
        }

        private Task<(int, string)> Run(IReadOnlyList<string> args, CancellationToken ct)
        {
            Commands.Add(args.ToArray());
            if (args[0] == "--list") return Task.FromResult((0, Registered));
            if (args[0] == "--import")
            {
                if (FailImport) return Task.FromResult((17, "import interrupted"));
                Registered = args[1];
            }
            if (args.Contains("-c"))
            {
                if (FailInitialize) return Task.FromResult((18, "initializer failed"));
                Identity = Regex.Match(args[^1], "'[0-9a-f]{32}'").Value.Trim('\'');
            }
            if (args[^1] == "/etc/splat/guest.id") return Task.FromResult((0, Identity));
            if (args[^1] == "/etc/splat/agent.token")
            {
                TokenReads++;
                return Task.FromResult((0, Token));
            }
            return Task.FromResult((0, ""));
        }

        public async Task Import()
        {
            Assert.Equal(1, (await Lifecycle.PlanMountAsync()).ExitCode);
            Assert.Equal(SubstrateChange.ImportGuest, Lifecycle.Planned);
            SubstrateReport result = await Lifecycle.ApplyAsync();
            Assert.True(result.Succeeded, result.Text);
        }

        public void SeedOwnedRegistration()
        {
            // This fixture tests connection ownership separately from import/atomic replacement.
            // The real import path remains covered by the tests above and below.
            Registered = Guest.Distribution;
            Identity = Guid.NewGuid().ToString("N");
            Directory.CreateDirectory(Guest.StateDirectory);
            File.WriteAllText(Path.Combine(Guest.StateDirectory, "import.json"), JsonSerializer.Serialize(new
            {
                Distribution = Registered, Identity, Phase = "ready",
            }));
        }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }

    [Fact]
    public async Task ImportPlan_IsReadOnly_AndApplyImportsOnlyTheReviewedGuestOnce()
    {
        using var f = new Fixture();
        SubstrateReport plan = await f.Lifecycle.PlanMountAsync();
        Assert.Contains(f.Guest.Distribution, plan.Text);
        Assert.Contains("SHA-256", plan.Text);
        Assert.Contains("retains the guest", plan.Text);
        Assert.Equal(SubstrateChange.ImportGuest, f.Lifecycle.Planned);
        Assert.Single(f.Commands);
        Assert.Equal(new[] { "--list", "--quiet" }, f.Commands[0]);
        Assert.False(Directory.Exists(f.Guest.StateDirectory));

        Assert.True((await f.Lifecycle.ApplyAsync()).Succeeded);
        Assert.Equal(new[] { "--import", f.Guest.Distribution, f.Guest.StorageDirectory,
            Path.Combine(f.Linux, "rootfs.tar.xz"), "--version", "2" }, f.Commands[2]);
        Assert.Equal(new[] { "--terminate", f.Guest.Distribution }, f.Commands[^1]);
        Assert.DoesNotContain(f.Commands.SelectMany(c => c), arg => arg is "--shutdown" or "--set-default" or "--unregister");
        Assert.DoesNotContain(f.Commands, c => c.Contains("splat-agent"));
        Assert.Equal(SubstrateChange.None, f.Lifecycle.Planned);
        int count = f.Commands.Count;
        Assert.False((await f.Lifecycle.ApplyAsync()).Succeeded);
        Assert.Equal(count, f.Commands.Count);
    }

    [Fact]
    public async Task ChangedArchiveAndMetadata_RequireANewPlan()
    {
        using var f = new Fixture();
        await f.Lifecycle.PlanMountAsync();
        f.WriteArchive("different but internally consistent payload");
        SubstrateReport result = await f.Lifecycle.ApplyAsync();
        Assert.Contains("changed after the plan", result.Text);
        Assert.False(result.Succeeded);
        Assert.DoesNotContain(f.Commands, c => c[0] == "--import");
        Assert.False(Directory.Exists(f.Guest.StateDirectory));
    }

    [Fact]
    public async Task CorruptArchive_AuthorizesNothing()
    {
        using var f = new Fixture();
        File.AppendAllText(Path.Combine(f.Linux, "rootfs.tar.xz"), "tamper");
        Assert.Contains("does not match", (await f.Lifecycle.PlanMountAsync()).Text);
        Assert.Equal(SubstrateChange.None, f.Lifecycle.Planned);
        Assert.False((await f.Lifecycle.ApplyAsync()).Succeeded);
        Assert.DoesNotContain(f.Commands, c => c[0] == "--import");
    }

    [Fact]
    public async Task ExistingUnownedName_IsNeverAdopted()
    {
        using var f = new Fixture();
        f.Registered = "Ubuntu\r\n" + string.Join("\0", f.Guest.Distribution.ToUpperInvariant().ToCharArray()) + "\0\r\n";
        Assert.Contains("Refusing to adopt", (await f.Lifecycle.PlanMountAsync()).Text);
        Assert.Equal(SubstrateChange.None, f.Lifecycle.Planned);
        Assert.Single(f.Commands);
        Assert.False(Directory.Exists(f.Guest.StateDirectory));
    }

    [Fact]
    public async Task ANameClaimedAfterPlanning_PreventsImport()
    {
        using var f = new Fixture();
        await f.Lifecycle.PlanMountAsync();
        f.Registered = f.Guest.Distribution;
        Assert.Contains("changed after the plan", (await f.Lifecycle.ApplyAsync()).Text);
        Assert.DoesNotContain(f.Commands, c => c[0] == "--import");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PartialImport_IsRecorded_AndCannotBeRetriedOrRemovedAutomatically(bool initialization)
    {
        using var f = new Fixture();
        f.FailImport = !initialization;
        f.FailInitialize = initialization;
        await f.Lifecycle.PlanMountAsync();
        Assert.False((await f.Lifecycle.ApplyAsync()).Succeeded);
        string receipt = Path.Combine(f.Guest.StateDirectory, "import.json");
        Assert.Contains("importing", File.ReadAllText(receipt));
        Assert.Contains("incomplete", (await f.Lifecycle.PlanMountAsync()).Text);
        Assert.Equal(SubstrateChange.None, f.Lifecycle.Planned);
        Assert.Single(f.Commands, c => c[0] == "--import");
        Assert.DoesNotContain(f.Commands, c => c[0] is "--unregister" or "--terminate");
    }

    [Fact]
    public async Task CheckSpendsTheImportPlan_WithoutFallingBackToTheDefaultGuest()
    {
        using var f = new Fixture();
        await f.Lifecycle.PlanMountAsync();
        int count = f.Commands.Count;
        Assert.Contains("not imported", (await f.Lifecycle.CheckAsync()).Text);
        Assert.Equal(SubstrateChange.None, f.Lifecycle.Planned);
        Assert.False((await f.Lifecycle.ApplyAsync()).Succeeded);
        Assert.Equal(count, f.Commands.Count);
    }

    [Fact]
    public async Task OwnedCommands_AreBoundToTheImportedGuest_AndRejectAReplacedMarker()
    {
        using var f = new Fixture();
        await f.Import();
        f.Commands.Clear();
        await f.Guest.RunAsync(new[] { "-e", "/bin/true" }, default);
        Assert.Equal(2, f.Commands.Count);
        Assert.All(f.Commands, c => Assert.Equal(new[] { "-d", f.Guest.Distribution }, c.Take(2)));
        f.Identity = new string('0', 32);
        f.Commands.Clear();
        await Assert.ThrowsAsync<IOException>(() => f.Guest.RunAsync(new[] { "-e", "must-not-run" }, default));
        Assert.Single(f.Commands);
        Assert.DoesNotContain(f.Commands, c => c.Contains("must-not-run"));
        Assert.False((await f.Lifecycle.PlanUnmountAsync()).Succeeded);
        Assert.Equal(SubstrateChange.None, f.Lifecycle.Planned);
    }

    [Fact]
    public void DataRoots_GetDistinctGuestNames_AndLegacyRawImagesDoNotSelectLite()
    {
        using var f = new Fixture();
        var same = new BundledWslGuest(f.Linux, Path.Combine(f.Root, "data"));
        var other = new BundledWslGuest(f.Linux, Path.Combine(f.Root, "other-data"));
        Assert.Equal(f.Guest.Distribution, same.Distribution);
        Assert.NotEqual(f.Guest.Distribution, other.Distribution);
        string app = Path.Combine(f.Root, "App");
        Assert.NotNull(BundledWslGuest.BesideApp(app, Path.Combine(f.Root, "data")));
        Directory.Delete(Path.Combine(f.Linux, "Guest"), recursive: true);
        Assert.Null(BundledWslGuest.BesideApp(app, Path.Combine(f.Root, "data")));
    }

    [Fact]
    public void ManagedAndBundledGuests_CannotBeSelectedTogether()
    {
        using var f = new Fixture();
        Assert.Throws<ArgumentException>(() => new SubstrateLifecycle(bundledGuest: f.Guest,
            managedCheck: _ => Task.FromResult(new SubstrateReport(0, "managed"))));
    }

    [Fact]
    public async Task MissingPackageRecords_DoNotRedirectAnOwnedGuestToTheDefaultDistro()
    {
        using var f = new Fixture();
        await f.Import();
        Directory.Delete(Path.Combine(f.Linux, "Guest"), recursive: true);
        var selected = BundledWslGuest.BesideApp(Path.Combine(f.Root, "App"), Path.Combine(f.Root, "data"));
        Assert.NotNull(selected);
        Assert.Equal(f.Guest.Distribution, selected.Distribution);
    }

    [Fact]
    public async Task AChangedOwnershipMarker_RefusesACachedTokenConnectionWhileTheDaemonStillListens()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var f = new Fixture(((IPEndPoint)listener.LocalEndpoint).Port);
        f.SeedOwnedRegistration();

        async Task<StandInAgent.Exchange> ServeHealth()
        {
            using var server = await listener.AcceptTcpClientAsync(deadline.Token);
            using var stream = server.GetStream();
            return await StandInAgent.ServeAsync(stream, Fixture.Token, new[]
            {
                "{\"type\":\"HEALTH_RESPONSE\",\"bpfLsmActive\":true,\"cgroupV2Active\":true," +
                "\"overlayFsSupported\":true,\"kernelVersion\":\"test-kernel\",\"enforcing\":true,\"activeLeaseCount\":0}",
            }, deadline.Token);
        }
        // Two proven exchanges with one token read establish that the second used the cache.
        for (int i = 0; i < 2; i++)
        {
            var exchange = ServeHealth();
            var health = await f.Guest.Health.CheckHealthAsync(deadline.Token);
            Assert.True((await exchange).Proven);
            Assert.True(health.Authenticated && health.Enforcing, health.Message);
        }
        Assert.Equal(1, f.TokenReads);
        f.Commands.Clear();

        f.Identity = new string('0', 32);
        var refusal = await Assert.ThrowsAsync<IOException>(() => f.Guest.Executor.ConnectToDaemonAsync(deadline.Token));
        Assert.Contains("ownership marker", refusal.Message);
        Assert.Single(f.Commands);
        Assert.Equal("/etc/splat/guest.id", f.Commands[0][^1]);
        Assert.Equal(1, f.TokenReads);
        Assert.False(listener.Pending());
        Assert.DoesNotContain(f.Commands, c => c.Contains("/bin/systemctl"));
    }

    [Fact]
    public async Task AHealthCheckWithWrongOwnership_NeverConnectsOrReadsTheDaemonSecret()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var f = new Fixture(((IPEndPoint)listener.LocalEndpoint).Port);
        f.SeedOwnedRegistration();
        f.Identity = new string('0', 32);

        var health = await f.Guest.Health.CheckHealthAsync(deadline.Token);

        Assert.False(health.DaemonReachable);
        Assert.Contains("ownership marker", health.Message);
        Assert.Single(f.Commands);
        Assert.Equal("/etc/splat/guest.id", f.Commands[0][^1]);
        Assert.False(listener.Pending());
    }
}
