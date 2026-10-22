using System.Text.Json;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Linux;
using SplatMcp;

namespace MissionController.Tests;

public sealed partial class A2aBridgeTests
{
    private sealed class Lookup : ILeaseReceiptLookup
    {
        internal int Calls;
        internal bool Missing;
        public Task<LeaseOutcome?> RecoverReceiptAsync(LeaseSpec lease, CancellationToken ct = default)
        {
            Interlocked.Increment(ref Calls);
            if (Missing) return Task.FromResult<LeaseOutcome?>(null);
            var frames = LeaseReceiptRecoveryTests.SignedFrames(lease);
            return Task.FromResult<LeaseOutcome?>(WslLeasedExecutor.ReadRecoveredReceipt(lease, frames.Admission,
                frames.Exit, JsonSerializer.Serialize(lease.ExecutionContext, BoundLeaseReceipt.Json)));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LostReceiptRecoverySurvivesRestartAndArchivalWithoutRepeatingTheEffect(bool archive)
    {
        await _bridge.DisposeAsync();
        _config = _config with { MaxTasks = archive ? 1 : 64, MaxConcurrentTasks = archive ? 1 : 4 };
        _bridge = CreateBridge();
        _executor.Disconnect = true;
        var request = Message();
        var task = (await Call("SendMessage", request)).GetProperty("task");
        string id = task.GetProperty("id").GetString()!;
        if (archive) await Call("SendMessage", Message());
        int effects = _executor.Leases.Count;
        await _bridge.DisposeAsync();
        var lookup = new Lookup { Missing = true };
        _bridge = CreateBridge(lookup);
        await Assert.ThrowsAsync<A2aException>(() => Call("GetTask", new { id }, BobToken));
        Assert.Equal(0, lookup.Calls);
        var missing = await Call("GetTask", new { id });
        Assert.False(missing.GetProperty("metadata").GetProperty(A2aConfiguration.Extension).GetProperty("receiptRecovered").GetBoolean());
        lookup.Missing = false;
        var recovered = await Call("GetTask", new { id });
        Assert.Equal("TASK_STATE_FAILED", recovered.GetProperty("status").GetProperty("state").GetString());
        var metadata = recovered.GetProperty("metadata").GetProperty(A2aConfiguration.Extension);
        Assert.True(metadata.GetProperty("receiptRecovered").GetBoolean());
        Assert.True(metadata.GetProperty("workloadTerminationConfirmed").GetBoolean());
        Assert.Contains("tool output was lost", recovered.GetRawText());
        await _bridge.DisposeAsync();
        _bridge = CreateBridge(lookup);
        var retried = (await Call("SendMessage", request)).GetProperty("task");
        Assert.Equal(id, retried.GetProperty("id").GetString());
        Assert.Equal(2, lookup.Calls);
        Assert.Equal(effects, _executor.Leases.Count);
        Assert.Single(await _ledger.GetAuditLogsAsync(null, 100), row => row.Action == "A2A_RECEIPT_RECOVERED");
    }

    private sealed class BlockingCompiler : ITemplatePolicyCompiler
    {
        internal volatile bool Block;
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public LeaseSpec CompileTemplatePolicy(SingleToolTemplate template, Guid missionId, string workDir, uint seconds)
        {
            if (Block) { Entered.TrySetResult(); Release.Task.Wait(TimeSpan.FromSeconds(15)); }
            return new TemplatePolicyCompiler().CompileTemplatePolicy(template, missionId, workDir, seconds);
        }
    }

    [Fact]
    public async Task SlowAdmissionDoesNotBlockAnotherTasksPollingListingOrCancellation()
    {
        await _bridge.DisposeAsync();
        var compiler = new BlockingCompiler();
        _bridge = CreateBridge(compiler: compiler);
        _executor.Block = true;
        var first = (await Call("SendMessage", Message(immediate: true))).GetProperty("task");
        string id = first.GetProperty("id").GetString()!;
        await _executor.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        compiler.Block = true;
        var admission = Task.Run(() => Call("SendMessage", Message(immediate: true), BobToken));
        try
        {
            await compiler.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await Call("GetTask", new { id }).WaitAsync(TimeSpan.FromSeconds(2));
            await Call("ListTasks", new { }).WaitAsync(TimeSpan.FromSeconds(2));
            var canceled = await Call("CancelTask", new { id }).WaitAsync(TimeSpan.FromSeconds(2));
            Assert.Equal("TASK_STATE_CANCELED", canceled.GetProperty("status").GetProperty("state").GetString());
            Assert.False(admission.IsCompleted);
        }
        finally { compiler.Release.TrySetResult(); await admission; }
    }
}
