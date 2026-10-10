using System.Text;
using MissionController.Host;

namespace MissionController.Tests;

public sealed class ManagedBridgeClientTests
{
    [Fact]
    public async Task ACompleteResponse_DoesNotWaitForTheServiceToClose_AndPreservesSplitUtf8()
    {
        string response = "{\"result\":\"" + new string('界', 3000) + "\"}";
        using var pipe = new OpenPipe(Encoding.UTF8.GetBytes(response + "\n"));
        Assert.Equal(response, await ManagedBridgeClient.ReadResponseAsync(pipe, CancellationToken.None));
    }

    [Fact]
    public async Task ATruncatedResponse_IsNeverAcceptedAsACompleteFrame()
    {
        using var pipe = new MemoryStream(Encoding.UTF8.GetBytes("{\"result\":{}}"));
        await Assert.ThrowsAsync<EndOfStreamException>(() =>
            ManagedBridgeClient.ReadResponseAsync(pipe, CancellationToken.None));
    }

    [Fact]
    public async Task InvalidUtf8_IsRefusedInsteadOfSilentlyChangingTheResult()
    {
        using var pipe = new MemoryStream(new byte[] { 0xc3, 0x28, (byte)'\n' });
        await Assert.ThrowsAsync<DecoderFallbackException>(() =>
            ManagedBridgeClient.ReadResponseAsync(pipe, CancellationToken.None));
    }

    private sealed class OpenPipe(byte[] bytes) : MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            // A real service keeps the connection open after its newline. Detect an extra read
            // deterministically instead of letting a regression hang until a wall-clock timeout.
            if (Position == Length) throw new InvalidOperationException("Read beyond the complete response.");
            return base.ReadAsync(buffer[..Math.Min(buffer.Length, 5)], ct);
        }
    }
}
