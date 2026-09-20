using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using MissionController.Infrastructure.Linux;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Protocol 3's handshake on its own, against stand-ins on loopback: what each side proves, what a proof is
/// bound to, and that nothing but a nonce goes to anything that cannot prove it holds the token.
/// </summary>
public sealed class WslAgentSessionTests
{
    private const string Token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string Request = """{"type":"HEALTH_CHECK"}""";

    /// <summary>
    /// The same inputs and outputs are asserted in the daemon's auth.rs, so the bridge and the daemon cannot
    /// drift apart while each agrees with itself. Computed independently with Python's hmac module.
    /// </summary>
    [Fact]
    public void TheProofs_MatchTheVectorTheDaemonIsTestedAgainst()
    {
        byte[] key = Encoding.UTF8.GetBytes(Token);
        byte[] clientNonce = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] serverNonce = Convert.FromHexString("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        byte[] request = Encoding.UTF8.GetBytes(Request);

        Assert.Equal(
            "52265f2b72fe6c7801c6ffadbd9745a0a69bb165d31d71f31007e81f1c01ea7d",
            WslAgentSession.Hex(WslAgentSession.DaemonProof(key, clientNonce, serverNonce)));
        Assert.Equal(
            "835749efc2b9219f33027ab8571edebb135df57a55b6a0fbc79e1cc68c42c5aa",
            WslAgentSession.Hex(WslAgentSession.RequestProof(key, clientNonce, serverNonce, 0, request)));
        Assert.Equal(
            "2bb2251468dd196a6a88d2684c95beacdf2954864d0555e0143a124c30ca755d",
            WslAgentSession.Hex(WslAgentSession.RequestProof(key, clientNonce, serverNonce, 1, request)));
    }

    /// <summary>
    /// A CHALLENGE captured from the daemon on another connection is a valid proof - of that connection.
    /// Replayed here it proves nothing, because this connection's nonce is new, and nothing follows the HELLO.
    /// </summary>
    [Fact]
    public async Task AProofFromAnotherConnection_DoesNotOpenThisOne()
    {
        byte[] someoneElsesNonce = RandomNumberGenerator.GetBytes(WslAgentSession.ProofBytes);
        byte[] serverNonce = RandomNumberGenerator.GetBytes(WslAgentSession.ProofBytes);
        string captured = StandInAgent.Challenge(
            serverNonce, WslAgentSession.DaemonProof(Encoding.UTF8.GetBytes(Token), someoneElsesNonce, serverNonce));

        var (failure, sent) = await HandshakeAgainstAsync(_ => captured);

        Assert.IsType<WslAgentHandshakeException>(failure);
        Assert.Single(StandInAgent.Frames(sent));
    }

    /// <summary>An older daemon answers a HELLO as a request it does not know; the bridge reports that in its words.</summary>
    [Fact]
    public async Task AnOlderDaemonsRefusal_IsReportedInItsOwnWords()
    {
        var (failure, _) = await HandshakeAgainstAsync(_ =>
            """{"type":"STDERR","data":"SPLAT refused the request: missing or invalid authToken."}""");

        var refused = Assert.IsType<WslAgentHandshakeException>(failure);
        Assert.Contains("missing or invalid authToken", refused.Message);
        Assert.Contains("older than this bridge", refused.Message);
    }

    /// <summary>
    /// Whatever sits on the daemon's port can send a line it never ends. A StreamReader grew with it without
    /// limit; the bridge now abandons the connection at the daemon's own frame cap, having sent only the HELLO.
    /// </summary>
    [Fact]
    public async Task AFrameWithoutAnEnd_IsAbandonedAtTheCap_NotBufferedForever()
    {
        string endless = new string('x', WslAgentSession.MaxFrameBytes * 2);

        var (failure, sent) = await HandshakeAgainstAsync(_ => endless);

        Assert.IsType<InvalidDataException>(failure);
        Assert.Contains("without ending a frame", failure!.Message);
        Assert.Single(StandInAgent.Frames(sent));
    }

    /// <summary>Two identical requests on one connection carry different proofs, so neither stands in for the other.</summary>
    [Fact]
    public async Task EachRequestIsProvenForItsPlaceOnTheConnection()
    {
        byte[] key = Encoding.UTF8.GetBytes(Token);
        byte[] serverNonce = RandomNumberGenerator.GetBytes(WslAgentSession.ProofBytes);
        byte[] clientNonce = Array.Empty<byte>();

        var (failure, sent) = await HandshakeAgainstAsync(
            nonce =>
            {
                clientNonce = nonce;
                return StandInAgent.Challenge(serverNonce, WslAgentSession.DaemonProof(key, nonce, serverNonce));
            },
            async session =>
            {
                await session.SendAsync(Request, default);
                await session.SendAsync(Request, default);
            });

        Assert.Null(failure);
        string[] frames = StandInAgent.Frames(sent);
        Assert.Equal(3, frames.Length);
        Assert.Equal(ExpectedProof(key, clientNonce, serverNonce, 0), ProofIn(frames[1]));
        Assert.Equal(ExpectedProof(key, clientNonce, serverNonce, 1), ProofIn(frames[2]));
    }

    private static string ExpectedProof(byte[] key, byte[] clientNonce, byte[] serverNonce, ulong sequence) =>
        WslAgentSession.Hex(WslAgentSession.RequestProof(key, clientNonce, serverNonce, sequence, Encoding.UTF8.GetBytes(Request)));

    private static string? ProofIn(string frame)
    {
        using var doc = JsonDocument.Parse(frame);
        return doc.RootElement.GetProperty("proof").GetString();
    }

    /// <summary>
    /// Opens a session against a stand-in that answers the HELLO with <paramref name="answer"/>, runs
    /// <paramref name="then"/> on it if one opened, and returns the failure and every byte sent.
    /// </summary>
    private static async Task<(Exception? Failure, byte[] Sent)> HandshakeAgainstAsync(
        Func<byte[], string> answer, Func<WslAgentSession, Task>? then = null)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var standIn = Task.Run(async () =>
            {
                using var accepted = await listener.AcceptTcpClientAsync();
                using var stream = accepted.GetStream();
                return await StandInAgent.ImpersonateAsync(stream, answer);
            });

            Exception? failure = null;
            using (var client = new TcpClient())
            {
                await client.ConnectAsync(IPAddress.Loopback, port);
                try
                {
                    using var session = await WslAgentSession.OpenAsync(client.GetStream(), Token, default);
                    if (then is not null)
                    {
                        await then(session);
                    }
                }
                catch (Exception e)
                {
                    failure = e;
                }
            }

            return (failure, await standIn);
        }
        finally
        {
            listener.Stop();
        }
    }
}
