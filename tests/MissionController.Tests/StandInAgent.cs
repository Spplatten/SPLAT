using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Infrastructure.Linux;

namespace MissionController.Tests;

/// <summary>
/// The daemon's side of protocol 3, for tests that stand in for it: it answers the handshake under the token
/// it was given, checks the request's proof, and reports exactly what crossed the wire.
///
/// It proves things with the bridge's own functions, so on its own it could only show that the bridge agrees
/// with itself. What ties both to the Rust daemon is the fixed vector asserted in WslAgentSessionTests and in
/// auth.rs alike.
/// </summary>
internal static class StandInAgent
{
    /// <summary>Every byte the bridge sent on one connection, and its request if one arrived.</summary>
    internal sealed record Exchange(byte[] Raw, string? Request, bool Proven);

    private const string Refusal =
        """{"type":"STDERR","data":"SPLAT refused the request: the request's proof does not match this daemon's token.\n"}""";

    /// <summary>Plays the daemon on one connection: the handshake, one request, then <paramref name="replies"/>.</summary>
    public static async Task<Exchange> ServeAsync(Stream stream, string token, IReadOnlyList<string> replies, CancellationToken ct = default)
    {
        var raw = new MemoryStream();
        string? request = null;
        bool proven = false;
        try
        {
            byte[]? clientNonce = ClientNonce(await ReadLineAsync(stream, raw, ct));
            if (clientNonce is null)
            {
                return new Exchange(raw.ToArray(), null, false);
            }

            byte[] key = Encoding.UTF8.GetBytes(token);
            byte[] serverNonce = RandomNumberGenerator.GetBytes(WslAgentSession.ProofBytes);
            await WriteLineAsync(stream, Challenge(serverNonce, WslAgentSession.DaemonProof(key, clientNonce, serverNonce)), ct);

            string? frame = await ReadLineAsync(stream, raw, ct);
            if (frame is not null)
            {
                using var envelope = JsonDocument.Parse(frame);
                request = envelope.RootElement.TryGetProperty("request", out var r) ? r.GetString() : null;
                string? proof = envelope.RootElement.TryGetProperty("proof", out var p) ? p.GetString() : null;
                proven = request is not null && proof is { Length: WslAgentSession.ProofBytes * 2 }
                    && CryptographicOperations.FixedTimeEquals(
                        Convert.FromHexString(proof),
                        WslAgentSession.RequestProof(key, clientNonce, serverNonce, 0, Encoding.UTF8.GetBytes(request)));

                // A real daemon answers a request that does not prove itself with a refusal, and so does this.
                foreach (string reply in proven ? replies : new[] { Refusal })
                {
                    await WriteLineAsync(stream, reply, ct);
                }
            }
        }
        catch (IOException)
        {
            // The bridge hung up, which is how a bridge that refuses ends the conversation.
        }

        return new Exchange(raw.ToArray(), request, proven);
    }

    /// <summary>
    /// Plays something else on the daemon's port: reads the HELLO, answers with whatever <paramref name="answer"/>
    /// makes of its nonce, and records everything the bridge sends until it hangs up.
    /// </summary>
    public static async Task<byte[]> ImpersonateAsync(Stream stream, Func<byte[], string> answer, CancellationToken ct = default)
    {
        var raw = new MemoryStream();
        try
        {
            byte[]? clientNonce = ClientNonce(await ReadLineAsync(stream, raw, ct));
            if (clientNonce is not null)
            {
                await WriteLineAsync(stream, answer(clientNonce), ct);
                while (await ReadLineAsync(stream, raw, ct) is not null)
                {
                }
            }
        }
        catch (IOException)
        {
        }

        return raw.ToArray();
    }

    /// <summary>A CHALLENGE frame, with whatever proof the caller chooses to put in it.</summary>
    public static string Challenge(byte[] serverNonce, byte[] proof) => JsonSerializer.Serialize(new
    {
        type = "CHALLENGE",
        protocolVersion = WslAgentSession.ProtocolVersion,
        serverNonce = WslAgentSession.Hex(serverNonce),
        serverProof = WslAgentSession.Hex(proof),
    });

    /// <summary>The frames in what was sent, one per line.</summary>
    public static string[] Frames(byte[] raw) =>
        Encoding.UTF8.GetString(raw).Split('\n', StringSplitOptions.RemoveEmptyEntries);

    internal static byte[]? ClientNonce(string? hello)
    {
        if (hello is null)
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(hello);
            string? hex = doc.RootElement.TryGetProperty("clientNonce", out var n) ? n.GetString() : null;
            return hex is { Length: WslAgentSession.ProofBytes * 2 } ? Convert.FromHexString(hex) : null;
        }
        catch (Exception e) when (e is JsonException or FormatException or InvalidOperationException)
        {
            // Not a HELLO: what an older bridge would open with, or a HELLO behind a byte order mark.
            return null;
        }
    }

    internal static async Task<string?> ReadLineAsync(Stream stream, MemoryStream raw, CancellationToken ct)
    {
        var line = new MemoryStream();
        var one = new byte[1];
        while (await stream.ReadAsync(one, ct) == 1)
        {
            raw.WriteByte(one[0]);
            if (one[0] == (byte)'\n')
            {
                return Encoding.UTF8.GetString(line.ToArray());
            }

            line.WriteByte(one[0]);
        }

        return line.Length > 0 ? Encoding.UTF8.GetString(line.ToArray()) : null;
    }

    internal static async Task WriteLineAsync(Stream stream, string frame, CancellationToken ct)
    {
        await stream.WriteAsync(Encoding.UTF8.GetBytes(frame + "\n"), ct);
        await stream.FlushAsync(ct);
    }
}
