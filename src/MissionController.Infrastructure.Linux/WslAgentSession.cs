using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace MissionController.Infrastructure.Linux;

/// <summary>
/// One authenticated conversation with the daemon: protocol 3's handshake, then requests that each carry a
/// proof of the token instead of the token.
///
/// Protocol 2 put the token itself in every request, so a caller handed it to whatever answered on the
/// daemon's port - and while the daemon was not listening, any process in the guest could answer. On
/// 2026-09-13 a listener run as nobody on a free loopback port received what Windows sent it. Now the secret
/// never crosses the wire. The daemon proves it holds the token first, over a nonce this side chose, so a
/// listener that cannot is sent that nonce and nothing else. Then every request proves it too, over both
/// nonces, its place on the connection and its exact bytes, so a proof is good for one request on one
/// connection and a captured one is worth nothing.
///
/// What it does not do: authenticate the frames that come back after the handshake. On loopback nothing
/// sits between the two ends of a connection, and the handshake has already settled who is at the far one.
/// </summary>
public sealed class WslAgentSession : IDisposable
{
    /// <summary>The protocol this bridge speaks; the daemon refuses anything else.</summary>
    public const int ProtocolVersion = 3;

    /// <summary>Bytes in a nonce, and in a proof, which is SHA-256's output: 64 hex characters on the wire.</summary>
    public const int ProofBytes = 32;

    // Distinct labels, so neither proof can be passed off as the other.
    private static readonly byte[] DaemonLabel = Encoding.ASCII.GetBytes("splat-agent/3 daemon");
    private static readonly byte[] RequestLabel = Encoding.ASCII.GetBytes("splat-agent/3 request");

    private readonly StreamReader _reader;
    private readonly StreamWriter _writer;
    private readonly byte[] _key;
    private readonly byte[] _clientNonce;
    private readonly byte[] _serverNonce;
    private ulong _sequence;

    private WslAgentSession(StreamReader reader, StreamWriter writer, byte[] key, byte[] clientNonce, byte[] serverNonce)
    {
        _reader = reader;
        _writer = writer;
        _key = key;
        _clientNonce = clientNonce;
        _serverNonce = serverNonce;
    }

    /// <summary>
    /// Runs the handshake on <paramref name="stream"/>. Throws <see cref="WslAgentHandshakeException"/>,
    /// having sent nothing but a nonce, when whatever answered cannot prove it holds <paramref name="token"/>.
    /// </summary>
    public static async Task<WslAgentSession> OpenAsync(Stream stream, string token, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentException.ThrowIfNullOrEmpty(token);

        var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        var reader = new StreamReader(stream, encoding, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
        // UTF-8 WITHOUT a byte order mark. `Encoding.UTF8` emits one, so a StreamWriter built on it prepended
        // EF BB BF to the first write and the daemon answered every request with "Invalid JSON request:
        // expected value at line 1 column 1". A BOM is meaningless on a socket and fatal to a line-delimited
        // JSON protocol.
        var writer = new StreamWriter(stream, encoding, bufferSize: 4096, leaveOpen: true) { AutoFlush = true };

        try
        {
            byte[] key = Encoding.UTF8.GetBytes(token);
            byte[] clientNonce = RandomNumberGenerator.GetBytes(ProofBytes);
            string hello = JsonSerializer.Serialize(new
            {
                type = "HELLO",
                protocolVersion = ProtocolVersion,
                clientNonce = Hex(clientNonce),
            });
            await writer.WriteLineAsync(hello.AsMemory(), ct);

            string? answer = await reader.ReadLineAsync(ct);
            if (string.IsNullOrWhiteSpace(answer))
            {
                throw new WslAgentHandshakeException("The daemon's port closed the connection without answering the handshake.");
            }

            JsonElement challenge;
            try
            {
                using var doc = JsonDocument.Parse(answer);
                challenge = doc.RootElement.Clone();
            }
            catch (JsonException ex)
            {
                throw new WslAgentHandshakeException(
                    $"What answered on the daemon's port does not speak protocol {ProtocolVersion}: its first answer was not JSON.", ex);
            }

            if ((challenge.TryGetProperty("type", out var type) ? type.GetString() : null) != "CHALLENGE")
            {
                // A refusal, in its own words when it gave some. An older daemon answers a HELLO this way,
                // as a request it does not know.
                string said = challenge.TryGetProperty("data", out var data) ? data.GetString()?.Trim() ?? "" : "";
                throw new WslAgentHandshakeException(
                    $"What answered on the daemon's port did not answer the protocol {ProtocolVersion} handshake"
                    + (said.Length > 0 ? $", saying \"{said}\"" : ".")
                    + " A daemon older than this bridge answers that way.");
            }

            byte[]? serverNonce = FixedHex(challenge, "serverNonce");
            byte[]? proof = FixedHex(challenge, "serverProof");
            if (serverNonce is null || proof is null
                || !CryptographicOperations.FixedTimeEquals(proof, DaemonProof(key, clientNonce, serverNonce)))
            {
                throw new WslAgentHandshakeException(
                    "What answered on the daemon's port did not prove it holds this host's token, so nothing was sent "
                    + "to it. Either the token this host read is not the daemon's, or what is listening is not the "
                    + "SPLAT daemon.");
            }

            return new WslAgentSession(reader, writer, key, clientNonce, serverNonce);
        }
        catch
        {
            reader.Dispose();
            writer.Dispose();
            throw;
        }
    }

    /// <summary>Sends one request, proven for this connection and for its place on it.</summary>
    public async Task SendAsync(string requestJson, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(requestJson);

        byte[] proof = RequestProof(_key, _clientNonce, _serverNonce, _sequence++, Encoding.UTF8.GetBytes(requestJson));
        string frame = JsonSerializer.Serialize(new
        {
            type = "AUTHENTICATED",
            proof = Hex(proof),
            // As a string, so the daemon checks the proof over exactly these bytes before it parses any of
            // them. A proof over the parsed request would rest on two JSON serializers agreeing byte for byte.
            request = requestJson,
        });
        await _writer.WriteLineAsync(frame.AsMemory(), ct);
    }

    /// <summary>The daemon's next frame, or null once it has closed the connection.</summary>
    public ValueTask<string?> ReadLineAsync(CancellationToken ct) => _reader.ReadLineAsync(ct);

    /// <summary>The daemon's answer to a HELLO: HMAC-SHA256 under the token, over the caller's nonce and its own.</summary>
    public static byte[] DaemonProof(byte[] key, byte[] clientNonce, byte[] serverNonce) =>
        HMACSHA256.HashData(key, Concat(DaemonLabel, [0], clientNonce, serverNonce));

    /// <summary>
    /// A request's proof: HMAC-SHA256 under the token, over both nonces, the number of requests already sent on
    /// the connection, and the request's own bytes.
    /// </summary>
    public static byte[] RequestProof(byte[] key, byte[] clientNonce, byte[] serverNonce, ulong sequence, byte[] request)
    {
        byte[] place = new byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(place, sequence);
        return HMACSHA256.HashData(key, Concat(RequestLabel, [0], clientNonce, serverNonce, place, request));
    }

    /// <summary>Lowercase hex, the way nonces and proofs travel.</summary>
    public static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    public void Dispose()
    {
        _reader.Dispose();
        _writer.Dispose();
    }

    /// <summary>A 32-byte value from a hex string property, or null for anything else.</summary>
    private static byte[]? FixedHex(JsonElement frame, string property)
    {
        if (!frame.TryGetProperty(property, out var value) || value.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        string? hex = value.GetString();
        if (hex is not { Length: ProofBytes * 2 })
        {
            return null;
        }

        try
        {
            return Convert.FromHexString(hex);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int length = 0;
        foreach (byte[] part in parts)
        {
            length += part.Length;
        }

        byte[] all = new byte[length];
        int at = 0;
        foreach (byte[] part in parts)
        {
            part.CopyTo(all, at);
            at += part.Length;
        }

        return all;
    }
}

/// <summary>
/// The daemon's end of the handshake did not hold up, and nothing but this side's nonce was sent to it.
/// </summary>
public sealed class WslAgentHandshakeException : Exception
{
    public WslAgentHandshakeException(string message)
        : base(message)
    {
    }

    public WslAgentHandshakeException(string message, Exception inner)
        : base(message, inner)
    {
    }
}
