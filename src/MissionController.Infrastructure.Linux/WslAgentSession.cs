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
/// Since 2026-09-23 the frames that come back prove themselves too (roadmap 2.6). The HELLO asks for it,
/// a daemon that agrees says so in its CHALLENGE - under a label of its own, so the agreement cannot be
/// stripped off in transit - and then wraps every frame it sends as PROVEN, proven over both nonces, the
/// frame's number on the connection and its exact bytes: the request proof's shape, in the other
/// direction. A frame that does not prove itself ends the session, because nothing after it can be
/// believed, including where the next frame begins. A daemon that predates the field answers unwrapped
/// and is believed as before; <see cref="FramesProven"/> says which kind this session got, so a host can
/// report it rather than assume it.
/// </summary>
public sealed class WslAgentSession : IDisposable
{
    /// <summary>The protocol this bridge speaks; the daemon refuses anything else.</summary>
    public const int ProtocolVersion = 3;

    /// <summary>Bytes in a nonce, and in a proof, which is SHA-256's output: 64 hex characters on the wire.</summary>
    public const int ProofBytes = 32;

    // Distinct labels, so no proof can be passed off as another kind.
    private static readonly byte[] DaemonLabel = Encoding.ASCII.GetBytes("splat-agent/3 daemon");
    private static readonly byte[] DaemonFramesLabel = Encoding.ASCII.GetBytes("splat-agent/3 daemon+frames");
    private static readonly byte[] RequestLabel = Encoding.ASCII.GetBytes("splat-agent/3 request");
    private static readonly byte[] FrameLabel = Encoding.ASCII.GetBytes("splat-agent/3 frame");

    /// <summary>
    /// The most of one frame this side will hold while waiting for its newline: the daemon's own cap on a
    /// request, so the two sides bound each other alike. A StreamReader had no ceiling, so whatever sat on
    /// the daemon's port could grow this host by the size of a line it never ended.
    /// </summary>
    public const int MaxFrameBytes = 1024 * 1024;

    private readonly FrameReader _reader;
    private readonly StreamWriter _writer;
    private readonly byte[] _key;
    private readonly byte[] _clientNonce;
    private readonly byte[] _serverNonce;
    private ulong _sequence;
    private ulong _framesRead;

    private WslAgentSession(FrameReader reader, StreamWriter writer, byte[] key, byte[] clientNonce, byte[] serverNonce, bool framesProven)
    {
        _reader = reader;
        _writer = writer;
        _key = key;
        _clientNonce = clientNonce;
        _serverNonce = serverNonce;
        FramesProven = framesProven;
    }

    /// <summary>
    /// Whether the daemon agreed to prove every frame it sends on this connection. False from a daemon
    /// older than 2026-09-23, whose frames are then believed on the strength of the handshake alone.
    /// </summary>
    public bool FramesProven { get; }

    /// <summary>
    /// Runs the handshake on <paramref name="stream"/>. Throws <see cref="WslAgentHandshakeException"/>,
    /// having sent nothing but a nonce, when whatever answered cannot prove it holds <paramref name="token"/>.
    /// </summary>
    public static async Task<WslAgentSession> OpenAsync(Stream stream, string token, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentException.ThrowIfNullOrEmpty(token);

        var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        var reader = new FrameReader(stream);
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
                // Ask for the daemon's frames to be proven. An older daemon ignores the field and
                // answers under the plain label, which is how the two ages agree.
                proveFrames = true,
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
            // Checked under the label for what the daemon SAID: a CHALLENGE that claims proven frames
            // must have been proven as one, and one that stays silent must have been proven as plain.
            // So a relay that added or removed the claim leaves a proof this check refuses.
            bool framesProven = challenge.TryGetProperty("framesProven", out var fp) && fp.ValueKind == JsonValueKind.True;
            if (serverNonce is null || proof is null
                || !CryptographicOperations.FixedTimeEquals(proof, DaemonProof(key, clientNonce, serverNonce, framesProven)))
            {
                throw new WslAgentHandshakeException(
                    "What answered on the daemon's port did not prove it holds this host's token, so nothing was sent "
                    + "to it. Either the token this host read is not the daemon's, or what is listening is not the "
                    + "SPLAT daemon.");
            }

            return new WslAgentSession(reader, writer, key, clientNonce, serverNonce, framesProven);
        }
        catch
        {
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

    /// <summary>
    /// The daemon's next frame, or null once it has closed the connection. On a session whose frames are
    /// proven, the frame is unwrapped from its PROVEN envelope only once its proof holds for its place;
    /// a frame that does not prove itself throws <see cref="WslAgentFrameException"/>, and nothing after
    /// it should be read.
    /// </summary>
    public async ValueTask<string?> ReadLineAsync(CancellationToken ct)
    {
        string? line = await _reader.ReadLineAsync(ct);
        return line is null || !FramesProven ? line : Unwrap(line);
    }

    /// <summary>
    /// The frame inside a PROVEN envelope, checked over its exact bytes and for its number on this
    /// connection before any of them is parsed - the same order the daemon uses for a request.
    /// </summary>
    private string Unwrap(string line)
    {
        string? frame = null;
        byte[]? proof = null;
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if ((root.TryGetProperty("type", out var type) ? type.GetString() : null) == "PROVEN"
                && root.TryGetProperty("frame", out var inner) && inner.ValueKind == JsonValueKind.String)
            {
                frame = inner.GetString();
                proof = FixedHex(root, "proof");
            }
        }
        catch (JsonException)
        {
            // Not an envelope at all: refused below, like one whose proof does not hold.
        }

        if (frame is null || proof is null
            || !CryptographicOperations.FixedTimeEquals(proof, FrameProof(_key, _clientNonce, _serverNonce, _framesRead, Encoding.UTF8.GetBytes(frame))))
        {
            throw new WslAgentFrameException(
                $"The daemon agreed to prove every frame on this connection, and frame {_framesRead} did not prove itself "
                + "for its place, so nothing from here on is believed. Either something sits between this host and the "
                + "daemon, or the daemon and this bridge disagree about the protocol.");
        }

        _framesRead++;
        return frame;
    }

    /// <summary>
    /// The daemon's answer to a HELLO: HMAC-SHA256 under the token, over the caller's nonce and its own -
    /// under a label of its own when the daemon will prove its frames, so that agreement is in the proof.
    /// </summary>
    public static byte[] DaemonProof(byte[] key, byte[] clientNonce, byte[] serverNonce, bool provesFrames = false) =>
        HMACSHA256.HashData(key, Concat(provesFrames ? DaemonFramesLabel : DaemonLabel, [0], clientNonce, serverNonce));

    /// <summary>
    /// A daemon frame's proof: HMAC-SHA256 under the token, over both nonces, the number of frames the daemon
    /// already sent on the connection, and the frame's own bytes.
    /// </summary>
    public static byte[] FrameProof(byte[] key, byte[] clientNonce, byte[] serverNonce, ulong sequence, byte[] frame)
    {
        byte[] place = new byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(place, sequence);
        return HMACSHA256.HashData(key, Concat(FrameLabel, [0], clientNonce, serverNonce, place, frame));
    }

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
        _writer.Dispose();
    }

    /// <summary>
    /// Newline-delimited frames off the socket, holding at most <see cref="MaxFrameBytes"/> of one while
    /// waiting for its end. Decoded as UTF-8, a trailing carriage return dropped, null once the peer has
    /// closed with nothing pending: the shape StreamReader.ReadLineAsync gave, minus its unbounded growth.
    /// </summary>
    private sealed class FrameReader
    {
        private readonly Stream _stream;
        private byte[] _buffer = new byte[4096];
        private int _length;

        public FrameReader(Stream stream) => _stream = stream;

        public async ValueTask<string?> ReadLineAsync(CancellationToken ct)
        {
            while (true)
            {
                int newline = Array.IndexOf(_buffer, (byte)'\n', 0, _length);
                if (newline >= 0)
                {
                    string line = Decode(newline);
                    int rest = _length - (newline + 1);
                    Buffer.BlockCopy(_buffer, newline + 1, _buffer, 0, rest);
                    _length = rest;
                    return line;
                }

                if (_length > MaxFrameBytes)
                {
                    throw new InvalidDataException(
                        $"The daemon's port sent more than {MaxFrameBytes} bytes without ending a frame, so the connection was abandoned.");
                }

                if (_length == _buffer.Length)
                {
                    Array.Resize(ref _buffer, Math.Min(_buffer.Length * 2, MaxFrameBytes + 4096));
                }

                int read = await _stream.ReadAsync(_buffer.AsMemory(_length), ct);
                if (read == 0)
                {
                    if (_length == 0)
                    {
                        return null;
                    }

                    string tail = Decode(_length);
                    _length = 0;
                    return tail;
                }

                _length += read;
            }
        }

        private string Decode(int end)
        {
            if (end > 0 && _buffer[end - 1] == (byte)'\r')
            {
                end--;
            }

            return Encoding.UTF8.GetString(_buffer, 0, end);
        }
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
/// A frame the daemon sent on a connection it agreed to prove did not prove itself for its place. The
/// session is over: what came before it stands, and nothing after it is read.
/// </summary>
public sealed class WslAgentFrameException : Exception
{
    public WslAgentFrameException(string message)
        : base(message)
    {
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
