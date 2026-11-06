using System.Diagnostics;
using System.Text;

namespace Splat.AlertSidecar;

// The guest protocol is byte-defined, not Environment.NewLine-defined. In particular, a
// Windows StreamWriter.WriteLine used to send CRLF, which the Linux command parser rejected.
internal static class WitnessWire
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    internal static async Task WriteAsync(Stream output, string frame, CancellationToken ct)
    {
        if (frame.Contains('\n') || frame.Contains('\r')) throw new InvalidDataException("Embedded wire delimiter.");
        byte[] bytes = Utf8.GetBytes(frame + "\n");
        if (bytes.Length > 16385) throw new InvalidDataException("Witness request exceeded budget.");
        await output.WriteAsync(bytes, ct);
        await output.FlushAsync(ct);
    }
    internal static async Task<byte[]> ReadAsync(Stream input, CancellationToken ct)
    {
        using var frame = new MemoryStream(); byte[] one = new byte[1];
        while (await input.ReadAsync(one, ct) != 0)
        {
            if (one[0] == 10) return frame.ToArray();
            if (one[0] == 13) throw new InvalidDataException("CR is not a witness frame delimiter.");
            if (frame.Length == 16384) throw new InvalidDataException("Witness response exceeded budget.");
            frame.WriteByte(one[0]);
        }
        // A syntactically valid JSON object cut off before LF is still a truncated frame.
        throw new EndOfStreamException("Witness ended without a complete frame.");
    }
    internal static async Task DrainAsync(Stream input, CancellationToken ct)
    {
        // Drain stderr with constant memory so an error burst cannot deadlock the child's stdout.
        // Do not echo arbitrary child diagnostics into reports that may later be shared.
        byte[] bytes = new byte[4096];
        while (await input.ReadAsync(bytes, ct) != 0) { }
    }
}
