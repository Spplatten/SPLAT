using System.Diagnostics;
using System.Text;

namespace Splat.AlertSidecar;

internal static class WitnessWireChecks
{
    internal static async Task<int> RunAsync(string python, string peerPath)
    {
        int checks = 0;
        void Check(bool value, string name)
        {
            if (!value) throw new InvalidDataException(name);
            checks++; Console.WriteLine("PASS wire: " + name);
        }
        async Task Refuse(byte[] bytes, string name)
        {
            bool refused = false;
            using var stream = new MemoryStream(bytes);
            try { _ = await WitnessWire.ReadAsync(stream, CancellationToken.None); }
            catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException) { refused = true; }
            Check(refused, name);
        }
        try
        {
            using var output = new MemoryStream();
            await WitnessWire.WriteAsync(output, "check", CancellationToken.None);
            Check(output.ToArray().SequenceEqual("check\n"u8.ToArray()), "Windows host emits LF-only bytes without BOM");
            await Refuse("{}"u8.ToArray(), "EOF before delimiter is refused even for valid JSON");
            await Refuse("{}\r\n"u8.ToArray(), "CRLF response refused");
            await Refuse([], "empty EOF refused");
            await Refuse(Encoding.ASCII.GetBytes(new string('x', 16385) + "\n"), "oversized frame refused");
            bool embeddedRefused = false;
            try { await WitnessWire.WriteAsync(output, "check\nafter", CancellationToken.None); }
            catch (InvalidDataException) { embeddedRefused = true; }
            Check(embeddedRefused, "embedded command delimiter refused");
            bool canceled = false;
            try { using var input = new MemoryStream("{}\n"u8.ToArray()); _ = await WitnessWire.ReadAsync(input, new CancellationToken(true)); }
            catch (OperationCanceledException) { canceled = true; }
            Check(canceled, "reader cancellation respected");

            if (!File.Exists(peerPath)) throw new FileNotFoundException("Python wire peer missing.");
            var start = new ProcessStartInfo(python) { UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (string arg in new[] { "-I", Path.GetFullPath(peerPath), "--wire-peer" }) start.ArgumentList.Add(arg);
            using var process = Process.Start(start) ?? throw new IOException("Cannot start Python contract peer.");
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            Task stderr = WitnessWire.DrainAsync(process.StandardError.BaseStream, timeout.Token);
            try
            {
                await WitnessWire.WriteAsync(process.StandardInput.BaseStream, "{\"version\":1,\"probe\":\"wire-λ\"}", timeout.Token);
                using var before = StrictJson.Parse(await WitnessWire.ReadAsync(process.StandardOutput.BaseStream, timeout.Token));
                Check(before.RootElement.GetProperty("probe").GetString() == "wire-λ", "UTF-8 crosses a real C# to Python process pipe");
                foreach (string command in new[] { "check", "after" })
                {
                    await WitnessWire.WriteAsync(process.StandardInput.BaseStream, command, timeout.Token);
                    using var reply = StrictJson.Parse(await WitnessWire.ReadAsync(process.StandardOutput.BaseStream, timeout.Token));
                    Check(reply.RootElement.GetProperty("phase").GetString() == command,
                        "real Python witness parser accepts " + command);
                }
                process.StandardInput.Dispose();
                await process.WaitForExitAsync(timeout.Token); await stderr;
                Check(process.ExitCode == 0, "peer completed despite a 256 KiB stderr burst");
            }
            finally
            {
                if (!process.HasExited)
                {
                    try { process.Kill(); } catch (InvalidOperationException) when (process.HasExited) { }
                }
                await timeout.CancelAsync();
                try { await stderr; } catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
            }
            Console.WriteLine($"PASS {checks} witness wire checks; real process pipes, no WSL/cgroup/Falcon proof.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Witness wire checks failed: " + ex.GetType().Name);
            return 1;
        }
    }
}
