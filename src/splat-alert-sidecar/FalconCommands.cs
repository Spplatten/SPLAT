using System.Security.Cryptography;
using System.Text.Json;

namespace Splat.AlertSidecar;

internal static class FalconCommands
{
    internal static int? TryRun(string[] args)
    {
        if (args.Length == 0 || args[0] is not ("--inspect-falcon-profile" or "--check-falcon-event")) return null;
        try
        {
            if (args[0] == "--inspect-falcon-profile" && args.Length == 2)
            {
                byte[] bytes=ConfigurationFiles.Read(args[1]);
                using var doc=StrictJson.Parse(bytes);
                var profile=doc.RootElement.Deserialize<FalconProfile>(Binding.Json) ?? throw new JsonException();
                profile.Check();
                Console.WriteLine(JsonSerializer.Serialize(new { profileSha256=Convert.ToHexString(SHA256.HashData(bytes)),
                    profile.Version,profile.EventType,notice="Syntax checked; operator review of field semantics is still required." }));
                return 0;
            }
            if (args[0] == "--check-falcon-event" && args.Length == 4)
            {
                using var doc=StrictJson.Parse(ConfigurationFiles.Read(args[1]));
                var binding=doc.RootElement.Deserialize<Binding>(Binding.Json) ?? throw new JsonException();
                long now=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); binding.Check(now);
                var adapter=new FalconAdapter(binding,ConfigurationFiles.Read(args[2]));
                using var input=StrictJson.Parse(ConfigurationFiles.Read(args[3]));
                var alert=adapter.Normalize(input.RootElement,now);
                Console.WriteLine(JsonSerializer.Serialize(new { binding.TaskId,alert.Source,alert.Rule,alert.AlertId,
                    alert.ObservedUnixMs,dispatched=false }));
                return 0;
            }
            throw new ArgumentException("Expected profile path, or binding/profile/event paths.");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or InvalidOperationException or ArgumentException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Falcon offline check refused: "+ex.GetType().Name);
            return 2;
        }
    }
}
