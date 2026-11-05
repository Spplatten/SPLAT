using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace Splat.AlertSidecar;

// Vendor schema selection is explicit. A renamed field or schema change must not silently switch
// identity semantics. JSON pointers address exact keys, including flattened keys containing dots.
internal sealed record FalconProfile(int Version, string EventType, string EventTypePointer,
    string TenantPointer, string AgentPointer, string ProcessInstancePointer, string RulePointer,
    string EventIdPointer, string EventTimePointer, string TimeEncoding)
{
    internal void Check()
    {
        string[] pointers = { EventTypePointer,TenantPointer,AgentPointer,ProcessInstancePointer,RulePointer,EventIdPointer,EventTimePointer };
        if (Version != 1 || !Binding.ValidIdentifier(EventType) || TimeEncoding is not ("unix-ms" or "unix-s" or "iso8601")
            || pointers.Distinct(StringComparer.Ordinal).Count() != pointers.Length)
            throw new InvalidDataException("Invalid Falcon profile version, fields or time encoding.");
        foreach (string pointer in pointers) JsonPointer.Check(pointer);
    }
}

internal sealed class FalconAdapter
{
    private readonly Binding _binding;
    private readonly FalconProfile _profile;
    internal string ProfileHash { get; }
    internal FalconAdapter(Binding binding, byte[] profileBytes)
    {
        if (binding.Source != "falcon" || binding.Falcon is null)
            throw new InvalidDataException("Falcon mode requires an admission identity.");
        using var document = StrictJson.Parse(profileBytes);
        _profile = document.RootElement.Deserialize<FalconProfile>(Binding.Json) ?? throw new JsonException("Missing profile");
        _profile.Check();
        ProfileHash = Convert.ToHexString(SHA256.HashData(profileBytes));
        if (!string.Equals(ProfileHash,binding.Falcon.ProfileSha256,StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Falcon profile differs from the admission-approved hash.");
        _binding = binding;
    }
    internal Alert Normalize(JsonElement root, long now)
    {
        // All identities must match before copying the host-owned native identity into an Alert.
        // No fallbacks to ComputerName/Hostname, parent PID, nearest timestamp or a new /proc lookup.
        var identity = _binding.Falcon!;
        if (Text(root,_profile.EventTypePointer) != _profile.EventType
            || Text(root,_profile.TenantPointer) != identity.TenantId
            || Text(root,_profile.AgentPointer) != identity.AgentId
            || Text(root,_profile.ProcessInstancePointer) != identity.ProcessInstanceId
            || Text(root,_profile.RulePointer) != _binding.Rule)
            throw new InvalidDataException("Falcon event does not match the approved task identity and rule.");
        long observed = Timestamp(JsonPointer.Read(root,_profile.EventTimePointer),_profile.TimeEncoding);
        if (observed < identity.NotBeforeUnixMs) throw new InvalidDataException("Event predates admission.");
        var alert = new Alert(1,"falcon",Text(root,_profile.EventIdPointer),_binding.Rule,_binding.Node,
            _binding.Boot,_binding.Cgroup,_binding.Pid,_binding.StartTicks,observed);
        if (!_binding.Matches(alert,now)) throw new InvalidDataException("Stale, future, expired or invalid Falcon event.");
        return alert;
    }
    private static string Text(JsonElement root,string pointer)
    {
        var field = JsonPointer.Read(root,pointer);
        if (field.ValueKind == JsonValueKind.String) return field.GetString()!;
        // Preserve every digit of vendor IDs beyond IEEE-754's exact integer range. Floating-point
        // and exponent notation are rejected rather than rounded into another process identity.
        if (field.ValueKind == JsonValueKind.Number)
        {
            string value = field.GetRawText();
            if (value.Length is > 0 and <= 128 && value.All(char.IsAsciiDigit)) return value;
        }
        throw new JsonException("Expected exact string or unsigned integer field.");
    }
    internal static long Timestamp(JsonElement field,string encoding)
    {
        if (encoding == "iso8601")
        {
            if (field.ValueKind != JsonValueKind.String) throw new JsonException("ISO timestamp must be a string.");
            string value = field.GetString()!;
            bool zone = value.EndsWith('Z') || value.Length >= 6 && value[^3] == ':' && value[^6] is '+' or '-';
            if (!zone || !field.TryGetDateTimeOffset(out var timestamp)) throw new JsonException("ISO timestamp needs an explicit offset.");
            return timestamp.ToUnixTimeMilliseconds();
        }
        string raw = field.ValueKind == JsonValueKind.String ? field.GetString()! : field.GetRawText();
        if (field.ValueKind is not (JsonValueKind.String or JsonValueKind.Number)
            || !long.TryParse(raw,NumberStyles.None,CultureInfo.InvariantCulture,out long number))
            throw new JsonException("Expected an unsigned integer timestamp.");
        try { return encoding == "unix-s" ? checked(number * 1000) : number; }
        catch (OverflowException ex) { throw new JsonException("Timestamp overflow.", ex); }
    }
}

internal static class JsonPointer
{
    internal static void Check(string pointer)
    {
        if (pointer is not { Length: > 1 and <= 512 } || pointer[0] != '/' || pointer.Count(c=>c=='/') > 8)
            throw new InvalidDataException("Expected a bounded JSON pointer.");
        for (int i=0;i<pointer.Length;i++)
        {
            if (char.IsControl(pointer[i])) throw new InvalidDataException("Control character in JSON pointer.");
            if (pointer[i]=='~' && (++i>=pointer.Length || pointer[i] is not ('0' or '1')))
                throw new InvalidDataException("Invalid JSON pointer escape.");
        }
    }
    internal static JsonElement Read(JsonElement root,string pointer)
    {
        var node = root;
        foreach (string encoded in pointer.Split('/').Skip(1))
        {
            string key = encoded.Replace("~1","/",StringComparison.Ordinal).Replace("~0","~",StringComparison.Ordinal);
            // Single event only: arrays and batches are rejected; no silent first-event selection.
            if (node.ValueKind != JsonValueKind.Object || !node.TryGetProperty(key,out var child))
                throw new JsonException("Missing field or non-object JSON pointer traversal.");
            node = child;
        }
        return node;
    }
}

internal static class StrictJson
{
    internal static JsonDocument Parse(ReadOnlyMemory<byte> bytes)
    {
        var document = JsonDocument.Parse(bytes,new JsonDocumentOptions { MaxDepth=8 });
        try
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw new JsonException("One object required.");
            Check(document.RootElement);
            return document;
        }
        catch { document.Dispose(); throw; }
    }
    private static void Check(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var keys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!keys.Add(property.Name)) throw new JsonException("Duplicate JSON key.");
                Check(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var child in element.EnumerateArray()) Check(child);
    }
}
