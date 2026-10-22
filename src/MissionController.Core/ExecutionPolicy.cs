using System.Text.Json.Serialization;

namespace MissionController.Core.Models;

// These are additional restrictions, never authority to expose a path outside the existing jail.
// A tree grant is explicit runtime support (for example shared libraries); file is the default.
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record FileAccessGrant(
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("access")] IReadOnlyList<string> Access,
    [property: JsonPropertyName("scope")] string Scope = "file");

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ExecutionPolicy(
    [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
    [property: JsonPropertyName("architecture")] string Architecture,
    [property: JsonPropertyName("syscalls")] IReadOnlyList<string> Syscalls,
    [property: JsonPropertyName("fileGrants")] IReadOnlyList<FileAccessGrant> FileGrants)
{
    public void Validate()
    {
        if (SchemaVersion != 1 || Architecture != "x86_64")
            throw new InvalidOperationException("Execution policy requires schemaVersion 1 and architecture x86_64.");
        if (Syscalls is null || Syscalls.Count is < 1 or > 128
            || Syscalls.Any(s => string.IsNullOrEmpty(s) || s.Length > 48
                || s.Any(c => !(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_')))
            || Syscalls.Distinct(StringComparer.Ordinal).Count() != Syscalls.Count)
            throw new InvalidOperationException("Declare 1 to 128 unique syscall names; the guest refuses names outside its supported set.");
        if (new[] { "execve", "exit_group", "write", "close" }.Any(s => !Syscalls.Contains(s)))
            throw new InvalidOperationException("Execution policy must explicitly allow the launch syscalls execve, exit_group, write and close.");
        if (FileGrants is null || FileGrants.Count > 64)
            throw new InvalidOperationException("Declare at most 64 file grants, including the executable and its runtime dependencies.");
        var paths = new HashSet<string>(StringComparer.Ordinal);
        foreach (var grant in FileGrants)
        {
            if (grant is null || string.IsNullOrEmpty(grant.Path) || grant.Path.Length > 4096
                || !grant.Path.StartsWith('/') || grant.Path == "/" || grant.Path.Contains('\0')
                || grant.Path[1..].Split('/').Any(p => p is "" or "." or "..") || !paths.Add(grant.Path))
                throw new InvalidOperationException("File grants require unique absolute Linux paths without empty, '.' or '..' components.");
            if (grant.Scope is not ("file" or "tree") || grant.Access is null || grant.Access.Count is < 1 or > 3
                || grant.Access.Any(a => a is not ("read" or "write" or "execute"))
                || grant.Access.Distinct(StringComparer.Ordinal).Count() != grant.Access.Count
                || (grant.Scope == "tree" && grant.Access.Contains("write")))
                throw new InvalidOperationException("File grants allow read, write and execute; explicit tree grants allow only read and execute. Writable files must already exist.");
        }
    }
}
