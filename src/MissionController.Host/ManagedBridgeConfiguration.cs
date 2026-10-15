using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Runtime.Versioning;

namespace MissionController.Host;

[SupportedOSPlatform("windows")]
public sealed record ManagedBridgeConfiguration(
    int Schema, string ServiceName, string ServiceSid, string PipeName, string Distribution,
    int Port, string StateDirectory, string WorkspaceDirectory, string[] OperatorSids, string Egress = "",
    string? AgentId = null, string? AgentVersion = null)
{
    public static ManagedBridgeConfiguration Load(string path, bool serving = false)
    {
        path = Path.GetFullPath(path);
        // Read permission is harmless; a writable config, executable parent, or junction is not.
        RequireAdministratorOwnedPath(path);
        var config = JsonSerializer.Deserialize<ManagedBridgeConfiguration>(File.ReadAllText(path))
            ?? throw new InvalidDataException("Empty managed configuration.");
        config.Validate(serving);
        if (serving && WindowsIdentity.GetCurrent().User?.Value != config.ServiceSid)
            throw new UnauthorizedAccessException("The bridge must run under its configured service identity.");
        if (serving)
        {
            RequireAdministratorOwnedPath(Environment.ProcessPath!);
            config.RequirePrivateState();
        }
        return config;
    }

    internal void Validate(bool serving = false)
    {
        if ((AgentId is not null || AgentVersion is not null)
            && (!Regex.IsMatch(AgentId ?? "", @"\A[a-z][a-z0-9]*(?:-[a-z0-9]+)*\z")
                || AgentId!.Length > 48 || !Regex.IsMatch(AgentVersion ?? "", @"\A[0-9a-f]{64}\z")))
            throw new InvalidDataException("Managed agent endpoints require an agent ID and approved contract version.");
        if (Schema != 1 || !Name(ServiceName) || !Name(PipeName) || !Name(Distribution) || Port is < 1024 or > 65535)
            throw new InvalidDataException("Invalid managed bridge configuration.");
        _ = new SecurityIdentifier(ServiceSid);
        if (OperatorSids is not { Length: > 0 and <= 32 }) throw new InvalidDataException("Explicit operator SIDs are required.");
        foreach (string sid in OperatorSids)
        {
            _ = new SecurityIdentifier(sid);
            if (sid == ServiceSid || !sid.StartsWith("S-1-5-21-", StringComparison.Ordinal))
                throw new InvalidDataException("Operators must be explicit account SIDs, distinct from the service.");
        }
        foreach (string directory in new[] { StateDirectory, WorkspaceDirectory })
            if (!Path.IsPathFullyQualified(directory) || (serving && !Directory.Exists(directory)))
                throw new InvalidDataException("Managed directories must already exist at absolute paths.");
        string state = Path.GetFullPath(StateDirectory).TrimEnd(Path.DirectorySeparatorChar);
        string workspace = Path.GetFullPath(WorkspaceDirectory).TrimEnd(Path.DirectorySeparatorChar);
        if (state.Equals(workspace, StringComparison.OrdinalIgnoreCase) || state.StartsWith(workspace + "\\", StringComparison.OrdinalIgnoreCase)
            || workspace.StartsWith(state + "\\", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Workspace and private service state must be separate directories.");
        _ = string.IsNullOrEmpty(Egress) ? McpEgressPolicy.None : McpEgressPolicy.Parse(Egress);
    }

    private static bool Name(string value) => Regex.IsMatch(value ?? "", @"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z");

    internal static void RequireAdministratorOwnedPath(string path)
    {
        for (FileSystemInfo? entry = new FileInfo(path); entry is not null; entry = entry switch
        {
            FileInfo file => file.Directory,
            DirectoryInfo directory => directory.Parent,
            _ => null
        })
        {
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("Managed paths cannot traverse reparse points.");
            var acl = entry is FileInfo f ? (FileSystemSecurity)f.GetAccessControl() : ((DirectoryInfo)entry).GetAccessControl();
            var trusted = new HashSet<string>(StringComparer.Ordinal) { "S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" };
            string owner = acl.GetOwner(typeof(SecurityIdentifier))!.Value;
            if (!trusted.Contains(owner)) throw new UnauthorizedAccessException($"Managed path is not administrator-owned: {entry.FullName}");
            const FileSystemRights fileWrites = FileSystemRights.WriteData | FileSystemRights.AppendData |
                FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes | FileSystemRights.Delete |
                FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
            // ProgramData permits creation of siblings. That does not replace an existing protected
            // child; DELETE_CHILD, ownership and ACL changes on an ancestor would permit replacement.
            var writes = entry is FileInfo ? fileWrites : FileSystemRights.Delete |
                FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
            foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                // Inherit-only ACEs do not grant access to this object (ProgramData has such entries).
                if (rule.AccessControlType == AccessControlType.Allow && (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0
                    && (rule.FileSystemRights & writes) != 0 && !trusted.Contains(rule.IdentityReference.Value))
                    throw new UnauthorizedAccessException($"Untrusted write access to managed path: {entry.FullName}");
            }
        }
    }

    private void RequirePrivateState()
    {
        var directory = new DirectoryInfo(StateDirectory);
        if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Private state cannot be a reparse point.");
        RequireAdministratorOwnedPath(Path.Combine(directory.Parent!.FullName, "bridge.json"));
        var trusted = new HashSet<string>(StringComparer.Ordinal) { ServiceSid, "S-1-5-18", "S-1-5-32-544" };
        var acl = directory.GetAccessControl();
        if (!trusted.Contains(acl.GetOwner(typeof(SecurityIdentifier))!.Value))
            throw new UnauthorizedAccessException("Private state has an untrusted owner.");
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && !trusted.Contains(rule.IdentityReference.Value))
                throw new UnauthorizedAccessException("Private state must be accessible only to the service and administrators.");
    }
}
