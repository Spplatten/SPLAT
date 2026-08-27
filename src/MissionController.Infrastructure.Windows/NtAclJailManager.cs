using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Windows.Jails;

public sealed class NtAclJailManager : IJailManager
{
    private readonly string _baseJailsDirectory;

    public NtAclJailManager(string? baseJailsDirectory = null)
    {
        _baseJailsDirectory = baseJailsDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "MissionController",
            "Jails");
    }

    public async Task<string> ProvisionJailAsync(Guid missionId, CancellationToken cancellationToken = default)
    {
        string jailPath = Path.Combine(_baseJailsDirectory, missionId.ToString("D"));

        await Task.Run(() =>
        {
            if (Directory.Exists(jailPath))
            {
                Directory.Delete(jailPath, true);
            }

            Directory.CreateDirectory(jailPath);

            var dirInfo = new DirectoryInfo(jailPath);
            var dirSecurity = new DirectorySecurity();

            // CRITICAL HARDENING FIX 2: Strip parent ACL inheritance explicitly
            dirSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var currentUser = WindowsIdentity.GetCurrent().User;
            if (currentUser != null)
            {
                dirSecurity.AddAccessRule(new FileSystemAccessRule(
                    currentUser,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
            }

            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            dirSecurity.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            dirInfo.SetAccessControl(dirSecurity);
        }, cancellationToken);

        return jailPath;
    }

    public async Task DrainAndCleanupJailAsync(string jailPath, int maxRetries = 5, int retryDelayMs = 200)
    {
        if (!Directory.Exists(jailPath))
            return;

        int attempts = 0;
        int delay = retryDelayMs;

        while (attempts < maxRetries)
        {
            try
            {
                // Trigger garbage collection to release any unmanaged RCW handles before deleting
                GC.Collect();
                GC.WaitForPendingFinalizers();

                Directory.Delete(jailPath, true);
                return;
            }
            catch (IOException)
            {
                attempts++;
                if (attempts >= maxRetries)
                {
                    // If still locked, leave for startup orphan sweeper
                    break;
                }
                await Task.Delay(delay);
                delay *= 2; // Exponential backoff
            }
            catch (UnauthorizedAccessException)
            {
                attempts++;
                if (attempts >= maxRetries)
                    break;
                await Task.Delay(delay);
            }
        }
    }

    public async Task<int> SweepOrphanJailsAsync(CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(_baseJailsDirectory))
            return 0;

        int sweptCount = 0;
        await Task.Run(() =>
        {
            var directories = Directory.GetDirectories(_baseJailsDirectory);
            foreach (var dir in directories)
            {
                try
                {
                    // Check if directory is older than 1 hour or orphaned
                    var info = new DirectoryInfo(dir);
                    if (DateTime.UtcNow - info.CreationTimeUtc > TimeSpan.FromMinutes(30))
                    {
                        Directory.Delete(dir, true);
                        sweptCount++;
                    }
                }
                catch
                {
                    // Silently ignore active locked directories
                }
            }
        }, cancellationToken);

        return sweptCount;
    }
}
