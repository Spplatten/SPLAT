using System;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;

namespace MissionController.Infrastructure.Windows.Security;

/// <summary>
/// Resolves the operator from the Windows logon session the process is running under.
///
/// For a local operator console this is the correct answer, and a stronger one than a self-issued
/// token would be: the OS already authenticated this principal against the SAM or a domain
/// controller, and the app has no separate authority it could add on top. Bolting a login screen
/// onto a desktop app that runs as the logged-in user would be a ceremony, not a control.
///
/// The SID is carried as the principal id because it is the stable identifier - an account can be
/// renamed, and an audit trail that only recorded the display name would silently lose the link.
/// </summary>
public sealed class WindowsOperatorIdentityProvider : IOperatorIdentityProvider
{
    private readonly string? _transport;
    private OperatorIdentity? _cached;

    public WindowsOperatorIdentityProvider(string? transport = null)
    {
        _transport = transport;
    }

    public ValueTask<OperatorIdentity> ResolveAsync(CancellationToken cancellationToken = default)
    {
        // The logon session cannot change for the lifetime of the process, so this is resolved once.
        // It is not merely an optimisation: WindowsIdentity.GetCurrent() allocates a token handle
        // per call, and this sits on the mission dispatch path.
        return ValueTask.FromResult(_cached ??= Resolve());
    }

    private OperatorIdentity Resolve()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();

            if (string.IsNullOrWhiteSpace(identity.Name))
            {
                return OperatorIdentity.Unknown(_transport);
            }

            return new OperatorIdentity(
                DisplayName: identity.Name,
                PrincipalId: identity.User?.Value,
                Method: OperatorAuthenticationMethod.WindowsAuthenticated,
                Transport: _transport);
        }
        catch (Exception)
        {
            // Failing to read the token must not take down a mission, but it must also never be
            // papered over with a plausible-looking name - the row is marked unauthenticated.
            return OperatorIdentity.Unknown(_transport);
        }
    }
}
