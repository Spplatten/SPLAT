using System;
using System.Threading;
using System.Threading.Tasks;

namespace MissionController.Core;

/// <summary>
/// Returns a fixed identity. Intended for tests and for hosts that resolve their principal once at
/// startup, not as a way to hand a hand-written name to the ledger - the constructor takes a fully
/// formed <see cref="OperatorIdentity"/>, so whatever provenance it carries has to be stated
/// explicitly rather than implied by a bare string.
/// </summary>
public sealed class StaticOperatorIdentityProvider : IOperatorIdentityProvider
{
    private readonly OperatorIdentity _identity;

    public StaticOperatorIdentityProvider(OperatorIdentity identity)
    {
        _identity = identity ?? throw new ArgumentNullException(nameof(identity));
    }

    public ValueTask<OperatorIdentity> ResolveAsync(CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(_identity);
}
