using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Models;

namespace MissionController.Core.Interfaces;

/// <summary>
/// Extends <see cref="ILeasedExecutor"/> with secret-step support. A secret lease attaches an
/// opaque grant to the EXECUTE_TOOL frame; the daemon delivers the vault credential on the
/// child's sealed stdin and discards stdout/stderr.
/// </summary>
public interface ISecretLeasedExecutor : ILeasedExecutor
{
    /// <summary>
    /// Execute a lease step that carries a secret. The grant was obtained from
    /// <see cref="ISecretIssuance"/> and is consumed atomically by the daemon.
    /// </summary>
    /// <param name="lease">The compiled lease policy.</param>
    /// <param name="command">Absolute path to the tool binary in the guest.</param>
    /// <param name="argv">Already-split arguments.</param>
    /// <param name="secretGrant">The 64-hex opaque grant from the broker.</param>
    /// <param name="violations">BPF-LSM violation events.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>
    /// The execution result. stdout/stderr will be empty (the daemon discards secret-step output),
    /// but the signed EXIT receipt, violation events and lease outcome are present.
    /// </returns>
    Task<ProcessExecutionResult> ExecuteSecretLeasedAsync(
        LeaseSpec lease,
        string command,
        IReadOnlyList<string> argv,
        string secretGrant,
        IProgress<LeaseViolationEvent>? violations = null,
        CancellationToken ct = default);
}
