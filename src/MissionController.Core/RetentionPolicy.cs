using System;

namespace MissionController.Core.Models;

/// <summary>
/// Layer 10 - Retention policy.
///
/// Windows are per-COLUMN rather than per-row because the sensitivity of what a mission produces is
/// wildly uneven. A mission's identity, template, timing and exit code are operationally useful and
/// carry nothing an attacker wants. Its RawOutput is a verbatim dump from `wevtutil`, `Get-LocalUser`
/// or `reg query` - SIDs, account names, password-policy state, LAPS configuration. Deleting whole
/// rows on one schedule would either discard useful operational history early or retain the
/// dangerous part for as long as the harmless part. So the payload columns are scrubbed on short
/// clocks and the metadata skeleton survives.
///
/// Defaults are deliberately aggressive on raw telemetry and conservative on the audit chain, which
/// is the pairing most regulated buyers actually need: prove WHAT happened for years, retain the
/// sensitive contents of what was read for days.
/// </summary>
public sealed record RetentionPolicy
{
    /// <summary>
    /// Verbatim sensor dumps. The highest-value target on the box and the fastest-decaying in
    /// usefulness - after triage closes, nobody re-reads a week-old event log dump.
    /// </summary>
    public TimeSpan RawOutputRetention { get; init; } = TimeSpan.FromDays(7);

    /// <summary>Operator-supplied parameters: hostnames, account names, whatever was typed in.</summary>
    public TimeSpan InputParameterRetention { get; init; } = TimeSpan.FromDays(7);

    /// <summary>
    /// Model prose. Lower risk than RawOutput but not zero - an analysis routinely quotes the
    /// telemetry it was given, so it outlives the raw dump only modestly.
    /// </summary>
    public TimeSpan AiAnalysisRetention { get; init; } = TimeSpan.FromDays(30);

    /// <summary>
    /// RAG corpus. Embeddings are partially invertible, so the vector is treated as sensitive as the
    /// text that produced it and the whole index row goes at once.
    /// </summary>
    public TimeSpan SemanticIndexRetention { get; init; } = TimeSpan.FromDays(30);

    /// <summary>
    /// When audit payloads are cryptographically erased. The ROW is never deleted - only its
    /// free-text Details, and only for entries whose chain commits to a digest rather than the
    /// plaintext. Longer than the telemetry windows because the audit trail is the compliance
    /// artifact, shorter than the row retention because the free text is the part that leaks.
    /// </summary>
    public TimeSpan AuditDetailRetention { get; init; } = TimeSpan.FromDays(90);

    /// <summary>
    /// Reclaim free pages after a sweep. VACUUM rewrites the database file, which is what actually
    /// removes purged bytes from disk; it is also the most expensive part of the sweep, so it is
    /// skippable for callers running the job on a tight interval.
    /// </summary>
    public bool VacuumAfterSweep { get; init; } = true;

    /// <summary>
    /// Delete vault secrets whose recorded expiry has passed. Off by default: a token whose refresh
    /// handler is mid-flight must not have its secret pulled out from under it, so callers opt in
    /// once they own the lifecycle.
    /// </summary>
    public bool PurgeExpiredVaultSecrets { get; init; } = false;

    /// <summary>Nothing is ever purged. For air-gapped forensic builds that must retain everything.</summary>
    public static RetentionPolicy Disabled { get; } = new()
    {
        RawOutputRetention = TimeSpan.MaxValue,
        InputParameterRetention = TimeSpan.MaxValue,
        AiAnalysisRetention = TimeSpan.MaxValue,
        SemanticIndexRetention = TimeSpan.MaxValue,
        AuditDetailRetention = TimeSpan.MaxValue,
        VacuumAfterSweep = false
    };

    /// <summary>
    /// Tightest defensible windows for regulated deployments that want telemetry gone almost
    /// immediately and keep only the audit skeleton.
    /// </summary>
    public static RetentionPolicy Strict { get; } = new()
    {
        RawOutputRetention = TimeSpan.FromDays(1),
        InputParameterRetention = TimeSpan.FromDays(1),
        AiAnalysisRetention = TimeSpan.FromDays(7),
        SemanticIndexRetention = TimeSpan.FromDays(7),
        AuditDetailRetention = TimeSpan.FromDays(30),
        PurgeExpiredVaultSecrets = true
    };
}

/// <summary>What a sweep actually erased. Returned so the run can be written to the audit trail.</summary>
public sealed record RetentionSweepResult(
    int RawOutputsScrubbed,
    int InputParametersScrubbed,
    int AiAnalysesScrubbed,
    int SemanticRowsDeleted,
    int AuditDetailsRedacted,
    int LegacyAuditEntriesSkipped,
    int VaultSecretsPurged,
    bool Vacuumed)
{
    public int TotalErased =>
        RawOutputsScrubbed + InputParametersScrubbed + AiAnalysesScrubbed +
        SemanticRowsDeleted + AuditDetailsRedacted + VaultSecretsPurged;

    public string Summary =>
        $"Retention sweep: {RawOutputsScrubbed} raw outputs, {InputParametersScrubbed} parameter sets, " +
        $"{AiAnalysesScrubbed} analyses scrubbed; {SemanticRowsDeleted} index rows and " +
        $"{VaultSecretsPurged} expired secrets deleted; {AuditDetailsRedacted} audit payloads redacted " +
        $"({LegacyAuditEntriesSkipped} legacy entries not redactable); vacuum={Vacuumed}.";
}
