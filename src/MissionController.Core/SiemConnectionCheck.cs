namespace MissionController.Core.Models;

/// <summary>Evidence from a single probe, not a promise of durable delivery or indexing.</summary>
public enum SiemConnectionEvidence
{
    None,
    LocalDatagramSent,
    TcpConnected,
    TlsAuthenticated,
    IngestionApiAccepted
}

public sealed record SiemConnectionCheck(SiemConnectionEvidence Evidence, string Detail)
{
    public bool Succeeded => Evidence != SiemConnectionEvidence.None;
}
