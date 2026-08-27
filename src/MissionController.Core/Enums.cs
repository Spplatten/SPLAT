namespace MissionController.Core.Enums;

public enum MissionStatus
{
    Draft,
    Queued,
    ProvisioningJail,
    SpawningSuspended,
    BindingJobObject,
    Executing,
    StreamingAiAnalysis,
    DrainingJail,
    Completed,
    Failed,
    Terminated,
    Quarantined
}

public enum ProcessIntegrityLevel
{
    Untrusted,
    Low,
    Medium,
    High
}

public enum MissionChunkType
{
    Stdout,
    Stderr,
    AiToken,
    Metric,
    SystemWarning,
    StatusChange,
    // Raised when no live model is connected and the AI analysis that follows is a local
    // simulation. The UI renders this as an unmistakable banner so simulated text can never
    // masquerade as genuine model output.
    SimulatedNotice,
    Completed
}

public enum SiemProtocol
{
    SyslogUdp,
    SyslogTcpTls,
    Cef,
    MicrosoftSentinel
}

public enum ComplianceFramework
{
    Soc2Type2,
    Hipaa,
    CmmcLevel2,
    Iso27001
}

public enum EdrProviderType
{
    MicrosoftDefenderForEndpoint,
    CrowdStrikeFalcon,
    GenericLocal
}

public enum EndpointIsolationState
{
    NotIsolated,
    Isolated,
    IsolationPending,
    Unknown
}

