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

