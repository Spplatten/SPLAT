namespace MissionController.Core.Enums;

// There was a twelve-value MissionStatus here that no engine, view model or test ever read. The
// mission's states are the MissionChunkType.StatusChange chunks the engine emits, in the one order
// MissionExecutionEngine runs them; an enum beside that, consulted by nothing, only suggested a
// second state machine that could drift from the first.

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

public enum TemplateKind
{
    DiagnosticAgent,
    TaskAgent,
    ProjectAgent
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
    SentinelOne,
    GenericLocal
}

public enum EndpointIsolationState
{
    NotIsolated,
    Isolated,
    IsolationPending,
    Unknown
}

/// <summary>
/// Names WHICH process opens an <c>EgressRule</c>'s destination. The rule always recorded a
/// destination; it never recorded who reaches it, and the two legs of a mission have completely
/// different containment stories.
///
/// The distinction is load-bearing rather than descriptive. Every template carries an EgressRule,
/// and the default one names the AI gateway - a host-side call the provider client already pins.
/// Reading that default as a SENSOR destination is what made the Linux policy compiler open the
/// network for all ~40 templates when almost none of their tools touch it, and it is the fact the
/// Windows sandbox needs in order to decide whether a tool may have a network stack at all.
/// </summary>
public enum EgressScope
{
    /// <summary>
    /// The destination is reached by the HOST's provider client for the AI synthesis leg, inside
    /// SPLAT's own process. The sensor tool needs no network whatsoever, so it can be launched with
    /// no network capability and the denial is enforced by the kernel rather than declared in prose.
    /// </summary>
    ModelGateway = 0,

    /// <summary>
    /// The sensor tool itself opens this destination. Enforcing the specific FQDN needs a filtering
    /// layer (a broker or WFP); an AppContainer can only choose network / no-network, so a tool in
    /// this scope is granted a network stack and its destination remains a governance claim on
    /// Windows until that layer lands.
    /// </summary>
    ToolProcess = 1
}

