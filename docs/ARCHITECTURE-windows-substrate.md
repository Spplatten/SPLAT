<!-- Companion to ARCHITECTURE.md. Covers MissionController.Infrastructure.Windows: what a Windows
     sensor tool process experiences, in the order it experiences it. Read out of the tree at
     f5ed4a3 on 2026-09-12, after the interop surface moved to source-generated P/Invoke.
     Where this disagrees with the code, the code wins and this is the bug. -->

# Windows substrate — what a sensor tool process experiences

Every tool SPLAT launches on Windows — a mission's sensor, a remediation, a Copilot tool call —
goes through the same launcher and the same four primitives. They are standard defense in depth,
close to the Chromium sandbox recipe, and the [README](../README.md) says plainly that this half is
not the moat. What is worth knowing precisely is **which of them apply to a given tool**, because
not all of them always do.

| Primitive | Class | Seam |
| --- | --- | --- |
| Per-mission directory with a protected ACL | [`NtAclJailManager`](../src/MissionController.Infrastructure.Windows/NtAclJailManager.cs) | `IJailManager` |
| CPU, memory and process-count clamps | [`Win32JobSandbox`](../src/MissionController.Infrastructure.Windows/Win32JobSandbox.cs) | `IJobSandbox` |
| Reduced authority | [`RestrictedTokenProvider`](../src/MissionController.Infrastructure.Windows/RestrictedTokenProvider.cs) | `IRestrictedTokenProvider` |
| No network stack | [`SensorAppContainer`](../src/MissionController.Infrastructure.Windows/SensorAppContainer.cs) | applied by the launcher |
| The suspended launch that ties them together | [`SuspendedProcessLauncher`](../src/MissionController.Infrastructure.Windows/SuspendedProcessLauncher.cs) | `IProcessLauncher` |

Every P/Invoke declaration lives in
[`Win32Interop.cs`](../src/MissionController.Infrastructure.Windows/Win32Interop.cs). All 25 are
`[LibraryImport]` — marshalling code generated at compile time, no runtime IL stubs — which imposes
two rules on anyone adding to that file:

- **Spell the entry point.** `[LibraryImport]` is always exact-spelling. `[DllImport]` with
  `CharSet.Unicode` probed for the `W`-suffixed export; the generator never does. `CreateJobObject`
  is declared with `EntryPoint = "CreateJobObjectW"` for exactly this reason — without it the
  declaration compiles with zero diagnostics and throws `EntryPointNotFoundException` the first time
  a sandbox is built. It is the one mistake in this file the compiler will not catch, so
  [`Win32InteropMigrationTests`](../tests/MissionController.Tests/Win32InteropMigrationTests.cs)
  constructs a real job object to catch it instead.
- **Keep the structs blittable.** A struct carrying a managed reference is rejected outright
  (`SYSLIB1051`), which is why `STARTUPINFO`'s three reserved `LPWSTR` fields are `nint` rather than
  `string` — nothing here assigns them. That rewrite had to leave the native layout untouched,
  because `STARTUPINFOEX`'s size *is* the `cb` that tells the kernel to read the extended form: get
  it wrong and step 3 below silently stops applying. Size and offsets are asserted, not assumed.

## The launch, in order

`MissionExecutionEngine` drives `SuspendedProcessLauncher.LaunchSuspendedInJobAsync`:

1. **Jail.** `ProvisionJailAsync` creates `<data root>\Jails\{missionId}`
   with a protected DACL — inheritance from the parent severed — granting full control to the
   operator and to SYSTEM, and `Modify` to SPLAT's AppContainer SID. It becomes the tool's working
   directory.
2. **Job object.** The constructor arms `KILL_ON_JOB_CLOSE`, `DIE_ON_UNHANDLED_EXCEPTION` and an
   active-process ceiling before any caller can touch it, so a job is never briefly escapable. The
   breakaway flags are absent on purpose: `SILENT_BREAKAWAY_OK` once let
   `powershell -c "Start-Process x"` walk out of the sandbox unclamped. `ConfigureExtendedLimits`
   then applies the template's memory and CPU clamps.
3. **Network isolation, if the template qualifies** — see [who gets it](#who-gets-the-appcontainer).
   The launcher builds a proc-thread attribute list carrying `SECURITY_CAPABILITIES` with the
   container SID and a capability count of zero, and sets `EXTENDED_STARTUPINFO_PRESENT`. If no
   container can be furnished the launch throws `SecurityException`; it never falls back to an
   unconfined process.
4. **Restricted token, if the tool requires one** (`SingleToolDefinition.RequiresRestrictedToken`,
   default true). A token that cannot be built also throws.
5. **Create suspended.** `CreateProcessAsUserW` with the restricted token, or `CreateProcessW`
   without one — each through its `…ExtendedW` form when the attribute list is present — with
   `CREATE_SUSPENDED | CREATE_NO_WINDOW` and the jail as working directory.
6. **Assign, then resume.** The process joins the job *before* `ResumeThread`, so every clamp is
   in force before its first instruction.
7. **Wait.** stdout and stderr drain from anonymous pipes. A timeout terminates everything in the
   job with exit code 99; a cancellation does the same with 130 and rethrows.
8. **Read back** the exit code, and the CPU and peak-memory figures from the job object itself.
9. **Drain.** The engine drains and deletes the jail on every exit path, retrying while handles
   close. `SweepOrphanJailsAsync` removes what a crash left behind.

A launch that throws becomes a `MISSION_FAILED` ledger row and a readable failure in the stream; it
never reaches the operator as a dead stream.

## What each primitive does not do

The [non-enforcement table](#what-this-substrate-does-not-do) is the consolidated boundary: each
gap names its consequence and the source or measurement that establishes its scope. Source review
and a live negative probe are different evidence, and the table identifies where a probe is absent.

## Who gets the AppContainer

One expression in `MissionExecutionEngine` decides it:

~~~csharp
denyNetworkAccess: !template.EgressRule.ToolProcessNeedsNetwork && !template.ToolNeedsLocalSubsystems
~~~

| Template | Contained | Why |
| --- | --- | --- |
| Egress scope `ModelGateway`, with `NetworkDenialMeasuredHarmless` declared | **Yes** | The sensor needs no network, and its catalog entry opts in after a comparison inside and outside containment |
| `ModelGateway`, without that measured opt-in | No | Denial could blind the sensor to local services. `Containment_AlsoBlocksWmi_WhichIsWhyWmiTemplatesAreExempt` measures one such failure; per-template comparisons decide the opt-in |
| Egress scope `ToolProcess` | No | An AppContainer is network-or-none, so it cannot admit the one host this sensor needs. The declared FQDN stays an audited claim until a broker or WFP filter exists |

`SingleToolTemplate.ToolNeedsLocalSubsystems` in [`Models.cs`](../src/MissionController.Core/Models.cs)
is the inverse of `NetworkDenialMeasuredHarmless`. The earlier command-text scan was retired;
[NetworkToolsUnderDenialTests](../tests/MissionController.Tests/NetworkToolsUnderDenialTests.cs)
checks the catalog's opt-ins by running both paths. Linux-leased templates use the guest's policy.

## The run record

- When a mission ends, [`MissionExecutionEngine`](../src/MissionController.Core/MissionExecutionEngine.cs)
  seals what it observed into one `MISSION_RUN_FACTS` ledger row: the template's hash, the bound
  command line (scrubbed like the tool's output), the workspace, the job object's limits **as queried
  back from the kernel**, the tool's token **as read from the process before it ran**, the exit code
  against the template's contract, the redaction count, the model, the quality gate's verdict, and the
  teardown order with what was still running at it.
- [`MissionRunRecordAssembler`](../src/MissionController.Infrastructure.Data/Compliance/MissionRunRecordAssembler.cs)
  builds the six-group record from that row and the mission's other rows, and from nothing else. A
  mission with no facts row is refused rather than described from what is left.
- [`ComplianceArchiveExporter`](../src/MissionController.Infrastructure.Data/Compliance/ComplianceArchiveExporter.cs)
  writes the bundle: the record, the entries, a Merkle proof for each, the two verification scripts,
  and `signature.json` when a signing key is configured. An unsigned bundle says so, and its scripts
  exit 2 rather than 0.

## Remediation, secrets and identity

- [`SandboxedRemediationEngine`](../src/MissionController.Infrastructure.Windows/Remediation/SandboxedRemediationEngine.cs)
  runs a template's declared fix — and its rollback, where the action declares one — through the
  same jail, job object and launcher, with a ledger row for each. Wired in the console only.
  Each step runs only if it declares a postcondition, a probe and the output it expects, and its
  verdict is that measurement, never the exit code; a step that declares none is refused unrun.
  The shipped catalog defines no fixes yet.
- [`DpapiCredentialVault`](../src/MissionController.Infrastructure.Windows/DpapiCredentialVault.cs)
  keeps one file per secret under `<data root>\Vault`, protected with DPAPI
  `CurrentUser` scope and fixed application entropy. That protects against other accounts and
  offline copies; any process running as the operator can decrypt it.
- [`WindowsOperatorIdentityProvider`](../src/MissionController.Infrastructure.Windows/WindowsOperatorIdentityProvider.cs)
  names the Windows logon session as the operator for ledger attribution.

The Copilot / Semantic Kernel adapter under
[`Copilot/`](../src/MissionController.Infrastructure.Windows/Copilot) drives these same primitives;
it is covered with the other entry points in
[ARCHITECTURE-agent-surface.md](ARCHITECTURE-agent-surface.md#the-copilot--semantic-kernel-adapter).

## Measured, and how

| What | Where |
| --- | --- |
| The overhead of the governed launch path against the same tool run bare | [`src/splat-bench`](../src/splat-bench), evidence in [`src/splat-bench/evidence`](../src/splat-bench/evidence). `DocumentationDriftTests` refuses a latency promise the recorded run does not support |
| Network denial, and the WMI wall that comes with it | `SensorNetworkContainmentTests` — needs a PowerShell host |
| Token reduction | `EgressAndPrivilegeHardeningTests` |
| Job clamps and the launcher | `HardeningSubsystemTests`, `ProcessLauncherTests` |
| Fixes and rollbacks | `RemediationEngineTests` |

## What this substrate does not do

This table is the Windows counterpart to the Linux [supported-policy contract](../native/splat-agent/SUPPORTED_POLICY.md#not-policed-and-not-claimed-to-be).
It describes the operator-account Windows sensor path, not the in-progress managed WSL bridge.
Source references establish implementation limits; named tests establish only the behavior their
assertions exercise. None of these rows claims an independent security assessment.

The catalog census is **58 templates: 8 Windows network-denied, 38 Windows network-capable,
12 Linux-leased**. The 38 comprise 0 that need network access and 38 that need local Windows
subsystems. These figures are checked against `CapabilityManifest.CensusOf` by
`DocumentationDriftTests.TheWindowsNonEnforcementTable_MatchesTheCatalogAndOpenUiGap`.

| Gap | Consequence | Evidence and limits of that evidence |
| --- | --- | --- |
| **Destination pinning on Windows** | A network-capable tool is not restricted to its declared FQDN or port by SPLAT. `IEgressFirewall` guards the control plane's model requests, not a child tool's sockets. | [MissionExecutionEngine](../src/MissionController.Core/MissionExecutionEngine.cs) passes a network-denial boolean to [SuspendedProcessLauncher](../src/MissionController.Infrastructure.Windows/SuspendedProcessLauncher.cs); neither installs a destination filter. [CapabilityManifestTests](../tests/MissionController.Tests/CapabilityManifestTests.cs) binds the census. Source-confirmed gap; no WFP/broker enforcement is claimed. |
| **Network denial for local-subsystem templates** | The AppContainer is omitted where it prevents the sensor reading Windows services. Those tools retain a network stack even when their task needs no external connection. | [SensorNetworkContainmentTests](../tests/MissionController.Tests/SensorNetworkContainmentTests.cs), `Containment_AlsoBlocksWmi_WhichIsWhyWmiTemplatesAreExempt`, measures the WMI wall; [NetworkToolsUnderDenialTests](../tests/MissionController.Tests/NetworkToolsUnderDenialTests.cs) compares declared-denied templates inside and outside the container. A passing network test establishes only the endpoints and controls it actually exercised. |
| **Filesystem confinement outside AppContainer** | The jail protects its scratch directory from other principals; it does not prevent the tool accessing other files allowed to its token. The restricted token retains the operator's user SID. | [NtAclJailManager](../src/MissionController.Infrastructure.Windows/NtAclJailManager.cs) grants the operator full control. [HardeningSubsystemTests](../tests/MissionController.Tests/HardeningSubsystemTests.cs) measures ACL inheritance removal, not read confinement. [RestrictedTokenProvider](../src/MissionController.Infrastructure.Windows/RestrictedTokenProvider.cs) reduces privileges, admin membership and integrity without creating a new user. |
| **AppContainer filesystem proof** | The container's filesystem access depends on Windows ACLs and its shared `SPLAT.Sensor.Contained` SID; SPLAT does not claim a separately measured per-mission filesystem boundary for this path. | [SensorAppContainer](../src/MissionController.Infrastructure.Windows/SensorAppContainer.cs) reuses one profile; [NtAclJailManager](../src/MissionController.Infrastructure.Windows/NtAclJailManager.cs) grants that SID access to jails. Network-denial measurements do not prove filesystem isolation; a dedicated filesystem/cross-mission negative probe is absent. |
| **Job-object UI limits** | SPLAT sets no clipboard or window-messaging restrictions for the operator's desktop. A job's resource limits do not establish those UI restrictions; other Windows access checks may still apply. | [Win32JobSandbox](../src/MissionController.Infrastructure.Windows/Win32JobSandbox.cs) sets extended and CPU limits, not `JobObjectBasicUIRestrictions`; [WindowStationAccess](../src/MissionController.Infrastructure.Windows/WindowStationAccess.cs) grants launch access to the current desktop. The [roadmap](ROADMAP.md#open-not-scheduled) leaves UI limits open. Source review only: no clipboard/window-message negative probe or UI-limit run-record readback is claimed. |
| **Job objects as file/socket policy** | CPU, memory, process-count and lifetime clamps do not select files, executable identities or network destinations. Those require separate controls. | [Win32JobSandbox](../src/MissionController.Infrastructure.Windows/Win32JobSandbox.cs) shows the information classes applied and queried. [EgressAndPrivilegeHardeningTests](../tests/MissionController.Tests/EgressAndPrivilegeHardeningTests.cs), `JobSandbox_NeverPermitsBreakaway_SoChildrenCannotLeaveContainment`, checks job membership flags, not file/socket mediation. |
| **Resistance to the operator** | A same-account process can access the operator's own files and user-scoped secrets; a local administrator is outside the containment boundary. Token reduction of a child does not isolate SPLAT from its host operator. | [DpapiCredentialVault](../src/MissionController.Infrastructure.Windows/DpapiCredentialVault.cs) uses `CurrentUser` protection; [EgressAndPrivilegeHardeningTests](../tests/MissionController.Tests/EgressAndPrivilegeHardeningTests.cs) checks the child's reduced token. The [threat model](THREAT-MODEL.md#who-may-drive-the-lease-daemon) separately records the owner-root WSL limit. These controls do not establish protection from a malicious operator. |

The documentation test keeps this table and its evidence links present, derives the census from
the current catalog, and requires the UI-limits row while that roadmap item remains open. Closing
a row requires the implementation and a measurement that earns the narrower gap.
