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

1. **Jail.** `ProvisionJailAsync` creates `%LOCALAPPDATA%\MissionController\Jails\{missionId}`
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

- **The job object** bounds CPU, memory and process count, and guarantees the whole tree dies with
  the job. It has no concept of a socket or a file.
- **The restricted token** keeps only `SeChangeNotifyPrivilege` (`DISABLE_MAX_PRIVILEGE`), marks
  Administrators (`S-1-5-32-544`) `USE_FOR_DENY_ONLY`, and lowers integrity to Medium. It still
  carries the operator's own user SID, so the tool reads and writes whatever the operator can,
  short of what needed admin membership or High integrity.
  [`EgressAndPrivilegeHardeningTests`](../tests/MissionController.Tests/EgressAndPrivilegeHardeningTests.cs)
  asserts the result against `whoami` running inside the sandbox.
- **The jail** keeps other principals out of the tool's scratch space. It is not a read boundary
  for the tool: outside the AppContainer, the tool reaches whatever its de-privileged token
  reaches.
- **The AppContainer** removes the network stack — DNS and a raw-IP connect both fail inside it,
  proven differentially in
  [`SensorNetworkContainmentTests`](../tests/MissionController.Tests/SensorNetworkContainmentTests.cs).
  It is also an RPC wall: WMI/CIM, the Event Log service, Defender and the SCM are unreachable from
  inside it. Standard AppContainer semantics also limit file access to objects whose ACLs admit the
  container — which is why the jail grants it an ACE — but that read confinement is not separately
  measured in this repository. The profile, `SPLAT.Sensor.Contained`, is created once per machine
  without privilege; renaming it strands the ACE every jail grants.

## Who gets the AppContainer

One expression in `MissionExecutionEngine` decides it:

~~~csharp
denyNetworkAccess: !template.EgressRule.ToolProcessNeedsNetwork && !template.ToolNeedsLocalSubsystems
~~~

| Template | Contained | Why |
| --- | --- | --- |
| Egress scope `ModelGateway`, no local-subsystem cmdlets | **Yes** | The sensor needs no network; SPLAT's own process makes the model call |
| `ModelGateway`, but the command line uses `Get-CimInstance`, `Get-WinEvent`, `Get-MpComputerStatus`, `Get-Service` or a relative | No | The container would break the sensor. `Containment_AlsoBlocksWmi_WhichIsWhyWmiTemplatesAreExempt` fails if Windows ever lets an AppContainer through, so the exemption cannot outlive its reason |
| Egress scope `ToolProcess` | No | An AppContainer is network-or-none, so it cannot admit the one host this sensor needs. The declared FQDN stays an audited claim until a broker or WFP filter exists |

The subsystem check is a text scan of the tool's own command line
(`SingleToolTemplate.ToolNeedsLocalSubsystems` in [`Models.cs`](../src/MissionController.Core/Models.cs)).
A false positive costs one template its containment; a false negative would fail in front of an
operator as an unexplained sensor error. The scan is biased toward the survivable mistake, and
per-template verification is the durable fix.

## Remediation, secrets and identity

- [`SandboxedRemediationEngine`](../src/MissionController.Infrastructure.Windows/Remediation/SandboxedRemediationEngine.cs)
  runs a template's declared fix — and its rollback, where the action declares one — through the
  same jail, job object and launcher, with a ledger row for each. Wired in the console only.
- [`DpapiCredentialVault`](../src/MissionController.Infrastructure.Windows/DpapiCredentialVault.cs)
  keeps one file per secret under `%LOCALAPPDATA%\MissionController\Vault`, protected with DPAPI
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

- Pin **which** host a `ToolProcess`-scoped sensor reaches.
- Deny the network to templates exempted for WMI, the Event Log, Defender or the SCM.
- Confine a tool's reads outside the AppContainer.
- Resist the operator. Everything runs as the operator's own account, so an administrator on the
  machine can undo all of it — the same limit the
  [ledger](ARCHITECTURE-control-plane.md#evidence-and-memory) states for its own integrity.
