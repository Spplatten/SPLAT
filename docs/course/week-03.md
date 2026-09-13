# Week 3 — processes, scheduling and Windows authority

## Lesson A: creating a process is a sequence

**Outcome:** explain the first point where child instructions may execute.

A process owns an address space and resources; a thread is a schedulable execution stream. The scheduler can run a newly runnable thread before its parent's next line executes. Starting a child and attaching limits afterward therefore creates an execution window.

User-mode code requests privileged OS services through system-call boundaries. A Win32 API can perform library work before making those transitions, so a P/Invoke call is not necessarily one syscall. Windows access checks use the caller's security context; kernel-mode authority is separate from merely running an elevated user-mode process.

SPLAT's [launcher](../../src/MissionController.Infrastructure.Windows/SuspendedProcessLauncher.cs) creates the child suspended, assigns it to a configured job, then calls ResumeThread. Trace failure between every pair of operations. If assignment fails, resuming anyway defeats the sequence's purpose.

Job Objects group processes for resource limits, accounting and termination. They do not by themselves implement a filesystem allow-list or destination policy. [Microsoft's Job Object reference](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

## Lesson B: resource limits and authority are different

**Outcome:** distinguish CPU quota, tokens, ACLs and network capabilities.

The [job](../../src/MissionController.Infrastructure.Windows/Win32JobSandbox.cs) limits resources. The [restricted token](../../src/MissionController.Infrastructure.Windows/RestrictedTokenProvider.cs) reduces privilege. The [jail manager](../../src/MissionController.Infrastructure.Windows/NtAclJailManager.cs) sets workspace permissions. The [AppContainer](../../src/MissionController.Infrastructure.Windows/SensorAppContainer.cs) constrains capabilities.

These mechanisms answer different questions. A process using little RAM can still have excessive file authority. A working directory names where relative paths start; it does not remove absolute paths. An AppContainer may also deny RPC required by WMI or other sensor subsystems, which explains why compatibility exceptions require per-template scrutiny.

Inspect ExecuteMissionAsync's denyNetworkAccess expression. Its decision depends on whether the tool needs network access and whether the sensor remains functional in an AppContainer. Do not infer universal network denial from a template's model-gateway FQDN.

## Lab: trace admission before effects

~~~powershell
rg -n 'AssignProcess|ResumeThread|TerminateAllProcesses' src/MissionController.Infrastructure.Windows
rg -n 'GovernedArgumentBinder.Bind|ProvisionJailAsync|denyNetworkAccess' src/MissionController.Core/MissionExecutionEngine.cs
~~~

1. Draw CreatedSuspended → LimitsAssigned → Running → Exited → Drained.
2. Add arrows for assignment failure, resume failure, timeout and cancellation.
3. Use the fake-launcher pattern in [FailureIsNotEvidenceTests](../../tests/MissionController.Tests/FailureIsNotEvidenceTests.cs) to record launcher calls.
4. Add a fixture assertion that an invalid bound parameter produces zero launches and no provisioned jail.
5. For a nonzero sensor exit, assert failure and zero indexing into accepted semantic evidence.

The [selected regression gate](../../coursework/Run-Course.ps1) runs existing related cases. A live Win32 extension may use [ProcessLauncherTests](../../tests/MissionController.Tests/ProcessLauncherTests.cs) in a temporary workspace; report actual host prerequisites.

**Cybersecurity case:** authority must be established before effects. Inspect how pre-execution binding and identity validation enforce that ordering at different boundaries.

**Repair practice:** strengthen a failure-path assertion, not a screenshot of successful launch. A simulated ordering trace establishes orchestration behavior only; observing real child behavior is a separate gate.

**Submit:** state diagram, failure injection and evidence level.

**Check yourself:** Can a Job Object alone deny a TCP destination? Why suspend first?

**Answer checkpoint:** a job is not a destination firewall. Suspension prevents the scheduler from running child instructions before required limits attach.
