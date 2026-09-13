# Week 9 — composition, interface design and presentation

## Lesson A: dependencies decide where a repair belongs

**Outcome:** choose the narrowest owner of a system guarantee.

The Core interfaces describe needed behavior. Infrastructure implements operating-system, storage and network effects. [MCP Main](../../src/splat-mcp/Program.cs) constructs these objects explicitly; [App.xaml.cs](../../src/MissionController.UI/App.xaml.cs) registers UI dependencies. These composition points decide lifetime and which implementation actually runs.

A wrapper is appropriate for observation and a bounded translation. Validation shared by all callers belongs in the authoritative boundary, not only in one view. A DNS fix belongs where policy is compiled; a lease-kill guarantee belongs where the process tree is owned. Trace every consumer before widening a shared interface.

At this baseline the current project plan makes the MCP path the shipping focus and retains WinUI as a separate .NET 9 consumer. Study the UI because it teaches composition and interaction, but do not turn the course into an unsolicited UI migration. See the [current plan](../audits/2026-09-09-oem-subtraction-plan.md).

## Lesson B: CPU work becomes pixels

**Outcome:** explain the boundary between state, view and GPU.

The [monitor view model](../../src/MissionController.UI/LiveMissionMonitorViewModel.cs) starts a mission, consumes chunks, changes observable properties and requests cancellation. Follow model-unavailable labeling and metric conversion: missing measurements should remain distinguishable from observed zero.

[SwapChainRenderLoop](../../src/MissionController.UI/Graphics/SwapChainRenderLoop.cs) schedules frames and supplies a renderer interface. The actual native backend owns GPU resources, command submission, presentation and device-loss handling. Read the call sites before claiming that a renderer contract proves a live rendering backend.

HLSL expresses shader computations used by graphics hardware, often across many pixels. That execution model differs from a C# task or a mission scheduler. Inspect the [shader](../../src/MissionController.UI/Graphics/Shaders/MissionControllerComposite.hlsl) and its compilation targets. A compiled shader proves an asset exists; a visible correct frame requires runtime inspection. [Microsoft's HLSL reference](https://learn.microsoft.com/en-us/windows/win32/direct3dhlsl/dx-graphics-hlsl).

## Lab: build a small teaching host

~~~powershell
rg -n 'AddSingleton|AddTransient|new WslLeasedExecutor|new SqliteChainedAuditLedger' src
rg -n 'IsRunning|ResolveAsync|RunStreamAsync|CancelMission' src/MissionController.UI/LiveMissionMonitorViewModel.cs
~~~

1. Draw a dependency graph for MCP and a separate graph for the UI.
2. Add a teaching composition function that supplies a fake ILeasedExecutor wrapped in MeasuredLeasedExecutor.
3. Trace the function's ownership of ActivitySource and ActivityListener through shutdown.
4. Show unavailable metrics as unavailable in a console projection; do not initialize them to measured zero.
5. Choose one [repair ticket](repair-tickets.md). Write a one-page decision: trigger, current behavior, proposed behavior, owner, alternate approach, tests and migration impact.
6. As an extension, investigate two concurrent StartMissionAsync calls that both enter before identity resolution finishes. Treat a race as a hypothesis until a deterministic fixture reproduces it.

Expected: one composition substitution with no security policy duplicated into a display component.

**Cybersecurity case:** UI-only validation is bypassable by another caller. Authority should be checked at the service boundary that owns the effect.

**Repair practice:** R5 makes workspace choice explicit at the MCP composition root. Parsing options after constructing the database and registries would already be too late for a side-effect-free help/error path.

**Submit:** two dependency diagrams and the capstone repair decision.

**Check yourself:** Can shader compilation prove pixels rendered? Should every constructor call start resources immediately?

**Answer checkpoint:** compilation and runtime rendering are separate gates; composition should make startup effects and lifetimes deliberate.
