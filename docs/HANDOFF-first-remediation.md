# Handoff — the first template that changes something

**Written 2026-10-08.** For whoever declares the catalogue's first `RemediationAction`. Every fact
below was measured on 2026-10-08 by evaluating the code or running the probe named beside it, not
recalled from a document; where a number is quoted, the command that produced it is quoted with it.

The product's claim is that an agent's actions are contained and provable. Today no agent takes an
action: **0 of 58 templates declare a remediation**, counted by evaluating
`GovernedTemplateCatalog.All` through a compiled reference, never by grepping the partial classes.
The containment is real and nothing exercises it. This page closes that, once, for one template.

---

## 1. What is already built — do not redo it

The acting stack exists, is tested and is wired into the app.

- [`SandboxedRemediationEngine`](../src/MissionController.Infrastructure.Windows/Remediation/SandboxedRemediationEngine.cs)
  (292 lines) executes a fix and a rollback, each in a freshly provisioned jail inside a job object
  capped at 256 MB / 80% CPU, 45s for the action and 30s for the validation probe.
- It is registered at [`App.xaml.cs:197`](../src/MissionController.UI/App.xaml.cs) and injected into
  `QuickDiagnosticianViewModel`, so the UI can already run one.
- `RemediationEngineTests.cs` holds eight tests, including the two that matter most: a step
  declaring no postcondition is refused before anything runs, and a process that exits 0 while the
  measured state disagrees is reported `PostconditionFailed`.

The engine's contract, which the declaration has to satisfy:

| | |
|---|---|
| No postcondition declared | refused before launch; ledger row `REMEDIATION_FIX_REFUSED` / `REMEDIATION_ROLLBACK_REFUSED` |
| Before launch | `REMEDIATION_FIX_INITIATED` carries the executable, the arguments and the postcondition text |
| Verdict source | exit 0 **and** `valResult.StandardOutput.Contains(ValidationExpectedOutput)` |
| Both true | `VerifiedFix`, or `Restored` for a rollback |
| Exit 0, measurement false | `PostconditionFailed` — fail-closed, by design |
| Non-zero exit or timeout | `ExecutionFailed`; the 45s timeout says the change may be half-applied |

Note the match is a plain substring over stdout. The validation command must therefore print a token
that appears when the postcondition holds and never when it does not.

---

## 2. The blocker nobody has hit, because nobody has tried

`AvailableRemediations` is not empty because authors forgot it. **It cannot be reached from the
catalogue's builder.** Every template is constructed through
[`GovernedTemplateCatalog.Template(...)`](../src/MissionController.Infrastructure.Data/Catalog/GovernedTemplateCatalog.cs),
whose parameter list has no remediation argument, and which calls the convenience constructor on
`SingleToolTemplate` ([`Models.cs`](../src/MissionController.Core/Models.cs), the nine-argument
overload). That constructor hardcodes:

```csharp
Array.Empty<RemediationAction>());
```

So the first job is a builder change, not a template edit. Add an optional
`IReadOnlyList<RemediationAction>? remediations = null` to `Template(...)` and pass it through to the
primary constructor. Keep it optional and last so all 58 existing call sites are untouched.

One constraint that is already written down and easy to trip over:
`PostconditionCheck` and `RollbackPostconditionCheck` are `[property: JsonIgnore]` delegates.
`SqliteTemplateRegistry` stores templates as JSON, so a template read back from the registry has
lost any code-based check and the engine then refuses the step. **Declare the postcondition as a
command, not a delegate**, or the remediation works from the shipped catalogue and refuses itself
after a round trip through the registry. `ATemplateWhoseFixCarriesACodeCheck_StillSavesAsJson`
covers the serialisation; nothing covers the refusal-after-reload, which is worth a test.

---

## 3. Use `sysops-time-sync`, and here is why it is the right one

Defined at [`GovernedTemplateCatalog.SysOps.cs:139`](../src/MissionController.Infrastructure.Data/Catalog/GovernedTemplateCatalog.SysOps.cs).
Its tool is `cmd.exe`, so the fix can use the same executable the template already names.

Its own source comment records the failure mode: *"W32Time starts on a trigger, so the same template
produced evidence one day and an access-denied the next."* That is not hypothetical. On the machine
this was written on:

```
sc.exe query w32time      ->  STATE : 1  STOPPED      (exit 0)
w32tm /query /status      ->  0x80070426  The service has not been started.
```

So the diagnostic currently cannot answer on this host, the cause is a stopped service, and the
remedy is to start it. Fix and rollback are both one command, both idempotent if written as below,
and both measurable with a distinct token. That is as clean as a first remediation gets.

Note `sc query` **exits 0 whether the service is running or stopped** — measured above. The exit
code proves nothing here; the substring is doing all the work, which is exactly the case
`ValidationExpectedOutput` exists for.

---

## 4. The declaration

```csharp
new RemediationAction(
    ActionId: "sysops-time-sync-start-w32time",
    TemplateId: "sysops-time-sync",
    Title: "Start the Windows Time service",
    Description: "W32Time is stopped, so the time diagnostic cannot read status, peers or offset. "
               + "Starting it restores the sensor's ability to answer; it does not change the clock.",
    RiskLevel: RemediationRiskLevel.Safe,
    CanRollback: true,
    FixExecutable: CmdExe,
    // `sc start` is asynchronous and returns 1056 if the service is already running, so the exit
    // code of `sc` alone would report a false failure on a healthy host. The command ends on a
    // findstr whose exit code is 0 only once the service reports RUNNING, which makes the fix
    // idempotent and self-checking before the separate validation probe ever runs.
    FixArguments: "/c sc start w32time & ping -n 4 127.0.0.1 >nul & sc query w32time | findstr /C:\"RUNNING\"",
    RollbackExecutable: CmdExe,
    RollbackArguments: "/c sc stop w32time & ping -n 4 127.0.0.1 >nul & sc query w32time | findstr /C:\"STOPPED\"",
    ValidationExecutable: CmdExe,
    ValidationArguments: "/c sc query w32time",
    PostconditionDescription: "W32Time reports RUNNING, so the diagnostic's own sensor can answer",
    ValidationExpectedOutput: "RUNNING",
    RollbackValidationExecutable: CmdExe,
    RollbackValidationArguments: "/c sc query w32time",
    RollbackValidationExpectedOutput: "STOPPED")
```

`ping -n 4 127.0.0.1` is a sleep, not a network probe: `timeout /t` reads the console and fails
under a redirected launch. If the service is still `START_PENDING` when the probe runs, the
measurement fails and the verdict is `PostconditionFailed`. That is correct behaviour, not a defect —
the engine is reporting that it could not prove the state it was asked to prove. Do not relax it
into a retry loop without deciding, in writing, how long a half-applied change may go unreported.

The rollback stops the service, which restores the state observed before the fix. It is not a
"better" state, and the description should not imply it is.

---

## 5. The decision that is not the implementer's to take

The engine launches both fix and validation with `dropAdminPrivileges: false` — *"Remediation may
require standard system repair permissions."* That declines to drop admin. **It cannot grant it.**

Measured on 2026-10-08 with `sc.exe sdshow w32time`:

```
D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)...
```

`RP` is `SERVICE_START`. `SY` and `BA` have it. `IU` — Interactive Users — has
`CCLCSWLOCRRC`: query, yes; start, no. The session this was measured in was **not elevated**
(`WindowsPrincipal.IsInRole(Administrator)` returned false).

So this remediation refuses on an unelevated SPLAT, every time, correctly, with
`ExecutionFailed`. Making it land means SPLAT.exe runs elevated — one process holding an elevated
token, spawning restricted children for sensors and unrestricted ones for fixes. That is a change to
the product's security posture and to what a compromise of the UI process is worth. It belongs in
[`THREAT-MODEL.md`](THREAT-MODEL.md) with an argument, and it is the operator's call, not the
implementer's.

**Do not make that change as part of this work.** The declaration is correct and testable without
it, because the valuable paths — refusal with no postcondition, and fail-closed when the measurement
disagrees — do not need the service to start.

---

## 6. Done looks like

1. `Template(...)` takes an optional remediation list; all 58 existing call sites unchanged.
2. `sysops-time-sync` carries the action above, and `GovernedTemplateCatalog.All` evaluated in a
   scratch console reports exactly one template with a remediation.
3. A test proves the fail-closed direction against this template specifically: the engine refuses
   when the postcondition is stripped, and reports `PostconditionFailed` when the validation probe
   returns stdout without the token. The engine's own tests already cover the mechanism; this proves
   the catalogue's first declaration is wired to it.
4. A test proves the registry round trip: the action survives JSON, and a code-delegate check does
   not — so nobody later declares one as a delegate and ships a remediation that refuses itself.
5. The elevation question written into `THREAT-MODEL.md` as open, with the SDDL evidence above.

Not in scope, and worth saying so: chaining diagnose → fix → re-diagnose through
`GovernedInvestigationLoop`. The loop already caps at five steps, refuses repeats and restricts
selection to the catalogue, so it needs no change — but a chain that acts is a second decision, and
it should wait until one remediation has run under a real verdict.
