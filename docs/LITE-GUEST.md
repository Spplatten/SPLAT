# SPLAT Lite guest: implementation and proof boundaries

Status: partial, reviewed 2026-11-11. The builder, package staging and console import flow are
present. A real console import of the current archive, its kernel proof through that flow,
compiled installer, upgrade and clean uninstall remain unproven.

## Evidence

`packaging/evidence/lite-guest-packaging.json` records eight packaging checks under PowerShell 7.6.9
and byte-verified staging of `20261014T000000Z-r2` on 2026-11-11. It records archive hash
`9c5fab831ffbb821166c0426574fede9f5b48f26f741d1a2ac31829efee4ace5`, 131
packages, 137 staged files, and `sourceStatus: NOT_INCLUDED`. The checks reject changed archives,
missing licence records, mismatched source versions, wrong package counts, changes during copying
and a false claim that source archives were included. These are packaging checks, not a boot test.

`packaging/evidence/lite-guest-console.json` now records a normal, targeted VSTest run after a
separate build, with source, assembly and raw-result hashes. The 2026-11-11 run is **INCOMPLETE**:

| Test group | Passed | Failed | What was exercised |
| --- | ---: | ---: | --- |
| `BundledWslGuestTests` | 11 | 3 | Import plans and guest ownership against a recording WSL stand-in; three cases stop at denied atomic receipt replacement |
| `ManagedSubstrateCheckTests` | 4 | 0 | Cold startup, token-read ordering, wrong-token refusal and authenticated enforcement against a protocol stand-in |
| `SplatGuestPackagingTests` | 0 | 8 | Windows PowerShell 5.1 rejects script execution with `AuthorizationManager check failed` |

The separate PowerShell 7 packaging run above passes all eight cases; it does not establish
PowerShell 5.1 compatibility. The atomic update remains in the implementation. No checks are
skipped or converted to passing results because this environment refuses an operation.
Both evidence files hash source as UTF-8 with LF line endings so checkout line endings do not
change which source the measurement identifies.

The October testhost socket restriction did not reproduce in the November targeted run.
Automatic approval rejected an attempt to run the remaining cases outside the sandbox because
escalated permissions are disabled. Receipt replacement, PowerShell 5.1 and the packaged
executable still require checks in the deployment environment.

There is later native evidence: the [2026-11-05 Debian guest probe](../native/splat-agent/evidence/2026-11-05-splat-guest/daemon-probe.json)
and [2026-11-08 daemon probe](../native/splat-agent/evidence/daemon-probe.json) record root enforcement
against BPF source `d5bb4cad`. PR #18 merged at `27876a9`. These records supersede the old
"waiting for #18" status, but do not prove a console import of the `r2` archive.

## Build and package

The guest builder is `packaging/build-splat-guest.ps1` with its companion shell script, restored
from upstream commit `838789c`. It creates a Debian minbase filesystem and records exact binary
and source package versions, copyright files and the archive hash. Run it with `-WithSources` to
request source downloads; merely listing source URLs is not a downloaded source bundle.

Pass `-GuestBuildDirectory <snapshot-output>` to `packaging/build-community-installer.ps1` along
with its required Windows payload, MCP binary, daemon binary, compiler and output arguments.
This option replaces `-RootfsPath` and `-RootfsSha256`; combining them is refused. It stages:

- `Linux/rootfs.tar.xz`, checked against the build hash and size;
- `Linux/Guest/BUILD.json`, package and source inventories, and copyright records;
- `Linux/Guest/sources/` when source files were supplied.

Only recognized guest records are copied. `PACKAGE-MANIFEST.json` records guest metadata and
source status, and `verify-community-package.ps1` rechecks them against the packaged files.
Included source files are labelled `FILES_INCLUDED_COMPLETENESS_UNVERIFIED`: their presence is
not a finding that corresponding source is complete. The current local build has no source files.
Existing raw-rootfs input remains available for lab packages; it does not select the Lite flow.

To repeat the packaging measurement without building an installer or changing WSL:

```powershell
& .\packaging\probe-splat-guest-package.ps1 -GuestBuildDirectory .\dist\splat-guest\20261014T000000Z-r2
```

To rebuild and repeat the console, managed-health and PowerShell packaging tests:

```powershell
& .\packaging\probe-splat-guest-console.ps1 -DotNet "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe"
```

Use the installed SDK 10 path if the environment redirects `LOCALAPPDATA`. The probe uses a new
results directory, preserves a non-passing result, and refuses to write evidence if a source or
measured assembly changes during the run. It never imports a real WSL distribution.

## Console flow

An unmanaged console with `Linux/Guest` records selects the bundled guest. A prior local import
receipt keeps that selection even if package records disappear. A managed-service configuration
continues to use its administrator's service and does not import a local guest.

On the Kernel Lease page, **Plan mount** first shows an import plan when no owned guest exists.
The plan names the archive, its SHA-256, storage directory and a `SPLAT-Lite-<suffix>` distribution
name derived from this SPLAT data root. **Import Lite guest: apply the plan below** rechecks the
archive and registration, imports only that guest, enables its systemd and restricted Windows-drive
mount settings, records an ownership marker, and terminates that new guest to apply the settings.
It does not run daemon provisioning. The operator then plans a second mount to review daemon
installation and any required host-wide boot-line changes.

The import is single use: another check or plan spends it. A changed archive or claimed name
requires another plan. Existing registrations without this import's receipt are refused.
Subsequent provision, check, token, service-start and lease keep-alive operations name this
distribution explicitly. Guest commands check its identity marker against the Windows receipt.
Missing or mismatched ownership refuses the operation; it does not select the default distro.

Since 2026-11-11, ownership is checked before each daemon connection as well. Previously the
keep-alive shell could fail its marker check while a connection proceeded using a cached token.
The connection check covers execution, health and receipt recovery. The regression first completes
two authenticated health exchanges using one token read, then changes the marker and verifies that
the next connection is refused before it reaches the listener. A separate control checks refusal
before any token read. Both cases pass in the targeted evidence above. This is local registration
consistency, not caller isolation from the owning Windows account.

The receipt and a separate mount manifest live under `<SPLAT data root>/lite-guest/`. An interrupted
import keeps a receipt marked `importing` and requires inspection. Recovery must first establish
which registration and files the failed attempt created; no automatic retry adopts a registration
and no cleanup automatically unregisters one. The receipt is local ownership bookkeeping, not a
security boundary against the Windows account that owns it.

**Unmount** reverses only recorded daemon setup. It retains the imported distribution and its data.
The Windows installer likewise does not unregister it. Complete lifecycle removal and upgrade
remain deployment work to prove; do not describe this flow as a clean uninstall.

## Remaining release measurements

Run the normal tests after a separate SDK 10 build, then import the packaged archive on a clean
machine and prove daemon startup, authenticated enforcement, lease execution, restart, sleep and
reboot behavior. Repeat with a configured managed service and a non-administrator operator.
Exercise failed and interrupted imports, changed ownership markers, upgrades, retained data and
deliberate guest removal. Prove the exact installed daemon and guest archive used by that flow;
the native records above do not substitute for this installation measurement.
The source bundle, relinking materials, trusted signing and wider release gates remain open.
