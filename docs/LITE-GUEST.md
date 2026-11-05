# SPLAT Lite guest: implementation and proof boundaries

Status: partial. The builder, package staging and console import flow are present. A real import,
kernel proof in this guest, compiled installer, upgrade and clean uninstall remain unproven.

## Evidence

`packaging/evidence/lite-guest-packaging.json` records eight packaging checks under PowerShell 7.6.5
and byte-verified staging of the local Debian snapshot build. It records the archive hash, 131
packages, 137 staged files, and `sourceStatus: NOT_INCLUDED`. The checks reject changed archives,
missing licence records, mismatched source versions, wrong package counts, changes during copying
and a false claim that source archives were included. These are packaging checks, not a boot test.

`tests/MissionController.Tests/BundledWslGuestTests.cs` exercises import consent and ownership with
a recording WSL stand-in. `packaging/evidence/lite-guest-console.json` records the direct compiled
test invocation, its cases and source hashes. Nine checks pass; three stop at an atomic receipt
replacement denied by this environment. The evidence verdict is **INCOMPLETE**. The same
`File.Move(source, destination, overwrite: true)` failure was reproduced with two isolated files;
the atomic update remains in the implementation and needs execution in the deployment environment.
This is not a VSTest suite result or a real WSL import.
Both evidence files hash source as UTF-8 with LF line endings so checkout line endings do not
change which source the measurement identifies.

The normal VSTest runner could not establish its testhost socket in this sandbox (Windows socket
error 10013). Windows PowerShell 5.1 script execution was also denied here. Neither limitation is a
passing result. The ordinary suite, PowerShell 5.1 and the packaged executable still need their
normal deployment-environment checks.

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
& .\packaging\probe-splat-guest-package.ps1 -GuestBuildDirectory .\dist\splat-guest\20261014T000000Z
```

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
deliberate guest removal. Root re-proof still waits for PR #18 and a clean substrate source tree.
The source bundle, relinking materials, trusted signing and wider release gates remain open.
