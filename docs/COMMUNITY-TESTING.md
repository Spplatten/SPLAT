# SPLAT community test candidate

This is an experimental binary installer, not a completed secondary-principal deployment.
The installer carries the complete compiled Windows payload, including its DLLs, a standalone
MCP executable and the Linux daemon. No compiler is required to inspect or launch the Windows
payload. PACKAGE-MANIFEST.json records the bundled runtime and SHA-256 of every Windows file.
DEPENDENCIES.json identifies project sources and DLLs that match cached dependencies byte for byte;
ThirdParty contains package license metadata and available notices. Third-party DLLs keep their
original licenses. SPLAT-Source.zip supplies the source snapshot and packaging scripts; the source
reference is not a claim that the preserved binaries were rebuilt from it.

**Do not distribute this candidate as release-ready.** The secondary-principal Windows bridge
service and its authenticated named-pipe client are not implemented. Registering another account's
distro alone does not make the existing operator-side bridge able to use it. The ten-minute
measurement below is a prerequisite to that work, not an installer feature that closes Row 2.4.
Local administrators are outside that proposed boundary.

## Installation and licensing

Run the Setup executable interactively. It presents the full AGPL-3.0 and the Platten Industries
commercial-license option, and installs the compiled payload under Program Files. Its hash is
supplied beside it. This candidate is unsigned; a checksum is not publisher authentication.
Installation does not create a Windows account, change certificate trust, select a default WSL
distro, stop existing workloads, or remove WSL data on uninstall.

AGPL binary distribution requires providing the corresponding source under the license's terms,
including applicable custom-library source and build material. Confirm that source inventory before
sharing. Enterprise use does not automatically require buying a license, independent programs do
not become AGPL merely by communicating with SPLAT, and patches do not have to be submitted to
Platten Industries. Contributions and commercial grants require their own applicable agreements.
The authoritative terms are in LICENSE; COMMERCIAL.md describes the alternative offer.

## Loopback protocol tests

Use an isolated test machine. Retain the installer SHA-256, PACKAGE-MANIFEST.json, Windows and WSL
versions, BPF source hash, daemon binary hash, and raw pass/fail evidence. Keep real tokens and private
signing material out of reports. The protocol authenticates possession of a shared secret; a process
running as the distro owner can obtain that secret.

Exercise wrong-secret authentication, a fake daemon that can receive only the initial nonce,
replayed requests on the same and on a fresh connection, sequence gaps, altered authenticated
frames, truncated and oversized frames, client disconnect, expiry and concurrent leases. Confirm
zero unauthorized workload launches and zero unauthorized output, with a permitted request as the
positive control. Existing source tests are WslAgentSessionTests and WslLeasedExecutorWireTests;
the native probe is native/splat-agent/probe-daemon.sh in the corresponding source package.
The bundled evidence records past runs; it does not certify a new machine or a rebuilt daemon.

## Row 2.4: the ten-minute registration measurement

1. On a disposable test machine, use two distinct standard local Windows accounts: owner and operator.
   Record both SIDs with `whoami /user`. Keep an existing working operator-owned distro as a control.
2. Sign in as the owner. If the package includes a verified rootfs, inspect the plan, then register
   a new distro with the packaged `bootstrap-community-wsl.ps1`, supplying `-Distro SPLAT-Boundary`,
   `-ExpectedOwnerSid`, `-OperatorSid`, and `-Apply` only for the actual import. WSL2 and active
   BPF-LSM must already be available; the hook enables systemd and restarts only the newly imported
   distro. The rootfs must contain Python 3 and systemd. If provisioning refuses
   after import, inspect that new distro; do not rerun the import over it. The hook installs only a
   lab daemon and explicitly reports that the Windows bridge service is missing.
3. From the owner session, create an evidence directory writable to that owner and run
   `probe-caller-identity.ps1 -Mode Owner -Distro SPLAT-Boundary -OutputPath <owner.json>`.
4. Within 30 minutes, from the operator session, run
   `probe-caller-identity.ps1 -Mode Operator -Distro <operator-owned-control-distro> -OwnerEvidence <owner.json> -OutputPath <operator.json>`.
   An own-distro root control must succeed; the other registration must be absent and return
   `WSL_E_DISTRO_NOT_FOUND`. A timeout, missing control, filtered administrator, or name collision
   does not establish the desired standard-account boundary.
5. Measure reachability of the owner daemon from the operator session separately, with a successful
   owner-side connection control. The supplied registration probe marks TCP reachability and caller
   authorization NOT_MEASURED. Record which listener answered; an open port alone is not proof that
   it belongs to the other account. A second-principal install is not accepted until a permitted
   operator MCP request succeeds through the new bridge while direct token access and direct daemon
   access fail. That bridge is not in this candidate.

Preserve the raw records even when the experiment fails. No result here automatically closes Row 2.4.
Do not import an export of a developer's working distro: it can contain tokens, histories and keys.

## Installer acceptance on a clean machine

Check first install, repeat install, upgrade refusal while the console is running, missing WSL,
missing BPF-LSM, wrong rootfs hash, existing distro name, failed bootstrap and uninstall. Confirm
all Windows DLL hashes match the manifest, the console's self-test opens every page, and unrelated
distros and operator data survive. The candidate has not yet passed this matrix.

References: [GNU AGPL-3.0](https://www.gnu.org/licenses/agpl-3.0.html), sections 1, 5, 6 and 13;
[GNU licensing FAQ](https://www.gnu.org/licenses/gpl-faq.html#GPLRequireSourcePostedPublic);
[Microsoft WSL import instructions](https://learn.microsoft.com/windows/wsl/use-custom-distro);
[Inno Setup license page](https://jrsoftware.org/ishelp/topic_setup_licensefile.htm).
