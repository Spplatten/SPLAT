# SPLAT distribution readiness — 2026-10-06

**Verdict: suitable for supervised installer and protocol evaluation; not ready for the requested
turnkey deployment under a secondary Windows principal.** The installer candidate preserves the
existing Windows application and bundles the Linux inputs. It does not implement the missing Windows
bridge service or close roadmap Row 2.4. Nothing was sent to Discord or another recipient.

| Gate | Verified result |
| --- | --- |
| Existing Windows payload | 553 files, 248,688,200 bytes; all 293 DLLs preserved by SHA-256. .NET 10.0.12 and Windows App SDK 2.5.1, not .NET 9. |
| DLL provenance | Six MissionController DLLs have matching projects under `src`; 287 DLLs match restored third-party package contents byte for byte, including MSIX runtime entries. Zero unresolved DLLs in this payload. No extra DLLs found outside build/output directories in this workspace. |
| Existing application source reference | The console DLL records commit `00ae926cea7dc6d7625c36f4dc50ac438f338876`. Current HEAD was `9086eec78057a7556d459688225224ff499045c9`; no `src` or `native` changes occur between those revisions. Preserved binaries were not rebuilt. |
| Managed test suite | 913 passed, 0 failed, 0 skipped in the clean PowerShell environment. Initial inherited module paths caused three failures; the failed run is retained separately. These counts are suite results, not a claim that every live-host branch executed. |
| Console smoke test | The exact preserved executable opened and loaded all nine pages. |
| Dependency advisories | NuGet reported zero vulnerable direct/transitive packages across nine solution projects. This does not scan an arbitrary custom binary or certify the Linux rootfs. |
| Linux artifact build | Portable daemon and self-contained MCP executable built successfully. Embedded daemon verified; the daemon requires glibc 2.39 or later. No existing daemon was replaced. |
| Recorded kernel evidence | Daemon and last-hop records are PASS and match current BPF source SHA-256 `6fc637d8e30f375e7b64a51a2438202515cf12cf008fff78b2f8b719a9a8b4f1`. The recorded daemon binary hash differs from the newly rebuilt portable daemon; no new privileged proof was run for this package. |
| Rootfs | Clean Canonical Ubuntu 26.04 amd64 root archive; SHA-256 `ccd08a7a76cdc69034dd2682b4913bdd051cb71ad87d0b66689015aa068e61c8` matches the publisher checksum fetched over HTTPS. Python 3 and systemd entries verified. This is not an export of the operator's distro. |
| Secondary principal | Current workspace evidence records partial registration isolation; operator was an unelevated administrator, and port 50051 had no valid owner-side control. Token exclusion, Windows service authorization and an audited operator lease remain unproven. See THREAT-MODEL.md. |
| Packaging refusal checks | Incorrect rootfs checksum, incomplete Windows payload and an existing output/payload directory are refused before staging. Same-principal and wrong-owner bootstrap attempts are refused before WSL import. PowerShell scripts parse; guest shell hook passes syntax checking. |
| Installer trust and lifecycle | Candidate is unsigned. Elevated installation, owner-session bootstrap, upgrade and uninstall have not been tested on a clean Windows machine. |

## Package behavior

`packaging/build-community-installer.ps1` takes the existing `dist/App` as the Windows payload;
it never republishes over it or guesses which DLLs are needed. It copies and hashes every file,
adds the newly built MCP and Linux daemon, a clean rootfs, source snapshot, dependency inventory,
third-party license metadata and testing instructions, then compiles Inno Setup. Existing outputs
are refused rather than removed. SHA256SUMS.txt covers the staged payload; a separate checksum
covers the resulting Setup executable. Every manifest explicitly records the open deployment gates.

The installer writes the payload under Program Files and requires its interactive license page.
AGPL-3.0 and the Platten Industries commercial-license option appear in the installer version
resource, installed notices and package manifest. The portable-client, MCP and MSIX packaging
paths also copy the license materials. Existing DLL bytes are not rewritten or relicensed.

The WSL hook must be run in an existing, distinct standard owner account. It verifies the expected
SID and rootfs/daemon hashes; refuses administrator owners and existing distro names; imports one
new WSL2 distro; enables systemd; restarts only that new distro; and installs the daemon after
checking cgroup v2 and active BPF-LSM. It does not create accounts, change the user's default distro
or .wslconfig, or provide the missing Windows service. Runtime behavior of this hook is **built,
unproven**. Only syntax and refusal paths were checked here.

## Remaining release work

1. Implement and review the Windows service and authenticated named-pipe route under the separate
   principal. Governance must remain on that side of the boundary. Test both permitted operator
   requests and direct-access refusals using two standard accounts and positive controls.
2. Install this exact package on a disposable clean Windows machine. Complete the lifecycle and
   failure matrix in COMMUNITY-TESTING.md, including WSL/kernel prerequisites and bootstrap failure.
3. Re-run the privileged daemon and last-hop probes against the bundled portable daemon and rootfs;
   bind the resulting evidence to the exact shipped binaries. Preserve the separate source-hash proof.
4. Finish redistribution review of the source snapshot, native linked dependencies and third-party
   notices, and use the intended publisher signing certificate for a public installer. The Windows
   DLL provenance inventory is complete; that alone is not a legal clearance or reproducible build.

## License correction

The proposed “entire stack” and “anything that touches the DLLs” language is not in the installer.
AGPL distinguishes covered combined works from independent aggregates. Its network-source rule
concerns modified covered versions, and it does not require submitting patches to the original
author. Commercial use can comply with AGPL; a separate commercial agreement offers alternative
terms for rights Platten Industries can grant. Packaging Microsoft's DLLs does not transfer their
copyright to Platten Industries. See [GNU AGPL-3.0](https://www.gnu.org/licenses/agpl-3.0.html),
especially sections 1, 5, 6 and 13, and the [GNU licensing FAQ](https://www.gnu.org/licenses/gpl-faq.en.html).

Upstream implementation references: [Inno Setup license page](https://jrsoftware.org/ishelp/topic_setup_licensefile.htm),
[version metadata](https://jrsoftware.org/ishelp/topic_setup_versioninfodescription.htm),
[Microsoft WSL import](https://learn.microsoft.com/windows/wsl/use-custom-distro), and
[Canonical rootfs listing](https://cloud-images.ubuntu.com/releases/resolute/release/).
