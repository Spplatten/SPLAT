# Community installer build — 2026-10-09

**Verdict: built and self-verified as a supervised test candidate, not a release.** The installer
is unsigned, the clean-machine matrix in `COMMUNITY-TESTING.md` has not been run, and the
secondary-principal bridge is not built. The installer and its payload are not committed; this
record is what remains in the repository.

## What was built

| Item | Value |
| --- | --- |
| Installer | `SPLAT-Community-0.2.0-Setup.exe`, 391,859,916 bytes |
| Installer SHA-256 | `33d2c7bb8d0885ec5bed1f4ecaabaa7bf21ef078b231b6947b02d72ffcc39436` |
| Source reference | `2aecf4f`, plus the working-copy `packaging/` scripts and the two community documents |
| Compiler | Inno Setup 6.7.3 |
| Payload | 636 files: 553 Windows files from `dist/App`, the MCP executable, the Linux daemon, the rootfs, a 578-entry source archive, licenses and manifests |
| MCP SHA-256 | `caa03db5f7a2c979a6fe91ed77e361b26c17ffe63ab33ad818f232a1291099cd`, built from `9086eec` |
| Daemon SHA-256 | `4d4631baa247e3823a9e257787b7f66f3f63595de4cbb10ba34841547bcba16b` |
| Rootfs SHA-256 | `ccd08a7a76cdc69034dd2682b4913bdd051cb71ad87d0b66689015aa068e61c8`, Ubuntu 26.04 amd64 |
| BPF source SHA-256 | `6fc637d8e30f375e7b64a51a2438202515cf12cf008fff78b2f8b719a9a8b4f1`, matching `daemon-probe.json` |

## Evidence

- **Source corresponds to the binaries.** `git diff 00ae926 2aecf4f -- src native` is empty, so the
  committed source the console (`00ae926`) and MCP (`9086eec`) were built from is the source
  archived. The build ran from a fresh clone of `2aecf4f`, so another agent's uncommitted `src`
  changes are absent from the archive: `src/splat-mcp/ManagedBridgeHost.cs` is not in it.
- **Tests.** 913 passed, 0 failed, 0 skipped on that clone; build had 0 warnings. The count is
  lower than the working tree's because uncommitted tests were not in the clone.
- **Package verification.** `packaging/verify-community-package.ps1` passed all 636 files and the
  manifest's Windows, MCP, daemon and rootfs hashes. On a copy with one flipped byte and one added
  file it refused both. Over the earlier 0.2.0 candidate it refuses one item: that manifest
  predates the `mcpSha256` field.
- **Wizard.** A non-elevated copy of the same script was driven through every page and captured.
  The welcome, license and finish pages show the SPLAT artwork and the licensor block. The real
  installer requires elevation and was not run.

## Not established

Clean-machine installation, upgrade, uninstall and bootstrap; the privileged probes against this
daemon binary and rootfs; publisher signing; the secondary-principal bridge (Row 2.4).
