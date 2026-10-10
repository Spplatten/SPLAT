# The end goal: SPLAT you can mount

> **This is a design, not a claim.** Nothing below describes what SPLAT does today unless it is
> marked **exists**, and every such mark points to its evidence. The README,
> [`SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md) and the
> [roadmap](ROADMAP.md) are the record of what is true. This page holds the destination, so that
> those documents never have to carry an aspiration as if it had shipped.

## The end state

SPLAT is a kit you bring to a computer, not a product you install on it. It arrives on a flash drive
or from a download and mounts onto a Windows machine after asking. While mounted, it turns on
kernel-enforced leases for the AI agents that run there, both SPLAT's own specialists and outside
agents through MCP, and it keeps a ledger of what they did. When you unmount it, the machine goes
back to how it was, except for the evidence you chose to keep.

## What the leases are for

A lease is worth what it costs only when the agent inside it can change something. SPLAT was designed
for AI orchestration: an agent that sets up an app on Meta, TikTok or X and wires its webhooks, or
changes a codebase and proves its tests still pass, with one approval for the whole job. Containment
is the reason that is safe to allow. It is not the destination on its own.

This page used to describe only the kit and the leases, which is how the destination came to read
as a cage with nothing in it. As of 2026-10-09 no template in the catalogue declares an action, and
every one reads. The pieces that would let an agent act, which of them already **exist**, and the
order to build the rest are in [SCOPE-acting-agents.md](SCOPE-acting-agents.md) and
[roadmap P5](ROADMAP.md).

## Way in 1: the SPLAT drive

### What is on the drive

```
SPLAT (E:)
  Mount SPLAT.cmd        the one thing a person runs; it asks before it changes anything
  splat\splat-mcp.exe    server, doctor, provision and unmount, in one self-contained file
  splat\app\             the operator console, with .NET and the Windows App SDK inside it
  splat\SHA256SUMS       every file's hash, checked before anything runs
  splat\data\            ledger, workspace and evidence, when mounted portable
  autorun.inf            the drive's name and icon, and nothing else (see below)
```

### Plugging it in

Windows has not started a program from a USB drive on insertion since Windows 7, nor XP and Vista
since update KB971029.
`autorun.inf` can still give the drive a name and an icon, which is where the logo will go; check it
on the target Windows build. It cannot run anything, and SPLAT should not want it to: a drive that
installs a root daemon the moment it is plugged in is exactly what malware looks like. So the drive
shows up with SPLAT's name and icon, and the person opens it and runs `Mount SPLAT`, which asks
first. An AutoPlay handler installed at the first mount might offer "Mount SPLAT" on later
insertions, but whether Windows 11 lets an installed handler claim a volume by its contents is
**unverified**.

### Mounting, in order

1. **Verify the drive.** Check every file against `SHA256SUMS`, and each executable's Authenticode
   signature. Signing needs a code-signing certificate, which is yours to buy.
2. **Run `doctor`**, so the person sees what this host can enforce before anything changes.
   **Exists**: roadmap 1.2.
3. **Ask.** List exactly what mounting changes on this host: the `.wslconfig` boot line, the daemon
   at `/opt/splat`, its unit and token, the `/mnt` stopgap, and any MCP client entries. Then offer
   Mount or Cancel.
4. **Provision.** **Exists**: `splat-mcp provision --apply` got a clean machine to enforcing on
   2026-09-18 ([record](../native/splat-agent/evidence/clean-machine/README.md)). It stops once for
   the operator's `wsl --shutdown`; the launcher can ask for that restart in the same dialog.
5. **Record a mount manifest**, on the drive and on the host: every file written and every line
   appended, each with what was there before.
6. **Start the console from the drive**, and register `splat-mcp` with the MCP clients the person
   chose.

**Unmounting** plays the manifest backwards. It stops the server, removes the daemon, its unit and
token, takes out only the lines the mount added, and removes the client entries it wrote. Then it
says what, if anything, it could not restore. The evidence stays on the drive.

### Two modes

- **Portable**, the default. The ledger, workspace and evidence live on the drive, so the drive is
  the record of every machine it was mounted on. This is the containment-assessment kit.
- **Host.** Data stays on the host, as it does today.

### Keys

The ledger key must not travel with the ledger it protects. A lost drive that carries both is a
ledger anyone can rewrite. Keep the key on a second device, such as another USB key or a hardware
key, or on your own machine and verify the drive's ledger there. **Exists**: the keyed ledger
(roadmap 3.2). Where the key lives in the drive model is your decision.

### What the host must have

- **For kernel enforcement:** Windows 11 on x64, the only version tried, and WSL2 with systemd and
  glibc 2.39 or newer. **Exists**: these are the checks `provision` runs today.
- **Without WSL:** the drive still mounts the Windows half, meaning the AppContainer sensors, the
  file tools and the ledger. `doctor` already says so when `run_command` and `run_code` cannot be
  enforced (**exists**).
- **Not over SSH:** a session reached over SSH cannot run the network-denied sensors
  ([roadmap](ROADMAP.md), open items).

### A cleaner footprint, to decide

Mount SPLAT's own WSL distro rather than installing into the user's. A `wsl --import` of a small
SPLAT image from the drive would keep `/opt/splat`, the unit and the token out of the user's
Ubuntu. It would also fix the glibc version and turn unmount into a single `wsl --unregister`. The
kernel boot line stays host-wide, because every distro shares one kernel. So that line, and the
restart it needs, remain the one change a mount makes to the whole machine.

## Way in 2: from the cloud, as a wrapper or SDK

- **The same mount, downloaded.** A signed release, meaning the executable and `SHA256SUMS`, and a
  small bootstrap (`mount.ps1`) that downloads, verifies, and runs the same consent-then-mount flow.
  Unmount is the same as above. **Exists**: the single self-contained executable and its SHA-256
  (roadmap 1.4). It is neither signed nor released.
- **Package managers**, each a thin way to fetch that same file:
  - winget, for Windows;
  - npm (`npx splat-mcp`), which needs a release and an npm account, left to you in roadmap 1.4;
  - PyPI, for `splat-langgraph`, which today installs only from source with `pip install -e`;
  - NuGet, for .NET agents.
- **The SDK shape.** SPLAT's API is MCP, so an SDK is a typed MCP client pointed at `splat-mcp`.
  `splat-langgraph` already is one, for Python (**exists**). A `splat run -- <command>` wrapper would
  give tools that do not speak MCP the same lease from a shell.
- **Hosted SPLAT for cloud agents.** The daemon runs on a stock kernel (**exists**, WSL2's), so on a
  cloud Linux VM it could contain agents that run there. Two things stand in the way, and both are
  real work:
  - The daemon listens only on loopback, on purpose.
  - It identifies callers by a shared secret, not by who they are (roadmap 2.4).

  A remote caller needs an authenticated transport and a real identity first.

## Where each piece stands

| Piece | Today | Delivered by |
| --- | --- | --- |
| One self-contained server, daemon inside | **Exists** | 1.4, 1.9 |
| Provision onto a clean host | **Exists**, with one operator restart | 1.3; the clean-machine record |
| Runs from any folder | `splat-mcp` ran from a user folder on the second machine; not yet tried from removable media | 4.4 |
| Keyed ledger | **Exists** since 2026-09-18 | 3.2 |
| Data beside the executable (portable mode) | **Exists** since 2026-09-25. One root for both hosts, chosen by `SPLAT_DATA_DIR` or a `splat.portable` marker beside the executable, and named by `doctor`. What is not yet proven is a run from removable media | 4.1 |
| Unmount, from a manifest | **Exists** since 2026-09-26. `provision --apply` writes the manifest; `splat-mcp unmount` plays it backwards and names what it could not restore. Not yet run against a real guest | 4.2 |
| A console that needs nothing installed | Partly. The Windows App SDK is already inside it, but .NET is not | 4.3 |
| The drive, its launcher, its name and icon | Missing; the logo comes later | 4.4 |
| MCP client entries written at mount, removed at unmount | Missing | 4.5 |
| SPLAT's own WSL distro | Missing, and a decision first | 4.6 |
| Signed releases and a cloud bootstrap | Missing; the certificate and accounts are yours | 4.7 |
| Kernel enforcement with no change to the host | Not possible. The boot line is shared by every distro | — |
| A hosted daemon for remote callers | Missing; blocked on caller identity | 2.4, then later |

## Order

1. **The cheap, load-bearing pieces:** 4.1 portable data and 4.3 the self-contained console.
2. **4.2 unmount.** A mount is honest only if it can be undone.
3. **The launcher and the drive.**
4. **The cloud bootstrap**, which reuses all of the above.

Signing gates any distribution. The hosted daemon waits for 2.4.

## Decisions that are yours

- Where the ledger key lives when the ledger travels on the drive.
- A code-signing certificate.
- Which MCP clients a mount may write entries into.
- Whether SPLAT gets its own WSL distro or keeps installing into the user's.
- The npm account and the package names.
- The logo.
