# Agent app profiles

SPLAT contains the work an agent sends through it: `run_command`, `run_code` and the templates. It
contains nothing the agent app does with its **own** tools. An agent app that still has a built-in
shell or web fetch can run a command or reach a site without SPLAT seeing it, and no lease, proxy
or receipt covers that.

A profile here is a settings file for one agent app that turns those built-in tools off, so the
SPLAT MCP tools are the only way left to run something or fetch something.

**A profile is configuration of someone else's program. It is not enforcement.**
- SPLAT cannot tell whether it is installed, and no SPLAT receipt says anything about it.
- It holds only as well as the agent app honours its own settings.
- An MCP server other than SPLAT that offers a shell or a fetch tool is not covered by it.

## Claude Code

File: [`claude-code/managed-settings.json`](claude-code/managed-settings.json)

It denies four built-in tools — `Bash`, `PowerShell`, `WebFetch`, `WebSearch` — and turns off the
mode that skips permission checks. File reading and editing tools are left on; they are neither a
shell nor a network path.

Install it as Claude Code's **managed** settings, which a user's or a project's settings cannot
override. Copy the file to:

| System | Path |
| :--- | :--- |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux, WSL | `/etc/claude-code/managed-settings.json` |

Writing there needs administrator rights, which is the point: the agent cannot edit it.

If a managed settings file already exists, merge the `permissions.deny` entries into it instead of
replacing the file.

To check it took effect, start Claude Code, run `/permissions`, and confirm the four tools are
listed as denied. Then ask it to run a shell command: it should have no tool to do that with other
than SPLAT's.

**Not measured here.** The paths and key names above are Claude Code's documented ones as of
2026-11. Nothing in this repository runs Claude Code against this file, so check it on the
version you deploy.
