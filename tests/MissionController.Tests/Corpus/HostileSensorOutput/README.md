# Hostile sensor output

Real sensor shapes — `ipconfig`, `tasklist`, `Get-Service`, `dir`, `journalctl`, `reg query` — each
carrying text an attacker could actually put there. Every string planted below sits in a field that
is genuinely attacker-writable on a host they already touched: a service display name, a process
image name, a file name, a DNS suffix, a registry value, a log line they caused to be written.

These are not prompts. They are the bytes a sensor hands SPLAT, and SPLAT puts them in a model's
context window. `PromptInjectionCorpusTests` runs the whole directory through the real prompt
assembly and asserts the delimiting survives each one.

**Adding a case:** drop a `.txt` file here. It is picked up by enumeration, so no test changes. Give
it a name that says what the planted text tries to do. Keep the surrounding telemetry realistic —
the corpus is only worth its file size if the planted line is the only artificial thing in it.

**Why enumeration, not a hard-coded list:** the standing instruction is to run every prompt change
against this corpus. A list in a `.cs` file is one a prompt change can quietly leave behind; a
directory read at test time cannot be.
