# Handoff — a Google Forms feedback survey for the community test candidate

**Written 2026-10-09.** For whichever agent picks this up. Read [`AGENTS.md`](../AGENTS.md) first.

## Goal

Build one Google Form that community testers fill in after installing
`SPLAT-Community-0.2.0-Setup.exe`, SHA-256
`33d2c7bb8d0885ec5bed1f4ecaabaa7bf21ef078b231b6947b02d72ffcc39436`. Every answer must be
comparable across testers and traceable to the exact package they ran. The source of truth for
what testers do is [`COMMUNITY-TESTING.md`](COMMUNITY-TESTING.md). The build is recorded in
[`audits/2026-10-09-community-installer-build.md`](audits/2026-10-09-community-installer-build.md).

## Decisions that belong to the operator — ask, never guess

1. **The Google account that owns the form and its response sheet.**
2. **Whether the form collects email addresses.** Default to off. If on, the form must say why.
3. **Who may be contacted for follow-up**, and the address follow-ups come from.
4. **Where the form link is published.** Building it is not permission to share it.

## Build method

Write the form as a Google Apps Script, `packaging/community-feedback-form.gs`, that creates the
form and links a response spreadsheet when run once from the operator's account. A script can be
reviewed, versioned and rebuilt; a hand-clicked form cannot. The operator runs it, or approves each
step if you drive the browser. Do not commit the form's URL, edit link or response sheet ID.

## Privacy rules the form must enforce in its own text

The repository is public and a past audit found host reconnaissance leaking through fixtures, so
the form must not become a second leak.

- **No file-upload questions.** They force a Google sign-in and copy files into the owner's Drive.
- **No raw probe output.** `probe-caller-identity.ps1` records contain account SIDs and machine
  details. Ask for verdicts and hashes; ask whether the tester will share raw records privately.
- **A warning above every free-text box:** do not paste tokens, `agent.token`, keys, passwords,
  usernames, hostnames, IP addresses or paths containing a username.
- **No required personal fields.** A handle is optional.

## Form structure

Use these sections in order. Required means the form will not submit without it.

### 1. Package identity
- Installer SHA-256 you verified, short answer, required, validated as 64 hex characters.
- Did it match the published checksum? Yes / No / Did not check. Required.
- Did `packaging\verify-community-package.ps1` pass over the install folder? PASS / FAIL / Not run.
  On FAIL, a paragraph for the `FAIL` lines it printed.

### 2. Machine
- Windows edition and build, for example `Windows 11 Pro 26200`. Required.
- WSL version from `wsl --version`. Required.
- Kernel version inside WSL from `uname -r`.
- Is BPF-LSM active (`cat /sys/kernel/security/lsm` lists `bpf`)? Yes / No / Did not check.
- Was this a clean or disposable machine? Clean / Disposable VM / Daily-use machine.
- Signed into Windows as: Standard user / Administrator.

### 3. Installation
One row per checklist item from the clean-machine section of `COMMUNITY-TESTING.md`, as a grid
with columns Pass / Fail / Not tried: first install, repeat install, upgrade refused while the
console runs, missing WSL, missing BPF-LSM, wrong rootfs hash, existing distro name, failed
bootstrap, uninstall, unrelated distros and data survived.
- Did SmartScreen or antivirus block the installer? Yes, and I continued / Yes, and I stopped / No.
- Did the console open, and did every page load? Yes / Some pages failed / Did not open.
- Paragraph: anything that failed, in the tester's words.

### 4. Protocol tests (optional section)
A grid with Pass / Fail / Not tried for: wrong secret, fake daemon sees only the first nonce,
replay on the same connection, replay on a new connection, sequence gap, altered frame, truncated
frame, oversized frame, client disconnect, lease expiry, concurrent leases, permitted request as
the positive control.
- Any unauthorized workload launch or output observed? No / Yes. On Yes, branch to a paragraph and
  ask the tester to also report it privately, using the contact the operator chose in decision 3.

### 5. Row 2.4 registration measurement (optional section)
- Did the operator session see the owner's distro? Absent with `WSL_E_DISTRO_NOT_FOUND` /
  Visible / Did not run.
- Did the own-distro root control succeed? Yes / No / Did not run.
- Will you share the raw owner and operator JSON privately? Yes / No.

### 6. Overall
- Linear scale 1–5: how clear were the install instructions?
- Linear scale 1–5: how confident are you that the package you ran is the one published?
- Paragraph: what should change before a wider release?
- Optional handle for credit in the record. Optional follow-up consent checkbox.

## Acceptance

- The script runs once and produces a form whose sections, required fields and SHA-256
  validation match this page. Submit one test response with a malformed hash and confirm refusal.
- Submit one valid test response, confirm it lands in the sheet, then delete it.
- The form's description names the package version and checksum, links the testing guide, states
  that the candidate is unsigned and not release-ready, and repeats the privacy rules.
- Nothing in the repository contains the form's URLs or IDs.

## Out of scope

Sharing the form, publishing the installer, or emailing testers. Each needs the operator's explicit
approval of the channel and the text.
