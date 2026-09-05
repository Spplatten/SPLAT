<!-- INTERNAL. Working target list for cold outreach, built for a start with no warm network.
     Segments are ordered by speed-to-cash, not by deal size. The named companies are archetype
     EXAMPLES to help pattern-match; nothing here asserts a verified need at any specific firm -
     confirm the pain from their own public writing before you send anything. -->

# Cold outreach: who to approach, and where to find them

Ordered by how fast they can say yes, not by how much they could eventually pay. Starting cold, the
scarce resource is replies, not prospects.

---

## Tier 1 — Engineer buyers with discretionary spend (days to decide)

### 1. Startups whose product executes user- or model-authored code
The sharpest pain in the market. If their product runs generated code, containment is already on their
risk register and probably assigned to someone.

- **Why now:** they cannot ship to enterprise customers without an answer to "what stops it."
- **Where to find them:** the Y Combinator company directory filtered to recent AI batches; Product
  Hunt AI-agent launches; "Show HN" posts for agent frameworks; GitHub topics `mcp`, `ai-agents`,
  `code-interpreter`, `agent-sandbox`.
- **Who to contact:** founding engineer or CTO. At this size, that is the buyer.
- **Opener angle:** the evidence file, and one specific question about *their* execution path.

### 2. Teams building MCP servers or agent platforms
They hit the containment problem directly and most ship with a plain subprocess.

- **Where to find them:** GitHub search for MCP server repos; issues and discussions containing
  "sandbox", "isolation", "untrusted code" in those repos. **An open issue about sandboxing is a
  buying signal with a name attached.**
- **Opener angle:** reply to the actual issue with substance first. Do not pitch in the issue.

### 3. AI consultancies and integrators building agents for clients
They must answer "is this safe" for every client, and they bill for the answer rather than absorbing it.

- **Where to find them:** LinkedIn search for "AI agent" + "consulting"; agencies posting agent case
  studies; firms hiring "AI platform engineer".
- **Opener angle:** partner framing, not vendor framing — you make their deliverable defensible.

---

## Tier 2 — The underserved Windows flank (your actual shipped strength)

### 4. MSPs and IT-automation shops running automation on client endpoints
Almost all agent-sandboxing work is Linux and container shaped. SPLAT's **shipped** half is Windows:
job objects, restricted tokens, ACL-jailed workspaces, secret scrubbing, and a chained audit ledger.
Nobody is selling that to Windows fleet operators.

- **Why now:** they are being asked to run AI automation on customer machines and carry the liability.
- **Where to find them:** r/msp; MSP community Slack and Discord groups; regional MSP association member
  lists; vendors' partner directories.
- **Who to contact:** owner or head of service delivery — small firms, direct decisions.
- **Opener angle:** the audit ledger and per-job lease, framed as *client-defensible evidence of what
  the automation touched*. This is a compliance story, not a kernel story.

### 5. Mid-size regulated firms that just deployed coding assistants
Fintech, health tech, legal tech — 100 to 1,000 people. Real budget, real obligations, and far faster
than a Fortune 500 security org.

- **Why now:** developers are using Copilot, Claude Code, or Cursor with local terminal/filesystem access.
  Cloud sandbox alternatives require shipping private company source code, databases, and IP to third-party
  cloud infrastructure—which compliance and legal teams immediately reject.
- **Where to find them:** LinkedIn job posts mentioning Copilot, Cursor, or Claude Code rollouts;
  companies publicly announcing internal AI programs.
- **Who to contact:** Head of Security or Head of Platform Engineering. **Not** the CISO cold.
- **Opener angle:** SPLAT runs locally on the developer's box on an unmodified kernel (stock WSL2), keeping
  code and execution entirely on-premises without cloud sandbox data exfiltration risk.
- **Caveat:** be honest that the ledger is unkeyed. Do not sell tamper-proof to a regulated buyer.

### 6. CI/CD & platform teams running agentic PR and build workflows
Untrusted PR code, third-party actions, and automated code generation create severe supply-chain execution risk.
A build step is an even better fit for a capability lease than a chat agent is: it is already declarative,
already short-lived, and already carries an execution manifest.

- **Why now:** teams want agents to review PRs, run tests, and execute fixes without giving malicious PRs
  ambient access to build runners or corporate CI secrets.
- **Where to find them:** GitHub discussions around CI security; teams maintaining GitHub Actions runners;
  DevOps engineers posting about automated agent CI pipelines.
- **Who to contact:** Head of DevOps, Platform Architect, or Lead Infrastructure Engineer.
- **Opener angle:** capability leases (task-scoped, time-boxed, destination-clamped) applied directly to
  build runner steps on stock kernels.

---

## Tier 3 — Amplifiers, not customers (the real fix for having no network)

### 7. Practitioners who write publicly about prompt injection and agent security
They will not buy. They can make you non-cold, which is worth more than any single deal right now.

- **Where to find them:** authors of prompt-injection writeups, maintainers of agent-security tooling,
  speakers at AI-security tracks, and active commenters on agent-safety threads.
- **The ask:** never a sale. "I recorded a kernel refusing three agent operations on a stock WSL2
  kernel and the evidence is machine-checked — would you tell me where it's weak?"
- **Why it works:** you are handing a domain expert something falsifiable and asking them to break it.
  That is a genuinely interesting invitation, and it costs them ten minutes.

---

## Working sheet — the first 25

Track these five columns and nothing else. Twenty-five well-chosen names beat two hundred scraped ones.

| # | Company | Segment | Person + role | Evidence they have this pain (link) | Sent | Reply |
| :- | :------ | :------ | :------------ | :---------------------------------- | :--- | :---- |

**Rule for the last column before "Sent":** if you cannot paste a link showing this specific company
has this specific problem — an open issue, a job post, a conference talk, a blog paragraph — do not
contact them yet. That link is the first line of your email, and without it you are sending spam.
