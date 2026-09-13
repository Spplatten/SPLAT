# Week 5 — files, databases and evidence integrity

## Lesson A: a path is a name, not an object

**Outcome:** explain traversal, links and check/use races.

Filesystems translate names into objects and enforce permissions during access. A normalized path beginning with the workspace text can still be misleading: a similarly named sibling is outside, and a junction inside the workspace may redirect elsewhere.

[WorkspaceGuard](../../src/splat-mcp/WorkspaceGuard.cs) opens handles, resolves their final locations and uses verified handles for access. Trace OpenForRead and OpenForWrite separately: creation and replacement make the write case different. Reopening a path after checking it asks the filesystem a new question and can introduce a time-of-check/time-of-use race.

This Windows MCP guard and the Linux inode deny-list protect different operations. Do not transfer the Windows workspace guarantee to a Linux workload merely because both use a directory called a workspace.

## Lesson B: durable state and trustworthy state

**Outcome:** distinguish transactions, persistence, hashing and keyed authentication.

[SqliteStorageContext](../../src/MissionController.Infrastructure.Data/SqliteStorageContext.cs) configures WAL and synchronous NORMAL. WAL supports readers while writes are logged, but still has a single writer at a time. Checkpointing and synchronization policy affect durability; a transaction being committed is not an unconditional power-loss guarantee under every setting. [SQLite's WAL reference](https://www.sqlite.org/wal.html).

[AppendLogAsync](../../src/MissionController.Infrastructure.Data/SqliteChainedAuditLedger.cs) reads the previous hash and inserts the next row in one transaction. The chain commits to a salted digest of Details so controlled retention can remove plaintext without simply breaking every later link. Verification must still connect displayed details to their commitment.

A hash chain can reveal changes relative to a trusted anchor; an attacker able to replace the complete unkeyed chain can recompute it. HMAC additionally depends on a secret. Neither proves that the original event description was true, and a Merkle membership proof alone does not prove that an export contains every event. [HMACSHA256 reference](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha256).

## Lab: a temporary ledger with an unavailable key

~~~powershell
.\coursework\Run-Course.ps1 -Gate Regression
rg -n 'GetHmacKeyAsync|BeginTransactionAsync|DetailsCommitment|VerifyLedgerIntegrityAsync' src/MissionController.Infrastructure.Data/SqliteChainedAuditLedger.cs
~~~

1. Read the temporary-database setup in [AuditPayloadAndPreExecutionAuthTests](../../tests/MissionController.Tests/AuditPayloadAndPreExecutionAuthTests.cs).
2. Follow the existing cases for edited details, fake redaction, real redaction and keyed verification.
3. Build a credential-vault fixture that throws on retrieval. Keep its database separate from the operator's live ledger.
4. Record today's behavior when that configured vault becomes unavailable. Compare it with a proposed explicit “key required” mode.
5. Design assertions for no unkeyed append in required mode, preserved cancellation and intentional unkeyed development mode.

Expected baseline: existing tamper regressions pass. The key-required behavior is a proposed repair, not a guarantee the current constructor expresses.

**Cybersecurity case:** availability fallback can change the trust model. Losing access to a signing key must not silently make a required keyed ledger unkeyed.

**Repair practice:** ticket R3. First define the mode at composition, then patch key retrieval and append/verification behavior together. Document recovery for existing ledgers; do not rewrite history automatically.

**Submit:** file-handle trace, temporary-ledger test and trust-anchor explanation.

**Check yourself:** Does a valid hash prove a sensor's statement? Is NORMAL synonymous with maximum power-loss durability?

**Answer checkpoint:** no. Integrity, event truth and physical durability are separate properties.
