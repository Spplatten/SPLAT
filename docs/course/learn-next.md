# What to learn next as a beginner systems architect

Start with **programming fluency, debugging, and making small design decisions you can explain and test**. Pair the course's bottom-up study of the machine with top-down questions about users, requirements, cost and failure.

Use one additional practice session within your existing weekly study budget. Choose one resource at a time and apply it to a small program before moving on.

## Your first three priorities

| Priority | Learn | A concrete sign of progress |
| --- | --- | --- |
| 1. Read and change a small program | C# types, functions, collections, exceptions, interfaces and tests; then async and cancellation | You can explain a function's inputs, effects and failure cases, then change it and verify the result. |
| 2. Debug systematically | Breakpoints, stepping, stack traces, logs, small reproductions and Git diffs | You can find why a program failed and demonstrate that the fix addresses that cause. |
| 3. Turn a request into a design | User needs, constraints, data ownership, failure behavior and tradeoffs | You can describe a small solution on one page and explain why you chose it. |

C# is a useful first focus because it lets you work directly with this repository's Core and application code. Add enough C and Rust to follow the native boundaries as the course reaches them.

[Microsoft's introductory C# path](https://learn.microsoft.com/en-us/training/paths/get-started-c-sharp-part-1/) provides a starting point for syntax and basic programs. [MIT's Missing Semester](https://missing.csail.mit.edu/) covers command-line tools, development environments, debugging, profiling and Git. Its shell examples need the appropriate Unix shell; PowerShell has different syntax.

## Skills to add around the ten-week course

### 1. Requirements and measurable quality

Learn to ask who uses the system, what they need to accomplish, and what constraints matter. Constraints include privacy, supported devices, response time, budget, maintainability and the skills of the people operating it.

Replace a vague goal with a testable statement. For a practice job runner, “reliable” might become “after a restart, every accepted job has an explicit state and an uncertain job is never silently marked completed.” This is a proposed requirement, not a claim about SPLAT.

**Exercise:** write five requirements for your practice program. For each, name the observation that would show it failed. Include one deliberate non-goal to keep the project small.

### 2. Data structures, state and ownership

Learn lists, dictionaries, sets, queues and graphs. Learn what Big O describes: how work or storage grows with input size. Then connect those structures to real decisions: a dictionary finds a job by ID; a queue orders pending work; a graph represents stage dependencies.

For every important value, identify its authoritative owner, allowed changes and lifetime. A copied UI value, cache and database row can disagree unless the update rules are explicit.

**Exercise:** draw Pending → Running → Completed/Failed for a job. Add Cancelled and Interrupted only after defining their meanings. Decide which transitions survive restart and which component may perform them.

### 3. Basic mathematics and capacity estimates

Practice units, rates, percentages, Boolean logic and simple probability. Learn the difference between average latency and a percentile, and record workload size when comparing performance.

For example, 200 events/second × 500 bytes/event × 86,400 seconds/day is **8.64 GB/day in decimal units**, before indexes, metadata, backups or replication. That estimate helps you ask about retention before choosing storage.

**Exercise:** estimate your runner's daily event volume, then measure a sample. Explain why the estimate and measurement differ. Report wall time and memory with their units.

### 4. Databases and recovery

Deepen your understanding of primary keys, constraints, transactions, indexes, migrations and backups. Decide whether an operation must happen entirely or not at all. Learn what happens if the process stops between two writes.

A backup is useful when you can restore it and demonstrate that the restored application behaves correctly.

**Exercise:** keep practice data in a temporary SQLite database. Reject duplicate job IDs with a database constraint. Restore a backup into a separate directory and compare the recovered records. Add a schema field without losing existing rows.

### 5. Networking and partial failure

Trace one request through name resolution, connection establishment, application framing and response handling. Learn that a timeout can leave the result uncertain: the server may have completed an action while the reply was lost.

An idempotent operation can be repeated without adding another effect. A request ID is useful only if the receiver durably associates it with the result and checks duplicates appropriately.

**Exercise:** use a local fixture that records a completed job but drops its reply. Retry the same request and show whether you created a duplicate. Define the behavior before adding retry logic.

### 6. Security design and trust boundaries

Identify the assets, who may act on them, attacker-controlled inputs, and where authority is checked. Distinguish authentication, which establishes identity, from authorization, which decides the permitted action.

Draw the data flow and mark places where trust changes. Select a plausible misuse and write a test that proves the forbidden effect did not occur. OWASP describes threat modeling as a repeatable design activity that follows a system as it changes. [OWASP threat-modeling guidance](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html).

**Exercise:** pass a rejected identity to your practice runner. Assert both a rejected response and zero job starts. Add an allowed control so a program that rejects everyone cannot pass.

### 7. Operations and reliability

Learn configuration, startup/shutdown, health checks, logs, metrics, tracing, dependency updates and recovery procedures. Ask how someone will recognize and repair a failure when you are unavailable.

A service-level indicator is a measurement of behavior; an objective is the target you choose for it. Useful targets follow user needs and a defined observation window. [Google's introduction to service-level objectives](https://sre.google/sre-book/service-level-objectives/).

**Exercise:** give your runner a small operating note: how to start it, locate its data, recognize a failed job and recover after interruption. Have another person follow it without extra explanation.

### 8. Communication and architectural decisions

Practice explaining the system at different levels: who uses it, which applications communicate, and what the relevant modules own. C4 provides these levels of diagrams; start with the system context and add detail where it answers a question. [C4 diagram guidance](https://c4model.com/diagrams).

An architecture decision record can be short: context, options, choice, consequences and what evidence would make you reconsider. Include development effort and operating cost alongside technical behavior.

**Exercise:** compare keeping the practice runner in one process with splitting it into a service. State the requirement that would justify the split, the additional failure cases and the cost of operating it.

## One small project to connect the skills

Build a **local job notebook** in a separate learning directory. Begin with fixed in-memory operations such as counting words or computing a checksum; add external process execution later through the existing coursework seam.

| Stage | Add | Demonstrate before advancing |
| --- | --- | --- |
| 1 | A command-line program with a few fixed jobs | Valid input works; invalid input produces a clear error. |
| 2 | Typed job IDs and explicit states | Invalid transitions and duplicate IDs are rejected. |
| 3 | Temporary SQLite persistence | Restart preserves accepted records and identifies interrupted work. |
| 4 | Cancellation and a bounded queue | Queue-full and cancellation behavior are explicit and tested. |
| 5 | A fake remote worker | Lost replies and repeated requests do not silently duplicate effects. |
| 6 | A simple identity policy and trace | Rejected callers start no work; traces omit private payloads. |
| 7 | Recovery instructions and a design note | Someone else can understand, operate and recover the program. |

For each stage, follow the same cycle: predict the behavior, implement a small change, inject one failure, observe the result, and explain the tradeoff. Reuse the [course's contract lab](../../coursework/Splat.CourseLab/Program.cs) when you reach execution boundaries.

This is a practice-project specification; these additional stages have not been implemented by the guide.

## Go deeper when the fundamentals feel comfortable

| Interest | Resource | Start with |
| --- | --- | --- |
| How a computer is built from logic upward | [Nand to Tetris](https://www.nand2tetris.org/) | Logic-gate and arithmetic projects, then the CPU |
| Why operating systems behave as they do | [Operating Systems: Three Easy Pieces](https://pages.cs.wisc.edu/~remzi/OSTEP/) | Processes and address spaces, then concurrency and persistence |
| How systems are kept working in practice | [Google's SRE book](https://sre.google/sre-book/table-of-contents/) | Objectives, monitoring and troubleshooting |

Later specialization can include compiler construction, distributed consensus, advanced networking, cloud operations, kernel programming or formal verification. Choose according to the systems you want to build after completing a small program you can debug and recover.

## Your next four study sessions

1. **Programming:** build the smallest command-line job notebook and explain every line you wrote.
2. **Debugging:** introduce a wrong result, find it with a breakpoint, and preserve the case as a regression.
3. **Design:** write the five requirements, state diagram and authoritative data owner.
4. **Failure:** simulate an interrupted job and make the outcome explicit after restart.

You are developing architectural judgment when you can explain what a system promises, which component owns each promise, how it can fail, and what evidence supports your choice.
