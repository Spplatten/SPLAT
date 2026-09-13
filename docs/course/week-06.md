# Week 6 — IPC, networking and identity

## Lesson A: a stream needs a protocol

**Outcome:** trace arguments and output across process and machine boundaries.

MCP enters through standard input/output in [Program.cs](../../src/splat-mcp/Program.cs). The guest bridge uses TCP and newline-delimited JSON. TCP transports an ordered byte stream, not application messages: a frame may arrive across several reads, and several frames may share a read.

[WslLeasedExecutor](../../src/MissionController.Infrastructure.Linux/WslLeasedExecutor.cs) sends protocolVersion 2 and argv as an array using UTF-8 without a BOM. The daemon emits STDOUT, STDERR, VIOLATION and EXIT frames. Trace a structured violation separately from diagnostic stderr.

Framing needs budgets. A read-until-newline call can accumulate an arbitrarily long line if no limit exists before allocation. A timeout bounds time, not necessarily bytes. A bounded parser must distinguish malformed, incomplete and oversized input without logging secrets.

## Lesson B: principal, destination and data policy

**Outcome:** identify three independent questions at an external boundary.

Who may request the effect? [HandleToolsCallAsync](../../src/splat-mcp/McpServerHandler.cs) resolves the actor before dispatch. The Rust daemon independently validates its shared token before accepting tool execution. The trusted principal of a local stdio process is not automatically a remote HTTP identity.

Where may data go? The tool's egress policy and the model gateway's egress policy differ. [EgressFirewallHandler](../../src/MissionController.Infrastructure.Network/EgressFirewallHandler.cs) scopes approved FQDNs; [HardenedHttpClientFactory](../../src/MissionController.Infrastructure.Network/HardenedHttpClientFactory.cs) disables automatic redirects so a redirected request cannot silently bypass that check.

What may be sent? Credential filtering and DLP transform payloads before downstream consumers. TLS protects a connection; it does not decide whether a model should receive the data or whether the caller was authorized.

## Lab: choose one protocol repair

~~~powershell
rg -n 'ReadLineAsync|read_line|protocolVersion|authToken' src/splat-mcp src/MissionController.Infrastructure.Linux native/splat-agent/src/main.rs
rg -n 'CompileTemplatePolicy|GetHostAddresses|127.0.0.1' src tests
~~~

1. Draw both transports and label which principal authenticates at each.
2. Read [WslLeasedExecutorWireTests](../../tests/MissionController.Tests/WslLeasedExecutorWireTests.cs): no BOM, intact fields, token requirement and structured violation.
3. Choose R1 (DNS) or R4 (bounded framing) from [repair tickets](repair-tickets.md).
4. For DNS, inject a resolver that succeeds, returns only IPv6, or throws. Verify that failed resolution never grants a new loopback destination.
5. For framing, use an in-memory reader with a split Unicode sequence, exactly-at-limit frame, one-byte-over frame and EOF without a delimiter.

Expected: wire preservation tests remain green; the newly specified repair has its own failing baseline before implementation.

**Cybersecurity case:** authentication can precede execution while parsing still consumes unbounded resources. Ordering a token check correctly does not establish a complete denial-of-service boundary.

**Repair practice:** an FQDN resolution failure currently causes the compiler to add 127.0.0.1. Refuse unresolved policy rather than substitute authority. First identify actual CompileTemplatePolicy callers; the MCP command handler also constructs leases directly.

**Submit:** byte/frame diagram, caller-identity trace and resolver or framing regression.

**Check yourself:** Are TCP reads message boundaries? Does a model's approved host authorize the sensor's network?

**Answer checkpoint:** neither. Application framing and separately scoped destination policy are required.
