# Volume 04: Zero-Copy Streaming & Shared Memory Ring Buffers

## Master Table of Contents
1. [High-Throughput Telemetry in Kernel Containment](#1-high-throughput-telemetry-in-kernel-containment)
2. [Architecture of `BPF_MAP_TYPE_RINGBUF`](#2-architecture-of-bpf_map_type_ringbuf)
3. [The Reserve/Submit Pattern vs. Perf Event Buffers](#3-the-reservesubmit-pattern-vs-perf-event-buffers)
4. [User-Space Ring Drain & Zero-Copy Pointer Casting](#4-user-space-ring-drain--zero-copy-pointer-casting)
5. [The Inter-Process Protocol Stream: Windows Bridge to Linux Guest](#5-the-inter-process-protocol-stream-windows-bridge-to-linux-guest)
6. [The Fatal Byte Order Mark (BOM) Hazard in Line Protocols](#6-the-fatal-byte-order-mark-bom-hazard-in-line-protocols)
7. [Line-by-Line Code Breakdown: Ring Buffers & Streaming](#7-line-by-line-code-breakdown-ring-buffers--streaming)
8. [Step-by-Step Numerical Walkthrough: Ring Buffer Head/Tail Advancements](#8-step-by-step-numerical-walkthrough-ring-buffer-headtail-advancements)
9. [Interactive University Checkpoints & Debugging Puzzles](#9-interactive-university-checkpoints--debugging-puzzles)

---

## 1. High-Throughput Telemetry in Kernel Containment

When a security policy enforces execution boundaries within the kernel, reporting violations to user-space auditing systems must satisfy four uncompromising constraints:
1. **Deterministic Containment Under Load**: Telemetry generation must never delay or prevent security enforcement. Even if telemetry buffers overflow, the kernel's denial decision (`-EPERM`) must remain absolute.
2. **Zero In-Kernel Memory Allocations**: BPF programs run in atomic kernel contexts where page allocation (`kmalloc`) is prohibited.
3. **Hardware Sympathy & Low Latency**: Security events must travel from kernel context to user-space audit queues without unnecessary data copies.
4. **Resilience Against Denial of Service**: A rogue subprocess triggering millions of failed syscalls per second must not exhaust host memory or lock up the kernel.

---

## 2. Architecture of `BPF_MAP_TYPE_RINGBUF`

Linux kernel 5.8 introduced `BPF_MAP_TYPE_RINGBUF`, replacing the legacy `BPF_MAP_TYPE_PERF_EVENT_ARRAY`. The BPF ring buffer is a high-performance **Multiple-Producer, Single-Consumer (MPSC)** memory-mapped queue:

```
+─────────────────────────────────────────────────────────────────────────────+
| KERNEL BPF RING BUFFER MEMORY MAP                                           |
+─────────────────────────────────────────────────────────────────────────────+
| Page 0: Consumer Page (Read-Only to Kernel, Read-Write to User Space)       |
|   - consumer_pos (u64): Tracks the byte offset consumed by user space       |
+─────────────────────────────────────────────────────────────────────────────+
| Page 1: Producer Page (Read-Write to Kernel, Read-Only to User Space)       |
|   - producer_pos (u64): Tracks the byte offset reserved by kernel producers |
+─────────────────────────────────────────────────────────────────────────────+
| Data Pages (Power of 2 Size: e.g., 1 MiB = 256 Pages of 4 KiB)              |
|   - Holds variable-length records.                                          |
|   - Mapped TWICE continuously in virtual memory:                            |
|     [ Data Page 0 .. 255 ] followed immediately by [ Data Page 0 .. 255 ]   |
|     This double-mapping allows records straddling the ring boundary to be   |
|     accessed as contiguous memory without wrapping logic!                   |
+─────────────────────────────────────────────────────────────────────────────+
```

```
RECORD STRUCTURE IN RING BUFFER MEMORY:
+-------------------+-------------------+-------------------------------------+
| Header (8 Bytes)  | Struct Payload    | Trailing Zero Padding               |
| Length (u32) +    | violation_event   | (Padded to 8-byte alignment)        |
| Flags (u32)       | (36 Bytes)        | (4 Bytes)                           |
+-------------------+-------------------+-------------------------------------+
```

---

## 3. The Reserve/Submit Pattern vs. Perf Event Buffers

In legacy perf event arrays, an event must be constructed in a temporary BPF per-CPU array scratchpad and then copied into the perf ring via `bpf_perf_event_output()`. This introduces memory copying and requires statically sizing per-CPU buffers.

In contrast, `BPF_MAP_TYPE_RINGBUF` implements a two-phase **Reserve/Submit** protocol:

```
PHASE 1: RESERVATION
BPF Program executes:
  struct violation_event *e = bpf_ringbuf_reserve(&violations, sizeof(*e), 0);
  
Kernel Actions:
  1. Atomically increments producer_pos by (sizeof(*e) + 8).
  2. Sets the record header's BUSY flag.
  3. Returns a direct pointer to the allocated memory inside the data page!

PHASE 2: IN-PLACE POPULATION
BPF Program writes directly to fields:
  e->cgroup_id = cgid;
  e->pid       = pid;
  e->hook      = hook;
  e->detail    = detail;

PHASE 3: SUBMISSION
BPF Program executes:
  bpf_ringbuf_submit(e, 0);

Kernel Actions:
  1. Clears the BUSY flag on the record header.
  2. Issues memory barrier to ensure payload writes are visible before header update.
  3. Wakes up the user-space polling thread if notifications are active.
```

If the ring buffer is exhausted (`producer_pos - consumer_pos + size > ring_size`), `bpf_ringbuf_reserve` returns `NULL`. SPLAT handles this gracefully: the hook returns `-EPERM` immediately, ensuring the operation is denied even when telemetry cannot be recorded.

---

## 4. User-Space Ring Drain & Zero-Copy Pointer Casting

In `splat-agent` (`native/splat-agent/src/main.rs`), a dedicated OS thread polls the ring buffer using `libbpf-rs`:

```rust
let violations_map = &skel.maps.violations;
let mut rb = RingBufferBuilder::new();
rb.add(violations_map, move |data: &[u8]| {
    if data.len() >= std::mem::size_of::<RawViolationEvent>() {
        // Zero-copy pointer cast: directly view the memory-mapped slice as a struct
        let raw = unsafe { &*(data.as_ptr() as *const RawViolationEvent) };
        let event = ViolationEvent::from_raw(raw);
        let _ = ringbuf_viol_tx.send(event);
    }
    0
})?;
let built_rb = rb.build()?;
std::thread::spawn(move || {
    while let Ok(_) = built_rb.poll(Duration::from_millis(100)) {}
});
```

Because `data: &[u8]` points directly into the memory-mapped ring buffer pages shared with the kernel, user space reads the violation payload with zero buffer copies.

---

## 5. The Inter-Process Protocol Stream: Windows Bridge to Linux Guest

Communication between the Windows host (`WslLeasedExecutor`) and the Linux guest (`splat-agent`) occurs over a bidirectional, newline-delimited JSON-RPC stream:

```
+─────────────────────────────────────────────────────────────────────────────+
| BIDIRECTIONAL WIRE PROTOCOL FRAMING                                         |
+─────────────────────────────────────────────────────────────────────────────+
| Request Frame (Windows -> Linux):                                           |
|   {"type":"EXECUTE_TOOL","protocolVersion":2,"authToken":"...","command":   |
|    "/bin/sh","argv":["-c","cat /etc/shadow"],...}\n                         |
|                                                                             |
| Stream Chunks (Linux -> Windows):                                           |
|   {"type":"STDOUT","data":"line 1 content\n"}\n                             |
|   {"type":"VIOLATION","cgroupId":4170,"pid":108,"hook":2,"detail":12048}\n  |
|   {"type":"STDERR","data":"cat: /etc/shadow: Operation not permitted\n"}\n  |
|   {"type":"EXIT","exitCode":1}\n                                            |
+─────────────────────────────────────────────────────────────────────────────+
```

### Unbounded Memory DoS Defense
A fundamental vulnerability in line-delimited stream readers is that `read_line()` will allocate memory continuously until it encounters `\n`. An attacker opening a raw connection could stream gigabytes of continuous non-newline bytes, causing the daemon to exhaust its memory.

SPLAT protects against this in `native/splat-agent/src/main.rs`:

```rust
const MAX_FRAME_BYTES: usize = 1024 * 1024; // 1 MiB Hard Ceiling

async fn read_frame(reader: &mut (impl AsyncBufRead + Unpin), line: &mut String) -> Result<usize> {
    line.clear();
    // take(MAX_FRAME_BYTES + 1) reads at most 1,048,577 bytes
    let read = reader.take(MAX_FRAME_BYTES as u64 + 1).read_line(line).await?;
    if read > MAX_FRAME_BYTES && !line.ends_with('\n') {
        bail!("a request frame may not exceed {MAX_FRAME_BYTES} bytes");
    }
    Ok(read)
}
```

---

## 6. The Fatal Byte Order Mark (BOM) Hazard in Line Protocols

During the development of `WslLeasedExecutor.cs`, an elusive deserialization defect was uncovered. When invoking a tool, `splat-agent` rejected every request with:

```text
Invalid JSON request: expected value at line 1 column 1
```

### The Root Cause
In C#, constructing a `StreamWriter` with `Encoding.UTF8` defaults to prepending the Unicode Byte Order Mark:

```
UTF-8 BOM Preamble: [0xEF, 0xBB, 0xBF]
```

While the BOM is valid in file headers to denote Unicode encoding, on a network socket stream it represents three illegal preamble bytes preceding the JSON opening brace `{`. The serde JSON parser inside the Rust daemon halted at byte 0, reporting that `0xEF` is an invalid token.

```
STREAM CORRUPTION VIA DEFAULT ENCODING:
  Wire Hex: EF BB BF 7B 22 74 79 70 65 22 3A ...
  Chars:    [BOM]    {  "  t  y  p  e  "  : ...
                     ▲
                     Rust serde expected '{' here; rejected with error!

CORRECTED IMPLEMENTATION (NO BOM):
  using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
  Wire Hex: 7B 22 74 79 70 65 22 3A ...
  Chars:    {  "  t  y  p  e  "  : ...
```

---

## 7. Line-by-Line Code Breakdown: Ring Buffers & Streaming

### 7.1 In-Kernel Violation Reporting (`lease_lsm.bpf.c`)

```c
// Lines 130-141: Non-Blocking Telemetry Reservation
static __always_inline void report(__u64 cgid, __u32 hook, __u32 detail)
{
    struct violation_event *e = bpf_ringbuf_reserve(&violations, sizeof(*e), 0);
    if (!e)
        return; // Ring buffer full: drop telemetry, but proceed to return -EPERM!
    e->cgroup_id = cgid;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->hook = hook;
    e->detail = detail;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}
```
*Architectural Rationale:* Notice the `if (!e) return;`. Telemetry submission is decoupled from security enforcement. In a denial-of-service scenario where the ring buffer is flooded, the BPF program drops the telemetry event but the hook still executes `return -EPERM`. Containment never hinges on telemetry availability.

---

## 8. Step-by-Step Numerical Walkthrough: Ring Buffer Head/Tail Advancements

Let us trace the internal byte offsets of a 1 MiB (`1,048,576` byte) BPF ring buffer during three successive violation events:

- `sizeof(struct violation_event)` = 36 bytes.
- Ring header = 8 bytes.
- Total slot size = 44 bytes $\rightarrow$ rounded to 8-byte alignment = 48 bytes.

| Sequence Point | `producer_pos` | `consumer_pos` | Delta (Bytes Queued) | State / Action |
| :---: | :---: | :---: | :---: | :--- |
| **Genesis** | `0` | `0` | `0` | Buffer empty. Consumer waiting on epoll. |
| **Event 1 Reserved** | `48` | `0` | `48` | Hook 1 reserves slot `[0..48]`. Header flag set to `BUSY`. |
| **Event 1 Submitted**| `48` | `0` | `48` | Header flag cleared. Notification signaled. |
| **Event 2 Reserved** | `96` | `0` | `96` | Hook 2 reserves slot `[48..96]`. |
| **Event 2 Submitted**| `96` | `0` | `96` | Header flag cleared. |
| **Consumer Reads 1** | `96` | `48` | `48` | User-space worker consumes Event 1; updates `consumer_pos`. |
| **Consumer Reads 2** | `96` | `96` | `0` | User-space worker consumes Event 2; buffer empty. |
| **Wraparound** | `1,048,624` | `1,048,576` | `48` | Offsets advance monotonically; modulo arithmetic handles wrap. |

---

## 9. Interactive University Checkpoints & Debugging Puzzles

### Checkpoint 4.1: The Argument Vector Splitting Vulnerability
**Scenario:** Version 1 of the daemon protocol accepted `arguments` as a single pre-formatted string: `"/bin/sh", "-c 'python3 script.py'"` and used `arguments.split_whitespace()` to construct the `argv` array.
- **Question:** What happens when an agent executes a Python one-liner with spaces: `python3 -c "print('hello world')"`?
- **Solution:** Splitting on whitespace destroys the quoting context. The string splits into:
  1. `python3`
  2. `-c`
  3. `'print('hello`
  4. `world')'`
  Python evaluates `'print('hello` as an unterminated string literal, resulting in an unrecoverable `SyntaxError`. In Version 2, arguments must be transmitted as an explicit `argv` array of strings, ensuring arguments containing spaces remain intact across the wire.

### Checkpoint 4.2: The Spurious Allow on Expired Leases
**Scenario:** A developer writes a cleanup loop that removes a lease from the BPF maps *before* terminating the workload processes running in that cgroup.
- **Question:** Why does deleting the map entries before killing the processes result in an immediate security breach?
- **Solution:** In SPLAT's BPF hooks, the first check evaluates:
  ```c
  if (!is_leased(cgid)) return 0; // Allow
  ```
  If the daemon deletes the cgroup ID from `leased_cgroups` while a rogue process is still running inside that cgroup, any subsequent exec, open, or connect operation performed by the process evaluates `is_leased(cgid) == false`. The kernel immediately permits the action without restriction! The daemon must always terminate all processes within the cgroup *before* unregistering the lease maps.
