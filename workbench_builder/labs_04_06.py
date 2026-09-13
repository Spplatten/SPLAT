# workbench_builder/labs_04_06.py
# Interactive definition for Labs 04, 05, and 06

def get_labs_04_06_js():
    return """
// LABS 04 - 06 DEFINITION
const LABS_04_06 = [
  // =========================================================================
  // LAB 04
  // =========================================================================
  {
    id: 4,
    volume: "Volume 04",
    tier: "Tier 2: Mechanics",
    shortTitle: "Zero-Copy Ringbuf & BOM Trap",
    title: "Zero-Copy BPF Ringbuf Framing & The UTF-8 BOM Trap",
    objective: "Master zero-copy shared memory ring buffer framing in BPF_MAP_TYPE_RINGBUF and debug the catastrophic UTF-8 BOM deserialization crash in Rust.",
    stages: [
      {
        title: "Stage 1: BPF Ring Buffer Header Framing & Pointer Math",
        theory: "BPF_MAP_TYPE_RINGBUF entries consist of a 4-byte header containing the payload length and commit flags (BPF_RINGBUF_BUSY_BIT = 0x80000000, BPF_RINGBUF_DISCARD_BIT = 0x40000000), followed by the payload, padded to the next 8-byte boundary. Allocation size is: round_up(4 + payload_len, 8).",
        task: "Enter a payload size in bytes and calculate the exact total memory allocated by bpf_ringbuf_reserve.",
        leftTitle: "RINGBUF ENTRY CALCULATOR",
        leftSub: "BPF_MAP_TYPE_RINGBUF",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:12px;">
            <div>
              <label style="color:#c9d1d9; font-size:12px; font-weight:600; display:block; margin-bottom:4px;">Payload Size (Bytes):</label>
              <input type="number" id="lab4_s1_payload" value="26" min="1" max="4096" style="width:100%; background:#161b22; border:1px solid #30363d; color:#fff; padding:6px 10px; border-radius:4px; font-family:var(--font-mono); font-size:12px;" oninput="LAB_RUNNERS.lab4_s1_calc()">
            </div>

            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:12px; font-family:var(--font-mono); font-size:12px; display:flex; flex-direction:column; gap:6px;">
              <div style="color:var(--accent-cyan); font-weight:700;">SLOT MEMORY BREAKDOWN:</div>
              <div style="color:#8b949e;">Header Size: <span style="color:#fff;">4 Bytes (uint32_t len | flags)</span></div>
              <div style="color:#8b949e;">Payload Size: <span style="color:#fff;" id="lab4_s1_disp_payload">26 Bytes</span></div>
              <div style="color:#8b949e;">Alignment Padding: <span style="color:var(--accent-amber);" id="lab4_s1_disp_pad">2 Bytes</span></div>
              <div style="color:var(--accent-green); font-weight:700; border-top:1px solid #30363d; padding-top:6px; margin-top:4px;">
                Total Allocated Slot: <span id="lab4_s1_disp_total">32 Bytes</span> (8-byte aligned)
              </div>
            </div>

            <div style="font-size:11.5px; color:#8b949e;">
              Formula: <code>(4 + payload + 7) & ~7</code>
            </div>
          </div>
        `,
        rightTitle: "RINGBUF POINTER ADVANCEMENT",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">KERNEL RING: bpf_ringbuf_reserve</span>
              <span style="color:#8b949e;">256 KB Buffer</span>
            </div>
            <div class="terminal-body" id="lab4_s1_term">
              <div class="term-line-dim">[SYS] Ready. Change payload size to test alignment calculation.</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab4_s1_verify()">▶ Verify Pointer Math</button>
              <button class="btn-action-next" id="lab4_s1_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          LAB_RUNNERS.lab4_s1_calc();
        }
      },

      {
        title: "Stage 2: Hex Dump Forensics & The UTF-8 BOM Hazard",
        theory: "A naive .NET StreamWriter(stream, Encoding.UTF8) prepends the 3-byte UTF-8 Byte Order Mark (0xEF, 0xBB, 0xBF). When passed into Rust's serde_json::from_slice, deserialization immediately fails with 'expected value at line 1 column 1'. SPLAT handles this zero-copy by slicing past the BOM (&buf[3..]) without heap allocation.",
        task: "Implement the zero-copy BOM stripper in Rust: if the first 3 bytes match 0xEF, 0xBB, 0xBF, return the slice starting at offset 3.",
        leftTitle: "RUST ZERO-COPY BOM SLICER",
        leftSub: "stream_parser.rs",
        renderLeft: (labId, sId) => `
          <div class="editor-container">
            <div class="editor-header">
              <span class="editor-filename">📄 stream_parser.rs</span>
              <div class="editor-actions">
                <button class="btn-editor" onclick="LAB_RUNNERS.lab4_s2_resetCode()">Reset Code</button>
              </div>
            </div>
            <div class="editor-main">
              <div class="editor-gutter" id="lab4_s2_gutter"></div>
              <textarea class="editor-textarea" id="lab4_s2_code" spellcheck="false"></textarea>
            </div>
          </div>
        `,
        rightTitle: "CARGO TEST RUNNER",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">CARGO TEST: test_strip_bom</span>
              <span style="color:#8b949e;">Zero-Allocation Check</span>
            </div>
            <div class="terminal-body" id="lab4_s2_term">
              <div class="term-line-dim">[CARGO] Ready. Implement the BOM stripper and click "Run Cargo Test".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab4_s2_verify()">▶ Run Cargo Test</button>
              <button class="btn-action-next" id="lab4_s2_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          const starter = `pub fn strip_utf8_bom(data: &[u8]) -> &[u8] {
    // Check if buffer begins with UTF-8 BOM [0xEF, 0xBB, 0xBF]
    if data.len() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
        &data[3..]
    } else {
        data
    }
}`;
          const ta = document.getElementById('lab4_s2_code');
          if (ta) {
            ta.value = SPLAT_APP.state.userCode['lab4_s2'] || starter;
            LAB_RUNNERS.updateGutter('lab4_s2_code', 'lab4_s2_gutter');
            ta.oninput = () => {
              LAB_RUNNERS.updateGutter('lab4_s2_code', 'lab4_s2_gutter');
              SPLAT_APP.state.userCode['lab4_s2'] = ta.value;
            };
          }
        }
      },

      {
        title: "Stage 3: Lock-Free Backpressure & Overflow Simulator",
        theory: "If the consumer drains the BPF ring buffer slower than the kernel produces audit events, the ring buffer fills up and bpf_ringbuf_reserve returns NULL, dropping critical audit logs. SPLAT uses adaptive polling with epoll backpressure to prevent packet loss.",
        task: "Adjust producer throughput and consumer polling frequency to maintain 0 dropped events under heavy load.",
        leftTitle: "TRAFFIC LOAD CONTROLS",
        leftSub: "EPoll Consumer",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:14px;">
            <div>
              <label style="color:#c9d1d9; font-size:12px; font-weight:600; display:flex; justify-content:space-between;">
                <span>Event Production Rate:</span>
                <span id="lab4_s3_prod_val" style="color:var(--accent-cyan);">20,000 evt/s</span>
              </label>
              <input type="range" id="lab4_s3_prod" min="5000" max="60000" step="5000" value="20000" style="width:100%;" oninput="LAB_RUNNERS.lab4_s3_update()">
            </div>

            <div>
              <label style="color:#c9d1d9; font-size:12px; font-weight:600; display:flex; justify-content:space-between;">
                <span>Consumer Drain Interval:</span>
                <span id="lab4_s3_drain_val" style="color:var(--accent-green);">10 ms</span>
              </label>
              <input type="range" id="lab4_s3_drain" min="5" max="100" step="5" value="10" style="width:100%;" oninput="LAB_RUNNERS.lab4_s3_update()">
            </div>

            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:12px; font-family:var(--font-mono); font-size:12px;">
              <div style="display:flex; justify-content:space-between; margin-bottom:6px;">
                <span style="color:var(--text-muted);">Ring Buffer Fullness:</span>
                <span id="lab4_s3_fill_pct" style="color:#fff;">35%</span>
              </div>
              <div style="width:100%; height:8px; background:#161b22; border-radius:4px; overflow:hidden;">
                <div id="lab4_s3_fill_bar" style="width:35%; height:100%; background:var(--accent-cyan); transition:width 0.2s;"></div>
              </div>
            </div>
          </div>
        `,
        rightTitle: "RINGBUF TELEMETRY MONITOR",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">TELEMETRY: ringbuf_perf_events</span>
              <span style="color:#8b949e;">Drop Counter</span>
            </div>
            <div class="terminal-body" id="lab4_s3_term">
              <div class="term-line-dim">[SYS] Ready. Click "Run 5-Second Load Test".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab4_s3_verify()">▶ Run 5-Second Load Test</button>
              <button class="btn-action-next" id="lab4_s3_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          LAB_RUNNERS.lab4_s3_update();
        }
      }
    ]
  },

  // =========================================================================
  // LAB 05
  // =========================================================================
  {
    id: 5,
    volume: "Volume 05",
    tier: "Tier 2: Mechanics",
    shortTitle: "1:1:1 State Machine & Grounding",
    title: "The 1:1:1 Governance State Machine & Cognitive Agent Loops",
    objective: "Enforce strict state progression through the 6-stage lifecycle and ground AI agent cognitive outputs against tamper-proof kernel telemetry logs.",
    stages: [
      {
        title: "Stage 1: State Transition Matrix Validator",
        theory: "The SPLAT execution state machine follows an irreversible unidirectional progression: Created (0) -> LeaseAcquired (1) -> SuspendedSpawn (2) -> Executing (3) -> TelemetryGrounded (4) -> Terminated (5). Any attempt to skip states (e.g. Created -> Executing) or rewind backwards results in immediate process quarantine.",
        task: "Test the state machine transition engine: execute legal transitions and observe how illegal jumps are intercepted and quarantined.",
        leftTitle: "STATE MACHINE CONTROLLER",
        leftSub: "CURRENT STATE: Created",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:12px;">
            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:12px; font-family:var(--font-mono); font-size:12px;">
              <span style="color:var(--text-muted);">ACTIVE STATE: </span>
              <span id="lab5_s1_cur_state" style="color:var(--accent-cyan); font-weight:700;">Created [0]</span>
            </div>

            <div style="font-size:12px; color:#c9d1d9;">Select Target Transition:</div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px;">
              <button class="btn-editor" onclick="LAB_RUNNERS.lab5_s1_step(1)">1: LeaseAcquired</button>
              <button class="btn-editor" onclick="LAB_RUNNERS.lab5_s1_step(2)">2: SuspendedSpawn</button>
              <button class="btn-editor" onclick="LAB_RUNNERS.lab5_s1_step(3)">3: Executing</button>
              <button class="btn-editor" onclick="LAB_RUNNERS.lab5_s1_step(4)">4: TelemetryGrounded</button>
              <button class="btn-editor" onclick="LAB_RUNNERS.lab5_s1_step(5)">5: Terminated</button>
              <button class="btn-editor" onclick="LAB_RUNNERS.lab5_s1_reset()" style="border-color:var(--accent-crimson);">Reset to Created</button>
            </div>
          </div>
        `,
        rightTitle: "GOVERNANCE STATE AUDITOR",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">FSM ENGINE: MissionStateMachine</span>
              <span style="color:#8b949e;">Audit Journal</span>
            </div>
            <div class="terminal-body" id="lab5_s1_term">
              <div class="term-line-dim">[FSM] Ready. Advance the state machine through the valid linear lifecycle 0 -> 1 -> 2 -> 3 -> 4 -> 5.</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab5_s1_verify()">▶ Audit Lifecycle Integrity</button>
              <button class="btn-action-next" id="lab5_s1_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          LAB_RUNNERS.lab5_s1_reset();
        }
      },

      {
        title: "Stage 2: Concurrency Race Condition Trap & Atomic CAS",
        theory: "When multiple worker threads attempt to claim an execution ticket simultaneously, naive check-then-set logic (if (state == 0) state = 1) suffers from a Time-of-Check to Time-of-Use (TOCTOU) race condition. In C#, Interlocked.CompareExchange must be used to guarantee single-lease issuance.",
        task: "Implement atomic lease acquisition using Interlocked.CompareExchange to eliminate double-lease vulnerabilities.",
        leftTitle: "C# ATOMIC LEASE ACQUISITION",
        leftSub: "LeaseManager.cs",
        renderLeft: (labId, sId) => `
          <div class="editor-container">
            <div class="editor-header">
              <span class="editor-filename">📄 LeaseManager.cs</span>
              <div class="editor-actions">
                <button class="btn-editor" onclick="LAB_RUNNERS.lab5_s2_resetCode()">Reset Code</button>
              </div>
            </div>
            <div class="editor-main">
              <div class="editor-gutter" id="lab5_s2_gutter"></div>
              <textarea class="editor-textarea" id="lab5_s2_code" spellcheck="false"></textarea>
            </div>
          </div>
        `,
        rightTitle: "CONCURRENT WORKER RACE SIMULATOR",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">RACE SIMULATOR: 100 Threads</span>
              <span style="color:#8b949e;">Ticket #42</span>
            </div>
            <div class="terminal-body" id="lab5_s2_term">
              <div class="term-line-dim">[TEST] Ready. Implement atomic CAS and click "Execute Race Simulation".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab5_s2_verify()">▶ Execute Race Simulation</button>
              <button class="btn-action-next" id="lab5_s2_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          const starter = `public static bool TryAcquireLease(ref int state)
{
    // Ensure thread-safe transition from Created (0) to LeaseAcquired (1)
    // Return true if and only if this thread successfully acquired the lease
    return Interlocked.CompareExchange(ref state, 1, 0) == 0;
}`;
          const ta = document.getElementById('lab5_s2_code');
          if (ta) {
            ta.value = SPLAT_APP.state.userCode['lab5_s2'] || starter;
            LAB_RUNNERS.updateGutter('lab5_s2_code', 'lab5_s2_gutter');
            ta.oninput = () => {
              LAB_RUNNERS.updateGutter('lab5_s2_code', 'lab5_s2_gutter');
              SPLAT_APP.state.userCode['lab5_s2'] = ta.value;
            };
          }
        }
      },

      {
        title: "Stage 3: Telemetry Grounder Fact-Checker",
        theory: "AI agents frequently hallucinate actions they never performed (e.g. claiming to have patched a file or made an HTTP request). The SPLAT Telemetry Grounder cross-references agent textual assertions against immutable kernel eBPF event traces, catching hallucinations before reports are committed.",
        task: "Verify agent claims against real eBPF kernel audit records to flag ungrounded actions.",
        leftTitle: "COGNITIVE AGENT CLAIM VS KERNEL AUDIT",
        leftSub: "Telemetry Cross-Checker",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:12px;">
            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:10px; font-family:var(--font-mono); font-size:11.5px;">
              <div style="color:var(--accent-purple); font-weight:700; margin-bottom:4px;">AGENT CLAIM:</div>
              <div style="color:#c9d1d9;">"Downloaded patch from https://10.0.0.5/update.tar.gz and wrote to /tmp/patch.bin"</div>
            </div>

            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:10px; font-family:var(--font-mono); font-size:11.5px;">
              <div style="color:var(--accent-green); font-weight:700; margin-bottom:4px;">KERNEL LSM TELEMETRY EVENTS:</div>
              <div style="color:#8b949e; line-height:1.6;">
                1. SYS_CONNECT: dest=10.0.0.5:443 [ALLOWED]<br>
                2. SYS_OPEN: file=/tmp/patch.bin mode=O_WRONLY [ALLOWED]
              </div>
            </div>

            <div style="font-size:12px; color:#c9d1d9;">Select Claim Verification Status:</div>
            <div style="display:flex; gap:10px;">
              <label style="cursor:pointer; display:flex; align-items:center; gap:6px;">
                <input type="radio" name="lab5_s3_status" value="grounded" checked>
                <span style="color:var(--accent-green);">GROUNDED (True claim)</span>
              </label>
              <label style="cursor:pointer; display:flex; align-items:center; gap:6px;">
                <input type="radio" name="lab5_s3_status" value="hallucinated">
                <span style="color:var(--accent-crimson);">HALLUCINATION</span>
              </label>
            </div>
          </div>
        `,
        rightTitle: "GROUNDING VERIFIER CONSOLE",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">GROUNDER: splat::telemetry_grounder</span>
              <span style="color:#8b949e;">Evidence Validation</span>
            </div>
            <div class="terminal-body" id="lab5_s3_term">
              <div class="term-line-dim">[SYS] Ready. Compare agent claims with kernel telemetry and click "Evaluate Grounding".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab5_s3_verify()">▶ Evaluate Grounding</button>
              <button class="btn-action-next" id="lab5_s3_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `
      }
    ]
  },

  // =========================================================================
  // LAB 06
  // =========================================================================
  {
    id: 6,
    volume: "Volume 06",
    tier: "Tier 2: Mechanics",
    shortTitle: "Memory Ownership Universes",
    title: "Memory Management & Ownership Universes",
    objective: "Overcome the eBPF 512-byte stack limit using per-CPU scratchpad maps, bridge Rust lifetimes with Box::into_raw, and prevent GC compaction pointer corruption in .NET 10.",
    stages: [
      {
        title: "Stage 1: eBPF 512-Byte Stack Frame Optimization",
        theory: "The Linux kernel restricts eBPF program stack frames to strictly 512 bytes. Allocating large arrays or path buffers (e.g. char path[512]) immediately trips the verifier error: 'looks like your program exceeds 512 bytes stack limit'. SPLAT allocates per-CPU scratchpad maps to handle large buffers.",
        task: "Refactor the C eBPF function to query the per-CPU array scratchpad map instead of allocating 512 bytes on the stack.",
        leftTitle: "C eBPF KERNEL SOURCE",
        leftSub: "path_filter.bpf.c",
        renderLeft: (labId, sId) => `
          <div class="editor-container">
            <div class="editor-header">
              <span class="editor-filename">📄 path_filter.bpf.c</span>
              <div class="editor-actions">
                <button class="btn-editor" onclick="LAB_RUNNERS.lab6_s1_resetCode()">Reset Code</button>
              </div>
            </div>
            <div class="editor-main">
              <div class="editor-gutter" id="lab6_s1_gutter"></div>
              <textarea class="editor-textarea" id="lab6_s1_code" spellcheck="false"></textarea>
            </div>
          </div>
        `,
        rightTitle: "BPF VERIFIER STACK FOOTPRINT",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">VERIFIER: bpf_check / check_stack_boundary</span>
              <span style="color:#8b949e;">Max: 512 Bytes</span>
            </div>
            <div class="terminal-body" id="lab6_s1_term">
              <div class="term-line-dim">[VERIFIER] Ready. Review scratchpad map code and click "Verify Stack Limit".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab6_s1_verify()">▶ Verify Stack Limit</button>
              <button class="btn-action-next" id="lab6_s1_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          const starter = `SEC("lsm/file_open")
int BPF_PROG(restrict_open, struct file *file)
{
    __u32 zero = 0;
    /* Use per-CPU scratchpad map to stay well under the 512-byte stack limit */
    char *scratch = bpf_map_lookup_elem(&splat_scratchpad, &zero);
    if (!scratch)
        return 0;

    /* Safe: stack frame size is under 64 bytes! */
    return 0;
}`;
          const ta = document.getElementById('lab6_s1_code');
          if (ta) {
            ta.value = SPLAT_APP.state.userCode['lab6_s1'] || starter;
            LAB_RUNNERS.updateGutter('lab6_s1_code', 'lab6_s1_gutter');
            ta.oninput = () => {
              LAB_RUNNERS.updateGutter('lab6_s1_code', 'lab6_s1_gutter');
              SPLAT_APP.state.userCode['lab6_s1'] = ta.value;
            };
          }
        }
      },

      {
        title: "Stage 2: Rust Lifetime & Box::into_raw FFI Pinning",
        theory: "When passing Rust objects across FFI boundaries into C callbacks, allowing Rust to drop the Box when the function exits creates an immediate use-after-free vulnerability. Calling Box::into_raw surrenders Rust's ownership, while Box::from_raw safely reclaims it during destruction.",
        task: "Implement safe ownership transfer across the C FFI boundary using Box::into_raw and Box::from_raw.",
        leftTitle: "RUST FFI BRIDGE",
        leftSub: "ffi_bridge.rs",
        renderLeft: (labId, sId) => `
          <div class="editor-container">
            <div class="editor-header">
              <span class="editor-filename">📄 ffi_bridge.rs</span>
              <div class="editor-actions">
                <button class="btn-editor" onclick="LAB_RUNNERS.lab6_s2_resetCode()">Reset Code</button>
              </div>
            </div>
            <div class="editor-main">
              <div class="editor-gutter" id="lab6_s2_gutter"></div>
              <textarea class="editor-textarea" id="lab6_s2_code" spellcheck="false"></textarea>
            </div>
          </div>
        `,
        rightTitle: "MIRROR VALGRIND / ASAN TEST",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">ASAN CHECK: ffi_lifetime_test</span>
              <span style="color:#8b949e;">0 Leaks / 0 UAF</span>
            </div>
            <div class="terminal-body" id="lab6_s2_term">
              <div class="term-line-dim">[ASAN] Ready. Verify Box conversion and click "Run Memory Safety Audit".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab6_s2_verify()">▶ Run Memory Safety Audit</button>
              <button class="btn-action-next" id="lab6_s2_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          const starter = `pub extern "C" fn splat_register_context(ctx: Box<AgentContext>) -> *mut AgentContext {
    // Surrender ownership to C host without invoking drop
    Box::into_raw(ctx)
}

pub extern "C" fn splat_destroy_context(ptr: *mut AgentContext) {
    if !ptr.is_null() {
        // Reclaim ownership and allow Rust to deallocate
        unsafe { drop(Box::from_raw(ptr)); }
    }
}`;
          const ta = document.getElementById('lab6_s2_code');
          if (ta) {
            ta.value = SPLAT_APP.state.userCode['lab6_s2'] || starter;
            LAB_RUNNERS.updateGutter('lab6_s2_code', 'lab6_s2_gutter');
            ta.oninput = () => {
              LAB_RUNNERS.updateGutter('lab6_s2_code', 'lab6_s2_gutter');
              SPLAT_APP.state.userCode['lab6_s2'] = ta.value;
            };
          }
        }
      },

      {
        title: "Stage 3: .NET GC Heap Compaction & Pinning Visualizer",
        theory: "The .NET Garbage Collector moves live objects in memory during Gen 2 heap compaction. If native C code holds an unpinned raw pointer (IntPtr) to a managed array, heap compaction silently moves the array, turning the native pointer into a catastrophic dangling pointer.",
        task: "Simulate GC compaction: observe pointer invalidation on unpinned memory, then apply GCHandleType.Pinned to keep the object stationary.",
        leftTitle: "MANAGED HEAP COMPACTION SIMULATOR",
        leftSub: ".NET 10 GC Engine",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:12px;">
            <div style="display:flex; justify-content:space-between; align-items:center; background:#161b22; padding:10px 14px; border-radius:6px; border:1px solid #30363d;">
              <span style="font-size:12px; color:var(--text-muted);">Managed Buffer Pointer:</span>
              <span id="lab6_s3_ptr" style="font-size:13px; font-weight:700; color:var(--accent-cyan); font-family:var(--font-mono);">0x7FF01040</span>
            </div>

            <div style="display:flex; gap:10px; font-size:12px;">
              <label style="cursor:pointer; display:flex; align-items:center; gap:6px;">
                <input type="checkbox" id="lab6_s3_pin">
                <span><strong>Pin Memory</strong> (GCHandleType.Pinned)</span>
              </label>
            </div>

            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:12px; font-family:var(--font-mono); font-size:11.5px;">
              <div style="color:var(--text-muted); margin-bottom:4px;">HEAP OBJECT ADDRESSES:</div>
              <div id="lab6_s3_obj_disp" style="color:#c9d1d9; line-height:1.6;">
                [Obj A: 0x7FF01000] (Dead)<br>
                [Obj B (Target): 0x7FF01040] (Live)<br>
                [Obj C: 0x7FF010A0] (Live)
              </div>
            </div>
          </div>
        `,
        rightTitle: "GC COMPACTION ENGINE CONSOLE",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">GC MONITOR: GC.Collect(2, GCCollectionMode.Compacting)</span>
              <span style="color:#8b949e;">Heap Compaction</span>
            </div>
            <div class="terminal-body" id="lab6_s3_term">
              <div class="term-line-dim">[GC] Ready. Toggle Pinning checkbox and click "Trigger GC Compaction".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab6_s3_verify()">▶ Trigger GC Compaction</button>
              <button class="btn-action-next" id="lab6_s3_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          LAB_RUNNERS.lab6_s3_update();
        }
      }
    ]
  }
];
"""
