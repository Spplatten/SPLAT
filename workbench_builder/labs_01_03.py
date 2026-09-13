# workbench_builder/labs_01_03.py
# Interactive definition for Labs 01, 02, and 03

def get_labs_01_03_js():
    return """
// LABS 01 - 03 DEFINITION
const LABS_01_03 = [
  // =========================================================================
  // LAB 01
  // =========================================================================
  {
    id: 1,
    volume: "Volume 01",
    tier: "Tier 1: Foundations",
    shortTitle: "Topology & Entry Points",
    title: "Multi-Language Environment Bootstrapping & Entry-Point Trace",
    objective: "Master the 1:1:1 multi-tier topology across .NET 10 host orchestrator, Rust bridge daemon, C eBPF kernel hooks, and constrained worker subprocesses.",
    stages: [
      {
        title: "Stage 1: Multi-Tier Topological Wiring Puzzle",
        theory: "SPLAT strictly mandates a 1:1:1 boundary: one host orchestrator (.NET 10 C#), one bridge daemon (Rust splat-agent), one Linux kernel security hook (eBPF LSM in C), and one isolated worker (AppContainer/cgroup). Bypassing the bridge daemon or allowing unauthenticated host-worker communication violates kernel governance invariants.",
        task: "Configure the four critical interconnect protocols to establish the airtight SPLAT runtime pipeline.",
        leftTitle: "TOPOLOGY CONNECTION SCHEMATIC",
        leftSub: "SYSTEM INTERCONNECT",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:14px;">
            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:12px; font-family:var(--font-mono); font-size:12px;">
              <div style="color:var(--accent-cyan); font-weight:700; margin-bottom:8px;">1:1:1 TOPOLOGY SCHEMATIC</div>
              <div style="line-height:1.7; color:#8b949e;">
                [Host Orchestrator (.NET 10)]<br>
                &nbsp;&nbsp;&nbsp;&nbsp;│ ──(1) Host-to-Bridge Protocol──►<br>
                [Bridge Daemon (Rust splat-agent)]<br>
                &nbsp;&nbsp;&nbsp;&nbsp;├──(2) Kernel Policy Hook──► [eBPF LSM (C)]<br>
                &nbsp;&nbsp;&nbsp;&nbsp;└──(3) Process Containment──► [Constrained Worker]
              </div>
            </div>

            <div style="display:flex; flex-direction:column; gap:10px; font-size:12.5px;">
              <div>
                <label style="color:#c9d1d9; font-weight:600; display:block; margin-bottom:4px;">(1) Host-to-Bridge Channel:</label>
                <select id="lab1_s1_p1" style="width:100%; background:#161b22; border:1px solid #30363d; color:#fff; padding:6px 8px; border-radius:4px; font-family:var(--font-mono);">
                  <option value="raw_http">Unauthenticated HTTP/1.1 (TCP Port 8080)</option>
                  <option value="uds_jsonrpc" selected>Authenticated JSON-RPC over Unix Domain Socket / Named Pipe</option>
                  <option value="shared_mem">Raw Shared Memory without sync primitives</option>
                </select>
              </div>

              <div>
                <label style="color:#c9d1d9; font-weight:600; display:block; margin-bottom:4px;">(2) Bridge-to-Kernel Hook Channel:</label>
                <select id="lab1_s1_p2" style="width:100%; background:#161b22; border:1px solid #30363d; color:#fff; padding:6px 8px; border-radius:4px; font-family:var(--font-mono);">
                  <option value="bpf_maps" selected>BPF Hash Maps (splat_leases) & Ring Buffer</option>
                  <option value="ptrace">ptrace(PTRACE_ATTACH) sys_enter hook</option>
                  <option value="signals">POSIX Signals (SIGSTOP / SIGCONT)</option>
                </select>
              </div>

              <div>
                <label style="color:#c9d1d9; font-weight:600; display:block; margin-bottom:4px;">(3) Bridge-to-Worker Spawn Channel:</label>
                <select id="lab1_s1_p3" style="width:100%; background:#161b22; border:1px solid #30363d; color:#fff; padding:6px 8px; border-radius:4px; font-family:var(--font-mono);">
                  <option value="system">libc system() command execution</option>
                  <option value="fork_raw">fork() without unshare() namespaces</option>
                  <option value="suspended_spawn" selected>Suspended Spawn + Token Stripping (Windows) / clone3 + unshare (Linux)</option>
                </select>
              </div>

              <div>
                <label style="color:#c9d1d9; font-weight:600; display:block; margin-bottom:4px;">(4) Kernel Enforced Gatekeeper:</label>
                <select id="lab1_s1_p4" style="width:100%; background:#161b22; border:1px solid #30363d; color:#fff; padding:6px 8px; border-radius:4px; font-family:var(--font-mono);">
                  <option value="ld_preload">LD_PRELOAD wrapper library</option>
                  <option value="lsm_hooks" selected>LSM Hooks: bprm_check_security + file_open</option>
                  <option value="seccomp_only">seccomp-bpf system call filter alone</option>
                </select>
              </div>
            </div>
          </div>
        `,
        rightTitle: "TOPOLOGY VALIDATOR & AUDIT TRACE",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">TERMINAL: /bin/splat-verify-topology</span>
              <span style="color:#8b949e;">eBPF Core Ring</span>
            </div>
            <div class="terminal-body" id="lab1_s1_term">
              <div class="term-line-dim">[SYS] Ready. Select interconnect channels and click "Verify Topology Architecture".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab1_s1_verify()">▶ Verify Topology Architecture</button>
              <button class="btn-action-next" id="lab1_s1_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `
      },

      {
        title: "Stage 2: CLI Parameter Injection & Security Gate",
        theory: "The splat-agent daemon is configured via command-line arguments. In production, parameter injection bugs can expose network ports (0.0.0.0), trigger path traversal (../../etc/shadow), or grant root privileges (workload UID 0). Strict parameter validation is the first defense line.",
        task: "Inspect CLI arguments for splat-agent and run security tests against injection attacks to configure a hardened daemon.",
        leftTitle: "DAEMON LAUNCH CONFIGURATION",
        leftSub: "CLI FLAGS INSPECTOR",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:12px;">
            <div>
              <label style="color:#c9d1d9; font-size:12px; font-weight:600; display:block; margin-bottom:4px;">--listen [Host IP:Port]:</label>
              <input type="text" id="lab1_s2_listen" value="127.0.0.1:50051" style="width:100%; background:#161b22; border:1px solid #30363d; color:#fff; padding:6px 10px; border-radius:4px; font-family:var(--font-mono); font-size:12px;">
            </div>

            <div>
              <label style="color:#c9d1d9; font-size:12px; font-weight:600; display:block; margin-bottom:4px;">--auth-token-file [Absolute Path]:</label>
              <input type="text" id="lab1_s2_auth" value="/var/run/splat/auth.token" style="width:100%; background:#161b22; border:1px solid #30363d; color:#fff; padding:6px 10px; border-radius:4px; font-family:var(--font-mono); font-size:12px;">
            </div>

            <div>
              <label style="color:#c9d1d9; font-size:12px; font-weight:600; display:block; margin-bottom:4px;">--workload-uid [Integer]:</label>
              <input type="number" id="lab1_s2_uid" value="1001" style="width:100%; background:#161b22; border:1px solid #30363d; color:#fff; padding:6px 10px; border-radius:4px; font-family:var(--font-mono); font-size:12px;">
            </div>

            <div>
              <label style="color:#c9d1d9; font-size:12px; font-weight:600; display:block; margin-bottom:4px;">--mock-bpf [Boolean]:</label>
              <select id="lab1_s2_mock" style="width:100%; background:#161b22; border:1px solid #30363d; color:#fff; padding:6px 10px; border-radius:4px; font-family:var(--font-mono); font-size:12px;">
                <option value="false" selected>false (Production Kernel LSM)</option>
                <option value="true">true (Development Mock Mode - INSECURE FOR PROD)</option>
              </select>
            </div>

            <div style="display:flex; flex-direction:column; gap:6px; margin-top:8px;">
              <span style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono);">SECURITY TEST PRESETS:</span>
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px;">
                <button class="btn-editor" onclick="LAB_RUNNERS.lab1_s2_setPreset('exploit_net')">Exploit: Bind 0.0.0.0</button>
                <button class="btn-editor" onclick="LAB_RUNNERS.lab1_s2_setPreset('exploit_root')">Exploit: UID 0 Root</button>
                <button class="btn-editor" onclick="LAB_RUNNERS.lab1_s2_setPreset('exploit_traversal')">Exploit: Path Traversal</button>
                <button class="btn-editor" onclick="LAB_RUNNERS.lab1_s2_setPreset('hardened')">Apply Hardened</button>
              </div>
            </div>
          </div>
        `,
        rightTitle: "CLI SECURITY EVALUATOR",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">EVALUATOR: splat_agent::cli_parser</span>
              <span style="color:#8b949e;">Argument Guard</span>
            </div>
            <div class="terminal-body" id="lab1_s2_term">
              <div class="term-line-dim">[SYS] Ready. Select presets or configure custom flags, then click "Audit CLI Parameters".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab1_s2_verify()">▶ Audit CLI Parameters</button>
              <button class="btn-action-next" id="lab1_s2_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `
      },

      {
        title: "Stage 3: Subprocess Environment Variable Sanitization",
        theory: "Child processes inherit the parent's environment variables by default. If an attacker injects variables such as LD_PRELOAD, PYTHONPATH, or manipulates PATH, they can hijack shared libraries or binary execution during worker process spawning.",
        task: "Implement the environment sanitization algorithm: strip dangerous variables (LD_PRELOAD, LD_LIBRARY_PATH, PYTHONPATH, NODE_OPTIONS) and enforce a normalized secure PATH.",
        leftTitle: "C# SANITIZATION IMPLEMENTATION",
        leftSub: "ProcessLauncher.cs",
        renderLeft: (labId, sId) => `
          <div class="editor-container">
            <div class="editor-header">
              <span class="editor-filename">📄 ProcessLauncher.cs</span>
              <div class="editor-actions">
                <button class="btn-editor" onclick="LAB_RUNNERS.lab1_s3_resetCode()">Reset Code</button>
              </div>
            </div>
            <div class="editor-main">
              <div class="editor-gutter" id="lab1_s3_gutter"></div>
              <textarea class="editor-textarea" id="lab1_s3_code" spellcheck="false"></textarea>
            </div>
          </div>
        `,
        rightTitle: "UNIT TEST SUITE",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">DOTNET TEST: EnvironmentSanitizerTests</span>
              <span style="color:#8b949e;">4 Test Cases</span>
            </div>
            <div class="terminal-body" id="lab1_s3_term">
              <div class="term-line-dim">[TEST] Ready. Review code and click "Run Test Suite".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab1_s3_verify()">▶ Run Test Suite</button>
              <button class="btn-action-next" id="lab1_s3_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          const starter = `public static Dictionary<string, string> SanitizeEnvironment(Dictionary<string, string> env)
{
    var clean = new Dictionary<string, string>();
    var dangerousKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "NODE_OPTIONS", "RUBYOPT"
    };

    foreach (var kvp in env)
    {
        // TODO: Strip dangerous variables
        if (dangerousKeys.Contains(kvp.Key)) continue;

        // TODO: Normalize PATH to standard safe directory
        if (kvp.Key.Equals("PATH", StringComparison.OrdinalIgnoreCase))
        {
            clean["PATH"] = "/usr/bin:/bin:/usr/local/bin";
            continue;
        }

        clean[kvp.Key] = kvp.Value;
    }

    return clean;
}`;
          const ta = document.getElementById('lab1_s3_code');
          if (ta) {
            ta.value = SPLAT_APP.state.userCode['lab1_s3'] || starter;
            LAB_RUNNERS.updateGutter('lab1_s3_code', 'lab1_s3_gutter');
            ta.oninput = () => {
              LAB_RUNNERS.updateGutter('lab1_s3_code', 'lab1_s3_gutter');
              SPLAT_APP.state.userCode['lab1_s3'] = ta.value;
            };
          }
        }
      }
    ]
  },

  // =========================================================================
  // LAB 02
  // =========================================================================
  {
    id: 2,
    volume: "Volume 02",
    tier: "Tier 1: Foundations",
    shortTitle: "Alignment & Kernel dev_t",
    title: "Binary Alignment, Struct Packing & The Kernel dev_t Bug",
    objective: "Eliminate memory padding holes in binary C/Rust contracts and diagnose the catastrophic device encoding divergence between glibc st_dev and Linux kernel s_dev.",
    stages: [
      {
        title: "Stage 1: Visual Struct Memory Layout Optimizer",
        theory: "In 64-bit architectures, natural alignment requires 8-byte integers to align on 8-byte boundaries, 4-byte integers on 4-byte boundaries, etc. Poor field ordering forces the compiler to insert dead padding bytes, increasing cache footprint and cache misses.",
        task: "Reorder the fields of LeasePolicyStruct using the Move buttons so that 8-byte words align naturally. Reduce struct size from 40 bytes to 24 bytes with 0 padding bytes!",
        leftTitle: "STRUCT FIELD CONTROLS & SIZING",
        leftSub: "LeasePolicyStruct",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:12px;">
            <div style="display:flex; justify-content:space-between; align-items:center; background:#161b22; padding:10px 14px; border-radius:6px; border:1px solid #30363d;">
              <div>
                <span style="font-size:12px; color:var(--text-muted);">Current Total Size: </span>
                <span id="lab2_s1_size" style="font-size:14px; font-weight:700; color:var(--accent-crimson); font-family:var(--font-mono);">40 Bytes</span>
              </div>
              <div>
                <span style="font-size:12px; color:var(--text-muted);">Padding Holes: </span>
                <span id="lab2_s1_pad" style="font-size:14px; font-weight:700; color:var(--accent-crimson); font-family:var(--font-mono);">16 Bytes</span>
              </div>
            </div>

            <div class="struct-field-list" id="lab2_s1_field_list">
              <!-- Rendered dynamically -->
            </div>
          </div>
        `,
        rightTitle: "64-BIT WORD MEMORY MAPPER",
        renderRight: (labId, sId) => `
          <div style="display:flex; flex-direction:column; height:400px; background:#090c10; border:1px solid var(--border-color); border-radius:8px; overflow:hidden;">
            <div class="terminal-header">
              <span class="terminal-title">MEMORY MAP: 8-BYTE ROWS (64-BIT ALIGNED)</span>
              <span style="color:#8b949e;">Green: Data | Red: Padding</span>
            </div>
            <div style="flex:1; padding:14px; overflow-y:auto;" id="lab2_s1_grid_container">
              <!-- Memory grid rendered dynamically -->
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab2_s1_verify()">▶ Verify Struct Optimization</button>
              <button class="btn-action-next" id="lab2_s1_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          LAB_RUNNERS.lab2_s1_init();
        }
      },

      {
        title: "Stage 2: Bitwise Bitmask Slicer & The Kernel dev_t Decoder",
        theory: "glibc's st_dev encodes the major number in bits 8..19 and minor in bits 0..7. The Linux kernel's internal s_dev packs major into bits 20..31: (major << 20) | minor. Passing raw st_dev from userspace into an eBPF hash map lookup key causes a lookup mismatch, breaking LSM filesystem enforcement!",
        task: "Input Major/Minor numbers (e.g. Major: 8, Minor: 1 for /dev/sda1) and analyze the bitwise divergence between glibc and kernel representations.",
        leftTitle: "DEVICE NUMBER BIT SLICER",
        leftSub: "st_dev vs s_dev",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:14px;">
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
              <div>
                <label style="color:#c9d1d9; font-size:12px; font-weight:600; display:block; margin-bottom:4px;">Device Major Number:</label>
                <input type="number" id="lab2_s2_major" value="8" min="0" max="4095" style="width:100%; background:#161b22; border:1px solid #30363d; color:#fff; padding:6px 10px; border-radius:4px; font-family:var(--font-mono); font-size:12px;" oninput="LAB_RUNNERS.lab2_s2_calc()">
              </div>
              <div>
                <label style="color:#c9d1d9; font-size:12px; font-weight:600; display:block; margin-bottom:4px;">Device Minor Number:</label>
                <input type="number" id="lab2_s2_minor" value="1" min="0" max="1048575" style="width:100%; background:#161b22; border:1px solid #30363d; color:#fff; padding:6px 10px; border-radius:4px; font-family:var(--font-mono); font-size:12px;" oninput="LAB_RUNNERS.lab2_s2_calc()">
              </div>
            </div>

            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:12px; font-family:var(--font-mono); font-size:11.5px; display:flex; flex-direction:column; gap:8px;">
              <div style="color:var(--accent-cyan); font-weight:700;">GLIBC st_dev ENCODING:</div>
              <div style="color:#c9d1d9;" id="lab2_s2_glibc_hex">Hex: 0x00000801</div>
              <div style="color:#8b949e; word-break:break-all;" id="lab2_s2_glibc_bin">Bits: 00000000 00000000 00001000 00000001</div>

              <div style="color:var(--accent-green); font-weight:700; margin-top:8px;">LINUX KERNEL s_dev ENCODING:</div>
              <div style="color:#c9d1d9;" id="lab2_s2_kernel_hex">Hex: 0x00800001</div>
              <div style="color:#8b949e; word-break:break-all;" id="lab2_s2_kernel_bin">Bits: 00000000 10000000 00000000 00000001</div>
            </div>

            <div style="font-size:12px; color:var(--accent-amber); background:rgba(255,183,0,0.1); border:1px solid rgba(255,183,0,0.3); padding:8px 10px; border-radius:4px;">
              ⚠ Notice how bit 8 in glibc maps to bit 20 in the kernel. A hash map lookup with raw st_dev will never match!
            </div>
          </div>
        `,
        rightTitle: "SOCRATIC KERNEL BUG AUDIT",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">AUDIT: kernel::fs::dev_t_encoder</span>
              <span style="color:#8b949e;">eBPF Map Matcher</span>
            </div>
            <div class="terminal-body" id="lab2_s2_term">
              <div class="term-line-dim">[SYS] Ready. Inspect the bitwise formulas above.</div>
              <div class="term-line-info">[Q] Which C macro correctly normalizes glibc st_dev into Linux kernel s_dev?</div>
              <div style="margin-top:10px; display:flex; flex-direction:column; gap:6px;">
                <label style="cursor:pointer; display:flex; align-items:center; gap:8px;">
                  <input type="radio" name="lab2_s2_answer" value="1">
                  <span>A) <code>#define TO_S_DEV(dev) (dev)</code></span>
                </label>
                <label style="cursor:pointer; display:flex; align-items:center; gap:8px;">
                  <input type="radio" name="lab2_s2_answer" value="2">
                  <span>B) <code>#define TO_S_DEV(dev) ((major(dev) &lt;&lt; 20) | minor(dev))</code></span>
                </label>
                <label style="cursor:pointer; display:flex; align-items:center; gap:8px;">
                  <input type="radio" name="lab2_s2_answer" value="3">
                  <span>C) <code>#define TO_S_DEV(dev) (dev &gt;&gt; 12)</code></span>
                </label>
              </div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab2_s2_verify()">▶ Verify Formula</button>
              <button class="btn-action-next" id="lab2_s2_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          LAB_RUNNERS.lab2_s2_calc();
        }
      },

      {
        title: "Stage 3: Live eBPF Struct Alignment & Verifier Patch",
        theory: "The eBPF kernel verifier rejects unaligned 64-bit loads with 'misaligned stack access off (0x0 + 4) size 8'. To guarantee zero verifier rejections across Clang optimizations, binary structs passed over BPF ringbuf must feature explicit padding or 8-byte field alignment.",
        task: "Patch the C event struct so that timestamp_ns is placed at an 8-byte aligned offset and total struct size is a multiple of 8.",
        leftTitle: "C eBPF CONTRACT HEADER",
        leftSub: "splat_event.h",
        renderLeft: (labId, sId) => `
          <div class="editor-container">
            <div class="editor-header">
              <span class="editor-filename">📄 splat_event.h</span>
              <div class="editor-actions">
                <button class="btn-editor" onclick="LAB_RUNNERS.lab2_s3_resetCode()">Reset Code</button>
              </div>
            </div>
            <div class="editor-main">
              <div class="editor-gutter" id="lab2_s3_gutter"></div>
              <textarea class="editor-textarea" id="lab2_s3_code" spellcheck="false"></textarea>
            </div>
          </div>
        `,
        rightTitle: "eBPF VERIFIER SIMULATOR",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">KERNEL VERIFIER: libbpf / bpf_prog_load</span>
              <span style="color:#8b949e;">Alignment Check</span>
            </div>
            <div class="terminal-body" id="lab2_s3_term">
              <div class="term-line-dim">[VERIFIER] Ready. Review struct alignment and click "Validate with eBPF Verifier".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab2_s3_verify()">▶ Validate with eBPF Verifier</button>
              <button class="btn-action-next" id="lab2_s3_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          const starter = `struct splat_event {
    __u32 pid;
    __u32 _pad1;          /* Explicit 4-byte padding to align 64-bit field */
    __u64 timestamp_ns;   /* 8-byte aligned at offset 8 */
    __u16 event_type;     /* Offset 16 */
    __u16 _pad2;          /* Explicit 2-byte padding */
    __u32 _pad3;          /* Explicit 4-byte padding -> total 24 bytes */
};`;
          const ta = document.getElementById('lab2_s3_code');
          if (ta) {
            ta.value = SPLAT_APP.state.userCode['lab2_s3'] || starter;
            LAB_RUNNERS.updateGutter('lab2_s3_code', 'lab2_s3_gutter');
            ta.oninput = () => {
              LAB_RUNNERS.updateGutter('lab2_s3_code', 'lab2_s3_gutter');
              SPLAT_APP.state.userCode['lab2_s3'] = ta.value;
            };
          }
        }
      }
    ]
  },

  // =========================================================================
  // LAB 03
  // =========================================================================
  {
    id: 3,
    volume: "Volume 03",
    tier: "Tier 1: Foundations",
    shortTitle: "Windows Token & AppContainer",
    title: "Windows Suspended-Spawn, Token Stripping & AppContainer Jails",
    objective: "Implement zero-trust Windows process containment using CreateProcessAsUser suspended spawn, token privilege stripping, and capability-isolated AppContainer sandboxes.",
    stages: [
      {
        title: "Stage 1: Windows Token Privilege Deconstruction",
        theory: "Windows processes inherit powerful privileges by default. SeDebugPrivilege enables injecting DLLs into lsass.exe or any system process; SeImpersonatePrivilege enables local privilege escalation via named pipe potato attacks. SPLAT strips all dangerous privileges before releasing suspended threads.",
        task: "Strip all high-risk privileges from the worker access token, leaving only harmless essential privileges like SeChangeNotifyPrivilege.",
        leftTitle: "TOKEN PRIVILEGE AUDITOR",
        leftSub: "ADJUSTTOKENPRIVILEGES",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:12px;">
            <div style="display:flex; justify-content:space-between; align-items:center; background:#161b22; padding:10px 14px; border-radius:6px; border:1px solid #30363d;">
              <span style="font-size:12px; color:var(--text-muted);">Privilege Attack Surface:</span>
              <span id="lab3_s1_risk" style="font-size:14px; font-weight:700; color:var(--accent-crimson); font-family:var(--font-mono);">100% CRITICAL</span>
            </div>

            <div style="display:flex; flex-direction:column; gap:8px; font-size:12px;" id="lab3_s1_priv_list">
              <!-- Dynamically populated -->
            </div>
          </div>
        `,
        rightTitle: "SECURITY BLAST-RADIUS ANALYZER",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">SECURITY SCANNER: splat::win32::token</span>
              <span style="color:#8b949e;">Restricted Token</span>
            </div>
            <div class="terminal-body" id="lab3_s1_term">
              <div class="term-line-dim">[SYS] Ready. Toggle privileges on the left, then click "Apply Token Policy".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab3_s1_verify()">▶ Apply Token Policy</button>
              <button class="btn-action-next" id="lab3_s1_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          LAB_RUNNERS.lab3_s1_init();
        }
      },

      {
        title: "Stage 2: P/Invoke Parameter Assembly for Suspended Spawn",
        theory: "Spawning an AppContainer process requires calling CreateProcess with CREATE_SUSPENDED (0x4) and EXTENDED_STARTUPINFO_PRESENT (0x80000). The STARTUPINFOEX structure wraps an opaque ProcThreadAttributeList containing the SECURITY_CAPABILITIES pointer.",
        task: "Complete the C# P/Invoke logic to combine the creation flags and initialize the attribute list pointer correctly.",
        leftTitle: "C# WIN32 P/INVOKE WRAPPER",
        leftSub: "AppContainerLauncher.cs",
        renderLeft: (labId, sId) => `
          <div class="editor-container">
            <div class="editor-header">
              <span class="editor-filename">📄 AppContainerLauncher.cs</span>
              <div class="editor-actions">
                <button class="btn-editor" onclick="LAB_RUNNERS.lab3_s2_resetCode()">Reset Code</button>
              </div>
            </div>
            <div class="editor-main">
              <div class="editor-gutter" id="lab3_s2_gutter"></div>
              <textarea class="editor-textarea" id="lab3_s2_code" spellcheck="false"></textarea>
            </div>
          </div>
        `,
        rightTitle: "WIN32 API TEST SUITE",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">TEST RUNNER: Win32ProcessTests</span>
              <span style="color:#8b949e;">3 Test Cases</span>
            </div>
            <div class="terminal-body" id="lab3_s2_term">
              <div class="term-line-dim">[TEST] Ready. Verify P/Invoke flags and click "Run P/Invoke Test".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab3_s2_verify()">▶ Run P/Invoke Test</button>
              <button class="btn-action-next" id="lab3_s2_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          const starter = `public static uint GetAppContainerCreationFlags()
{
    // Required: CREATE_SUSPENDED (0x00000004) | EXTENDED_STARTUPINFO_PRESENT (0x00080000)
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;

    return CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT;
}`;
          const ta = document.getElementById('lab3_s2_code');
          if (ta) {
            ta.value = SPLAT_APP.state.userCode['lab3_s2'] || starter;
            LAB_RUNNERS.updateGutter('lab3_s2_code', 'lab3_s2_gutter');
            ta.oninput = () => {
              LAB_RUNNERS.updateGutter('lab3_s2_code', 'lab3_s2_gutter');
              SPLAT_APP.state.userCode['lab3_s2'] = ta.value;
            };
          }
        }
      },

      {
        title: "Stage 3: AppContainer Capability Stripping & Network Isolation",
        theory: "By default, AppContainer sandboxes block all network sockets and file system access outside their dedicated package folder. However, granting internetClient or privateNetworkClientServer permits outbound TCP/UDP traffic.",
        task: "Strip all network capabilities and run simulated attack probes to verify that the worker cannot contact internal or external networks.",
        leftTitle: "CAPABILITY POLICY MATRIX",
        leftSub: "SECURITY_CAPABILITIES",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:14px;">
            <div style="font-size:12.5px; color:#c9d1d9;">Select AppContainer capabilities to grant to the child process:</div>

            <div style="display:flex; flex-direction:column; gap:10px; font-size:12px;">
              <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                <input type="checkbox" id="lab3_s3_cap_net">
                <span><code>internetClient</code> (Outbound Internet Traffic)</span>
              </label>

              <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                <input type="checkbox" id="lab3_s3_cap_lan">
                <span><code>privateNetworkClientServer</code> (Inbound/Outbound LAN)</span>
              </label>

              <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                <input type="checkbox" id="lab3_s3_cap_docs">
                <span><code>documentsLibrary</code> (Access Host Documents)</span>
              </label>
            </div>

            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:12px; font-family:var(--font-mono); font-size:11.5px;">
              <div style="color:var(--accent-cyan); font-weight:700; margin-bottom:6px;">CONTAINMENT SPECIFICATION:</div>
              <div style="color:#8b949e;">Strict Zero-Network isolation policy requires 0 network capability SIDs.</div>
            </div>
          </div>
        `,
        rightTitle: "PROBE HARNESS & ACCESS MONITOR",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">MONITOR: AppContainer Probe Suite</span>
              <span style="color:#8b949e;">4 Probes</span>
            </div>
            <div class="terminal-body" id="lab3_s3_term">
              <div class="term-line-dim">[SYS] Ready. Uncheck all capabilities for zero-trust isolation, then click "Execute Attack Probes".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab3_s3_verify()">▶ Execute Attack Probes</button>
              <button class="btn-action-next" id="lab3_s3_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `
      }
    ]
  }
];
"""
