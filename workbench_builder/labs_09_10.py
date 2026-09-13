# workbench_builder/labs_09_10.py
# Interactive definition for Labs 09 and 10

def get_labs_09_10_js():
    return """
// LABS 09 - 10 DEFINITION
const LABS_09_10 = [
  // =========================================================================
  // LAB 09
  // =========================================================================
  {
    id: 9,
    volume: "Volume 09",
    tier: "Tier 3: Mastery",
    shortTitle: "Live BPF-LSM & x64 Assembly",
    title: "Live In-Kernel BPF-LSM Programming & Disassembly Analysis",
    objective: "Author production Linux Security Module (LSM) hooks in eBPF C, step through x64 Windows syscall assembly instructions, and resolve kernel verifier unbounded pointer rejections.",
    stages: [
      {
        title: "Stage 1: Production BPF-LSM Hook Implementation",
        theory: "The bprm_check_security LSM hook fires whenever any process invokes execve(). SPLAT retrieves the current cgroup ID via bpf_get_current_cgroup_id(). If the process belongs to a managed lease, it inspects the executable path and returns -EPERM (-1) to kill unauthorized binaries before a single user-space instruction runs.",
        task: "Implement the bprm_check_security hook: look up the policy map and return -1 (-EPERM) if an unauthorized executable is launched.",
        leftTitle: "C eBPF LSM HOOK",
        leftSub: "lease_lsm.bpf.c",
        renderLeft: (labId, sId) => `
          <div class="editor-container">
            <div class="editor-header">
              <span class="editor-filename">📄 lease_lsm.bpf.c</span>
              <div class="editor-actions">
                <button class="btn-editor" onclick="LAB_RUNNERS.lab9_s1_resetCode()">Reset Code</button>
              </div>
            </div>
            <div class="editor-main">
              <div class="editor-gutter" id="lab9_s1_gutter"></div>
              <textarea class="editor-textarea" id="lab9_s1_code" spellcheck="false"></textarea>
            </div>
          </div>
        `,
        rightTitle: "IN-KERNEL EXECUTION TRACER",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">KERNEL LSM: bprm_check_security</span>
              <span style="color:#8b949e;">Sandbox Enforcement</span>
            </div>
            <div class="terminal-body" id="lab9_s1_term">
              <div class="term-line-dim">[LSM] Ready. Implement the security hook and click "Test In-Kernel Enforcement".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab9_s1_verify()">▶ Test In-Kernel Enforcement</button>
              <button class="btn-action-next" id="lab9_s1_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          const starter = `SEC("lsm/bprm_check_security")
int BPF_PROG(splat_bprm_check, struct linux_binprm *bprm)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct lease_policy *policy = bpf_map_lookup_elem(&splat_leases, &cgroup_id);
    if (!policy)
        return 0; /* Unmanaged host process: allow */

    /* Enforce binary whitelist for isolated agent */
    if (policy->is_restricted) {
        /* Block unauthorized shell execution */
        return -1; /* -EPERM */
    }

    return 0;
}`;
          const ta = document.getElementById('lab9_s1_code');
          if (ta) {
            ta.value = SPLAT_APP.state.userCode['lab9_s1'] || starter;
            LAB_RUNNERS.updateGutter('lab9_s1_code', 'lab9_s1_gutter');
            ta.oninput = () => {
              LAB_RUNNERS.updateGutter('lab9_s1_code', 'lab9_s1_gutter');
              SPLAT_APP.state.userCode['lab9_s1'] = ta.value;
            };
          }
        }
      },

      {
        title: "Stage 2: x64 Assembly Stepper & Windows Syscall Sequence",
        theory: "Under the Windows x64 ABI, executing a system call uses the 'syscall' instruction. Because syscall overwrites RCX with the return RIP and R11 with RFLAGS, the kernel fastcall convention moves the first argument from RCX into R10 before executing the syscall instruction.",
        task: "Step through the 4-instruction x64 assembly sequence for NtSetInformationJobObject and observe CPU registers and privilege transitions.",
        leftTitle: "x64 DISASSEMBLY STEPPER",
        leftSub: "NtSetInformationJobObject",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:12px;">
            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:10px; font-family:var(--font-mono); font-size:12px;">
              <div id="asm_line_0" style="padding:4px; border-radius:3px;">0x7FF01010: <span style="color:var(--accent-purple);">mov</span> r10, rcx &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:#6272a4;">; Save JobHandle into r10</span></div>
              <div id="asm_line_1" style="padding:4px; border-radius:3px;">0x7FF01013: <span style="color:var(--accent-purple);">mov</span> eax, 0x002A &nbsp;&nbsp;&nbsp;&nbsp;<span style="color:#6272a4;">; Syscall SSN: NtSetInfoJob</span></div>
              <div id="asm_line_2" style="padding:4px; border-radius:3px;">0x7FF01018: <span style="color:var(--accent-cyan); font-weight:700;">syscall</span> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:#6272a4;">; Ring 3 -> Ring 0 Transition</span></div>
              <div id="asm_line_3" style="padding:4px; border-radius:3px;">0x7FF0101A: <span style="color:var(--accent-purple);">ret</span> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:#6272a4;">; Return NTSTATUS in RAX</span></div>
            </div>

            <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px; font-family:var(--font-mono); font-size:11px;">
              <div style="background:#161b22; padding:6px; border-radius:4px; border:1px solid #30363d;">RIP: <span id="reg_rip" style="color:#fff;">0x7FF01010</span></div>
              <div style="background:#161b22; padding:6px; border-radius:4px; border:1px solid #30363d;">RAX: <span id="reg_rax" style="color:var(--accent-amber);">0x00000000</span></div>
              <div style="background:#161b22; padding:6px; border-radius:4px; border:1px solid #30363d;">RCX: <span id="reg_rcx" style="color:var(--accent-cyan);">0x000004A8</span></div>
              <div style="background:#161b22; padding:6px; border-radius:4px; border:1px solid #30363d;">R10: <span id="reg_r10" style="color:var(--accent-green);">0x00000000</span></div>
            </div>

            <div style="display:flex; gap:8px;">
              <button class="btn-editor" onclick="LAB_RUNNERS.lab9_s2_step()">Step Instruction (F10)</button>
              <button class="btn-editor" onclick="LAB_RUNNERS.lab9_s2_reset()">Reset CPU</button>
            </div>
          </div>
        `,
        rightTitle: "CPU HARDWARE REGISTERS CONSOLE",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">CPU STATE: x86_64 User Mode (Ring 3)</span>
              <span style="color:#8b949e;">GDB Stepper</span>
            </div>
            <div class="terminal-body" id="lab9_s2_term">
              <div class="term-line-dim">[CPU] Ready. Click "Step Instruction" to execute the syscall sequence.</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab9_s2_verify()">▶ Complete Syscall Step</button>
              <button class="btn-action-next" id="lab9_s2_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          LAB_RUNNERS.lab9_s2_reset();
        }
      },

      {
        title: "Stage 3: BPF Verifier Unbounded Pointer Diagnostics",
        theory: "The Linux kernel eBPF verifier uses abstract interpretation to prove program termination and memory safety. If code performs pointer arithmetic with a variable offset without proving that the offset is bounded (e.g. if (offset >= MAX_LEN) return -1;), the verifier aborts with 'R1 invalid mem access 'inv''.",
        task: "Inspect the raw verifier log, identify the unbounded pointer arithmetic, and patch the C code with an explicit upper-bound check.",
        leftTitle: "C eBPF PACKET PARSER",
        leftSub: "verifier_patch.c",
        renderLeft: (labId, sId) => `
          <div class="editor-container">
            <div class="editor-header">
              <span class="editor-filename">📄 verifier_patch.c</span>
              <div class="editor-actions">
                <button class="btn-editor" onclick="LAB_RUNNERS.lab9_s3_resetCode()">Reset Code</button>
              </div>
            </div>
            <div class="editor-main">
              <div class="editor-gutter" id="lab9_s3_gutter"></div>
              <textarea class="editor-textarea" id="lab9_s3_code" spellcheck="false"></textarea>
            </div>
          </div>
        `,
        rightTitle: "KERNEL VERIFIER LOG ANALYZER",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">KERNEL LOG: /dev/bpf_verifier</span>
              <span style="color:#8b949e;">Verification Failure</span>
            </div>
            <div class="terminal-body" id="lab9_s3_term">
              <div class="term-line-dim">0: (79) r1 = *(u64 *)(r10 - 8)</div>
              <div class="term-line-dim">1: (69) r2 = *(u16 *)(r1 + 0)</div>
              <div class="term-line-dim">2: (0f) r1 += r2</div>
              <div class="term-line-fail">R1 invalid mem access 'inv' (unbounded offset in R2)</div>
              <div class="term-line-warn">Hint: Insert 'if (offset >= 256) return -1;' before dereference.</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab9_s3_verify()">▶ Recompile & Verify</button>
              <button class="btn-action-next" id="lab9_s3_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          const starter = `int parse_payload(char *buf, __u16 offset)
{
    /* REQUIRED: Prove to verifier that offset is bounded! */
    if (offset >= 256)
        return -1;

    char val = buf[offset];
    return (int)val;
}`;
          const ta = document.getElementById('lab9_s3_code');
          if (ta) {
            ta.value = SPLAT_APP.state.userCode['lab9_s3'] || starter;
            LAB_RUNNERS.updateGutter('lab9_s3_code', 'lab9_s3_gutter');
            ta.oninput = () => {
              LAB_RUNNERS.updateGutter('lab9_s3_code', 'lab9_s3_gutter');
              SPLAT_APP.state.userCode['lab9_s3'] = ta.value;
            };
          }
        }
      }
    ]
  },

  // =========================================================================
  // LAB 10
  // =========================================================================
  {
    id: 10,
    volume: "Volume 10",
    tier: "Tier 3: Mastery",
    shortTitle: "VSOCK, WFP & Certification",
    title: "Retrospective, WFP Callout & Capstone Certification",
    objective: "Design hypervisor-isolated VSOCK channels, trace Windows Filtering Platform network callouts, and pass the Master Systems Engineering credential exam.",
    stages: [
      {
        title: "Stage 1: Hyper-V VSOCK vs Loopback Peer Authentication",
        theory: "Loopback TCP (127.0.0.1) is vulnerable to local port hijacking: any process on the machine can bind the port or sniff packets. In contrast, Hyper-V AF_VSOCK routes traffic through the hypervisor memory bus using Context IDs (VMID), guaranteeing cryptographically verified peer identity.",
        task: "Compare TCP Loopback vs AF_VSOCK security guarantees and verify hypervisor peer isolation.",
        leftTitle: "IPC PROTOCOL COMPARISON",
        leftSub: "TCP vs AF_VSOCK vs Named Pipes",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:10px; font-size:12px;">
            <table class="bit-slicer-table">
              <thead>
                <tr>
                  <th>Feature</th>
                  <th>TCP Loopback</th>
                  <th>AF_VSOCK</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td style="text-align:left;">Network Stack</td>
                  <td>TCP/IP (Overhead)</td>
                  <td style="color:var(--accent-green);">Direct VM Bus</td>
                </tr>
                <tr>
                  <td style="text-align:left;">Port Hijacking</td>
                  <td style="color:var(--accent-crimson);">Vulnerable</td>
                  <td style="color:var(--accent-green);">Immune (VMID)</td>
                </tr>
                <tr>
                  <td style="text-align:left;">Peer Identity</td>
                  <td>Tokens in payload</td>
                  <td style="color:var(--accent-green);">Kernel Hardware Verified</td>
                </tr>
              </tbody>
            </table>

            <div style="font-size:11.5px; color:#8b949e; margin-top:6px;">
              Select the primary architectural advantage of AF_VSOCK for SPLAT:
            </div>
            <select id="lab10_s1_ans" style="background:#161b22; border:1px solid #30363d; color:#fff; padding:6px; border-radius:4px; font-family:var(--font-mono); font-size:12px;">
              <option value="speed">Lower latency than TCP alone</option>
              <option value="peer_id" selected>Hardware hypervisor VMID enforcement eliminates port hijacking</option>
              <option value="legacy">Backwards compatibility with Windows 98</option>
            </select>
          </div>
        `,
        rightTitle: "SECURITY PROTOCOL EVALUATOR",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">EVALUATOR: hyperv_vsock::peer_auth</span>
              <span style="color:#8b949e;">VMID Check</span>
            </div>
            <div class="terminal-body" id="lab10_s1_term">
              <div class="term-line-dim">[SYS] Ready. Select the architectural advantage and click "Verify Architecture".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab10_s1_verify()">▶ Verify Architecture</button>
              <button class="btn-action-next" id="lab10_s1_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `
      },

      {
        title: "Stage 2: Windows Filtering Platform (WFP) Callout Driver",
        theory: "Windows AppContainers can be granted network access while still strictly restricted by a kernel WFP callout driver. At FWPM_LAYER_ALE_AUTH_CONNECT_V4, the driver extracts the destination IP and SNI domain, blocking unauthorized egress even if the container tries raw TCP sockets.",
        task: "Trace network connection requests through the WFP Callout filter and verify that unauthorized destination IPs are blocked with FWP_ACTION_BLOCK.",
        leftTitle: "WFP ALE CONNECTION INSPECTOR",
        leftSub: "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:12px;">
            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:10px; font-family:var(--font-mono); font-size:11.5px;">
              <div style="color:var(--accent-cyan); font-weight:700; margin-bottom:4px;">ALLOWED EGRESS DESTINATION:</div>
              <div style="color:#fff;">https://api.splat.internal (10.0.50.10:443)</div>
            </div>

            <div style="font-size:12px; color:#c9d1d9;">Select Test Connection Packet:</div>
            <select id="lab10_s2_target" style="background:#161b22; border:1px solid #30363d; color:#fff; padding:6px; border-radius:4px; font-family:var(--font-mono); font-size:12px;">
              <option value="allowed">10.0.50.10:443 (api.splat.internal - Authorized API)</option>
              <option value="c2">198.51.100.25:8080 (Attacker C2 Server)</option>
              <option value="dns">8.8.8.8:53 (Unauthorized DNS Tunnel)</option>
            </select>
          </div>
        `,
        rightTitle: "WFP KERNEL CALLOUT ENGINE",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">WFP DRIVER: SplatAclCallout</span>
              <span style="color:#8b949e;">Packet Filter</span>
            </div>
            <div class="terminal-body" id="lab10_s2_term">
              <div class="term-line-dim">[WFP] Ready. Select a packet destination and click "Inject Network Packet".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab10_s2_verify()">▶ Inject Network Packet</button>
              <button class="btn-action-next" id="lab10_s2_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `
      },

      {
        title: "Stage 3: Master Systems Engineering Credential Exam",
        theory: "The final capstone exam synthesizes architectural mechanics across all 10 volumes: memory packing, device encoding, token stripping, ring buffer framing, atomic CAS, eBPF stack bounds, false sharing, and WFP kernel containment.",
        task: "Answer 4 comprehensive architectural scenario questions to achieve your Master Systems Engineering Credential.",
        leftTitle: "EXAMINATION QUESTIONS",
        leftSub: "Curriculum Synthesis",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:14px; font-size:12px;">
            <div>
              <strong>Q1: Why does passing raw glibc st_dev into an eBPF map fail?</strong>
              <div style="margin-top:4px;">
                <label style="display:block; cursor:pointer;"><input type="radio" name="exam_q1" value="a" checked> glibc packs major into bits 8..19, while kernel s_dev packs major into bits 20..31</label>
                <label style="display:block; cursor:pointer;"><input type="radio" name="exam_q1" value="b"> glibc uses 32-bit floats for device numbers</label>
              </div>
            </div>

            <div>
              <strong>Q2: What causes false sharing in multi-core processors?</strong>
              <div style="margin-top:4px;">
                <label style="display:block; cursor:pointer;"><input type="radio" name="exam_q2" value="a" checked> Independent variables accessed by different cores share the same 64-byte cache line</label>
                <label style="display:block; cursor:pointer;"><input type="radio" name="exam_q2" value="b"> Operating system paging tables running out of RAM</label>
              </div>
            </div>

            <div>
              <strong>Q3: Why must .NET StreamWriter specify UTF8Encoding(false)?</strong>
              <div style="margin-top:4px;">
                <label style="display:block; cursor:pointer;"><input type="radio" name="exam_q3" value="a" checked> To suppress the 0xEF, 0xBB, 0xBF BOM that breaks Rust serde JSON parsing</label>
                <label style="display:block; cursor:pointer;"><input type="radio" name="exam_q3" value="b"> To compress data with gzip</label>
              </div>
            </div>

            <div>
              <strong>Q4: How does SPLAT eliminate second-order command injection?</strong>
              <div style="margin-top:4px;">
                <label style="display:block; cursor:pointer;"><input type="radio" name="exam_q4" value="a" checked> Single-pass regex substitution using MatchEvaluator so replaced tokens are never re-evaluated</label>
                <label style="display:block; cursor:pointer;"><input type="radio" name="exam_q4" value="b"> Calling string.Replace in an infinite loop</label>
              </div>
            </div>
          </div>
        `,
        rightTitle: "CREDENTIAL EVALUATION ENGINE",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">ACADEMIC BOARD: Capstone Evaluation</span>
              <span style="color:#8b949e;">Certification Grade</span>
            </div>
            <div class="terminal-body" id="lab10_s3_term">
              <div class="term-line-dim">[BOARD] Ready. Answer all questions on the left and click "Grade Capstone Exam".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab10_s3_verify()">▶ Grade Capstone Exam</button>
              <button class="btn-action-next" id="lab10_s3_next_btn" onclick="SPLAT_APP.openCertificateModal()">View Master Credential 🎓</button>
            </div>
          </div>
        `
      }
    ]
  }
];
"""
