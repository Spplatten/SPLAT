# workbench_builder/labs_07_08.py
# Interactive definition for Labs 07 and 08

def get_labs_07_08_js():
    return """
// LABS 07 - 08 DEFINITION
const LABS_07_08 = [
  // =========================================================================
  // LAB 07
  // =========================================================================
  {
    id: 7,
    volume: "Volume 07",
    tier: "Tier 3: Mastery",
    shortTitle: "Security & Salted Erasure",
    title: "Security Defenses, Regex Argument Binder & Salted Cryptographic Erasure",
    objective: "Eliminate second-order command injection via single-pass token binding and implement GDPR/sovereignty compliant cryptographic erasure over immutable SHA-256 ledgers.",
    stages: [
      {
        title: "Stage 1: Second-Order Parameter Injection Exploitation",
        theory: "Naive command templating replaces variables sequentially: template.Replace('{url}', url).Replace('{dest}', dest). If an attacker supplies url = '{dest}' and dest = '; rm -rf /', the first pass replaces {url} with {dest}, and the second pass replaces BOTH occurrences, executing malicious commands!",
        task: "Simulate naive iterative substitution and observe how second-order injection executes arbitrary commands.",
        leftTitle: "TEMPLATE INJECTION SIMULATOR",
        leftSub: "Iterative string.Replace",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:12px;">
            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:10px; font-family:var(--font-mono); font-size:12px;">
              <div style="color:var(--text-muted); margin-bottom:4px;">COMMAND TEMPLATE:</div>
              <div style="color:var(--accent-cyan);">curl -s {url} -o {dest}</div>
            </div>

            <div>
              <label style="color:#c9d1d9; font-size:12px; font-weight:600; display:block; margin-bottom:4px;">Input Value for {url}:</label>
              <input type="text" id="lab7_s1_url" value="{dest}" style="width:100%; background:#161b22; border:1px solid #30363d; color:#fff; padding:6px 10px; border-radius:4px; font-family:var(--font-mono); font-size:12px;" oninput="LAB_RUNNERS.lab7_s1_update()">
            </div>

            <div>
              <label style="color:#c9d1d9; font-size:12px; font-weight:600; display:block; margin-bottom:4px;">Input Value for {dest}:</label>
              <input type="text" id="lab7_s1_dest" value="; /bin/sh -i;" style="width:100%; background:#161b22; border:1px solid #30363d; color:#fff; padding:6px 10px; border-radius:4px; font-family:var(--font-mono); font-size:12px;" oninput="LAB_RUNNERS.lab7_s1_update()">
            </div>

            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:10px; font-family:var(--font-mono); font-size:11.5px;">
              <div style="color:var(--accent-crimson); font-weight:700; margin-bottom:4px;">RESULTING COMMAND LINE:</div>
              <div id="lab7_s1_result" style="color:#fff; word-break:break-all;">curl -s ; /bin/sh -i; -o ; /bin/sh -i;</div>
            </div>
          </div>
        `,
        rightTitle: "ATTACK TRACE CONSOLE",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">AUDIT: Vulnerability Demonstration</span>
              <span style="color:#8b949e;">Second-Order Injection</span>
            </div>
            <div class="terminal-body" id="lab7_s1_term">
              <div class="term-line-dim">[SYS] Ready. Click "Analyze Vulnerability" to view why iterative replacement fails.</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab7_s1_verify()">▶ Analyze Vulnerability</button>
              <button class="btn-action-next" id="lab7_s1_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          LAB_RUNNERS.lab7_s1_update();
        }
      },

      {
        title: "Stage 2: Single-Pass Regex Token Binder & Parameter Guard",
        theory: "Single-pass regex substitution using Regex.Replace with a MatchEvaluator scans the template string in a single linear sweep. Because replaced substrings are never re-scanned, second-order recursive substitution is mathematically impossible.",
        task: "Implement the single-pass Regex binder with strict character validation (^[a-zA-Z0-9_\\-\\.\\/]+$).",
        leftTitle: "C# SECURE TOKEN BINDER",
        leftSub: "ArgumentBinder.cs",
        renderLeft: (labId, sId) => `
          <div class="editor-container">
            <div class="editor-header">
              <span class="editor-filename">📄 ArgumentBinder.cs</span>
              <div class="editor-actions">
                <button class="btn-editor" onclick="LAB_RUNNERS.lab7_s2_resetCode()">Reset Code</button>
              </div>
            </div>
            <div class="editor-main">
              <div class="editor-gutter" id="lab7_s2_gutter"></div>
              <textarea class="editor-textarea" id="lab7_s2_code" spellcheck="false"></textarea>
            </div>
          </div>
        `,
        rightTitle: "INJECTION FUZZING HARNESS",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">FUZZER: ArgumentBinderFuzzer</span>
              <span style="color:#8b949e;">4 Test Cases</span>
            </div>
            <div class="terminal-body" id="lab7_s2_term">
              <div class="term-line-dim">[FUZZER] Ready. Implement the single-pass binder and click "Run Injection Test".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab7_s2_verify()">▶ Run Injection Test</button>
              <button class="btn-action-next" id="lab7_s2_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          const starter = `public static string BindArguments(string template, Dictionary<string, string> args)
{
    var regex = new Regex(@"\\{([a-zA-Z0-9_]+)\\}");

    return regex.Replace(template, match =>
    {
        var key = match.Groups[1].Value;
        if (args.TryGetValue(key, out var val))
        {
            // Validate against strict allowlist: alphanumerics, underscores, dots, hyphens, slashes
            if (!Regex.IsMatch(val, @"^[a-zA-Z0-9_\\-\\.\\/]+$"))
                throw new ArgumentException($"Invalid parameter characters: {val}");
            return val;
        }
        return match.Value;
    });
}`;
          const ta = document.getElementById('lab7_s2_code');
          if (ta) {
            ta.value = SPLAT_APP.state.userCode['lab7_s2'] || starter;
            LAB_RUNNERS.updateGutter('lab7_s2_code', 'lab7_s2_gutter');
            ta.oninput = () => {
              LAB_RUNNERS.updateGutter('lab7_s2_code', 'lab7_s2_gutter');
              SPLAT_APP.state.userCode['lab7_s2'] = ta.value;
            };
          }
        }
      },

      {
        title: "Stage 3: Salted Cryptographic Erasure Ledger",
        theory: "Audit ledgers must be tamper-evident using SHA-256 hash chains. However, privacy laws (GDPR Right to Be Forgotten) require deleting sensitive fields. SPLAT solves this by hashing sensitive data with a high-entropy salt into an immutable commitment: Commitment = SHA256(Data || Salt). When erasure is triggered, Data and Salt are zeroed out; the commitment preserves the hash chain while making the plaintext mathematically unrecoverable.",
        task: "Inspect the ledger block, trigger sovereign erasure, and verify that the blockchain remains cryptographically valid.",
        leftTitle: "IMMUTABLE AUDIT LEDGER BLOCK",
        leftSub: "SHA-256 Commitment Chain",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:12px;">
            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:12px; font-family:var(--font-mono); font-size:11.5px; display:flex; flex-direction:column; gap:6px;">
              <div style="color:var(--accent-cyan); font-weight:700;">BLOCK #104: AGENT LEASE EXECUTION</div>
              <div>PrevHash: <span style="color:#8b949e;">0xa4f28e91b0c144ef...</span></div>
              <div>Event: <span style="color:#fff;">LEASE_ISSUED</span></div>
              <div>Sensitive Payload: <span id="lab7_s3_payload" style="color:var(--accent-amber);">"ApiKey: sk-live-992182741"</span></div>
              <div>Erasure Salt: <span id="lab7_s3_salt" style="color:#8b949e;">0x7c91f4d0e12a...</span></div>
              <div style="border-top:1px solid #30363d; padding-top:4px;">Commitment: <span style="color:var(--accent-green);">0xd82f...39b1</span></div>
              <div>Block Hash: <span id="lab7_s3_bhash" style="color:#fff;">0x19e0...74cc</span></div>
            </div>

            <button class="btn-editor" style="border-color:var(--accent-crimson); color:var(--accent-crimson);" onclick="LAB_RUNNERS.lab7_s3_erase()">🔥 Trigger Sovereign Cryptographic Erasure</button>
          </div>
        `,
        rightTitle: "BLOCKCHAIN INTEGRITY VERIFIER",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">VERIFIER: splat::crypto::hash_chain</span>
              <span style="color:#8b949e;">SHA-256 Audit</span>
            </div>
            <div class="terminal-body" id="lab7_s3_term">
              <div class="term-line-dim">[SYS] Ready. Click "Verify Ledger Integrity" to validate the hash chain.</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab7_s3_verify()">▶ Verify Ledger Integrity</button>
              <button class="btn-action-next" id="lab7_s3_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          LAB_RUNNERS.lab7_s3_reset();
        }
      }
    ]
  },

  // =========================================================================
  // LAB 08
  // =========================================================================
  {
    id: 8,
    volume: "Volume 08",
    tier: "Tier 3: Mastery",
    shortTitle: "False Sharing & SIMD",
    title: "Microarchitectural Optimization, Cache Line False Sharing & SIMD",
    objective: "Eliminate L1 cache line bouncing caused by false sharing using 64-byte alignment, and accelerate semantic embedding vector math using AVX2 SIMD intrinsics.",
    stages: [
      {
        title: "Stage 1: False Sharing & The MESI Protocol Simulator",
        theory: "CPUs fetch memory in 64-byte cache lines. When Core 0 writes to producer_seq (offset 0) and Core 1 writes to consumer_seq (offset 8), both variables reside in the SAME 64-byte line. Core 0's write triggers the MESI protocol to invalidate Core 1's cache line (Modified -> Invalid), causing continuous cache line bouncing and a 30x throughput collapse!",
        task: "Observe cache line bouncing, then apply alignas(64) cache line padding to isolate the counters onto separate cache lines.",
        leftTitle: "CPU L1 CACHE CONTROLLERS",
        leftSub: "MESI Invalidation Simulator",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:12px;">
            <div style="display:flex; justify-content:space-between; align-items:center; background:#161b22; padding:10px 14px; border-radius:6px; border:1px solid #30363d;">
              <span style="font-size:12px; color:var(--text-muted);">Queue Throughput:</span>
              <span id="lab8_s1_mops" style="font-size:14px; font-weight:700; color:var(--accent-crimson); font-family:var(--font-mono);">3.2 Mops/s</span>
            </div>

            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:12px; font-family:var(--font-mono); font-size:11.5px; display:flex; flex-direction:column; gap:6px;">
              <div style="color:var(--text-muted);">CACHE LINE 0x1000 (64 Bytes):</div>
              <div id="lab8_s1_line_desc" style="color:#c9d1d9;">
                [producer_seq (8B)] [consumer_seq (8B)] [48B unused]<br>
                <span style="color:var(--accent-crimson);">STATUS: FALSE SHARING DETECTED</span>
              </div>
            </div>

            <label style="cursor:pointer; display:flex; align-items:center; gap:8px; font-size:12.5px;">
              <input type="checkbox" id="lab8_s1_pad" onchange="LAB_RUNNERS.lab8_s1_toggle()">
              <span><strong>Apply alignas(64) Padding</strong></span>
            </label>
          </div>
        `,
        rightTitle: "HARDWARE PERFORMANCE COUNTERS",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">PERF: cache-misses, L1-dcache-load-misses</span>
              <span style="color:#8b949e;">MESI State</span>
            </div>
            <div class="terminal-body" id="lab8_s1_term">
              <div class="term-line-dim">[PERF] Ready. Observe the low throughput, then apply 64-byte padding and click "Verify Cache Isolation".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab8_s1_verify()">▶ Verify Cache Isolation</button>
              <button class="btn-action-next" id="lab8_s1_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          LAB_RUNNERS.lab8_s1_init();
        }
      },

      {
        title: "Stage 2: 128-Dimensional Vector Embedding Generator",
        theory: "Fast semantic retrieval requires dense vector representations of mission prompts. SPLAT extracts character trigrams and applies fast hashing to generate 128-dimensional dense float vectors, normalized via Euclidean L2 norm so that sum(v_i^2) == 1.0.",
        task: "Enter a prompt and inspect the generated 128-dimensional embedding vector heatmap.",
        leftTitle: "SEMANTIC EMBEDDING EXTRACTOR",
        leftSub: "128-Dim Normalized Vector",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:12px;">
            <div>
              <label style="color:#c9d1d9; font-size:12px; font-weight:600; display:block; margin-bottom:4px;">Mission Prompt:</label>
              <input type="text" id="lab8_s2_prompt" value="Execute sandboxed diagnostic scan and audit open ports" style="width:100%; background:#161b22; border:1px solid #30363d; color:#fff; padding:6px 10px; border-radius:4px; font-family:var(--font-mono); font-size:12px;" oninput="LAB_RUNNERS.lab8_s2_calc()">
            </div>

            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:10px;">
              <div style="font-size:11px; color:var(--text-muted); margin-bottom:6px; font-family:var(--font-mono);">VECTOR HEATMAP (128 DIMS):</div>
              <div id="lab8_s2_heatmap" style="display:grid; grid-template-columns:repeat(16, 1fr); gap:2px; height:80px;">
                <!-- Generated dynamically -->
              </div>
            </div>

            <div style="font-size:12px; color:var(--accent-green); font-family:var(--font-mono);">
              L2 Euclidean Norm: <span id="lab8_s2_norm">1.000000</span>
            </div>
          </div>
        `,
        rightTitle: "VECTOR EMBEDDING AUDITOR",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">EMBEDDING: splat::embeddings::vector128</span>
              <span style="color:#8b949e;">L2 Normalization</span>
            </div>
            <div class="terminal-body" id="lab8_s2_term">
              <div class="term-line-dim">[SYS] Ready. Inspect the vector heatmap and click "Validate Vector Normalization".</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab8_s2_verify()">▶ Validate Vector Normalization</button>
              <button class="btn-action-next" id="lab8_s2_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `,
        onMount: () => {
          LAB_RUNNERS.lab8_s2_calc();
        }
      },

      {
        title: "Stage 3: AVX2 SIMD Dot-Product Vectorizer",
        theory: "Computing cosine similarity between 128-dimensional vectors requires the dot product: dot = sum(A_i * B_i). Using 256-bit AVX2 registers (ymm), we process 8 single-precision floats per instruction using fused multiply-add (_mm256_fmadd_ps), accelerating semantic matching by 600%.",
        task: "Verify the 8-lane SIMD vector dot product against scalar accumulation.",
        leftTitle: "SIMD 8-LANE REGISTER VIEW",
        leftSub: "AVX2 ymm0 * ymm1",
        renderLeft: (labId, sId) => `
          <div style="display:flex; flex-direction:column; gap:12px;">
            <div style="background:#090c10; border:1px solid var(--border-color); border-radius:6px; padding:10px; font-family:var(--font-mono); font-size:11px;">
              <div style="color:var(--accent-cyan); font-weight:700; margin-bottom:4px;">YMM0 (Vector A - 8 Floats):</div>
              <div style="color:#c9d1d9;">[0.12, 0.45, -0.22, 0.81, 0.05, -0.33, 0.62, 0.19]</div>
              <div style="color:var(--accent-green); font-weight:700; margin-top:6px; margin-bottom:4px;">YMM1 (Vector B - 8 Floats):</div>
              <div style="color:#c9d1d9;">[0.10, 0.48, -0.20, 0.79, 0.04, -0.30, 0.60, 0.22]</div>
            </div>

            <div style="font-size:12px; color:#8b949e;">
              AVX2 Instruction: <code>_mm256_fmadd_ps(a, b, acc)</code><br>
              Processes 8 multiply-accumulate operations in a single clock cycle!
            </div>
          </div>
        `,
        rightTitle: "SIMD VS SCALAR BENCHMARK",
        renderRight: (labId, sId) => `
          <div class="terminal-container">
            <div class="terminal-header">
              <span class="terminal-title">BENCH: splat-bench::dot_product</span>
              <span style="color:#8b949e;">AVX2 vs Scalar</span>
            </div>
            <div class="terminal-body" id="lab8_s3_term">
              <div class="term-line-dim">[BENCH] Ready. Click "Run SIMD Benchmark" to compare AVX2 vs Scalar execution time.</div>
            </div>
            <div class="terminal-footer">
              <button class="btn-action-primary" onclick="LAB_RUNNERS.lab8_s3_verify()">▶ Run SIMD Benchmark</button>
              <button class="btn-action-next" id="lab8_s3_next_btn" onclick="SPLAT_APP.nextStage()">Next Stage ➔</button>
            </div>
          </div>
        `
      }
    ]
  }
];
"""
