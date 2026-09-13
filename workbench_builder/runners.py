# workbench_builder/runners.py
# All 30 interactive test runners, calculators, and verification algorithms

def get_runners_js():
    return """
// ==========================================================================
// SPLAT WORKBENCH TEST RUNNERS & INTERACTIVE LOGIC (LABS 01 - 10)
// ==========================================================================

const LAB_RUNNERS = {
  // Utility: update line numbers in code editor gutter
  updateGutter(textId, gutterId) {
    const ta = document.getElementById(textId);
    const gt = document.getElementById(gutterId);
    if (!ta || !gt) return;
    const lineCount = ta.value.split('\\n').length;
    let html = '';
    for (let i = 1; i <= lineCount; i++) {
      html += `<div class="gutter-line">${i}</div>`;
    }
    gt.innerHTML = html;
  },

  // -------------------------------------------------------------------------
  // LAB 01 RUNNERS
  // -------------------------------------------------------------------------
  lab1_s1_verify() {
    SPLAT_APP.clearTerm('lab1_s1_term');
    SPLAT_APP.playClick();
    const p1 = document.getElementById('lab1_s1_p1').value;
    const p2 = document.getElementById('lab1_s1_p2').value;
    const p3 = document.getElementById('lab1_s1_p3').value;
    const p4 = document.getElementById('lab1_s1_p4').value;

    SPLAT_APP.printTerm('lab1_s1_term', '[1/4] Auditing Host-to-Bridge Channel: ' + p1, 'info');
    if (p1 !== 'uds_jsonrpc') {
      SPLAT_APP.printTerm('lab1_s1_term', 'FAIL: Unauthenticated/unbounded channel. Must use authenticated Domain Socket/Named Pipe.', 'fail');
      SPLAT_APP.playFail();
      return;
    }
    SPLAT_APP.printTerm('lab1_s1_term', 'PASS: Secure local domain socket authenticated with SO_PEERCRED.', 'pass');

    SPLAT_APP.printTerm('lab1_s1_term', '[2/4] Auditing Bridge-to-Kernel Hook Channel: ' + p2, 'info');
    if (p2 !== 'bpf_maps') {
      SPLAT_APP.printTerm('lab1_s1_term', 'FAIL: Channel lacks kernel verifier guarantees. Must use BPF Hash Maps & Ring Buffer.', 'fail');
      SPLAT_APP.playFail();
      return;
    }
    SPLAT_APP.printTerm('lab1_s1_term', 'PASS: BPF map descriptor splat_leases locked to kernel memory.', 'pass');

    SPLAT_APP.printTerm('lab1_s1_term', '[3/4] Auditing Bridge-to-Worker Spawn Channel: ' + p3, 'info');
    if (p3 !== 'suspended_spawn') {
      SPLAT_APP.printTerm('lab1_s1_term', 'FAIL: Unconfined worker process execution.', 'fail');
      SPLAT_APP.playFail();
      return;
    }
    SPLAT_APP.printTerm('lab1_s1_term', 'PASS: Suspended spawn with token stripping verified.', 'pass');

    SPLAT_APP.printTerm('lab1_s1_term', '[4/4] Auditing Kernel Enforced Gatekeeper: ' + p4, 'info');
    if (p4 !== 'lsm_hooks') {
      SPLAT_APP.printTerm('lab1_s1_term', 'FAIL: Bypassable user-space gatekeeper. Must use LSM hooks.', 'fail');
      SPLAT_APP.playFail();
      return;
    }
    SPLAT_APP.printTerm('lab1_s1_term', 'PASS: In-kernel LSM hooks (bprm_check_security + file_open) verified.', 'pass');

    SPLAT_APP.printTerm('lab1_s1_term', '>>> TOPOLOGY AUDIT PASSED: 1:1:1 Invariant Satisfied! <<<', 'pass');
    SPLAT_APP.markStageComplete(1, 1, 100);
  },

  lab1_s2_setPreset(preset) {
    SPLAT_APP.playClick();
    if (preset === 'exploit_net') {
      document.getElementById('lab1_s2_listen').value = '0.0.0.0:50051; rm -rf /';
      document.getElementById('lab1_s2_auth').value = '/var/run/splat/auth.token';
      document.getElementById('lab1_s2_uid').value = '1001';
      document.getElementById('lab1_s2_mock').value = 'false';
    } else if (preset === 'exploit_root') {
      document.getElementById('lab1_s2_listen').value = '127.0.0.1:50051';
      document.getElementById('lab1_s2_auth').value = '/var/run/splat/auth.token';
      document.getElementById('lab1_s2_uid').value = '0';
      document.getElementById('lab1_s2_mock').value = 'false';
    } else if (preset === 'exploit_traversal') {
      document.getElementById('lab1_s2_listen').value = '127.0.0.1:50051';
      document.getElementById('lab1_s2_auth').value = '../../etc/shadow';
      document.getElementById('lab1_s2_uid').value = '1001';
      document.getElementById('lab1_s2_mock').value = 'false';
    } else if (preset === 'hardened') {
      document.getElementById('lab1_s2_listen').value = '127.0.0.1:50051';
      document.getElementById('lab1_s2_auth').value = '/var/run/splat/auth.token';
      document.getElementById('lab1_s2_uid').value = '1001';
      document.getElementById('lab1_s2_mock').value = 'false';
    }
  },

  lab1_s2_verify() {
    SPLAT_APP.clearTerm('lab1_s2_term');
    SPLAT_APP.playClick();
    const listen = document.getElementById('lab1_s2_listen').value.trim();
    const auth = document.getElementById('lab1_s2_auth').value.trim();
    const uid = parseInt(document.getElementById('lab1_s2_uid').value, 10);
    const mock = document.getElementById('lab1_s2_mock').value;

    let hasErrors = false;

    // Check listen IP
    if (listen.includes(';') || listen.includes('|') || listen.includes('&') || listen.includes('`')) {
      SPLAT_APP.printTerm('lab1_s2_term', 'CRITICAL FAIL: Shell metacharacters detected in --listen flag!', 'fail');
      hasErrors = true;
    } else if (!listen.startsWith('127.0.0.1') && !listen.startsWith('localhost') && !listen.startsWith('[::1]')) {
      SPLAT_APP.printTerm('lab1_s2_term', 'SECURITY ALERT: --listen is bound to public/external network: ' + listen, 'fail');
      hasErrors = true;
    } else {
      SPLAT_APP.printTerm('lab1_s2_term', 'PASS: --listen bound strictly to loopback interface.', 'pass');
    }

    // Check auth token path
    if (auth.includes('..')) {
      SPLAT_APP.printTerm('lab1_s2_term', 'CRITICAL FAIL: Directory traversal detected in --auth-token-file path: ' + auth, 'fail');
      hasErrors = true;
    } else if (!auth.startsWith('/') && !auth.match(/^[A-Za-z]:\\\\/)) {
      SPLAT_APP.printTerm('lab1_s2_term', 'FAIL: --auth-token-file must be an absolute path.', 'fail');
      hasErrors = true;
    } else {
      SPLAT_APP.printTerm('lab1_s2_term', 'PASS: --auth-token-file points to secure canonical path.', 'pass');
    }

    // Check UID
    if (uid === 0) {
      SPLAT_APP.printTerm('lab1_s2_term', 'CRITICAL FAIL: --workload-uid cannot be root (UID 0)!', 'fail');
      hasErrors = true;
    } else if (uid < 1000) {
      SPLAT_APP.printTerm('lab1_s2_term', 'WARN: --workload-uid is a system account (< 1000). Recommend unprivileged UID >= 1000.', 'warn');
    } else {
      SPLAT_APP.printTerm('lab1_s2_term', 'PASS: --workload-uid runs as unprivileged user (UID ' + uid + ').', 'pass');
    }

    // Check Mock BPF
    if (mock === 'true') {
      SPLAT_APP.printTerm('lab1_s2_term', 'FAIL: --mock-bpf is enabled! Production environments must enforce real kernel LSM.', 'fail');
      hasErrors = true;
    } else {
      SPLAT_APP.printTerm('lab1_s2_term', 'PASS: Production kernel LSM enforcement active.', 'pass');
    }

    if (hasErrors) {
      SPLAT_APP.printTerm('lab1_s2_term', '>>> AUDIT FAILED: Fix flagged vulnerabilities and re-run. <<<', 'fail');
      SPLAT_APP.playFail();
    } else {
      SPLAT_APP.printTerm('lab1_s2_term', '>>> AUDIT PASSED: Hardened daemon configuration verified! <<<', 'pass');
      SPLAT_APP.markStageComplete(1, 2, 100);
    }
  },

  lab1_s3_resetCode() {
    SPLAT_APP.playClick();
    delete SPLAT_APP.state.userCode['lab1_s3'];
    SPLAT_APP.switchStage(3);
  },

  lab1_s3_verify() {
    SPLAT_APP.clearTerm('lab1_s3_term');
    SPLAT_APP.playClick();
    const code = document.getElementById('lab1_s3_code').value;

    SPLAT_APP.printTerm('lab1_s3_term', '[TEST 1] Testing LD_PRELOAD injection removal...', 'info');
    if (code.includes('LD_PRELOAD') && code.includes('Contains')) {
      SPLAT_APP.printTerm('lab1_s3_term', '  Assert: "LD_PRELOAD=/tmp/evil.so" stripped -> PASS', 'pass');
    } else {
      SPLAT_APP.printTerm('lab1_s3_term', '  Assert: LD_PRELOAD stripped -> FAIL', 'fail');
      SPLAT_APP.playFail();
      return;
    }

    SPLAT_APP.printTerm('lab1_s3_term', '[TEST 2] Testing PYTHONPATH injection removal...', 'info');
    if (code.includes('PYTHONPATH')) {
      SPLAT_APP.printTerm('lab1_s3_term', '  Assert: "PYTHONPATH=/tmp/pylib" stripped -> PASS', 'pass');
    } else {
      SPLAT_APP.printTerm('lab1_s3_term', '  Assert: PYTHONPATH stripped -> FAIL', 'fail');
      SPLAT_APP.playFail();
      return;
    }

    SPLAT_APP.printTerm('lab1_s3_term', '[TEST 3] Testing PATH normalization...', 'info');
    if (code.includes('/usr/bin:/bin:/usr/local/bin') || code.includes('clean["PATH"]')) {
      SPLAT_APP.printTerm('lab1_s3_term', '  Assert: PATH normalized to standard system binaries -> PASS', 'pass');
    } else {
      SPLAT_APP.printTerm('lab1_s3_term', '  Assert: PATH normalized -> FAIL', 'fail');
      SPLAT_APP.playFail();
      return;
    }

    SPLAT_APP.printTerm('lab1_s3_term', '[TEST 4] Testing preservation of benign variables...', 'info');
    SPLAT_APP.printTerm('lab1_s3_term', '  Assert: SPLAT_LEASE_ID=42 preserved -> PASS', 'pass');

    SPLAT_APP.printTerm('lab1_s3_term', '>>> ALL 4 TEST CASES PASSED! Code verified. <<<', 'pass');
    SPLAT_APP.markStageComplete(1, 3, 100);
  },

  // -------------------------------------------------------------------------
  // LAB 02 RUNNERS
  // -------------------------------------------------------------------------
  lab2_s1_fields: [
    { name: 'status', size: 1, type: 'uint8_t' },
    { name: 'lease_id', size: 8, type: 'uint64_t' },
    { name: 'timeout_sec', size: 2, type: 'uint16_t' },
    { name: 'max_mem_mb', size: 4, type: 'uint32_t' },
    { name: 'flags', size: 1, type: 'uint8_t' },
    { name: 'cgroup_id', size: 8, type: 'uint64_t' }
  ],

  lab2_s1_init() {
    this.lab2_s1_render();
  },

  lab2_s1_move(index, dir) {
    SPLAT_APP.playClick();
    const newIdx = index + dir;
    if (newIdx < 0 || newIdx >= this.lab2_s1_fields.length) return;
    const temp = this.lab2_s1_fields[index];
    this.lab2_s1_fields[index] = this.lab2_s1_fields[newIdx];
    this.lab2_s1_fields[newIdx] = temp;
    this.lab2_s1_render();
  },

  lab2_s1_render() {
    const listEl = document.getElementById('lab2_s1_field_list');
    const gridEl = document.getElementById('lab2_s1_grid_container');
    if (!listEl || !gridEl) return;

    listEl.innerHTML = '';
    this.lab2_s1_fields.forEach((f, idx) => {
      const row = document.createElement('div');
      row.className = 'struct-field-item';
      row.innerHTML = `
        <span><strong style="color:var(--accent-cyan);">${f.type}</strong> ${f.name} <span style="color:#8b949e;">(${f.size}B)</span></span>
        <div class="field-controls">
          <button onclick="LAB_RUNNERS.lab2_s1_move(${idx}, -1)" ${idx === 0 ? 'disabled' : ''}>▲</button>
          <button onclick="LAB_RUNNERS.lab2_s1_move(${idx}, 1)" ${idx === this.lab2_s1_fields.length - 1 ? 'disabled' : ''}>▼</button>
        </div>
      `;
      listEl.appendChild(row);
    });

    // Calculate layout with 64-bit alignment
    let currentOffset = 0;
    let totalPadding = 0;
    const memoryBytes = [];

    this.lab2_s1_fields.forEach(f => {
      const align = f.size;
      const rem = currentOffset % align;
      if (rem !== 0) {
        const padNeeded = align - rem;
        for (let p = 0; p < padNeeded; p++) {
          memoryBytes.push({ type: 'pad', label: 'PAD' });
          currentOffset++;
          totalPadding++;
        }
      }
      for (let b = 0; b < f.size; b++) {
        memoryBytes.push({ type: 'data', label: f.name.slice(0, 4) });
        currentOffset++;
      }
    });

    // Struct size must be multiple of largest member (8)
    const structAlign = 8;
    const rem = currentOffset % structAlign;
    if (rem !== 0) {
      const tailPad = structAlign - rem;
      for (let p = 0; p < tailPad; p++) {
        memoryBytes.push({ type: 'pad', label: 'PAD' });
        currentOffset++;
        totalPadding++;
      }
    }

    const totalSize = currentOffset;
    document.getElementById('lab2_s1_size').innerText = `${totalSize} Bytes`;
    document.getElementById('lab2_s1_pad').innerText = `${totalPadding} Bytes`;

    if (totalSize === 24 && totalPadding === 0) {
      document.getElementById('lab2_s1_size').style.color = 'var(--accent-green)';
      document.getElementById('lab2_s1_pad').style.color = 'var(--accent-green)';
    } else {
      document.getElementById('lab2_s1_size').style.color = 'var(--accent-crimson)';
      document.getElementById('lab2_s1_pad').style.color = 'var(--accent-crimson)';
    }

    // Render memory rows (8 bytes per row)
    gridEl.innerHTML = '';
    const numRows = Math.ceil(memoryBytes.length / 8);
    for (let r = 0; r < numRows; r++) {
      const rowDiv = document.createElement('div');
      rowDiv.className = 'mem-row';
      const offsetHex = '0x' + (r * 8).toString(16).padStart(2, '0').toUpperCase();
      rowDiv.innerHTML = `<span class="mem-offset-label">${offsetHex}:</span>`;
      const cellsDiv = document.createElement('div');
      cellsDiv.className = 'mem-byte-cells';

      for (let b = 0; b < 8; b++) {
        const byteIdx = r * 8 + b;
        const cell = document.createElement('div');
        if (byteIdx < memoryBytes.length) {
          const item = memoryBytes[byteIdx];
          cell.className = `mem-cell ${item.type === 'data' ? 'active-field' : 'pad-field'}`;
          cell.innerText = item.label;
        } else {
          cell.className = 'mem-cell';
          cell.innerText = '-';
        }
        cellsDiv.appendChild(cell);
      }
      rowDiv.appendChild(cellsDiv);
      gridEl.appendChild(rowDiv);
    }
  },

  lab2_s1_verify() {
    SPLAT_APP.playClick();
    const padText = document.getElementById('lab2_s1_pad').innerText;
    const sizeText = document.getElementById('lab2_s1_size').innerText;

    if (sizeText === '24 Bytes' && padText === '0 Bytes') {
      SPLAT_APP.showToast('Struct perfectly optimized: 24 bytes, 0 padding holes!', 'success');
      SPLAT_APP.markStageComplete(2, 1, 100);
    } else {
      SPLAT_APP.showToast('Struct not optimal yet. Place 8-byte types first!', 'error');
      SPLAT_APP.playFail();
    }
  },

  lab2_s2_calc() {
    const major = parseInt(document.getElementById('lab2_s2_major').value, 10) || 0;
    const minor = parseInt(document.getElementById('lab2_s2_minor').value, 10) || 0;

    // glibc st_dev: major at 8..19, minor at 0..7
    const glibcVal = ((major & 0xfff) << 8) | (minor & 0xff);
    // kernel s_dev: (major << 20) | minor
    const kernelVal = ((major << 20) | (minor & 0xfffff)) >>> 0;

    const toHex32 = n => '0x' + (n >>> 0).toString(16).padStart(8, '0').toUpperCase();
    const toBin32 = n => {
      const b = (n >>> 0).toString(2).padStart(32, '0');
      return `${b.slice(0,8)} ${b.slice(8,16)} ${b.slice(16,24)} ${b.slice(24,32)}`;
    };

    document.getElementById('lab2_s2_glibc_hex').innerText = 'Hex: ' + toHex32(glibcVal);
    document.getElementById('lab2_s2_glibc_bin').innerText = 'Bits: ' + toBin32(glibcVal);
    document.getElementById('lab2_s2_kernel_hex').innerText = 'Hex: ' + toHex32(kernelVal);
    document.getElementById('lab2_s2_kernel_bin').innerText = 'Bits: ' + toBin32(kernelVal);
  },

  lab2_s2_verify() {
    SPLAT_APP.clearTerm('lab2_s2_term');
    SPLAT_APP.playClick();
    const selected = document.querySelector('input[name="lab2_s2_answer"]:checked');
    if (!selected) {
      SPLAT_APP.printTerm('lab2_s2_term', 'Please select an option first.', 'warn');
      return;
    }

    if (selected.value === '2') {
      SPLAT_APP.printTerm('lab2_s2_term', 'PASS: Option B is correct!', 'pass');
      SPLAT_APP.printTerm('lab2_s2_term', 'Formula ((major(dev) << 20) | minor(dev)) packs major into bits 20..31, matching kernel s_dev exactly.', 'info');
      SPLAT_APP.printTerm('lab2_s2_term', '>>> AUDIT PASSED: Kernel dev_t encoding bug resolved! <<<', 'pass');
      SPLAT_APP.markStageComplete(2, 2, 100);
    } else {
      SPLAT_APP.printTerm('lab2_s2_term', 'FAIL: Incorrect formula. Kernel packs major into bit 20 onwards.', 'fail');
      SPLAT_APP.playFail();
    }
  },

  lab2_s3_resetCode() {
    SPLAT_APP.playClick();
    delete SPLAT_APP.state.userCode['lab2_s3'];
    SPLAT_APP.switchStage(3);
  },

  lab2_s3_verify() {
    SPLAT_APP.clearTerm('lab2_s3_term');
    SPLAT_APP.playClick();
    const code = document.getElementById('lab2_s3_code').value;

    SPLAT_APP.printTerm('lab2_s3_term', '[VERIFIER] Checking 64-bit load alignment for timestamp_ns...', 'info');
    if (code.includes('timestamp_ns') && (code.includes('_pad') || code.includes('aligned(8)'))) {
      SPLAT_APP.printTerm('lab2_s3_term', '  offsetof(timestamp_ns) == 8 -> Aligned to 8 bytes! [PASS]', 'pass');
      SPLAT_APP.printTerm('lab2_s3_term', '  sizeof(struct splat_event) == 24 -> Multiple of 8 bytes! [PASS]', 'pass');
      SPLAT_APP.printTerm('lab2_s3_term', '>>> KERNEL VERIFIER: SUCCESS! 0 alignment rejections. <<<', 'pass');
      SPLAT_APP.markStageComplete(2, 3, 100);
    } else {
      SPLAT_APP.printTerm('lab2_s3_term', '  misaligned stack access off (0x0 + 4) size 8! [REJECTED]', 'fail');
      SPLAT_APP.printTerm('lab2_s3_term', '  Insert padding after pid to align timestamp_ns to offset 8.', 'warn');
      SPLAT_APP.playFail();
    }
  },

  // -------------------------------------------------------------------------
  // LAB 03 RUNNERS
  // -------------------------------------------------------------------------
  lab3_s1_privs: [
    { name: 'SeDebugPrivilege', desc: 'Attach debugger to any system process', dangerous: true, stripped: false },
    { name: 'SeImpersonatePrivilege', desc: 'Impersonate named pipe clients (Potato exploits)', dangerous: true, stripped: false },
    { name: 'SeAssignPrimaryTokenPrivilege', desc: 'Assign primary tokens to child processes', dangerous: true, stripped: false },
    { name: 'SeBackupPrivilege', desc: 'Bypass file read permissions', dangerous: true, stripped: false },
    { name: 'SeRestorePrivilege', desc: 'Bypass file write permissions', dangerous: true, stripped: false },
    { name: 'SeChangeNotifyPrivilege', desc: 'Traverse directories (Standard benign privilege)', dangerous: false, stripped: false }
  ],

  lab3_s1_init() {
    const listEl = document.getElementById('lab3_s1_priv_list');
    if (!listEl) return;
    listEl.innerHTML = '';
    this.lab3_s1_privs.forEach((p, idx) => {
      const item = document.createElement('div');
      item.style.cssText = 'background:#161b22; border:1px solid #30363d; padding:8px 12px; border-radius:4px; display:flex; justify-content:space-between; align-items:center;';
      item.innerHTML = `
        <div>
          <div style="font-family:var(--font-mono); font-weight:600; color:${p.dangerous ? '#fff' : 'var(--accent-green)'};">${p.name}</div>
          <div style="font-size:11px; color:#8b949e;">${p.desc}</div>
        </div>
        <button class="btn-editor" id="lab3_s1_btn_${idx}" onclick="LAB_RUNNERS.lab3_s1_toggle(${idx})" style="border-color:${p.stripped ? 'var(--accent-green)' : 'var(--accent-crimson)'}; color:${p.stripped ? 'var(--accent-green)' : 'var(--accent-crimson)'};">
          ${p.stripped ? 'STRIPPED ✓' : 'RETAINED ⚠'}
        </button>
      `;
      listEl.appendChild(item);
    });
    this.lab3_s1_updateRisk();
  },

  lab3_s1_toggle(idx) {
    SPLAT_APP.playClick();
    this.lab3_s1_privs[idx].stripped = !this.lab3_s1_privs[idx].stripped;
    const btn = document.getElementById(`lab3_s1_btn_${idx}`);
    if (btn) {
      const p = this.lab3_s1_privs[idx];
      btn.innerText = p.stripped ? 'STRIPPED ✓' : 'RETAINED ⚠';
      btn.style.borderColor = p.stripped ? 'var(--accent-green)' : 'var(--accent-crimson)';
      btn.style.color = p.stripped ? 'var(--accent-green)' : 'var(--accent-crimson)';
    }
    this.lab3_s1_updateRisk();
  },

  lab3_s1_updateRisk() {
    const dangerousRetained = this.lab3_s1_privs.filter(p => p.dangerous && !p.stripped).length;
    const riskEl = document.getElementById('lab3_s1_risk');
    if (!riskEl) return;
    if (dangerousRetained === 0) {
      riskEl.innerText = '0% HARDENED';
      riskEl.style.color = 'var(--accent-green)';
    } else {
      const pct = Math.round((dangerousRetained / 5) * 100);
      riskEl.innerText = `${pct}% CRITICAL`;
      riskEl.style.color = 'var(--accent-crimson)';
    }
  },

  lab3_s1_verify() {
    SPLAT_APP.clearTerm('lab3_s1_term');
    SPLAT_APP.playClick();
    const dangerousRetained = this.lab3_s1_privs.filter(p => p.dangerous && !p.stripped);
    if (dangerousRetained.length === 0) {
      SPLAT_APP.printTerm('lab3_s1_term', 'PASS: All 5 privilege escalation vectors successfully stripped!', 'pass');
      SPLAT_APP.printTerm('lab3_s1_term', 'SeChangeNotifyPrivilege retained for standard traversal.', 'info');
      SPLAT_APP.printTerm('lab3_s1_term', '>>> TOKEN SECURITY: Restricted token verified! <<<', 'pass');
      SPLAT_APP.markStageComplete(3, 1, 100);
    } else {
      SPLAT_APP.printTerm('lab3_s1_term', `FAIL: ${dangerousRetained.length} dangerous privileges remain active:`, 'fail');
      dangerousRetained.forEach(p => {
        SPLAT_APP.printTerm('lab3_s1_term', `  - ${p.name}`, 'warn');
      });
      SPLAT_APP.playFail();
    }
  },

  lab3_s2_resetCode() {
    SPLAT_APP.playClick();
    delete SPLAT_APP.state.userCode['lab3_s2'];
    SPLAT_APP.switchStage(2);
  },

  lab3_s2_verify() {
    SPLAT_APP.clearTerm('lab3_s2_term');
    SPLAT_APP.playClick();
    const code = document.getElementById('lab3_s2_code').value;

    SPLAT_APP.printTerm('lab3_s2_term', '[TEST 1] Testing CREATE_SUSPENDED flag (0x00000004)...', 'info');
    if (code.includes('CREATE_SUSPENDED')) {
      SPLAT_APP.printTerm('lab3_s2_term', '  Flag CREATE_SUSPENDED present -> PASS', 'pass');
    } else {
      SPLAT_APP.printTerm('lab3_s2_term', '  Missing CREATE_SUSPENDED -> FAIL', 'fail');
      SPLAT_APP.playFail();
      return;
    }

    SPLAT_APP.printTerm('lab3_s2_term', '[TEST 2] Testing EXTENDED_STARTUPINFO_PRESENT flag (0x00080000)...', 'info');
    if (code.includes('EXTENDED_STARTUPINFO_PRESENT')) {
      SPLAT_APP.printTerm('lab3_s2_term', '  Flag EXTENDED_STARTUPINFO_PRESENT present -> PASS', 'pass');
    } else {
      SPLAT_APP.printTerm('lab3_s2_term', '  Missing EXTENDED_STARTUPINFO_PRESENT -> FAIL', 'fail');
      SPLAT_APP.playFail();
      return;
    }

    SPLAT_APP.printTerm('lab3_s2_term', '>>> ALL 3 WIN32 CONTRACT TESTS PASSED! <<<', 'pass');
    SPLAT_APP.markStageComplete(3, 2, 100);
  },

  lab3_s3_verify() {
    SPLAT_APP.clearTerm('lab3_s3_term');
    SPLAT_APP.playClick();
    const net = document.getElementById('lab3_s3_cap_net').checked;
    const lan = document.getElementById('lab3_s3_cap_lan').checked;
    const docs = document.getElementById('lab3_s3_cap_docs').checked;

    SPLAT_APP.printTerm('lab3_s3_term', '[PROBE 1] Outbound connect to public web (1.1.1.1:443)...', 'info');
    if (net) {
      SPLAT_APP.printTerm('lab3_s3_term', '  SECURITY LEAK: Connected to internetClient! Probe breached sandbox.', 'fail');
    } else {
      SPLAT_APP.printTerm('lab3_s3_term', '  BLOCKED: WSAEACCES (10013) Access Denied by AppContainer kernel filter.', 'pass');
    }

    SPLAT_APP.printTerm('lab3_s3_term', '[PROBE 2] Outbound connect to private LAN (192.168.1.1:80)...', 'info');
    if (lan) {
      SPLAT_APP.printTerm('lab3_s3_term', '  SECURITY LEAK: Connected to LAN! Lateral movement possible.', 'fail');
    } else {
      SPLAT_APP.printTerm('lab3_s3_term', '  BLOCKED: WSAEACCES (10013) Access Denied.', 'pass');
    }

    SPLAT_APP.printTerm('lab3_s3_term', '[PROBE 3] File read C:\\\\Users\\\\Admin\\\\Documents\\\\keys.txt...', 'info');
    if (docs) {
      SPLAT_APP.printTerm('lab3_s3_term', '  SECURITY LEAK: Read documentsLibrary! Host sensitive data leaked.', 'fail');
    } else {
      SPLAT_APP.printTerm('lab3_s3_term', '  BLOCKED: ERROR_ACCESS_DENIED (5) Isolation verified.', 'pass');
    }

    SPLAT_APP.printTerm('lab3_s3_term', '[PROBE 4] File write to isolated LocalState folder...', 'info');
    SPLAT_APP.printTerm('lab3_s3_term', '  SUCCESS: Local sandbox storage write allowed.', 'pass');

    if (!net && !lan && !docs) {
      SPLAT_APP.printTerm('lab3_s3_term', '>>> TOTAL JAIL CONTAINMENT VERIFIED: 0 Capabilities granted. <<<', 'pass');
      SPLAT_APP.markStageComplete(3, 3, 100);
    } else {
      SPLAT_APP.printTerm('lab3_s3_term', '>>> AUDIT FAILED: Uncheck all capabilities for zero-trust containment. <<<', 'fail');
      SPLAT_APP.playFail();
    }
  },

  // -------------------------------------------------------------------------
  // LAB 04 RUNNERS
  // -------------------------------------------------------------------------
  lab4_s1_calc() {
    const payload = parseInt(document.getElementById('lab4_s1_payload').value, 10) || 0;
    const header = 4;
    const raw = header + payload;
    const total = (raw + 7) & ~7;
    const pad = total - raw;

    document.getElementById('lab4_s1_disp_payload').innerText = `${payload} Bytes`;
    document.getElementById('lab4_s1_disp_pad').innerText = `${pad} Bytes`;
    document.getElementById('lab4_s1_disp_total').innerText = `${total} Bytes`;
  },

  lab4_s1_verify() {
    SPLAT_APP.clearTerm('lab4_s1_term');
    SPLAT_APP.playClick();
    const payload = parseInt(document.getElementById('lab4_s1_payload').value, 10) || 0;
    const total = ((4 + payload + 7) & ~7);

    SPLAT_APP.printTerm('lab4_s1_term', `[KERNEL] bpf_ringbuf_reserve(&events, ${payload}, 0)...`, 'info');
    SPLAT_APP.printTerm('lab4_s1_term', `Header: 4B | Payload: ${payload}B | 8-byte aligned total: ${total}B`, 'pass');
    SPLAT_APP.printTerm('lab4_s1_term', `Commit pointer advanced by +${total} bytes.`, 'pass');
    SPLAT_APP.printTerm('lab4_s1_term', '>>> RING BUFFER FRAMING VERIFIED! <<<', 'pass');
    SPLAT_APP.markStageComplete(4, 1, 100);
  },

  lab4_s2_resetCode() {
    SPLAT_APP.playClick();
    delete SPLAT_APP.state.userCode['lab4_s2'];
    SPLAT_APP.switchStage(2);
  },

  lab4_s2_verify() {
    SPLAT_APP.clearTerm('lab4_s2_term');
    SPLAT_APP.playClick();
    const code = document.getElementById('lab4_s2_code').value;

    SPLAT_APP.printTerm('lab4_s2_term', '[CARGO] Running tests with incoming UTF-8 BOM byte stream...', 'info');
    if (code.includes('0xEF') && code.includes('0xBB') && code.includes('0xBF') && code.includes('&data[3..]')) {
      SPLAT_APP.printTerm('lab4_s2_term', '  Input: [0xEF, 0xBB, 0xBF, 0x7B, 0x22, ...] -> BOM detected!', 'pass');
      SPLAT_APP.printTerm('lab4_s2_term', '  Output: Zero-copy slice &data[3..] passed to serde_json::from_slice', 'pass');
      SPLAT_APP.printTerm('lab4_s2_term', '  Deserialization result: Ok(AgentRequest { id: 42 }) [PASS]', 'pass');
      SPLAT_APP.printTerm('lab4_s2_term', '>>> TEST PASSED: UTF-8 BOM hazard successfully eliminated! <<<', 'pass');
      SPLAT_APP.markStageComplete(4, 2, 100);
    } else {
      SPLAT_APP.printTerm('lab4_s2_term', '  serde_json Error: expected value at line 1 column 1 [FAIL]', 'fail');
      SPLAT_APP.printTerm('lab4_s2_term', '  Slice past [0xEF, 0xBB, 0xBF] using &data[3..]', 'warn');
      SPLAT_APP.playFail();
    }
  },

  lab4_s3_update() {
    const prod = parseInt(document.getElementById('lab4_s3_prod').value, 10);
    const drain = parseInt(document.getElementById('lab4_s3_drain').value, 10);
    document.getElementById('lab4_s3_prod_val').innerText = `${prod.toLocaleString()} evt/s`;
    document.getElementById('lab4_s3_drain_val').innerText = `${drain} ms`;

    // Simulated fill percentage
    const fill = Math.min(100, Math.round((prod * drain) / 6000));
    document.getElementById('lab4_s3_fill_pct').innerText = `${fill}%`;
    const bar = document.getElementById('lab4_s3_fill_bar');
    bar.style.width = `${fill}%`;
    bar.style.background = fill > 85 ? 'var(--accent-crimson)' : 'var(--accent-cyan)';
  },

  lab4_s3_verify() {
    SPLAT_APP.clearTerm('lab4_s3_term');
    SPLAT_APP.playClick();
    const prod = parseInt(document.getElementById('lab4_s3_prod').value, 10);
    const drain = parseInt(document.getElementById('lab4_s3_drain').value, 10);
    const fill = Math.round((prod * drain) / 6000);

    SPLAT_APP.printTerm('lab4_s3_term', `[LOAD] Generating ${prod.toLocaleString()} events/sec for 5 seconds...`, 'info');
    SPLAT_APP.printTerm('lab4_s3_term', `Consumer polling interval: ${drain}ms`, 'info');

    if (fill > 85) {
      const drops = Math.round((fill - 85) * 340);
      SPLAT_APP.printTerm('lab4_s3_term', `DROP ALERT: Ring buffer filled to 100%! Dropped ${drops} events!`, 'fail');
      SPLAT_APP.printTerm('lab4_s3_term', 'Increase consumer polling frequency or decrease drain interval.', 'warn');
      SPLAT_APP.playFail();
    } else {
      SPLAT_APP.printTerm('lab4_s3_term', `Buffer peak utilization: ${fill}% (Capacity: 256 KB)`, 'pass');
      SPLAT_APP.printTerm('lab4_s3_term', 'Dropped event counter: 0 events (100% telemetry capture)', 'pass');
      SPLAT_APP.printTerm('lab4_s3_term', '>>> LOAD TEST PASSED: Zero telemetry loss! <<<', 'pass');
      SPLAT_APP.markStageComplete(4, 3, 100);
    }
  },

  // -------------------------------------------------------------------------
  // LAB 05 RUNNERS
  // -------------------------------------------------------------------------
  lab5_s1_state: 0,
  lab5_s1_names: ['Created', 'LeaseAcquired', 'SuspendedSpawn', 'Executing', 'TelemetryGrounded', 'Terminated'],

  lab5_s1_reset() {
    this.lab5_s1_state = 0;
    const el = document.getElementById('lab5_s1_cur_state');
    if (el) el.innerText = 'Created [0]';
  },

  lab5_s1_step(target) {
    SPLAT_APP.playClick();
    if (target === this.lab5_s1_state + 1) {
      this.lab5_s1_state = target;
      document.getElementById('lab5_s1_cur_state').innerText = `${this.lab5_s1_names[target]} [${target}]`;
      SPLAT_APP.printTerm('lab5_s1_term', `Transition valid: -> ${this.lab5_s1_names[target]} [PASS]`, 'pass');
    } else {
      SPLAT_APP.printTerm('lab5_s1_term', `ILLEGAL TRANSITION: Cannot jump from ${this.lab5_s1_names[this.lab5_s1_state]} to ${this.lab5_s1_names[target]}! [QUARANTINE]`, 'fail');
      SPLAT_APP.playFail();
    }
  },

  lab5_s1_verify() {
    SPLAT_APP.clearTerm('lab5_s1_term');
    SPLAT_APP.playClick();
    if (this.lab5_s1_state === 5) {
      SPLAT_APP.printTerm('lab5_s1_term', 'PASS: Full 6-stage lifecycle completed from Created to Terminated.', 'pass');
      SPLAT_APP.printTerm('lab5_s1_term', '>>> FSM AUDIT PASSED: Unidirectional governance verified! <<<', 'pass');
      SPLAT_APP.markStageComplete(5, 1, 100);
    } else {
      SPLAT_APP.printTerm('lab5_s1_term', `FAIL: State machine currently at state ${this.lab5_s1_names[this.lab5_s1_state]}. Must reach Terminated [5].`, 'fail');
      SPLAT_APP.playFail();
    }
  },

  lab5_s2_resetCode() {
    SPLAT_APP.playClick();
    delete SPLAT_APP.state.userCode['lab5_s2'];
    SPLAT_APP.switchStage(2);
  },

  lab5_s2_verify() {
    SPLAT_APP.clearTerm('lab5_s2_term');
    SPLAT_APP.playClick();
    const code = document.getElementById('lab5_s2_code').value;

    SPLAT_APP.printTerm('lab5_s2_term', '[RACE SIMULATOR] Spawning 100 concurrent threads claiming Ticket #42...', 'info');
    if (code.includes('Interlocked.CompareExchange')) {
      SPLAT_APP.printTerm('lab5_s2_term', '  Thread #17 acquired lease via atomic CAS. (0 -> 1) [WINNER]', 'pass');
      SPLAT_APP.printTerm('lab5_s2_term', '  99 other threads intercepted by atomic CAS and rejected. [SAFE]', 'pass');
      SPLAT_APP.printTerm('lab5_s2_term', '  Total leases issued: EXACTLY 1 (Double-lease count: 0)', 'pass');
      SPLAT_APP.printTerm('lab5_s2_term', '>>> CONCURRENCY RACE VERIFIED: Atomic CAS invariant preserved! <<<', 'pass');
      SPLAT_APP.markStageComplete(5, 2, 100);
    } else {
      SPLAT_APP.printTerm('lab5_s2_term', '  RACE CONDITION TRIGGERED: Check-then-set allowed 4 duplicate leases! [DISASTER]', 'fail');
      SPLAT_APP.printTerm('lab5_s2_term', '  Use Interlocked.CompareExchange(ref state, 1, 0) == 0', 'warn');
      SPLAT_APP.playFail();
    }
  },

  lab5_s3_verify() {
    SPLAT_APP.clearTerm('lab5_s3_term');
    SPLAT_APP.playClick();
    const selected = document.querySelector('input[name="lab5_s3_status"]:checked');
    if (selected && selected.value === 'grounded') {
      SPLAT_APP.printTerm('lab5_s3_term', 'PASS: Claim verified against kernel eBPF trace.', 'pass');
      SPLAT_APP.printTerm('lab5_s3_term', '  SYS_CONNECT: dest=10.0.0.5:443 confirmed.', 'info');
      SPLAT_APP.printTerm('lab5_s3_term', '  SYS_OPEN: file=/tmp/patch.bin confirmed.', 'info');
      SPLAT_APP.printTerm('lab5_s3_term', '>>> TELEMETRY GROUNDING: Agent cognitive assertion verified! <<<', 'pass');
      SPLAT_APP.markStageComplete(5, 3, 100);
    } else {
      SPLAT_APP.printTerm('lab5_s3_term', 'FAIL: The claim was fully corroborated by the kernel trace.', 'fail');
      SPLAT_APP.playFail();
    }
  },

  // -------------------------------------------------------------------------
  // LAB 06 RUNNERS
  // -------------------------------------------------------------------------
  lab6_s1_resetCode() {
    SPLAT_APP.playClick();
    delete SPLAT_APP.state.userCode['lab6_s1'];
    SPLAT_APP.switchStage(1);
  },

  lab6_s1_verify() {
    SPLAT_APP.clearTerm('lab6_s1_term');
    SPLAT_APP.playClick();
    const code = document.getElementById('lab6_s1_code').value;

    SPLAT_APP.printTerm('lab6_s1_term', '[VERIFIER] Analyzing BPF stack frame allocation...', 'info');
    if (code.includes('bpf_map_lookup_elem') && code.includes('splat_scratchpad')) {
      SPLAT_APP.printTerm('lab6_s1_term', '  Per-CPU array map scratchpad used instead of stack.', 'pass');
      SPLAT_APP.printTerm('lab6_s1_term', '  Stack frame footprint: 32 bytes (Limit: 512 bytes) [PASS]', 'pass');
      SPLAT_APP.printTerm('lab6_s1_term', '>>> KERNEL VERIFIER: Program verified without stack overflow! <<<', 'pass');
      SPLAT_APP.markStageComplete(6, 1, 100);
    } else {
      SPLAT_APP.printTerm('lab6_s1_term', '  VERIFIER REJECTION: stack frame size exceeds 512 bytes limit! [FAIL]', 'fail');
      SPLAT_APP.printTerm('lab6_s1_term', '  Refactor to use bpf_map_lookup_elem(&splat_scratchpad, &zero)', 'warn');
      SPLAT_APP.playFail();
    }
  },

  lab6_s2_resetCode() {
    SPLAT_APP.playClick();
    delete SPLAT_APP.state.userCode['lab6_s2'];
    SPLAT_APP.switchStage(2);
  },

  lab6_s2_verify() {
    SPLAT_APP.clearTerm('lab6_s2_term');
    SPLAT_APP.playClick();
    const code = document.getElementById('lab6_s2_code').value;

    SPLAT_APP.printTerm('lab6_s2_term', '[ASAN] Auditing FFI lifetime bridge...', 'info');
    if (code.includes('Box::into_raw') && code.includes('Box::from_raw')) {
      SPLAT_APP.printTerm('lab6_s2_term', '  Box::into_raw surrendered ownership to C callback. [PASS]', 'pass');
      SPLAT_APP.printTerm('lab6_s2_term', '  Box::from_raw safely reclaimed ownership on destructor. [PASS]', 'pass');
      SPLAT_APP.printTerm('lab6_s2_term', '  ASAN Report: 0 byte leaks, 0 use-after-free faults.', 'pass');
      SPLAT_APP.printTerm('lab6_s2_term', '>>> MEMORY SAFETY VERIFIED: Rust FFI contract intact! <<<', 'pass');
      SPLAT_APP.markStageComplete(6, 2, 100);
    } else {
      SPLAT_APP.printTerm('lab6_s2_term', '  ASAN FAULT: heap-use-after-free on dereferencing callback pointer! [FAIL]', 'fail');
      SPLAT_APP.printTerm('lab6_s2_term', '  Use Box::into_raw and Box::from_raw to bridge lifetimes.', 'warn');
      SPLAT_APP.playFail();
    }
  },

  lab6_s3_update() {
    // Initial display
  },

  lab6_s3_verify() {
    SPLAT_APP.clearTerm('lab6_s3_term');
    SPLAT_APP.playClick();
    const pinned = document.getElementById('lab6_s3_pin').checked;

    SPLAT_APP.printTerm('lab6_s3_term', '[GC] Initiating Generation 2 Full Compaction...', 'info');
    if (pinned) {
      document.getElementById('lab6_s3_ptr').innerText = '0x7FF01040 (STATIONARY)';
      document.getElementById('lab6_s3_ptr').style.color = 'var(--accent-green)';
      document.getElementById('lab6_s3_obj_disp').innerHTML = `
        [Obj A: Compacted to 0x7FF00800]<br>
        [Obj B (Target): 0x7FF01040] <strong style="color:var(--accent-green);">(PINNED)</strong><br>
        [Obj C: Compacted to 0x7FF01080]
      `;
      SPLAT_APP.printTerm('lab6_s3_term', '  Obj B is PINNED in memory: GC compacted surrounding objects.', 'pass');
      SPLAT_APP.printTerm('lab6_s3_term', '  Native IntPtr remains 100% valid. 0 dangling pointer faults.', 'pass');
      SPLAT_APP.printTerm('lab6_s3_term', '>>> GC PINNING VERIFIED! <<<', 'pass');
      SPLAT_APP.markStageComplete(6, 3, 100);
    } else {
      document.getElementById('lab6_s3_ptr').innerText = '0x7FF01000 (DANGLING POINTER)';
      document.getElementById('lab6_s3_ptr').style.color = 'var(--accent-crimson)';
      document.getElementById('lab6_s3_obj_disp').innerHTML = `
        [Obj A: Reclaimed]<br>
        [Obj B (Target): MOVED to 0x7FF00800] <strong style="color:var(--accent-crimson);">(UNPINNED)</strong><br>
        [Obj C: MOVED to 0x7FF00840]
      `;
      SPLAT_APP.printTerm('lab6_s3_term', '  CATASTROPHIC FAULT: Obj B moved to 0x7FF00800 while native code held 0x7FF01040!', 'fail');
      SPLAT_APP.printTerm('lab6_s3_term', '  Accessing 0x7FF01040 now reads corrupt memory or causes Access Violation.', 'fail');
      SPLAT_APP.printTerm('lab6_s3_term', '  Check "Pin Memory" and re-run.', 'warn');
      SPLAT_APP.playFail();
    }
  },

  // -------------------------------------------------------------------------
  // LAB 07 RUNNERS
  // -------------------------------------------------------------------------
  lab7_s1_update() {
    const u = document.getElementById('lab7_s1_url').value;
    const d = document.getElementById('lab7_s1_dest').value;
    // Simulate iterative replace
    let cmd = 'curl -s {url} -o {dest}';
    cmd = cmd.replaceAll('{url}', u);
    cmd = cmd.replaceAll('{dest}', d);
    document.getElementById('lab7_s1_result').innerText = cmd;
  },

  lab7_s1_verify() {
    SPLAT_APP.clearTerm('lab7_s1_term');
    SPLAT_APP.playClick();
    const res = document.getElementById('lab7_s1_result').innerText;
    if (res.includes('; /bin/sh -i;')) {
      SPLAT_APP.printTerm('lab7_s1_term', 'VULNERABILITY CONFIRMED: Second-order recursive replacement injected arbitrary shell commands!', 'pass');
      SPLAT_APP.printTerm('lab7_s1_term', 'Why it failed: Step 1 turned {url} into {dest}. Step 2 turned both into malicious payload.', 'info');
      SPLAT_APP.printTerm('lab7_s1_term', '>>> AUDIT PASSED: Vulnerability successfully reproduced. <<<', 'pass');
      SPLAT_APP.markStageComplete(7, 1, 100);
    } else {
      SPLAT_APP.printTerm('lab7_s1_term', 'Input {dest} for {url} and ; /bin/sh -i; for {dest} to observe injection.', 'warn');
    }
  },

  lab7_s2_resetCode() {
    SPLAT_APP.playClick();
    delete SPLAT_APP.state.userCode['lab7_s2'];
    SPLAT_APP.switchStage(2);
  },

  lab7_s2_verify() {
    SPLAT_APP.clearTerm('lab7_s2_term');
    SPLAT_APP.playClick();
    const code = document.getElementById('lab7_s2_code').value;

    SPLAT_APP.printTerm('lab7_s2_term', '[FUZZER] Testing single-pass regex replacement against 4 attack vectors...', 'info');
    if (code.includes('Regex.Replace') && code.includes('Regex.IsMatch') && code.includes('^[a-zA-Z0-9_')) {
      SPLAT_APP.printTerm('lab7_s2_term', '  [Test 1] Nested placeholder attack {url} -> "{dest}": Neutralized [PASS]', 'pass');
      SPLAT_APP.printTerm('lab7_s2_term', '  [Test 2] Shell metacharacter injection "; rm -rf /": Rejected [PASS]', 'pass');
      SPLAT_APP.printTerm('lab7_s2_term', '  [Test 3] Pipe redirection attack "| nc evil": Rejected [PASS]', 'pass');
      SPLAT_APP.printTerm('lab7_s2_term', '  [Test 4] Valid alphanumeric path "/tmp/output.bin": Allowed [PASS]', 'pass');
      SPLAT_APP.printTerm('lab7_s2_term', '>>> SECURE ARGUMENT BINDER: All fuzzing tests passed! <<<', 'pass');
      SPLAT_APP.markStageComplete(7, 2, 100);
    } else {
      SPLAT_APP.printTerm('lab7_s2_term', '  FUZZER DETECTED INJECTION: Ensure single-pass Regex.Replace with allowlist validation.', 'fail');
      SPLAT_APP.playFail();
    }
  },

  lab7_s3_reset() {
    const p = document.getElementById('lab7_s3_payload');
    const s = document.getElementById('lab7_s3_salt');
    if (p) p.innerText = '"ApiKey: sk-live-992182741"';
    if (s) s.innerText = '0x7c91f4d0e12a...';
  },

  lab7_s3_erase() {
    SPLAT_APP.playClick();
    document.getElementById('lab7_s3_payload').innerText = '[ZEROIZED / PERMANENTLY ERASED]';
    document.getElementById('lab7_s3_payload').style.color = 'var(--text-dim)';
    document.getElementById('lab7_s3_salt').innerText = '[DESTROYED]';
    document.getElementById('lab7_s3_salt').style.color = 'var(--text-dim)';
    SPLAT_APP.showToast('Cryptographic erasure executed!', 'info');
  },

  lab7_s3_verify() {
    SPLAT_APP.clearTerm('lab7_s3_term');
    SPLAT_APP.playClick();
    const pText = document.getElementById('lab7_s3_payload').innerText;
    if (pText.includes('ZEROIZED')) {
      SPLAT_APP.printTerm('lab7_s3_term', '[BLOCKCHAIN AUDIT] Verifying SHA-256 hash chain...', 'info');
      SPLAT_APP.printTerm('lab7_s3_term', '  Block #104 Commitment (0xd82f...39b1) matches stored Block Hash! [PASS]', 'pass');
      SPLAT_APP.printTerm('lab7_s3_term', '  Sensitive payload: Completely unrecoverable (Entropy: 0 bits). [PASS]', 'pass');
      SPLAT_APP.printTerm('lab7_s3_term', '  GDPR Right to Be Forgotten: COMPLIANT.', 'pass');
      SPLAT_APP.printTerm('lab7_s3_term', '>>> IMMUTABLE CRYPTOGRAPHIC ERASURE VERIFIED! <<<', 'pass');
      SPLAT_APP.markStageComplete(7, 3, 100);
    } else {
      SPLAT_APP.printTerm('lab7_s3_term', 'Click "Trigger Sovereign Cryptographic Erasure" first.', 'warn');
    }
  },

  // -------------------------------------------------------------------------
  // LAB 08 RUNNERS
  // -------------------------------------------------------------------------
  lab8_s1_init() {
    this.lab8_s1_toggle();
  },

  lab8_s1_toggle() {
    const pad = document.getElementById('lab8_s1_pad').checked;
    const mops = document.getElementById('lab8_s1_mops');
    const desc = document.getElementById('lab8_s1_line_desc');
    if (!mops || !desc) return;

    if (pad) {
      mops.innerText = '128.5 Mops/s';
      mops.style.color = 'var(--accent-green)';
      desc.innerHTML = `
        [Line 0x1000: producer_seq (8B) + 56B pad] <strong style="color:var(--accent-green);">(Core 0 Exclusive)</strong><br>
        [Line 0x1040: consumer_seq (8B) + 56B pad] <strong style="color:var(--accent-green);">(Core 1 Exclusive)</strong><br>
        <span style="color:var(--accent-green);">STATUS: ZERO FALSE SHARING (Cache Lines Decoupled)</span>
      `;
    } else {
      mops.innerText = '3.2 Mops/s';
      mops.style.color = 'var(--accent-crimson)';
      desc.innerHTML = `
        [producer_seq (8B)] [consumer_seq (8B)] [48B unused]<br>
        <span style="color:var(--accent-crimson);">STATUS: FALSE SHARING DETECTED (MESI Invalidation Storm)</span>
      `;
    }
  },

  lab8_s1_verify() {
    SPLAT_APP.clearTerm('lab8_s1_term');
    SPLAT_APP.playClick();
    const pad = document.getElementById('lab8_s1_pad').checked;

    if (pad) {
      SPLAT_APP.printTerm('lab8_s1_term', 'PERF: L1-dcache-load-misses dropped from 94% down to 0.4%! [PASS]', 'pass');
      SPLAT_APP.printTerm('lab8_s1_term', 'Throughput jumped 40.1x to 128.5 Mops/s.', 'pass');
      SPLAT_APP.printTerm('lab8_s1_term', '>>> HARDWARE SYMPATHY VERIFIED: Cache line decoupled! <<<', 'pass');
      SPLAT_APP.markStageComplete(8, 1, 100);
    } else {
      SPLAT_APP.printTerm('lab8_s1_term', 'PERF: Core 0 writes invalidate Core 1 cache line on every clock cycle. [COLLAPSE]', 'fail');
      SPLAT_APP.printTerm('lab8_s1_term', 'Check "Apply alignas(64) Padding" to eliminate false sharing.', 'warn');
      SPLAT_APP.playFail();
    }
  },

  lab8_s2_calc() {
    const prompt = document.getElementById('lab8_s2_prompt').value || 'SPLAT';
    const heatEl = document.getElementById('lab8_s2_heatmap');
    if (!heatEl) return;

    heatEl.innerHTML = '';
    let sumSq = 0;
    const vals = [];

    for (let i = 0; i < 128; i++) {
      // Deterministic pseudo-random float based on prompt and index
      let hash = i * 2654435761;
      for (let c = 0; c < prompt.length; c++) {
        hash = (hash ^ prompt.charCodeAt(c)) * 16777619;
      }
      const val = ((hash % 1000) / 500) - 1.0;
      vals.push(val);
      sumSq += val * val;
    }

    const norm = Math.sqrt(sumSq);
    vals.forEach(v => {
      const normalized = v / norm;
      const cell = document.createElement('div');
      const intensity = Math.round(Math.abs(normalized) * 255);
      cell.style.background = normalized >= 0 ? `rgb(0, ${intensity}, ${intensity})` : `rgb(${intensity}, 50, 100)`;
      cell.title = `Dim ${vals.indexOf(v)}: ${normalized.toFixed(4)}`;
      heatEl.appendChild(cell);
    });

    document.getElementById('lab8_s2_norm').innerText = '1.000000';
  },

  lab8_s2_verify() {
    SPLAT_APP.clearTerm('lab8_s2_term');
    SPLAT_APP.playClick();
    SPLAT_APP.printTerm('lab8_s2_term', '[EMBEDDING] Validating 128-dimensional vector...', 'info');
    SPLAT_APP.printTerm('lab8_s2_term', '  Dimension count: 128 floats (512 bytes aligned) [PASS]', 'pass');
    SPLAT_APP.printTerm('lab8_s2_term', '  Euclidean L2 Norm: 1.000000 (Unit Sphere Normalized) [PASS]', 'pass');
    SPLAT_APP.printTerm('lab8_s2_term', '>>> VECTOR NORMALIZATION VERIFIED! <<<', 'pass');
    SPLAT_APP.markStageComplete(8, 2, 100);
  },

  lab8_s3_verify() {
    SPLAT_APP.clearTerm('lab8_s3_term');
    SPLAT_APP.playClick();
    SPLAT_APP.printTerm('lab8_s3_term', '[BENCH] Running 1,000,000 dot product iterations...', 'info');
    SPLAT_APP.printTerm('lab8_s3_term', '  Scalar Dot Product (CPU Loop): 42.1 ms', 'info');
    SPLAT_APP.printTerm('lab8_s3_term', '  AVX2 SIMD (_mm256_fmadd_ps): 6.8 ms (6.19x Speedup!) [PASS]', 'pass');
    SPLAT_APP.printTerm('lab8_s3_term', '  Numerical Epsilon: 0.0000000e+00 (Identical bitwise accuracy)', 'pass');
    SPLAT_APP.printTerm('lab8_s3_term', '>>> AVX2 SIMD VECTOR ACCELERATION VERIFIED! <<<', 'pass');
    SPLAT_APP.markStageComplete(8, 3, 100);
  },

  // -------------------------------------------------------------------------
  // LAB 09 RUNNERS
  // -------------------------------------------------------------------------
  lab9_s1_resetCode() {
    SPLAT_APP.playClick();
    delete SPLAT_APP.state.userCode['lab9_s1'];
    SPLAT_APP.switchStage(1);
  },

  lab9_s1_verify() {
    SPLAT_APP.clearTerm('lab9_s1_term');
    SPLAT_APP.playClick();
    const code = document.getElementById('lab9_s1_code').value;

    SPLAT_APP.printTerm('lab9_s1_term', '[LSM SIMULATOR] Testing bprm_check_security hook...', 'info');
    if (code.includes('bpf_get_current_cgroup_id') && code.includes('bpf_map_lookup_elem') && code.includes('-1')) {
      SPLAT_APP.printTerm('lab9_s1_term', '  [Test 1] Host system binary /usr/bin/python3: Allowed (ret: 0) [PASS]', 'pass');
      SPLAT_APP.printTerm('lab9_s1_term', '  [Test 2] Sandboxed agent binary /usr/bin/splat-worker: Allowed [PASS]', 'pass');
      SPLAT_APP.printTerm('lab9_s1_term', '  [Test 3] Sandboxed agent attempting /bin/sh: BLOCKED (-EPERM -1) [PASS]', 'pass');
      SPLAT_APP.printTerm('lab9_s1_term', '  [Test 4] Sandboxed agent attempting /usr/bin/nc: BLOCKED (-EPERM -1) [PASS]', 'pass');
      SPLAT_APP.printTerm('lab9_s1_term', '>>> IN-KERNEL LSM ENFORCEMENT VERIFIED! <<<', 'pass');
      SPLAT_APP.markStageComplete(9, 1, 100);
    } else {
      SPLAT_APP.printTerm('lab9_s1_term', '  LSM HOOK BYPASS: Hook failed to scope by cgroup or block unauthorized binary.', 'fail');
      SPLAT_APP.playFail();
    }
  },

  lab9_s2_stepIndex: 0,
  lab9_s2_reset() {
    this.lab9_s2_stepIndex = 0;
    for (let i = 0; i < 4; i++) {
      const el = document.getElementById(`asm_line_${i}`);
      if (el) el.style.background = 'transparent';
    }
    const l0 = document.getElementById('asm_line_0');
    if (l0) l0.style.background = 'rgba(0, 240, 255, 0.2)';
    const rip = document.getElementById('reg_rip');
    if (rip) rip.innerText = '0x7FF01010';
    const rax = document.getElementById('reg_rax');
    if (rax) rax.innerText = '0x00000000';
    const r10 = document.getElementById('reg_r10');
    if (r10) r10.innerText = '0x00000000';
  },

  lab9_s2_step() {
    SPLAT_APP.playClick();
    this.lab9_s2_stepIndex++;
    for (let i = 0; i < 4; i++) {
      const el = document.getElementById(`asm_line_${i}`);
      if (el) el.style.background = 'transparent';
    }

    if (this.lab9_s2_stepIndex === 1) {
      document.getElementById('asm_line_1').style.background = 'rgba(0, 240, 255, 0.2)';
      document.getElementById('reg_rip').innerText = '0x7FF01013';
      document.getElementById('reg_r10').innerText = '0x000004A8';
      SPLAT_APP.printTerm('lab9_s2_term', 'STEP 1: mov r10, rcx -> R10 receives JobHandle (0x4A8). RCX preserved for syscall.', 'info');
    } else if (this.lab9_s2_stepIndex === 2) {
      document.getElementById('asm_line_2').style.background = 'rgba(0, 240, 255, 0.2)';
      document.getElementById('reg_rip').innerText = '0x7FF01018';
      document.getElementById('reg_rax').innerText = '0x0000002A';
      SPLAT_APP.printTerm('lab9_s2_term', 'STEP 2: mov eax, 0x002A -> System Service Number (SSN) for NtSetInformationJobObject loaded into EAX.', 'info');
    } else if (this.lab9_s2_stepIndex === 3) {
      document.getElementById('asm_line_3').style.background = 'rgba(0, 240, 255, 0.2)';
      document.getElementById('reg_rip').innerText = '0x7FF0101A';
      document.getElementById('reg_rax').innerText = '0x00000000 (STATUS_SUCCESS)';
      SPLAT_APP.printTerm('lab9_s2_term', 'STEP 3: syscall -> CPU transitioned to Ring 0! Kernel handled NtSetInformationJobObject and returned 0 (STATUS_SUCCESS) in RAX.', 'pass');
    } else {
      this.lab9_s2_stepIndex = 3;
      SPLAT_APP.printTerm('lab9_s2_term', 'Syscall sequence already completed. Click "Complete Syscall Step".', 'pass');
    }
  },

  lab9_s2_verify() {
    SPLAT_APP.clearTerm('lab9_s2_term');
    SPLAT_APP.playClick();
    if (this.lab9_s2_stepIndex >= 3) {
      SPLAT_APP.printTerm('lab9_s2_term', 'PASS: x64 Windows fastcall syscall sequence executed successfully!', 'pass');
      SPLAT_APP.printTerm('lab9_s2_term', 'R10 argument preservation and RAX status code verified.', 'info');
      SPLAT_APP.printTerm('lab9_s2_term', '>>> DISASSEMBLY STEPPER VERIFIED! <<<', 'pass');
      SPLAT_APP.markStageComplete(9, 2, 100);
    } else {
      SPLAT_APP.printTerm('lab9_s2_term', 'Step through all assembly instructions using "Step Instruction" first.', 'warn');
    }
  },

  lab9_s3_resetCode() {
    SPLAT_APP.playClick();
    delete SPLAT_APP.state.userCode['lab9_s3'];
    SPLAT_APP.switchStage(3);
  },

  lab9_s3_verify() {
    SPLAT_APP.clearTerm('lab9_s3_term');
    SPLAT_APP.playClick();
    const code = document.getElementById('lab9_s3_code').value;

    SPLAT_APP.printTerm('lab9_s3_term', '[VERIFIER] Running abstract interpretation pass on pointer arithmetic...', 'info');
    if (code.includes('offset >=') || code.includes('offset >')) {
      SPLAT_APP.printTerm('lab9_s3_term', '  0: (79) r1 = *(u64 *)(r10 - 8)', 'dim');
      SPLAT_APP.printTerm('lab9_s3_term', '  1: (69) r2 = *(u16 *)(r1 + 0)', 'dim');
      SPLAT_APP.printTerm('lab9_s3_term', '  2: (25) if r2 > 0xff goto pc+2', 'dim');
      SPLAT_APP.printTerm('lab9_s3_term', '  3: (0f) r1 += r2 [R2 is proven bounded in [0, 255]]', 'pass');
      SPLAT_APP.printTerm('lab9_s3_term', '  4: (71) *(u8 *)(r1 + 0) = 0 [SAFE MEMORY ACCESS]', 'pass');
      SPLAT_APP.printTerm('lab9_s3_term', '>>> KERNEL VERIFIER SUCCESS: 0 unsafe memory paths! <<<', 'pass');
      SPLAT_APP.markStageComplete(9, 3, 100);
    } else {
      SPLAT_APP.printTerm('lab9_s3_term', '  R1 invalid mem access "inv" (unbounded arithmetic: R2 min=0, max=unknown)', 'fail');
      SPLAT_APP.printTerm('lab9_s3_term', '  Must add bounds check: if (offset >= 256) return -1;', 'warn');
      SPLAT_APP.playFail();
    }
  },

  // -------------------------------------------------------------------------
  // LAB 10 RUNNERS
  // -------------------------------------------------------------------------
  lab10_s1_verify() {
    SPLAT_APP.clearTerm('lab10_s1_term');
    SPLAT_APP.playClick();
    const ans = document.getElementById('lab10_s1_ans').value;
    if (ans === 'peer_id') {
      SPLAT_APP.printTerm('lab10_s1_term', 'PASS: Correct!', 'pass');
      SPLAT_APP.printTerm('lab10_s1_term', 'Hyper-V AF_VSOCK routes directly across the VM bus; context ID (VMID) is hardware enforced by the hypervisor, eliminating loopback TCP port-sniffing and token hijacking.', 'info');
      SPLAT_APP.printTerm('lab10_s1_term', '>>> ARCHITECTURE VERIFIED: Zero local network attack surface! <<<', 'pass');
      SPLAT_APP.markStageComplete(10, 1, 100);
    } else {
      SPLAT_APP.printTerm('lab10_s1_term', 'FAIL: Review the peer authentication security guarantees of AF_VSOCK.', 'fail');
      SPLAT_APP.playFail();
    }
  },

  lab10_s2_verify() {
    SPLAT_APP.clearTerm('lab10_s2_term');
    SPLAT_APP.playClick();
    const target = document.getElementById('lab10_s2_target').value;

    SPLAT_APP.printTerm('lab10_s2_term', '[WFP] Packet arriving at FWPM_LAYER_ALE_AUTH_CONNECT_V4...', 'info');
    if (target === 'allowed') {
      SPLAT_APP.printTerm('lab10_s2_term', '  Destination: 10.0.50.10:443 (api.splat.internal)', 'info');
      SPLAT_APP.printTerm('lab10_s2_term', '  Callout Action: FWP_ACTION_PERMIT [PASS]', 'pass');
      SPLAT_APP.printTerm('lab10_s2_term', '>>> ALLOWED EGRESS AUTHORIZED! <<<', 'pass');
      SPLAT_APP.markStageComplete(10, 2, 100);
    } else if (target === 'c2') {
      SPLAT_APP.printTerm('lab10_s2_term', '  Destination: 198.51.100.25:8080 (Attacker C2)', 'warn');
      SPLAT_APP.printTerm('lab10_s2_term', '  Callout Action: FWP_ACTION_BLOCK (WSAEACCES) [DROPPED]', 'fail');
      SPLAT_APP.printTerm('lab10_s2_term', '>>> WFP BLOCKED UNAUTHORIZED EGRESS! <<<', 'pass');
      SPLAT_APP.markStageComplete(10, 2, 100);
    } else {
      SPLAT_APP.printTerm('lab10_s2_term', '  Destination: 8.8.8.8:53 (DNS Tunnel Attempt)', 'warn');
      SPLAT_APP.printTerm('lab10_s2_term', '  Callout Action: FWP_ACTION_BLOCK [DROPPED]', 'fail');
      SPLAT_APP.printTerm('lab10_s2_term', '>>> WFP BLOCKED DNS TUNNEL! <<<', 'pass');
      SPLAT_APP.markStageComplete(10, 2, 100);
    }
  },

  lab10_s3_verify() {
    SPLAT_APP.clearTerm('lab10_s3_term');
    SPLAT_APP.playClick();
    const q1 = document.querySelector('input[name="exam_q1"]:checked')?.value;
    const q2 = document.querySelector('input[name="exam_q2"]:checked')?.value;
    const q3 = document.querySelector('input[name="exam_q3"]:checked')?.value;
    const q4 = document.querySelector('input[name="exam_q4"]:checked')?.value;

    let score = 0;
    if (q1 === 'a') score += 25;
    if (q2 === 'a') score += 25;
    if (q3 === 'a') score += 25;
    if (q4 === 'a') score += 25;

    SPLAT_APP.printTerm('lab10_s3_term', `CAPSTONE SCORE: ${score}% (Passing Grade: 80%)`, score >= 80 ? 'pass' : 'fail');
    if (score >= 80) {
      SPLAT_APP.printTerm('lab10_s3_term', 'CONGRATULATIONS! You have mastered the SPLAT Systems Architecture.', 'pass');
      SPLAT_APP.printTerm('lab10_s3_term', '>>> MASTER CREDENTIAL UNLOCKED! Click "View Master Credential" below. <<<', 'pass');
      SPLAT_APP.markStageComplete(10, 3, 300);
      SPLAT_APP.playVictory();
    } else {
      SPLAT_APP.printTerm('lab10_s3_term', 'Grade below passing requirement. Review incorrect answers and re-grade.', 'fail');
      SPLAT_APP.playFail();
    }
  }
};
"""
