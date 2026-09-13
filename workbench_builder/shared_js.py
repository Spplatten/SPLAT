# workbench_builder/shared_js.py
# Core application runtime, Web Audio synthesizer, state storage, and UI controller

def get_shared_js():
    return """
// ==========================================================================
// SPLAT LEARNING WORKBENCH RUNTIME ENGINE
// ==========================================================================

const SPLAT_APP = {
  activeLab: 1,
  activeStage: 1,
  state: {
    completedStages: {},
    userCode: {},
    soundMuted: false,
    studentName: "Systems Architect",
    score: 0
  },
  audioCtx: null,

  init() {
    this.loadState();
    this.setupAudio();
    this.setupEventListeners();
    this.renderSidebarNav();
    this.switchLab(1, 1);
    this.updateMasterUI();
    console.log("[*] SPLAT Learning Workbench runtime successfully initialized.");
  },

  // State Persistence
  saveState() {
    try {
      localStorage.setItem('splat_workbench_progress_v1', JSON.stringify(this.state));
    } catch (e) {
      console.warn("LocalStorage save error:", e);
    }
    this.updateMasterUI();
  },

  loadState() {
    try {
      const saved = localStorage.getItem('splat_workbench_progress_v1');
      if (saved) {
        this.state = Object.assign(this.state, JSON.parse(saved));
      }
    } catch (e) {
      console.warn("LocalStorage load error:", e);
    }
  },

  resetProgress() {
    if (confirm("Reset all laboratory progress, completed stages, and saved code?")) {
      this.state.completedStages = {};
      this.state.userCode = {};
      this.state.score = 0;
      this.saveState();
      this.switchLab(this.activeLab, 1);
      this.updateMasterUI();
      this.showToast("All lab progress has been reset.", "info");
    }
  },

  isStageCompleted(labNum, stageNum) {
    return !!this.state.completedStages[`lab${labNum}_s${stageNum}`];
  },

  markStageComplete(labNum, stageNum, points = 100) {
    const key = `lab${labNum}_s${stageNum}`;
    const firstTime = !this.state.completedStages[key];
    this.state.completedStages[key] = true;
    if (firstTime) {
      this.state.score = (this.state.score || 0) + points;
      this.playFanfare();
      this.showToast(`Stage ${String(stageNum).padStart(2, '0')} Complete! +${points} XP`, "success");
    } else {
      this.playPass();
      this.showToast(`Stage ${String(stageNum).padStart(2, '0')} Verified!`, "success");
    }
    this.saveState();
    this.updateMasterUI();

    // Show Next Button
    const nextBtn = document.getElementById(`lab${labNum}_s${stageNum}_next_btn`);
    if (nextBtn) {
      nextBtn.style.display = "inline-flex";
    }

    // Check if Lab Complete
    if (this.isLabComplete(labNum)) {
      this.showToast(`🏆 LAB ${String(labNum).padStart(2, '0')} FULLY COMPLETED!`, "success");
    }
  },

  isLabComplete(labNum) {
    return this.isStageCompleted(labNum, 1) &&
           this.isStageCompleted(labNum, 2) &&
           this.isStageCompleted(labNum, 3);
  },

  getTotalCompletedStages() {
    return Object.keys(this.state.completedStages).filter(k => this.state.completedStages[k]).length;
  },

  // Web Audio Synthesizer
  setupAudio() {
    const soundBtn = document.getElementById('audio-toggle-btn');
    if (soundBtn) {
      soundBtn.innerHTML = this.state.soundMuted ? '🔇 Audio OFF' : '🔊 Audio ON';
    }
  },

  toggleAudio() {
    this.state.soundMuted = !this.state.soundMuted;
    const soundBtn = document.getElementById('audio-toggle-btn');
    if (soundBtn) {
      soundBtn.innerHTML = this.state.soundMuted ? '🔇 Audio OFF' : '🔊 Audio ON';
    }
    this.saveState();
    if (!this.state.soundMuted) {
      this.playClick();
    }
  },

  getAudioContext() {
    if (!this.audioCtx) {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (AudioCtx) {
        this.audioCtx = new AudioCtx();
      }
    }
    if (this.audioCtx && this.audioCtx.state === 'suspended') {
      this.audioCtx.resume();
    }
    return this.audioCtx;
  },

  playClick() {
    if (this.state.soundMuted) return;
    const ctx = this.getAudioContext();
    if (!ctx) return;
    try {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(800, ctx.currentTime);
      gain.gain.setValueAtTime(0.04, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.02);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.02);
    } catch(e) {}
  },

  playPass() {
    if (this.state.soundMuted) return;
    const ctx = this.getAudioContext();
    if (!ctx) return;
    try {
      const t = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(523.25, t); // C5
      osc.frequency.setValueAtTime(783.99, t + 0.08); // G5
      gain.gain.setValueAtTime(0.08, t);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.25);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(t);
      osc.stop(t + 0.25);
    } catch(e) {}
  },

  playFail() {
    if (this.state.soundMuted) return;
    const ctx = this.getAudioContext();
    if (!ctx) return;
    try {
      const t = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(180, t);
      osc.frequency.linearRampToValueAtTime(130, t + 0.18);
      gain.gain.setValueAtTime(0.08, t);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.22);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(t);
      osc.stop(t + 0.22);
    } catch(e) {}
  },

  playFanfare() {
    if (this.state.soundMuted) return;
    const ctx = this.getAudioContext();
    if (!ctx) return;
    try {
      const t = ctx.currentTime;
      const notes = [523.25, 659.25, 783.99, 1046.50]; // C5, E5, G5, C6
      notes.forEach((freq, idx) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(freq, t + idx * 0.09);
        gain.gain.setValueAtTime(0.09, t + idx * 0.09);
        gain.gain.exponentialRampToValueAtTime(0.0001, t + idx * 0.09 + 0.28);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(t + idx * 0.09);
        osc.stop(t + idx * 0.09 + 0.3);
      });
    } catch(e) {}
  },

  // UI Navigation & Updating
  renderSidebarNav() {
    const list = document.getElementById('lab-nav-list');
    if (!list) return;
    list.innerHTML = '';

    LABS_DATA.forEach(lab => {
      const item = document.createElement('li');
      item.className = `lab-nav-item ${lab.id === this.activeLab ? 'active' : ''} ${this.isLabComplete(lab.id) ? 'completed' : ''}`;
      item.id = `nav-lab-${lab.id}`;
      item.onclick = () => {
        this.playClick();
        this.switchLab(lab.id, 1);
      };

      let completedCount = 0;
      if (this.isStageCompleted(lab.id, 1)) completedCount++;
      if (this.isStageCompleted(lab.id, 2)) completedCount++;
      if (this.isStageCompleted(lab.id, 3)) completedCount++;

      item.innerHTML = `
        <div class="lab-nav-top">
          <span class="lab-nav-num">LAB ${String(lab.id).padStart(2, '0')}</span>
          <span class="lab-nav-progress" id="nav-prog-${lab.id}">${completedCount}/3</span>
        </div>
        <div class="lab-nav-title">${lab.shortTitle}</div>
        <div class="lab-nav-volume">${lab.volume}</div>
      `;
      list.appendChild(item);
    });
  },

  updateMasterUI() {
    const total = this.getTotalCompletedStages();
    const pct = Math.round((total / 30) * 100);

    const bar = document.getElementById('master-progress-bar');
    if (bar) bar.style.width = `${pct}%`;

    const lbl = document.getElementById('master-progress-label');
    if (lbl) lbl.innerText = `${total}/30 STAGES (${pct}%)`;

    const scoreElem = document.getElementById('master-score-val');
    if (scoreElem) scoreElem.innerText = `${this.state.score || 0} XP`;

    // Update sidebar counts
    LABS_DATA.forEach(lab => {
      let count = 0;
      if (this.isStageCompleted(lab.id, 1)) count++;
      if (this.isStageCompleted(lab.id, 2)) count++;
      if (this.isStageCompleted(lab.id, 3)) count++;

      const pElem = document.getElementById(`nav-prog-${lab.id}`);
      if (pElem) {
        pElem.innerText = `${count}/3`;
      }
      const navItem = document.getElementById(`nav-lab-${lab.id}`);
      if (navItem) {
        if (count === 3) {
          navItem.classList.add('completed');
        } else {
          navItem.classList.remove('completed');
        }
      }
    });

    // Update stage tab badges
    for (let s = 1; s <= 3; s++) {
      const tab = document.getElementById(`stage-tab-${s}`);
      if (tab) {
        const isDone = this.isStageCompleted(this.activeLab, s);
        if (isDone) {
          tab.classList.add('completed');
          tab.querySelector('.stage-tab-status').innerHTML = '✓';
        } else {
          tab.classList.remove('completed');
          tab.querySelector('.stage-tab-status').innerHTML = s;
        }
      }
    }
  },

  switchLab(labId, stageId = 1) {
    this.activeLab = labId;
    this.activeStage = stageId;

    // Highlight sidebar
    document.querySelectorAll('.lab-nav-item').forEach(el => el.classList.remove('active'));
    const activeNav = document.getElementById(`nav-lab-${labId}`);
    if (activeNav) activeNav.classList.add('active');

    // Render Lab View
    const lab = LABS_DATA.find(l => l.id === labId);
    if (!lab) return;

    document.getElementById('lab-badge-vol').innerText = lab.volume;
    document.getElementById('lab-badge-tier').innerText = lab.tier;
    document.getElementById('lab-main-title').innerText = `LAB ${String(lab.id).padStart(2, '0')}: ${lab.title}`;
    document.getElementById('lab-objective').innerText = lab.objective;

    // Switch stage
    this.switchStage(stageId);
  },

  switchStage(stageId) {
    this.activeStage = stageId;
    this.playClick();

    // Tabs update
    document.querySelectorAll('.stage-tab').forEach((t, idx) => {
      if (idx + 1 === stageId) {
        t.classList.add('active');
      } else {
        t.classList.remove('active');
      }
    });

    // Content container render
    const lab = LABS_DATA.find(l => l.id === this.activeLab);
    const stage = lab.stages[stageId - 1];
    const container = document.getElementById('stage-content-container');

    container.innerHTML = `
      <div class="pedagogy-card">
        <h3><span>🔬</span> ${stage.title}</h3>
        <p>${stage.theory}</p>
        <div class="pedagogy-callout">
          <strong>⚡ ENGINEERING OBJECTIVE:</strong> ${stage.task}
        </div>
      </div>

      <div class="workbench-interactive-grid">
        <div class="workbench-panel">
          <div class="panel-header">
            <span class="panel-header-title">🛠️ ${stage.leftTitle || 'INTERACTIVE WORKSPACE'}</span>
            <span style="color:var(--text-muted); font-size:11px;">${stage.leftSub || ''}</span>
          </div>
          <div class="panel-body" id="stage-left-body">
            ${stage.renderLeft(this.activeLab, stageId)}
          </div>
        </div>

        <div class="workbench-panel">
          <div class="panel-header">
            <span class="panel-header-title">⚡ ${stage.rightTitle || 'DIAGNOSTIC CONSOLE & TEST RUNNER'}</span>
            <span style="color:var(--text-muted); font-size:11px;">AUTOMATED SUITE</span>
          </div>
          <div class="panel-body" id="stage-right-body" style="padding:0;">
            ${stage.renderRight(this.activeLab, stageId)}
          </div>
        </div>
      </div>
    `;

    // Trigger stage post-mount logic
    if (stage.onMount) {
      stage.onMount(this.activeLab, stageId);
    }

    // Restore next button if completed
    if (this.isStageCompleted(this.activeLab, stageId)) {
      const nextBtn = document.getElementById(`lab${this.activeLab}_s${stageId}_next_btn`);
      if (nextBtn) nextBtn.style.display = 'inline-flex';
    }

    this.updateMasterUI();
  },

  nextStage() {
    this.playClick();
    if (this.activeStage < 3) {
      this.switchStage(this.activeStage + 1);
    } else if (this.activeLab < 10) {
      this.switchLab(this.activeLab + 1, 1);
    } else {
      this.openCertificateModal();
    }
  },

  // Terminal Logging
  clearTerm(termId) {
    const el = document.getElementById(termId);
    if (el) el.innerHTML = '';
  },

  printTerm(termId, text, type = 'info') {
    const el = document.getElementById(termId);
    if (!el) return;
    const line = document.createElement('div');
    line.className = `term-line-${type}`;
    line.innerText = text;
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
  },

  // Toast System
  showToast(msg, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast-msg ${type}`;
    toast.innerHTML = `<span>${type === 'success' ? '✔' : type === 'error' ? '✖' : 'ℹ'}</span> <span>${msg}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(50px)';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  },

  // Modal Handlers
  openCertificateModal() {
    this.playClick();
    const modal = document.getElementById('certificate-modal');
    if (modal) {
      modal.classList.add('open');
      this.renderCertificateSVG();
    }
  },

  closeModal(modalId) {
    this.playClick();
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.remove('open');
  },

  setupEventListeners() {
    // Stage tabs
    for (let s = 1; s <= 3; s++) {
      const tab = document.getElementById(`stage-tab-${s}`);
      if (tab) {
        tab.onclick = () => this.switchStage(s);
      }
    }
  }
};
"""
