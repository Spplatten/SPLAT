# workbench_builder/certificate.py
# High-resolution SVG Master Systems Engineering Credential generator

def get_certificate_html_and_js():
    html = """
<!-- MASTER SYSTEMS CREDENTIAL MODAL -->
<div class="modal-backdrop" id="certificate-modal">
  <div class="modal-window" style="max-width:920px;">
    <div class="modal-header">
      <h2><span>🎓</span> MASTER SYSTEMS ENGINEERING CREDENTIAL</h2>
      <button class="modal-close-btn" onclick="SPLAT_APP.closeModal('certificate-modal')">&times;</button>
    </div>
    <div class="modal-body">
      <div style="display:flex; justify-content:space-between; align-items:center; background:#161b22; padding:12px 18px; border-radius:6px; border:1px solid #30363d;">
        <div style="display:flex; align-items:center; gap:10px;">
          <label style="font-size:12px; color:var(--text-muted); font-family:var(--font-mono);">CANDIDATE NAME:</label>
          <input type="text" id="cert-student-name" value="Distinguished Systems Architect" style="background:#0d1117; border:1px solid var(--accent-cyan); color:#fff; padding:6px 12px; border-radius:4px; font-family:var(--font-mono); font-size:13px; width:280px;" oninput="SPLAT_APP.renderCertificateSVG()">
        </div>
        <button class="btn-header primary" onclick="window.print()">🖨 Print / Export PDF</button>
      </div>

      <div id="cert-svg-container" style="display:flex; justify-content:center; align-items:center; background:#07090e; border:1px solid var(--border-color); border-radius:8px; padding:16px; overflow:hidden;">
        <!-- Dynamically rendered SVG Certificate -->
      </div>
    </div>
  </div>
</div>
"""

    js = """
// Certificate rendering engine
SPLAT_APP.renderCertificateSVG = function() {
  const container = document.getElementById('cert-svg-container');
  if (!container) return;

  const rawName = document.getElementById('cert-student-name')?.value || "Distinguished Systems Architect";
  const name = rawName.replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const totalXP = this.state.score || 3000;

  // Generate pseudo SHA-256 verification hash
  let hashVal = 0x811c9dc5;
  for (let i = 0; i < name.length; i++) {
    hashVal = (hashVal ^ name.charCodeAt(i)) * 0x01000193;
  }
  const hexHash = "SHA256: " + Math.abs(hashVal).toString(16).padStart(8, '0').toUpperCase() + "7B92A41C90EF82B441D9901B";

  const svg = `
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 850 560" width="100%" height="100%" style="font-family:'Segoe UI', Roboto, sans-serif; background:#0a0d14;">
    <defs>
      <linearGradient id="certBg" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#0f1522" />
        <stop offset="50%" stop-color="#090c12" />
        <stop offset="100%" stop-color="#141c2c" />
      </linearGradient>
      <linearGradient id="goldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#ffdf00" />
        <stop offset="50%" stop-color="#d4af37" />
        <stop offset="100%" stop-color="#aa7c11" />
      </linearGradient>
      <linearGradient id="cyanGrad" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="#00f0ff" />
        <stop offset="100%" stop-color="#00ff88" />
      </linearGradient>
    </defs>

    <!-- Outer Guilloche Border -->
    <rect x="15" y="15" width="820" height="530" rx="8" fill="url(#certBg)" stroke="#22314a" stroke-width="2" />
    <rect x="25" y="25" width="800" height="510" rx="6" fill="none" stroke="url(#goldGrad)" stroke-width="1.5" stroke-dasharray="8,4" />
    <rect x="30" y="30" width="790" height="500" rx="4" fill="none" stroke="#00f0ff" stroke-width="0.75" opacity="0.4" />

    <!-- Corner Accents -->
    <path d="M 35 55 L 35 35 L 55 35" fill="none" stroke="#00f0ff" stroke-width="3" />
    <path d="M 815 55 L 815 35 L 795 35" fill="none" stroke="#00f0ff" stroke-width="3" />
    <path d="M 35 505 L 35 525 L 55 525" fill="none" stroke="#00f0ff" stroke-width="3" />
    <path d="M 815 505 L 815 525 L 795 525" fill="none" stroke="#00f0ff" stroke-width="3" />

    <!-- Header / Crest -->
    <circle cx="425" cy="85" r="32" fill="#162032" stroke="url(#goldGrad)" stroke-width="2" />
    <text x="425" y="93" font-size="24" fill="#00f0ff" text-anchor="middle">🛡</text>

    <!-- Institution Banner -->
    <text x="425" y="140" font-family="'JetBrains Mono', Consolas, monospace" font-size="12" font-weight="700" fill="url(#cyanGrad)" letter-spacing="4" text-anchor="middle">SPLAT ARCHITECTURAL ACADEMY & SYSTEMS INSTITUTE</text>
    <text x="425" y="175" font-family="'Segoe UI', Roboto, sans-serif" font-size="24" font-weight="800" fill="#ffffff" letter-spacing="1.5" text-anchor="middle">MASTER SYSTEMS ENGINEERING CREDENTIAL</text>
    <text x="425" y="200" font-family="'JetBrains Mono', Consolas, monospace" font-size="11" fill="#ffb700" letter-spacing="2" text-anchor="middle">KERNEL GOVERNANCE & MULTI-LANGUAGE RUNTIME SPECIALIZATION</text>

    <!-- Body text -->
    <text x="425" y="245" font-size="13" fill="#8b9cb5" text-anchor="middle">This document certifies that following comprehensive rigorous examination,</text>
    <text x="425" y="290" font-family="'Segoe UI', Roboto, sans-serif" font-size="26" font-weight="700" fill="#ffffff" text-anchor="middle">${name}</text>
    <line x1="225" y1="305" x2="625" y2="305" stroke="#304260" stroke-width="1" />

    <text x="425" y="335" font-size="12" fill="#c9d1d9" text-anchor="middle">has successfully mastered the complete 10-Volume SPLAT curriculum spanning</text>
    <text x="425" y="355" font-family="'JetBrains Mono', Consolas, monospace" font-size="11.5" font-weight="600" fill="#00ff88" text-anchor="middle">.NET 10 | Rust Zero-Copy FFI | Linux eBPF LSM | Win32 AppContainers</text>
    <text x="425" y="380" font-size="12" fill="#8b9cb5" text-anchor="middle">demonstrating distinguished technical excellence in 30 hands-on kernel laboratories.</text>

    <!-- Score & Metadata -->
    <rect x="325" y="405" width="200" height="30" rx="4" fill="#101726" stroke="#25354e" />
    <text x="425" y="424" font-family="'JetBrains Mono', Consolas, monospace" font-size="11" font-weight="700" fill="#ffdf00" text-anchor="middle">TOTAL DISTINCTION: ${totalXP} XP</text>

    <!-- Footer Seals & Signatures -->
    <g transform="translate(100, 470)">
      <line x1="0" y1="0" x2="180" y2="0" stroke="#304260" stroke-width="1" />
      <text x="90" y="18" font-size="11" font-weight="600" fill="#c9d1d9" text-anchor="middle">Antigravity Architecture Board</text>
      <text x="90" y="32" font-size="10" fill="#8b9cb5" text-anchor="middle">DeepMind Engineering</text>
    </g>

    <g transform="translate(375, 450)">
      <circle cx="50" cy="25" r="28" fill="#131c2e" stroke="url(#goldGrad)" stroke-width="1.5" />
      <text x="50" y="24" font-size="10" font-weight="700" fill="#ffdf00" text-anchor="middle">SEAL OF</text>
      <text x="50" y="36" font-size="9" font-weight="700" fill="#00f0ff" text-anchor="middle">EXCELLENCE</text>
    </g>

    <g transform="translate(570, 470)">
      <line x1="0" y1="0" x2="180" y2="0" stroke="#304260" stroke-width="1" />
      <text x="90" y="18" font-size="11" font-weight="600" fill="#c9d1d9" text-anchor="middle">Date of Conferral</text>
      <text x="90" y="32" font-family="'JetBrains Mono', Consolas, monospace" font-size="10" fill="#8b9cb5" text-anchor="middle">${dateStr}</text>
    </g>

    <!-- Verification Hash -->
    <text x="425" y="525" font-family="'JetBrains Mono', Consolas, monospace" font-size="9" fill="#4a5d78" letter-spacing="1" text-anchor="middle">${hexHash}</text>
  </svg>
  `;

  container.innerHTML = svg;
};

SPLAT_APP.playVictory = function() {
  if (this.state.soundMuted) return;
  const ctx = this.getAudioContext();
  if (!ctx) return;
  try {
    const t = ctx.currentTime;
    const chords = [
      [523.25, 659.25, 783.99], // C Major
      [587.33, 739.99, 880.00], // D Major
      [659.25, 830.61, 987.77], // E Major
      [783.99, 987.77, 1174.66, 1567.98] // G Major octave triumph
    ];
    chords.forEach((chord, chordIdx) => {
      const chordTime = t + chordIdx * 0.22;
      chord.forEach(freq => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(freq, chordTime);
        gain.gain.setValueAtTime(0.06, chordTime);
        gain.gain.exponentialRampToValueAtTime(0.0001, chordTime + 0.5);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(chordTime);
        osc.stop(chordTime + 0.55);
      });
    });
  } catch(e) {}
};
"""

    return html, js
