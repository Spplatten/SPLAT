# build_workbench.py
# Monolithic compilation engine for splat_learning_workbench.html

import os
import sys

# Ensure UTF-8 output on Windows
sys.stdout.reconfigure(encoding='utf-8')

print("[*] Starting compilation of splat_learning_workbench.html...")

# Import builder modules
try:
    from workbench_builder.css import get_css
    from workbench_builder.shared_js import get_shared_js
    from workbench_builder.labs_01_03 import get_labs_01_03_js
    from workbench_builder.labs_04_06 import get_labs_04_06_js
    from workbench_builder.labs_07_08 import get_labs_07_08_js
    from workbench_builder.labs_09_10 import get_labs_09_10_js
    from workbench_builder.runners import get_runners_js
    from workbench_builder.certificate import get_certificate_html_and_js
except ImportError as e:
    print(f"[!] Import error in workbench_builder: {e}")
    sys.exit(1)

OUTPUT_FILE = r"c:\C_AGENT_BUILDER\splat_learning_workbench.html"

css_content = get_css()
shared_js = get_shared_js()
labs_01_03 = get_labs_01_03_js()
labs_04_06 = get_labs_04_06_js()
labs_07_08 = get_labs_07_08_js()
labs_09_10 = get_labs_09_10_js()
runners_js = get_runners_js()
cert_html, cert_js = get_certificate_html_and_js()

init_js = """
if (document.readyState === 'loading') {
  window.addEventListener('DOMContentLoaded', () => SPLAT_APP.init());
} else {
  SPLAT_APP.init();
}
"""

html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SPLAT Learning Workbench & Kernel Lab Suite</title>
  <style>
{css_content}
  </style>
</head>
<body>

  <!-- APP HEADER -->
  <header class="app-header">
    <div class="brand-section">
      <div class="brand-badge">
        <div class="pulse-dot"></div>
        <span>SPLAT // WORKBENCH</span>
      </div>
      <div class="header-title-group">
        <h1>ADVANCED SYSTEMS LABORATORY & SOCRATIC WORKBENCH</h1>
        <p>10-Volume Engineering Suite • .NET 10 | Rust Zero-Copy | eBPF LSM | Win32 AppContainer</p>
      </div>
    </div>

    <div class="header-controls">
      <div class="master-progress-container">
        <span class="master-progress-label" id="master-progress-label">0/30 STAGES (0%)</span>
        <div class="master-progress-bar-outer">
          <div class="master-progress-bar-inner" id="master-progress-bar"></div>
        </div>
      </div>

      <div class="score-display">
        <span>⚡ XP:</span>
        <span id="master-score-val">0 XP</span>
      </div>

      <button class="btn-header" id="audio-toggle-btn" onclick="SPLAT_APP.toggleAudio()">🔊 Audio ON</button>
      <button class="btn-header" onclick="SPLAT_APP.resetProgress()">↺ Reset</button>
      <button class="btn-header primary" onclick="SPLAT_APP.openCertificateModal()">🎓 Credential</button>
    </div>
  </header>

  <!-- APP MAIN CONTAINER -->
  <div class="app-container">
    <!-- SIDEBAR -->
    <aside class="sidebar">
      <div class="sidebar-header">
        <span>Curriculum Modules</span>
        <span>10 Labs / 30 Stages</span>
      </div>
      <ul class="lab-nav-list" id="lab-nav-list">
        <!-- Injected via JavaScript -->
      </ul>
    </aside>

    <!-- MAIN VIEWPORT -->
    <main class="lab-viewport">
      <div class="lab-header-banner">
        <div class="lab-meta-row">
          <span class="lab-badge-vol" id="lab-badge-vol">Volume 01</span>
          <span class="lab-badge-tier" id="lab-badge-tier">Tier 1: Foundations</span>
        </div>
        <h2 class="lab-main-title" id="lab-main-title">Loading Lab...</h2>
        <p class="lab-objective" id="lab-objective">Laboratory objective description...</p>

        <!-- STAGE TABS -->
        <div class="stage-tab-bar">
          <button class="stage-tab active" id="stage-tab-1">
            <span class="stage-tab-status">1</span>
            <span>Stage 1: Architecture</span>
          </button>
          <button class="stage-tab" id="stage-tab-2">
            <span class="stage-tab-status">2</span>
            <span>Stage 2: Implementation</span>
          </button>
          <button class="stage-tab" id="stage-tab-3">
            <span class="stage-tab-status">3</span>
            <span>Stage 3: Verification</span>
          </button>
        </div>
      </div>

      <!-- STAGE CONTENT VIEWPORT -->
      <div class="stage-content-container" id="stage-content-container">
        <!-- Injected dynamically based on active stage -->
      </div>
    </main>
  </div>

  <!-- TOAST CONTAINER -->
  <div id="toast-container"></div>

  <!-- MODAL DIALOGS -->
{cert_html}

  <!-- APPLICATION LOGIC & DATA -->
  <script>
{labs_01_03}
{labs_04_06}
{labs_07_08}
{labs_09_10}

const LABS_DATA = [
  ...LABS_01_03,
  ...LABS_04_06,
  ...LABS_07_08,
  ...LABS_09_10
];

{shared_js}
{runners_js}
{cert_js}

{init_js}
  </script>
</body>
</html>
"""

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write(html_template)

file_size_kb = os.path.getsize(OUTPUT_FILE) / 1024
print(f"[✓] Successfully compiled {OUTPUT_FILE} ({file_size_kb:.1f} KB)")
