# workbench_builder/css.py
# Full responsive cyber-range CSS for SPLAT Learning Workbench

def get_css():
    return """
/* ==========================================================================
   SPLAT KERNEL WORKBENCH & ADVANCED SYSTEMS LAB SUITE
   CYBER-RANGE DARK TERMINAL DESIGN SYSTEM
   ========================================================================== */
:root {
  --bg-primary: #0a0d14;
  --bg-secondary: #101522;
  --bg-tertiary: #161f32;
  --bg-card: #131b2c;
  --bg-editor: #0d1117;
  --border-color: #212e48;
  --border-focus: #00f0ff;
  --accent-cyan: #00f0ff;
  --accent-green: #00ff88;
  --accent-amber: #ffb700;
  --accent-crimson: #ff3366;
  --accent-purple: #a371f7;
  --text-main: #e2e8f0;
  --text-muted: #8b9cb5;
  --text-dim: #4b5d78;
  --font-mono: "JetBrains Mono", "Fira Code", Consolas, "Courier New", monospace;
  --font-sans: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --radius-sm: 4px;
  --radius-md: 8px;
  --radius-lg: 12px;
  --shadow-glow-cyan: 0 0 15px rgba(0, 240, 255, 0.25);
  --shadow-glow-green: 0 0 15px rgba(0, 255, 136, 0.25);
  --shadow-glow-crimson: 0 0 15px rgba(255, 51, 102, 0.25);
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  background-color: var(--bg-primary);
  color: var(--text-main);
  font-family: var(--font-sans);
  line-height: 1.5;
  overflow-x: hidden;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

/* Scrollbar */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}
::-webkit-scrollbar-track {
  background: var(--bg-primary);
}
::-webkit-scrollbar-thumb {
  background: var(--border-color);
  border-radius: var(--radius-sm);
}
::-webkit-scrollbar-thumb:hover {
  background: var(--accent-cyan);
}

/* Top App Header */
header.app-header {
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border-color);
  padding: 12px 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky;
  top: 0;
  z-index: 100;
}

.brand-section {
  display: flex;
  align-items: center;
  gap: 14px;
}

.brand-badge {
  background: linear-gradient(135deg, rgba(0, 240, 255, 0.15), rgba(0, 255, 136, 0.15));
  border: 1px solid var(--accent-cyan);
  padding: 6px 12px;
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-weight: 700;
  font-size: 14px;
  color: var(--accent-cyan);
  letter-spacing: 1.5px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.brand-badge .pulse-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background-color: var(--accent-green);
  box-shadow: 0 0 8px var(--accent-green);
  animation: pulse-green 2s infinite;
}

@keyframes pulse-green {
  0% { transform: scale(0.95); opacity: 0.8; }
  50% { transform: scale(1.2); opacity: 1; }
  100% { transform: scale(0.95); opacity: 0.8; }
}

.header-title-group h1 {
  font-size: 16px;
  font-weight: 700;
  color: #fff;
  letter-spacing: 0.5px;
}

.header-title-group p {
  font-size: 12px;
  color: var(--text-muted);
}

.header-controls {
  display: flex;
  align-items: center;
  gap: 16px;
}

.master-progress-container {
  display: flex;
  align-items: center;
  gap: 12px;
  background: var(--bg-tertiary);
  padding: 6px 14px;
  border-radius: var(--radius-md);
  border: 1px solid var(--border-color);
}

.master-progress-label {
  font-size: 12px;
  font-family: var(--font-mono);
  color: var(--text-muted);
}

.master-progress-bar-outer {
  width: 140px;
  height: 8px;
  background: var(--bg-primary);
  border-radius: 4px;
  overflow: hidden;
  border: 1px solid var(--border-color);
}

.master-progress-bar-inner {
  height: 100%;
  width: 0%;
  background: linear-gradient(90deg, var(--accent-cyan), var(--accent-green));
  transition: width 0.4s ease;
  box-shadow: 0 0 8px var(--accent-cyan);
}

.score-display {
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--accent-amber);
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 6px;
}

.btn-header {
  background: var(--bg-tertiary);
  color: var(--text-main);
  border: 1px solid var(--border-color);
  padding: 6px 12px;
  border-radius: var(--radius-sm);
  font-size: 12px;
  font-family: var(--font-mono);
  cursor: pointer;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
  gap: 6px;
}
.btn-header:hover {
  background: var(--border-color);
  border-color: var(--accent-cyan);
  color: #fff;
}
.btn-header.primary {
  background: rgba(0, 240, 255, 0.15);
  border-color: var(--accent-cyan);
  color: var(--accent-cyan);
}
.btn-header.primary:hover {
  background: var(--accent-cyan);
  color: #000;
  box-shadow: var(--shadow-glow-cyan);
}

/* App Main Layout */
.app-container {
  display: flex;
  flex: 1;
  height: calc(100vh - 61px);
  overflow: hidden;
}

/* Sidebar */
aside.sidebar {
  width: 320px;
  background: var(--bg-secondary);
  border-right: 1px solid var(--border-color);
  display: flex;
  flex-direction: column;
  overflow-y: auto;
  flex-shrink: 0;
}

.sidebar-header {
  padding: 16px;
  border-bottom: 1px solid var(--border-color);
  font-size: 11px;
  font-family: var(--font-mono);
  text-transform: uppercase;
  letter-spacing: 1.2px;
  color: var(--text-muted);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.lab-nav-list {
  list-style: none;
  padding: 8px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.lab-nav-item {
  padding: 10px 12px;
  border-radius: var(--radius-md);
  border: 1px solid transparent;
  background: transparent;
  cursor: pointer;
  transition: all 0.2s ease;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.lab-nav-item:hover {
  background: var(--bg-tertiary);
  border-color: rgba(0, 240, 255, 0.2);
}

.lab-nav-item.active {
  background: rgba(0, 240, 255, 0.08);
  border-color: var(--accent-cyan);
  box-shadow: inset 3px 0 0 var(--accent-cyan);
}

.lab-nav-item.completed {
  border-color: rgba(0, 255, 136, 0.3);
}

.lab-nav-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.lab-nav-num {
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 700;
  color: var(--accent-cyan);
}

.lab-nav-progress {
  font-family: var(--font-mono);
  font-size: 10px;
  padding: 2px 6px;
  border-radius: var(--radius-sm);
  background: var(--bg-primary);
  color: var(--text-muted);
  border: 1px solid var(--border-color);
}

.lab-nav-item.completed .lab-nav-progress {
  color: var(--accent-green);
  border-color: var(--accent-green);
  background: rgba(0, 255, 136, 0.1);
}

.lab-nav-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-main);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.lab-nav-volume {
  font-size: 11px;
  color: var(--text-muted);
}

/* Main Lab Content Area */
main.lab-viewport {
  flex: 1;
  background: var(--bg-primary);
  overflow-y: auto;
  display: flex;
  flex-direction: column;
}

.lab-header-banner {
  background: linear-gradient(180deg, var(--bg-secondary) 0%, var(--bg-primary) 100%);
  padding: 24px 32px 16px 32px;
  border-bottom: 1px solid var(--border-color);
}

.lab-meta-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}

.lab-badge-vol {
  font-family: var(--font-mono);
  font-size: 11px;
  text-transform: uppercase;
  color: var(--accent-purple);
  background: rgba(163, 113, 247, 0.12);
  border: 1px solid rgba(163, 113, 247, 0.3);
  padding: 2px 8px;
  border-radius: var(--radius-sm);
}

.lab-badge-tier {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--accent-cyan);
  background: rgba(0, 240, 255, 0.12);
  border: 1px solid rgba(0, 240, 255, 0.3);
  padding: 2px 8px;
  border-radius: var(--radius-sm);
}

.lab-main-title {
  font-size: 22px;
  font-weight: 700;
  color: #fff;
  margin-bottom: 6px;
}

.lab-objective {
  font-size: 13.5px;
  color: var(--text-muted);
  max-width: 950px;
}

/* Stage Navigation Tabs */
.stage-tab-bar {
  display: flex;
  gap: 8px;
  margin-top: 16px;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 0;
}

.stage-tab {
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: 12px;
  padding: 8px 16px;
  cursor: pointer;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
  gap: 8px;
}

.stage-tab:hover {
  color: var(--text-main);
}

.stage-tab.active {
  color: var(--accent-cyan);
  border-bottom-color: var(--accent-cyan);
  background: rgba(0, 240, 255, 0.05);
}

.stage-tab.completed {
  color: var(--accent-green);
}

.stage-tab-status {
  width: 14px;
  height: 14px;
  border-radius: 50%;
  border: 1px solid currentColor;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 9px;
}

/* Stage Content Body */
.stage-content-container {
  padding: 24px 32px;
  display: flex;
  flex-direction: column;
  gap: 20px;
  max-width: 1400px;
}

.pedagogy-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-left: 3px solid var(--accent-cyan);
  border-radius: var(--radius-md);
  padding: 18px 20px;
}

.pedagogy-card h3 {
  font-size: 15px;
  color: #fff;
  margin-bottom: 8px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.pedagogy-card p {
  font-size: 13.5px;
  color: var(--text-main);
  margin-bottom: 10px;
  line-height: 1.6;
}

.pedagogy-card p:last-child {
  margin-bottom: 0;
}

.pedagogy-callout {
  background: rgba(0, 240, 255, 0.06);
  border: 1px solid rgba(0, 240, 255, 0.2);
  border-radius: var(--radius-sm);
  padding: 10px 14px;
  font-size: 12.5px;
  color: var(--accent-cyan);
  font-family: var(--font-mono);
  margin-top: 10px;
}

/* Interactive Workbench Grid */
.workbench-interactive-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 1100px) {
  .workbench-interactive-grid {
    grid-template-columns: 1fr;
  }
}

.workbench-panel {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.panel-header {
  background: var(--bg-tertiary);
  padding: 10px 16px;
  border-bottom: 1px solid var(--border-color);
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 12px;
  font-family: var(--font-mono);
}

.panel-header-title {
  color: #fff;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 8px;
}

.panel-body {
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 16px;
  flex: 1;
}

/* Code Editor Container */
.editor-container {
  display: flex;
  flex-direction: column;
  height: 400px;
  background: var(--bg-editor);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  overflow: hidden;
}

.editor-header {
  background: #161b22;
  border-bottom: 1px solid #30363d;
  padding: 8px 14px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-family: var(--font-mono);
  font-size: 11px;
}

.editor-filename {
  color: #c9d1d9;
  display: flex;
  align-items: center;
  gap: 6px;
}

.editor-actions {
  display: flex;
  gap: 8px;
}

.btn-editor {
  background: #21262d;
  border: 1px solid #30363d;
  color: #c9d1d9;
  font-family: var(--font-mono);
  font-size: 11px;
  padding: 4px 8px;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-editor:hover {
  background: #30363d;
  color: #fff;
}

.editor-main {
  display: flex;
  flex: 1;
  position: relative;
  overflow: hidden;
}

.editor-gutter {
  width: 44px;
  background: #0d1117;
  border-right: 1px solid #30363d;
  color: #484f58;
  font-family: var(--font-mono);
  font-size: 12px;
  padding: 10px 0;
  text-align: right;
  user-select: none;
  overflow: hidden;
}

.gutter-line {
  padding-right: 8px;
  line-height: 20px;
}

.editor-textarea {
  flex: 1;
  background: transparent;
  color: #f0f6fc;
  font-family: var(--font-mono);
  font-size: 12.5px;
  line-height: 20px;
  padding: 10px 12px;
  border: none;
  outline: none;
  resize: none;
  white-space: pre;
  overflow-wrap: normal;
  overflow-x: auto;
  tab-size: 4;
}

/* Terminal / Test Output */
.terminal-container {
  display: flex;
  flex-direction: column;
  height: 400px;
  background: #090c10;
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  overflow: hidden;
}

.terminal-header {
  background: #161b22;
  padding: 8px 14px;
  border-bottom: 1px solid #30363d;
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-family: var(--font-mono);
  font-size: 11px;
}

.terminal-title {
  color: var(--accent-green);
  display: flex;
  align-items: center;
  gap: 6px;
}

.terminal-body {
  flex: 1;
  padding: 12px 16px;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.6;
  color: #8b949e;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

.term-line-info { color: #58a6ff; }
.term-line-pass { color: var(--accent-green); font-weight: 600; }
.term-line-fail { color: var(--accent-crimson); font-weight: 600; }
.term-line-warn { color: var(--accent-amber); }
.term-line-dim { color: #484f58; }

.terminal-footer {
  background: #161b22;
  padding: 10px 14px;
  border-top: 1px solid #30363d;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.btn-action-primary {
  background: var(--accent-cyan);
  color: #000;
  border: none;
  padding: 8px 18px;
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  gap: 8px;
}

.btn-action-primary:hover {
  background: #38f8ff;
  box-shadow: var(--shadow-glow-cyan);
}

.btn-action-next {
  background: var(--accent-green);
  color: #000;
  border: none;
  padding: 8px 18px;
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.2s;
  display: none;
  align-items: center;
  gap: 8px;
}

.btn-action-next:hover {
  background: #39ff9e;
  box-shadow: var(--shadow-glow-green);
}

/* Custom Interactive Widgets */
.bit-slicer-table {
  width: 100%;
  border-collapse: collapse;
  font-family: var(--font-mono);
  font-size: 12px;
  margin-top: 10px;
}

.bit-slicer-table th, .bit-slicer-table td {
  border: 1px solid var(--border-color);
  padding: 8px;
  text-align: center;
}

.bit-slicer-table th {
  background: var(--bg-tertiary);
  color: var(--accent-cyan);
}

.bit-byte-box {
  display: inline-block;
  padding: 4px 6px;
  margin: 2px;
  border-radius: 3px;
  font-size: 11px;
}

.byte-major { background: rgba(0, 240, 255, 0.2); border: 1px solid var(--accent-cyan); color: #fff; }
.byte-minor { background: rgba(0, 255, 136, 0.2); border: 1px solid var(--accent-green); color: #fff; }
.byte-pad { background: rgba(255, 51, 102, 0.2); border: 1px solid var(--accent-crimson); color: #ff99aa; }
.byte-zero { background: rgba(255, 255, 255, 0.05); color: #666; }

/* Memory Struct Grid */
.memory-grid-container {
  display: flex;
  flex-direction: column;
  gap: 6px;
  background: #090c10;
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 14px;
}

.mem-row {
  display: flex;
  align-items: center;
  gap: 6px;
}

.mem-offset-label {
  width: 60px;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-dim);
}

.mem-byte-cells {
  display: flex;
  flex: 1;
  gap: 4px;
}

.mem-cell {
  flex: 1;
  height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: var(--font-mono);
  font-size: 11px;
  border-radius: 3px;
  background: #161b22;
  border: 1px solid #30363d;
  color: #c9d1d9;
  transition: all 0.2s;
}

.mem-cell.active-field {
  background: rgba(0, 240, 255, 0.2);
  border-color: var(--accent-cyan);
  color: #fff;
}

.mem-cell.pad-field {
  background: rgba(255, 51, 102, 0.25);
  border-color: var(--accent-crimson);
  color: #ff99aa;
}

.struct-field-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-top: 12px;
}

.struct-field-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  padding: 8px 12px;
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: 12px;
}

.field-controls button {
  background: #21262d;
  border: 1px solid #30363d;
  color: #c9d1d9;
  padding: 2px 8px;
  border-radius: 3px;
  cursor: pointer;
  margin-left: 4px;
}
.field-controls button:hover {
  background: #30363d;
  color: #fff;
}

/* Modal Overlay */
.modal-backdrop {
  position: fixed;
  top: 0;
  left: 0;
  width: 100vw;
  height: 100vh;
  background: rgba(0, 0, 0, 0.85);
  backdrop-filter: blur(8px);
  display: none;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-backdrop.open {
  display: flex;
}

.modal-window {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  max-width: 900px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 50px rgba(0,0,0,0.7);
  display: flex;
  flex-direction: column;
}

.modal-header {
  padding: 18px 24px;
  border-bottom: 1px solid var(--border-color);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.modal-header h2 {
  font-size: 18px;
  color: #fff;
  display: flex;
  align-items: center;
  gap: 10px;
}

.modal-close-btn {
  background: transparent;
  border: none;
  color: var(--text-muted);
  font-size: 20px;
  cursor: pointer;
}
.modal-close-btn:hover { color: #fff; }

.modal-body {
  padding: 24px;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

/* Toast Notifications */
#toast-container {
  position: fixed;
  bottom: 24px;
  right: 24px;
  z-index: 2000;
  display: flex;
  flex-direction: column;
  gap: 10px;
  pointer-events: none;
}

.toast-msg {
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-left: 4px solid var(--accent-cyan);
  padding: 12px 18px;
  border-radius: var(--radius-sm);
  color: #fff;
  font-size: 13px;
  font-family: var(--font-mono);
  box-shadow: 0 8px 20px rgba(0,0,0,0.5);
  animation: slide-in 0.3s forwards;
  pointer-events: auto;
  display: flex;
  align-items: center;
  gap: 10px;
}

.toast-msg.success { border-left-color: var(--accent-green); }
.toast-msg.error { border-left-color: var(--accent-crimson); }

@keyframes slide-in {
  from { transform: translateX(100%); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}
"""
