#!/usr/bin/env python3
"""
SPLAT Master Textbook Compilation Engine
Compiles the 10-volume curriculum into:
  1. Standalone HTML Web Book: master_textbook_compiled.html
  2. Publication-Grade Vector PDF: SPLAT_Master_Textbook.pdf (via Headless Chrome/Edge)
"""

import os
import sys
import glob
import subprocess

# Ensure UTF-8 output even on Windows CP1252 consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

import markdown
from pygments.formatters import HtmlFormatter

WORKSPACE_DIR = os.path.dirname(os.path.abspath(__file__))
TEXTBOOK_DIR = os.path.join(WORKSPACE_DIR, "textbook")
if not os.path.exists(TEXTBOOK_DIR):
    TEXTBOOK_DIR = os.path.join(WORKSPACE_DIR, "docs", "textbook")
HTML_OUT_FILE = os.path.join(WORKSPACE_DIR, "master_textbook_compiled.html")
PDF_OUT_FILE = os.path.join(WORKSPACE_DIR, "SPLAT_Master_Textbook.pdf")

VOLUMES = [
    ("Volume 01", "Volume_01_System_Topology_And_Multi_Language_Blueprint.md"),
    ("Volume 02", "Volume_02_Core_Data_Contracts_And_Struct_Anatomy.md"),
    ("Volume 03", "Volume_03_Native_FFI_And_Foreign_Function_Interfaces.md"),
    ("Volume 04", "Volume_04_Zero_Copy_Streaming_And_Shared_Memory_Ring_Buffers.md"),
    ("Volume 05", "Volume_05_Agent_Builder_Architecture_And_State_Machine_Pipelines.md"),
    ("Volume 06", "Volume_06_Memory_Management_And_Ownership_Universes.md"),
    ("Volume 07", "Volume_07_Security_Defenses_Validation_And_Exception_Trapping.md"),
    ("Volume 08", "Volume_08_Microarchitectural_Optimization_And_Hardware_Sympathy.md"),
    ("Volume 09", "Volume_09_Master_Laboratory_Suite_And_Guided_Interactive_Walkthroughs.md"),
    ("Volume 10", "Volume_10_Epilogue_And_Architectural_Evolution.md"),
]

def find_browser():
    candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None

def compile_html():
    print("=" * 70)
    print(" 🏛️  SPLAT TEXTBOOK COMPILATION ENGINE")
    print("=" * 70)
    print("[1/3] Reading and parsing markdown volumes...")

    md_engine = markdown.Markdown(
        extensions=[
            'extra',
            'codehilite',
            'toc',
            'sane_lists'
        ],
        extension_configs={
            'codehilite': {
                'css_class': 'codehilite',
                'linenums': False,
                'pygments_style': 'monokai'
            }
        }
    )

    formatter = HtmlFormatter(style='monokai')
    pygments_css = formatter.get_style_defs('.codehilite')

    toc_entries = []
    volume_html_blocks = []

    for label, filename in VOLUMES:
        filepath = os.path.join(TEXTBOOK_DIR, filename)
        if not os.path.exists(filepath):
            print(f"  [!] Warning: Missing volume file: {filename}")
            continue

        print(f"  --> Processing: {filename}")
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # Extract title from first H1
        first_line = content.strip().split("\n")[0].replace("#", "").strip()
        vol_id = filename.replace(".md", "")
        toc_entries.append((vol_id, label, first_line))

        # Reset markdown engine state between volumes
        md_engine.reset()
        html_body = md_engine.convert(content)
        
        # Wrap each volume in a distinct section with page-break styling
        wrapped_block = f"""
        <section class="volume-container" id="{vol_id}">
            <div class="volume-header-banner">
                <span class="vol-tag">{label}</span>
                <h1 class="vol-title">{first_line}</h1>
            </div>
            <div class="volume-content">
                {html_body}
            </div>
        </section>
        """
        volume_html_blocks.append(wrapped_block)

    print("[2/3] Generating responsive HTML Web Book...")

    toc_html = '<ul class="toc-list">\n'
    for vol_id, label, title in toc_entries:
        toc_html += f'  <li class="toc-item"><a href="#{vol_id}"><span class="toc-label">{label}:</span> {title}</a></li>\n'
    toc_html += '</ul>'

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SPLAT: Systems Architecture & Kernel Containment — Master Textbook</title>
    <style>
        :root {{
            --bg-primary: #121417;
            --bg-secondary: #1a1e24;
            --bg-tertiary: #222730;
            --text-main: #e2e8f0;
            --text-muted: #94a3b8;
            --accent-blue: #38bdf8;
            --accent-cyan: #06b6d4;
            --border-color: #334155;
            --code-bg: #1e222b;
            --sidebar-width: 320px;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-main);
            line-height: 1.65;
            display: flex;
        }}

        /* Sidebar Navigation */
        #sidebar {{
            width: var(--sidebar-width);
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            position: fixed;
            top: 0;
            left: 0;
            bottom: 0;
            overflow-y: auto;
            padding: 24px 16px;
            z-index: 100;
        }}

        .brand-title {{
            font-size: 1.15rem;
            font-weight: 800;
            color: var(--accent-blue);
            letter-spacing: -0.02em;
            margin-bottom: 6px;
        }}

        .brand-subtitle {{
            font-size: 0.78rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 24px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border-color);
        }}

        .toc-list {{
            list-style: none;
        }}

        .toc-item {{
            margin-bottom: 12px;
        }}

        .toc-item a {{
            color: var(--text-muted);
            text-decoration: none;
            font-size: 0.85rem;
            display: block;
            padding: 6px 10px;
            border-radius: 6px;
            transition: all 0.15s ease;
        }}

        .toc-item a:hover {{
            background: var(--bg-tertiary);
            color: var(--accent-cyan);
        }}

        .toc-label {{
            font-weight: 700;
            color: var(--accent-blue);
        }}

        /* Main Content */
        #main-content {{
            margin-left: var(--sidebar-width);
            flex: 1;
            padding: 48px 64px;
            max-width: 1100px;
        }}

        .cover-page {{
            padding: 80px 0 100px 0;
            border-bottom: 2px solid var(--border-color);
            margin-bottom: 60px;
        }}

        .cover-title {{
            font-size: 2.8rem;
            font-weight: 900;
            line-height: 1.15;
            color: #ffffff;
            margin-bottom: 16px;
        }}

        .cover-subtitle {{
            font-size: 1.35rem;
            color: var(--accent-blue);
            margin-bottom: 24px;
            font-weight: 400;
        }}

        .cover-meta {{
            color: var(--text-muted);
            font-size: 0.92rem;
            line-height: 1.7;
        }}

        .volume-container {{
            margin-bottom: 80px;
            padding-top: 20px;
        }}

        .volume-header-banner {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            padding: 24px 32px;
            border-radius: 12px;
            border-left: 6px solid var(--accent-blue);
            margin-bottom: 36px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        }}

        .vol-tag {{
            text-transform: uppercase;
            font-size: 0.75rem;
            font-weight: 800;
            letter-spacing: 0.1em;
            color: var(--accent-cyan);
            display: inline-block;
            margin-bottom: 8px;
        }}

        .vol-title {{
            font-size: 1.85rem;
            color: #ffffff;
            font-weight: 800;
            line-height: 1.25;
        }}

        /* Typography */
        h1, h2, h3, h4, h5, h6 {{
            color: #ffffff;
            margin-top: 1.6em;
            margin-bottom: 0.7em;
            font-weight: 700;
            letter-spacing: -0.01em;
        }}

        h2 {{
            font-size: 1.45rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 8px;
            color: var(--accent-blue);
        }}

        h3 {{
            font-size: 1.2rem;
            color: #f1f5f9;
        }}

        p {{
            margin-bottom: 1.2em;
            font-size: 0.98rem;
            color: #cbd5e1;
        }}

        ul, ol {{
            margin-bottom: 1.2em;
            padding-left: 28px;
            color: #cbd5e1;
        }}

        li {{
            margin-bottom: 0.4em;
        }}

        a {{
            color: var(--accent-blue);
            text-decoration: none;
        }}

        a:hover {{
            text-decoration: underline;
        }}

        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 24px 0;
            font-size: 0.9rem;
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
        }}

        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            background: var(--bg-tertiary);
            color: #ffffff;
            font-weight: 700;
        }}

        tr:hover td {{
            background: rgba(255, 255, 255, 0.02);
        }}

        /* Code Blocks */
        pre {{
            background: var(--code-bg) !important;
            padding: 18px 20px;
            border-radius: 8px;
            overflow-x: auto;
            margin: 20px 0;
            border: 1px solid #2d3748;
            font-family: "Cascadia Code", "Fira Code", Consolas, Monaco, monospace;
            font-size: 0.86rem;
            line-height: 1.5;
        }}

        code {{
            font-family: "Cascadia Code", "Fira Code", Consolas, Monaco, monospace;
            font-size: 0.88em;
            background: rgba(148, 163, 184, 0.15);
            padding: 2px 6px;
            border-radius: 4px;
            color: #f8fafc;
        }}

        pre code {{
            background: transparent;
            padding: 0;
            color: inherit;
        }}

        blockquote {{
            border-left: 4px solid var(--accent-blue);
            background: var(--bg-secondary);
            padding: 14px 20px;
            margin: 20px 0;
            border-radius: 0 8px 8px 0;
            color: #cbd5e1;
            font-style: italic;
        }}

        hr {{
            border: none;
            height: 1px;
            background: var(--border-color);
            margin: 40px 0;
        }}

        /* Syntax Highlighting */
        {pygments_css}

        /* Print Media Styles for Vector PDF */
        @media print {{
            body {{
                background-color: #ffffff !important;
                color: #0f172a !important;
                display: block !important;
            }}

            #sidebar {{
                display: none !important;
            }}

            #main-content {{
                margin-left: 0 !important;
                padding: 0 !important;
                max-width: 100% !important;
            }}

            .volume-container {{
                page-break-before: always;
            }}

            .volume-header-banner {{
                background: #f1f5f9 !important;
                border-left: 6px solid #0284c7 !important;
                color: #0f172a !important;
                box-shadow: none !important;
            }}

            .vol-title {{
                color: #0f172a !important;
            }}

            h1, h2, h3, h4 {{
                color: #0f172a !important;
                page-break-after: avoid;
            }}

            h2 {{
                border-bottom: 1px solid #cbd5e1 !important;
                color: #0369a1 !important;
            }}

            p, li {{
                color: #334155 !important;
            }}

            pre {{
                background: #f8fafc !important;
                color: #0f172a !important;
                border: 1px solid #e2e8f0 !important;
                page-break-inside: avoid;
            }}

            code {{
                background: #f1f5f9 !important;
                color: #0f172a !important;
            }}

            table {{
                background: #ffffff !important;
                border: 1px solid #e2e8f0 !important;
                page-break-inside: avoid;
            }}

            th {{
                background: #f8fafc !important;
                color: #0f172a !important;
            }}

            td {{
                border-bottom: 1px solid #e2e8f0 !important;
                color: #334155 !important;
            }}

            @page {{
                size: letter;
                margin: 20mm 15mm 20mm 15mm;
                @bottom-right {{
                    content: counter(page);
                    font-size: 9pt;
                    color: #64748b;
                }}
            }}
        }}
    </style>
</head>
<body>
    <nav id="sidebar">
        <div class="brand-title">🏛️ SPLAT ARCHITECTURE</div>
        <div class="brand-subtitle">University Master Textbook</div>
        {toc_html}
    </nav>
    <main id="main-content">
        <header class="cover-page">
            <h1 class="cover-title">SPLAT: Systems Architecture & Kernel Containment</h1>
            <div class="cover-subtitle">A Comprehensive University-Grade Treatise on Zero-Trust Agent Execution Substrates</div>
            <div class="cover-meta">
                <strong>Publisher:</strong> Platten Industries Systems Engineering Group<br>
                <strong>Target Platform:</strong> Windows 11 & Linux (WSL2 Kernel 6.18+ with BPF-LSM)<br>
                <strong>Tiers Analyzed:</strong> C (eBPF CO-RE), Rust (tokio, libbpf-rs), C# (.NET 10 CLR, Win32 P/Invoke)<br>
                <strong>Date of Publication:</strong> September 2026
            </div>
        </header>

        {''.join(volume_html_blocks)}
    </main>
</body>
</html>
"""

    with open(HTML_OUT_FILE, "w", encoding="utf-8") as f:
        f.write(full_html)

    size_mb = os.path.getsize(HTML_OUT_FILE) / (1024 * 1024)
    print(f"  [+] Compiled HTML Web Book: {HTML_OUT_FILE} ({size_mb:.2f} MB)")
    return HTML_OUT_FILE

def compile_pdf(html_path):
    print("[3/3] Compiling Vector PDF via Headless Chromium / Edge...")
    browser = find_browser()
    if not browser:
        print("  [!] Error: Neither Google Chrome nor Microsoft Edge was found.")
        print("      HTML Web Book is ready, but PDF compilation cannot proceed.")
        return False

    print(f"  --> Using Browser Engine: {browser}")
    cmd = [
        browser,
        "--headless=new",
        "--disable-gpu",
        "--allow-file-access-from-files",
        "--no-pdf-header-footer",
        f"--print-to-pdf={PDF_OUT_FILE}",
        html_path
    ]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if os.path.exists(PDF_OUT_FILE):
            size_mb = os.path.getsize(PDF_OUT_FILE) / (1024 * 1024)
            print(f"  [+] Compiled Master Vector PDF: {PDF_OUT_FILE} ({size_mb:.2f} MB)")
            return True
        else:
            print("  [!] Error: Browser did not generate PDF output.")
            print(res.stderr)
            return False
    except subprocess.CalledProcessError as e:
        print(f"  [!] Browser execution failed: {e}")
        print(e.stderr)
        return False

def main():
    html_path = compile_html()
    compile_pdf(html_path)
    print("=" * 70)
    print(" 🎓 COMPILATION FINISHED SUCCESSFULLY!")
    print(f" - HTML Book: {HTML_OUT_FILE}")
    print(f" - Vector PDF: {PDF_OUT_FILE}")
    print("=" * 70)

if __name__ == "__main__":
    main()
