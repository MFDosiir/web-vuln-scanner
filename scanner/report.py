"""
Report Generator
----------------
Formats scan results for terminal output or an HTML report file.
"""

from datetime import datetime
from pathlib import Path

# ANSI colour codes for terminal output
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
}


# ---------------------------------------------------------------------------
# Terminal report
# ---------------------------------------------------------------------------

def print_terminal_report(results: dict) -> None:
    url = results["target"]
    checks = results["checks"]

    print(f"\n{'='*60}")
    print(f"{BOLD}  SCAN REPORT{RESET}")
    print(f"  Target : {url}")
    print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    # ── Security Headers ──────────────────────────────────────────
    hdr = checks.get("security_headers", {})
    if hdr.get("status") == "error":
        print(f"{RED}[!] Security Headers check failed: {hdr['error']}{RESET}\n")
    else:
        s = hdr["summary"]
        print(f"{BOLD}[ Security Headers ]{RESET}  "
              f"{GREEN}{s['passed']} passed{RESET}  "
              f"{RED}{s['failed']} failed{RESET}  "
              f"(of {s['total']} checked)\n")

        for f in hdr["findings"]:
            icon  = f"{GREEN}✔{RESET}" if f["result"] == "PASS" else f"{RED}✘{RESET}"
            color = SEVERITY_COLOR.get(f["severity"], RESET)
            sev   = f"{color}[{f['severity']}]{RESET}" if f["result"] == "FAIL" else ""
            print(f"  {icon}  {f['header']:<40} {sev}")
            if f["result"] == "FAIL":
                print(f"      {CYAN}Why:{RESET} {f['why_it_matters']}")
                print(f"      {CYAN}Ref:{RESET} {f['owasp_ref']}")
                print(f"      {CYAN}Fix:{RESET} Add header → {f['recommended_value']}\n")

    # ── Exposed Files ─────────────────────────────────────────────
    exp = checks.get("exposed_files", {})
    s   = exp.get("summary", {})
    print(f"\n{BOLD}[ Exposed Files ]{RESET}  "
          f"Checked {s.get('paths_checked', 0)} paths  ·  "
          f"{RED}{s.get('exposed', 0)} exposed{RESET}  ·  "
          f"{YELLOW}{s.get('blocked', 0)} blocked{RESET}\n")

    findings = exp.get("findings", [])
    if not findings:
        print(f"  {GREEN}✔  No sensitive files found at common paths.{RESET}")
    else:
        for f in findings:
            color = RED if f["result"] == "EXPOSED" else YELLOW
            print(f"  {color}[{f['result']}]{RESET}  "
                  f"{SEVERITY_COLOR.get(f['severity'], '')}{f['severity']}{RESET}  "
                  f"{f['path']}")
            print(f"      {f['description']}")
            print(f"      URL: {f['url']}\n")

    print(f"{'='*60}\n")
    print("NOTE: Only scan sites you own or have explicit permission to test.\n")


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def save_html_report(results: dict) -> str:
    url     = results["target"]
    checks  = results["checks"]
    ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hdr     = checks.get("security_headers", {})
    exp     = checks.get("exposed_files", {})

    def badge(text, color):
        colors = {"red": "#e74c3c", "green": "#2ecc71", "yellow": "#f39c12", "blue": "#3498db"}
        bg = colors.get(color, "#999")
        return f'<span style="background:{bg};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:bold;">{text}</span>'

    # Build headers table rows
    header_rows = ""
    if hdr.get("status") == "ok":
        for f in hdr["findings"]:
            if f["result"] == "PASS":
                row_html = f"""
                <tr>
                  <td>{f['header']}</td>
                  <td>{badge('PASS','green')}</td>
                  <td>—</td>
                  <td style="color:#a8b8c8">✔ Present</td>
                  <td>—</td>
                </tr>"""
            else:
                sev_color = {"CRITICAL":"red","HIGH":"red","MEDIUM":"yellow","LOW":"blue"}.get(f["severity"],"blue")
                row_html = f"""
                <tr style="background:#1f1520;">
                  <td><strong>{f['header']}</strong></td>
                  <td>{badge('FAIL','red')}</td>
                  <td>{badge(f['severity'], sev_color)}</td>
                  <td style="font-size:0.85em;color:#c0ccd8">{f['why_it_matters']}</td>
                  <td style="font-family:monospace;font-size:0.8em;color:#d0dce8">{f['recommended_value']}</td>
                </tr>"""
            header_rows += row_html

    # Build exposed files rows
    exp_rows = ""
    exp_findings = exp.get("findings", [])
    if not exp_findings:
        exp_rows = '<tr><td colspan="4" style="color:#2ecc71;text-align:center;">No sensitive files found ✔</td></tr>'
    else:
        for f in exp_findings:
            color = "red" if f["result"] == "EXPOSED" else "yellow"
            sev_color = {"CRITICAL":"red","HIGH":"red","MEDIUM":"yellow","LOW":"blue"}.get(f["severity"],"blue")
            exp_rows += f"""
            <tr style="background:#1f1520;">
              <td style="font-family:monospace;color:#d0dce8">{f['path']}</td>
              <td>{badge(f['result'], color)}</td>
              <td>{badge(f['severity'], sev_color)}</td>
              <td style="font-size:0.85em;color:#c0ccd8">{f['description']}</td>
            </tr>"""

    h_sum = hdr.get("summary", {})
    e_sum = exp.get("summary", {})

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Scan Report — {url}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: system-ui, sans-serif; background: #0f1117; color: #e2e8f0; min-height: 100vh; }}
    header {{ background: #1a1d27; border-bottom: 2px solid #00d4aa; padding: 24px 40px; }}
    header h1 {{ font-size: 1.4em; color: #00d4aa; letter-spacing: 0.05em; }}
    header p  {{ color: #8892a4; font-size: 0.9em; margin-top: 4px; }}
    .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 40px; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); gap: 16px; margin-bottom: 40px; }}
    .card {{ background: #1a1d27; border-radius: 8px; padding: 20px 24px; border-top: 3px solid #00d4aa; }}
    .card .num {{ font-size: 2.2em; font-weight: 700; color: #00d4aa; }}
    .card .lbl {{ font-size: 0.8em; color: #8892a4; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.08em; }}
    section {{ margin-bottom: 48px; }}
    section h2 {{ font-size: 1.1em; text-transform: uppercase; letter-spacing: 0.1em; color: #00d4aa; border-bottom: 1px solid #2a2d3a; padding-bottom: 10px; margin-bottom: 20px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
    th {{ text-align: left; padding: 10px 14px; background: #1a1d27; color: #b0bcd0; font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.08em; }}
    td {{ padding: 10px 14px; border-bottom: 1px solid #2a2d3a; vertical-align: top; }}
    tr:hover td {{ background: #1e2130; }}
    .warning {{ background: #1a1500; border: 1px solid #f39c12; border-radius: 6px; padding: 12px 18px; font-size: 0.85em; color: #f39c12; margin-bottom: 32px; }}
  </style>
</head>
<body>
<header>
  <h1>⚡ Web Vulnerability Scanner — Report</h1>
  <p>Target: <strong style="color:#e2e8f0">{url}</strong> &nbsp;·&nbsp; Scanned: {ts}</p>
</header>
<div class="container">

  <div class="summary-grid">
    <div class="card"><div class="num">{h_sum.get('failed',0)}</div><div class="lbl">Missing Security Headers</div></div>
    <div class="card"><div class="num">{h_sum.get('passed',0)}</div><div class="lbl">Headers Present</div></div>
    <div class="card"><div class="num" style="color:{'#e74c3c' if e_sum.get('exposed',0) > 0 else '#00d4aa'}">{e_sum.get('exposed',0)}</div><div class="lbl">Exposed Sensitive Files</div></div>
    <div class="card"><div class="num">{e_sum.get('paths_checked',0)}</div><div class="lbl">Paths Probed</div></div>
  </div>

  <div class="warning">
    ⚠️  <strong>Legal notice:</strong> Only scan websites you own or have explicit written permission to test.
    Unauthorised scanning is illegal under the CFAA and equivalent laws worldwide.
  </div>

  <section>
    <h2>Security Headers</h2>
    <table>
      <thead><tr><th>Header</th><th>Result</th><th>Severity</th><th>Why it matters</th><th>Recommended value</th></tr></thead>
      <tbody>{header_rows}</tbody>
    </table>
  </section>

  <section>
    <h2>Exposed Sensitive Files</h2>
    <table>
      <thead><tr><th>Path</th><th>Result</th><th>Severity</th><th>Description</th></tr></thead>
      <tbody>{exp_rows}</tbody>
    </table>
  </section>

</div>
</body>
</html>"""

    out_dir  = Path("reports")
    out_dir.mkdir(exist_ok=True)
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    out_path = out_dir / filename
    out_path.write_text(html, encoding="utf-8")
    return str(out_path)
