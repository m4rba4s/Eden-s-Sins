#!/usr/bin/env python3
"""
HTML Report Generator — The Eden's Sins
Aggregates all tool outputs into a presentation-ready HTML report.

Usage:
    python3 report_gen.py --input results.json --output report.html
    python3 report_gen.py --live  # Run tools and generate report in one shot
"""

import argparse, json, os, subprocess, sys, time
from datetime import datetime
from pathlib import Path

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>The Eden's Sins — Assessment Report</title>
<style>
  :root {{
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #c9d1d9; --accent: #58a6ff; --red: #f85149;
    --green: #3fb950; --yellow: #d29922; --orange: #db6d28;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: -apple-system, 'SF Pro Text', Helvetica, Arial, sans-serif;
    line-height: 1.6; padding: 2rem;
  }}
  .container {{ max-width: 1000px; margin: 0 auto; }}
  h1 {{
    font-size: 2rem; color: #fff;
    border-bottom: 2px solid var(--accent); padding-bottom: 0.5rem;
    margin-bottom: 1.5rem;
  }}
  h1 span {{ color: var(--red); }}
  h2 {{
    font-size: 1.3rem; color: var(--accent);
    margin: 2rem 0 1rem; padding-bottom: 0.3rem;
    border-bottom: 1px solid var(--border);
  }}
  .meta {{ color: #8b949e; font-size: 0.85rem; margin-bottom: 2rem; }}
  .card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 1.2rem; margin-bottom: 1rem;
  }}
  .card-title {{
    font-weight: 600; color: #fff; font-size: 1rem;
    margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem;
  }}
  .badge {{
    display: inline-block; padding: 0.15rem 0.5rem; border-radius: 12px;
    font-size: 0.7rem; font-weight: 600; text-transform: uppercase;
  }}
  .badge-crit {{ background: var(--red); color: #fff; }}
  .badge-high {{ background: var(--orange); color: #fff; }}
  .badge-med  {{ background: var(--yellow); color: #000; }}
  .badge-low  {{ background: var(--green); color: #000; }}
  .badge-ok   {{ background: var(--green); color: #000; }}
  .badge-err  {{ background: var(--red); color: #fff; }}
  pre {{
    background: #0d1117; border: 1px solid var(--border);
    border-radius: 6px; padding: 1rem; overflow-x: auto;
    font-size: 0.8rem; color: #8b949e; margin-top: 0.5rem;
    max-height: 300px; overflow-y: auto;
  }}
  .stats {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem; margin: 1.5rem 0;
  }}
  .stat {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 1rem; text-align: center;
  }}
  .stat-value {{ font-size: 2rem; font-weight: 700; color: #fff; }}
  .stat-label {{ font-size: 0.75rem; color: #8b949e; text-transform: uppercase; }}
  .finding {{
    padding: 0.5rem 0; border-bottom: 1px solid var(--border);
  }}
  .finding:last-child {{ border-bottom: none; }}
  table {{
    width: 100%; border-collapse: collapse; margin: 0.5rem 0;
    font-size: 0.85rem;
  }}
  th, td {{
    padding: 0.5rem; text-align: left;
    border-bottom: 1px solid var(--border);
  }}
  th {{ color: var(--accent); font-weight: 600; }}
  .footer {{
    margin-top: 3rem; padding-top: 1rem;
    border-top: 1px solid var(--border);
    color: #8b949e; font-size: 0.75rem; text-align: center;
  }}
</style>
</head>
<body>
<div class="container">
  <h1>🍎🐍 The Eden's <span>Sins</span></h1>
  <div class="meta">
    <strong>macOS Purple Team Assessment Report</strong><br>
    Generated: {timestamp}<br>
    Target: {hostname} | macOS {os_version} | {arch}
  </div>

  <div class="stats">
    <div class="stat">
      <div class="stat-value">{total_tools}</div>
      <div class="stat-label">Tools Run</div>
    </div>
    <div class="stat">
      <div class="stat-value">{total_findings}</div>
      <div class="stat-label">Findings</div>
    </div>
    <div class="stat">
      <div class="stat-value" style="color:var(--red)">{critical_count}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat">
      <div class="stat-value">{risk_score}</div>
      <div class="stat-label">Risk Score</div>
    </div>
  </div>

  {sections}

  <div class="footer">
    The Eden's Sins — macOS Purple Team Assessment Framework<br>
    For authorized security testing only. Generated {timestamp}.
  </div>
</div>
</body>
</html>"""

SECTION_TEMPLATE = """
<h2>{icon} {title}</h2>
{cards}
"""

CARD_TEMPLATE = """
<div class="card">
  <div class="card-title">
    {tool_name}
    <span class="badge badge-{badge_class}">{status}</span>
  </div>
  <pre>{output}</pre>
</div>
"""


def get_system_info():
    """Get basic system info for the report header."""
    info = {"hostname": "unknown", "os_version": "?", "arch": "?"}
    try:
        info["hostname"] = subprocess.check_output(
            ["hostname"], text=True, timeout=5,
        ).strip()
    except Exception:
        pass
    try:
        info["os_version"] = subprocess.check_output(
            ["sw_vers", "-productVersion"], text=True, timeout=5,
        ).strip()
    except Exception:
        info["os_version"] = "N/A (not macOS)"
    import platform
    info["arch"] = platform.machine()
    return info


def run_tool(tool_path, args=None, timeout=60):
    """Run a single tool and capture output."""
    if args is None:
        args = []
    if tool_path.endswith(".py"):
        cmd = [sys.executable, tool_path] + args
    else:
        cmd = ["bash", tool_path] + args

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "status": "ok" if r.returncode == 0 else "error",
            "output": (r.stdout + r.stderr)[-3000:],
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "output": "Tool timed out"}
    except FileNotFoundError:
        return {"status": "missing", "output": f"Not found: {tool_path}"}


def generate_report(data, output_path):
    """Generate HTML report from collected data."""
    info = data.get("system_info", get_system_info())

    sections_html = ""
    total_findings = 0
    critical_count = 0
    total_tools = 0

    phase_icons = {
        "recon": "🔍", "bypass": "🛡️", "persist": "🪝",
        "privesc": "⬆️", "exfil": "📤",
    }
    phase_names = {
        "recon": "Reconnaissance", "bypass": "Defense Bypass",
        "persist": "Persistence", "privesc": "Privilege Escalation",
        "exfil": "Exfiltration",
    }

    for phase_key, results in data.get("results", {}).items():
        cards_html = ""
        for result in results:
            total_tools += 1
            status = result.get("status", "unknown")

            badge_class = {"ok": "ok", "error": "err", "timeout": "med"}.get(status, "low")

            output_text = result.get("output", result.get("stdout", ""))
            # Count "findings" heuristically
            for line in output_text.splitlines():
                if any(kw in line.lower() for kw in ["🔴", "critical", "fail", "denied"]):
                    total_findings += 1
                    if "critical" in line.lower() or "🔴" in line:
                        critical_count += 1

            # Escape HTML
            output_text = (output_text
                           .replace("&", "&amp;")
                           .replace("<", "&lt;")
                           .replace(">", "&gt;"))

            cards_html += CARD_TEMPLATE.format(
                tool_name=result.get("tool", "unknown"),
                badge_class=badge_class,
                status=status.upper(),
                output=output_text[:2000],
            )

        icon = phase_icons.get(phase_key, "📋")
        title = phase_names.get(phase_key, phase_key.title())
        sections_html += SECTION_TEMPLATE.format(
            icon=icon, title=title, cards=cards_html,
        )

    risk_score = min(100, critical_count * 15 + total_findings * 3)

    html = HTML_TEMPLATE.format(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        hostname=info.get("hostname", "?"),
        os_version=info.get("os_version", "?"),
        arch=info.get("arch", "?"),
        total_tools=total_tools,
        total_findings=total_findings,
        critical_count=critical_count,
        risk_score=f"{risk_score}/100",
        sections=sections_html,
    )

    Path(output_path).write_text(html)
    print(f"[+] Report generated: {output_path}")
    print(f"    Tools: {total_tools} | Findings: {total_findings} | Critical: {critical_count}")


def live_run(output_path):
    """Run all tools and generate report."""
    tools_dir = Path(__file__).parent.parent / "tools"
    data = {"system_info": get_system_info(), "results": {}}

    phases = {
        "recon": [
            ("macos_fingerprint.py", ["--output", "json"]),
            ("preflight.sh", []),
        ],
        "bypass": [
            ("tcc_audit.py", ["--check-bypasses"]),
            ("gatekeeper_check.sh", []),
        ],
        "exfil": [
            ("browser_creds.py", ["--browser", "all", "--metadata"]),
            ("ssh_harvest.py", []),
            ("wifi_harvest.sh", []),
        ],
    }

    for phase, tools in phases.items():
        data["results"][phase] = []
        subdir = tools_dir / phase
        for tool_name, args in tools:
            print(f"  Running {tool_name}...")
            result = run_tool(str(subdir / tool_name), args)
            result["tool"] = tool_name
            data["results"][phase].append(result)

    generate_report(data, output_path)


def main():
    p = argparse.ArgumentParser(description="Report Generator — The Eden's Sins")
    p.add_argument("--input", help="JSON input from attack_chain.py")
    p.add_argument("--output", default="/tmp/eden_report.html", help="Output HTML")
    p.add_argument("--live", action="store_true", help="Run tools + generate")
    args = p.parse_args()

    if args.live:
        live_run(args.output)
    elif args.input:
        data = json.loads(Path(args.input).read_text())
        generate_report(data, args.output)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
