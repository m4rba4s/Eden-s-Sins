#!/usr/bin/env python3
"""
The Eden's Sins — Kill Chain Orchestrator

Runs a full macOS Purple Team assessment in sequence:
  Recon → Bypass Analysis → Persistence Check → Privesc Scan → Exfil Demo

Usage:
    python3 attack_chain.py --phase all [--dry-run] [--output report.json]
    python3 attack_chain.py --phase recon
    python3 attack_chain.py --phase persist --dry-run
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

TOOLS_DIR = Path(__file__).parent.parent / "tools"

PHASES = {
    "recon": {
        "name": "Phase 1: Reconnaissance",
        "tools": [
            ("macos_fingerprint.py", ["--output", "json"]),
            ("keychain_dump.sh", []),
            ("log_hunter.sh", []),
        ],
        "subdir": "recon",
    },
    "bypass": {
        "name": "Phase 2: Defense Bypass Analysis",
        "tools": [
            ("tcc_audit.py", ["--check-bypasses"]),
            ("gatekeeper_check.sh", []),
        ],
        "subdir": "bypass",
    },
    "persist": {
        "name": "Phase 3: Persistence Check",
        "tools": [
            ("launch_agent_implant.py", ["list"]),
            ("dylib_hijack_scanner.py", ["--scan", "/usr/local/bin"]),
            ("login_item_persist.py", ["detect"]),
        ],
        "subdir": "persist",
    },
    "privesc": {
        "name": "Phase 4: Privilege Escalation Scan",
        "tools": [
            ("xpc_fuzzer.py", ["list", "--filter", "root"]),
            ("suid_hunter.sh", []),
        ],
        "subdir": "privesc",
    },
    "exfil": {
        "name": "Phase 5: Exfiltration Vectors",
        "tools": [
            ("keychain_exfil.py", ["--metadata"]),
            ("fsevents_monitor.py", ["--history"]),
        ],
        "subdir": "exfil",
    },
}


def run_tool(tool_path: str, args: list, dry_run: bool = False):
    """Execute a single tool and capture output."""
    if not os.path.exists(tool_path):
        return {"status": "missing", "output": f"Tool not found: {tool_path}"}

    if tool_path.endswith(".py"):
        cmd = [sys.executable, tool_path] + args
    elif tool_path.endswith(".sh"):
        cmd = ["bash", tool_path] + args
    else:
        cmd = [tool_path] + args

    if dry_run:
        return {"status": "dry-run", "command": " ".join(cmd)}

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
        )
        return {
            "status": "ok" if result.returncode == 0 else "error",
            "stdout": result.stdout[-2000:],
            "stderr": result.stderr[-500:] if result.returncode != 0 else "",
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def run_phase(phase_key: str, dry_run: bool = False):
    """Run all tools in a phase."""
    phase = PHASES[phase_key]
    results = []
    subdir = TOOLS_DIR / phase["subdir"]

    print(f"\n{'═' * 55}")
    print(f"  🐍 {phase['name']}")
    print(f"{'═' * 55}")

    for tool_name, tool_args in phase["tools"]:
        tool_path = str(subdir / tool_name)
        print(f"\n  ▸ Running: {tool_name}...")

        start = time.time()
        result = run_tool(tool_path, tool_args, dry_run)
        elapsed = time.time() - start

        result["tool"] = tool_name
        result["elapsed_s"] = round(elapsed, 2)
        results.append(result)

        status_icon = {
            "ok": "✅", "error": "❌", "timeout": "⏰",
            "dry-run": "🔵", "missing": "⚠️",
        }.get(result["status"], "?")

        print(f"    {status_icon} {result['status']} ({result['elapsed_s']}s)")

        if result.get("stdout") and not dry_run:
            # Show first few lines
            lines = result["stdout"].splitlines()[:5]
            for line in lines:
                print(f"    │ {line[:100]}")
            if len(result["stdout"].splitlines()) > 5:
                print(f"    │ ... ({len(result['stdout'].splitlines())} total lines)")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="The Eden's Sins — Kill Chain Orchestrator",
    )
    parser.add_argument(
        "--phase",
        choices=list(PHASES.keys()) + ["all"],
        default="all",
        help="Phase to run (default: all)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview only")
    parser.add_argument("--output", help="Save report as JSON")
    args = parser.parse_args()

    print("🍎🐍 THE EDEN'S SINS — macOS Purple Team Assessment")
    print(f"    Started: {datetime.now().isoformat()}")
    print(f"    Mode: {'DRY RUN' if args.dry_run else 'LIVE'}")

    all_results = {}

    if args.phase == "all":
        phases_to_run = list(PHASES.keys())
    else:
        phases_to_run = [args.phase]

    for phase_key in phases_to_run:
        all_results[phase_key] = run_phase(phase_key, args.dry_run)

    # Summary
    print(f"\n{'═' * 55}")
    print("  📊 Assessment Summary")
    print(f"{'═' * 55}")

    total = sum(len(v) for v in all_results.values())
    ok_count = sum(
        1 for v in all_results.values()
        for r in v if r["status"] == "ok"
    )
    err_count = sum(
        1 for v in all_results.values()
        for r in v if r["status"] == "error"
    )

    print(f"  Tools run: {total}")
    print(f"  Succeeded: {ok_count}")
    print(f"  Failed:    {err_count}")
    print(f"  Completed: {datetime.now().isoformat()}")

    if args.output:
        report = {
            "framework": "The Eden's Sins",
            "timestamp": datetime.now().isoformat(),
            "mode": "dry-run" if args.dry_run else "live",
            "results": all_results,
        }
        Path(args.output).write_text(json.dumps(report, indent=2))
        print(f"\n  [+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
