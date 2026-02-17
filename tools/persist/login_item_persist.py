#!/usr/bin/env python3
"""
Login Item Persistence — The Eden's Sins Phase 3
MITRE ATT&CK: T1547.015 Boot/Logon Autostart: Login Items

Manages macOS Login Items for persistence:
- Add/remove login items via osascript (AppleScript)
- Enumerate existing login items
- Detect suspicious login items

Login Items run programs when a user logs in, providing
user-level persistence without root access.

Usage:
    python3 login_item_persist.py list
    python3 login_item_persist.py add --name "MyApp" --path /path/to/binary
    python3 login_item_persist.py remove --name "MyApp"
    python3 login_item_persist.py detect

Author: The Eden's Sins / Purple Team
"""

import argparse
import json
import os
import plistlib
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class LoginItem:
    """Represents a single login item."""
    name: str
    path: str
    hidden: bool = False
    kind: str = "application"  # application, alias


@dataclass
class LoginItemReport:
    """Login items analysis report."""
    items: list = field(default_factory=list)
    suspicious: list = field(default_factory=list)
    total_count: int = 0


def _run(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    """Run command safely."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return -1, "", str(e)


def _osascript(script: str) -> tuple[int, str, str]:
    """Run AppleScript via osascript."""
    return _run(["osascript", "-e", script])


def list_login_items() -> LoginItemReport:
    """List all current login items."""
    report = LoginItemReport()

    # Method 1: AppleScript (works on all macOS versions)
    script = '''
    tell application "System Events"
        get properties of every login item
    end tell
    '''
    rc, out, err = _osascript(script)

    if rc == 0 and out:
        # Parse AppleScript output
        # Format varies — try structured approach
        name_script = '''
        tell application "System Events"
            set itemNames to name of every login item
            set itemPaths to path of every login item
            set itemHidden to hidden of every login item
            return {itemNames, itemPaths, itemHidden}
        end tell
        '''
        rc2, out2, _ = _osascript(name_script)
        if rc2 == 0:
            # Parse the response
            try:
                parts = out2.split(", ")
                # This is simplified — actual parsing is complex
                for part in parts:
                    part = part.strip()
                    if part and not part.startswith("{") and not part.endswith("}"):
                        report.items.append(asdict(LoginItem(
                            name=part,
                            path="(use 'list' for details)",
                        )))
            except Exception:
                pass

    # Method 2: backgrounditems.btm (Ventura+)
    btm_path = os.path.expanduser(
        "~/Library/Application Support/"
        "com.apple.backgroundtaskmanagementagent/backgrounditems.btm"
    )
    if os.path.exists(btm_path):
        try:
            with open(btm_path, "rb") as f:
                data = plistlib.load(f)
            # Extract items from BTM format
            if isinstance(data, dict):
                for key, val in data.items():
                    if isinstance(val, list):
                        for item in val:
                            if isinstance(item, dict):
                                name = item.get("Name", "unknown")
                                path = item.get("URL", item.get("Path", ""))
                                report.items.append(asdict(LoginItem(
                                    name=name,
                                    path=str(path),
                                )))
        except Exception:
            pass

    # Method 3: sfltool (Monterey+)
    rc, out, _ = _run(["sfltool", "dumpbtm"])
    if rc == 0 and out:
        for line in out.splitlines():
            if "path:" in line.lower() or "name:" in line.lower():
                report.items.append(asdict(LoginItem(
                    name=line.strip(),
                    path="(from sfltool)",
                )))

    report.total_count = len(report.items)
    return report


def add_login_item(
    name: str,
    path: str,
    hidden: bool = False,
) -> bool:
    """Add a login item via AppleScript."""
    if not os.path.exists(path):
        print(f"[-] Path does not exist: {path}")
        return False

    hidden_str = "true" if hidden else "false"

    # Use osascript to add login item
    script = f'''
    tell application "System Events"
        make login item at end with properties {{
            path:"{path}",
            hidden:{hidden_str},
            name:"{name}"
        }}
    end tell
    '''

    rc, out, err = _osascript(script)

    if rc == 0:
        print(f"[+] Login item added: {name} → {path}")
        if hidden:
            print(f"[+] Hidden: yes (won't show in Dock on login)")
        return True
    else:
        print(f"[-] Failed to add login item: {err}")
        print("[*] On macOS Ventura+, you may need to use Settings > General > Login Items")
        return False


def remove_login_item(name: str) -> bool:
    """Remove a login item by name."""
    script = f'''
    tell application "System Events"
        delete login item "{name}"
    end tell
    '''

    rc, out, err = _osascript(script)

    if rc == 0:
        print(f"[+] Login item removed: {name}")
        return True
    else:
        print(f"[-] Failed to remove login item: {err}")
        return False


def detect_suspicious(report: LoginItemReport) -> None:
    """Analyze login items for suspicious entries."""
    suspicious_indicators = [
        # Paths
        "/tmp/",
        "/var/tmp/",
        "/Users/Shared/",
        "/private/tmp/",
        # Names
        ".hidden",
        "com.apple.",  # Impersonating Apple (not in /System)
        # Extensions
        ".sh",
        ".py",
        ".scpt",
        ".command",
    ]

    for item in report.items:
        name = item.get("name", "").lower()
        path = item.get("path", "").lower()

        for indicator in suspicious_indicators:
            if indicator in name or indicator in path:
                item["suspicious"] = True
                item["reason"] = f"Matches indicator: {indicator}"
                report.suspicious.append(item)
                break


def print_detection_guide() -> None:
    """Print blue team detection guidance."""
    print("\n" + "=" * 60)
    print("  BLUE TEAM — Login Items Detection & Hardening")
    print("=" * 60)
    print("""
  Where Login Items Live:
    • ~/Library/Application Support/com.apple.backgroundtaskmanagementagent/
      backgrounditems.btm (Ventura+)
    • Older: ~/Library/Preferences/com.apple.loginitems.plist
    • Managed: /Library/Managed Preferences/<user>/

  Detection:
    • Monitor writes to backgrounditems.btm
    • Track AppleScript execution targeting "System Events"
    • ESF: ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
    • osquery: SELECT * FROM startup_items
    • KnockKnock (Objective-See): scans all login items

  Suspicious Patterns:
    • Login items pointing to /tmp, /var/tmp, /Users/Shared
    • Scripts (.sh, .py, .command) as login items
    • Items with names mimicking Apple services
    • Hidden login items (launch without Dock icon)
    • Recently added items (check file timestamp)

  Hardening:
    • Use MDM to manage allowed login items
    • Monitor BackgroundTaskManagement framework events
    • Restrict osascript execution for non-admin users
    • Regular audit of startup items
    • Santa can block unauthorized binary execution

  MITRE:
    • T1547.015 Boot or Logon Autostart Execution: Login Items
    • Data Sources: DS0022 (File), DS0017 (Command)
    """)


def format_report(report: LoginItemReport) -> str:
    """Format report as text."""
    lines = [
        "=" * 60,
        "  THE EDEN'S SINS — Login Items Report",
        "=" * 60,
        "",
        f"  Total login items: {report.total_count}",
        f"  Suspicious items : {len(report.suspicious)}",
        "",
    ]

    if report.items:
        lines.append("─" * 60)
        lines.append("  LOGIN ITEMS")
        lines.append("─" * 60)
        for item in report.items:
            suspicious = "🔴" if item.get("suspicious") else "🟢"
            lines.append(f"\n  {suspicious} {item.get('name', 'unknown')}")
            lines.append(f"     Path: {item.get('path', 'unknown')}")
            if item.get("reason"):
                lines.append(f"     ⚠️  {item['reason']}")

    if report.suspicious:
        lines.extend([
            "",
            "─" * 60,
            "  ⚠️  SUSPICIOUS ITEMS DETECTED",
            "─" * 60,
        ])
        for item in report.suspicious:
            lines.append(f"  🔴 {item.get('name')}: {item.get('reason')}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Login Item Persistence — The Eden's Sins",
    )
    subparsers = parser.add_subparsers(dest="action")

    # List
    subparsers.add_parser("list", help="List login items")

    # Add
    add_p = subparsers.add_parser("add", help="Add login item")
    add_p.add_argument("--name", required=True, help="Item name")
    add_p.add_argument("--path", required=True, help="Program path")
    add_p.add_argument(
        "--hidden", action="store_true",
        help="Launch hidden (no Dock icon)",
    )
    add_p.add_argument(
        "--dry-run", action="store_true",
        help="Preview only",
    )

    # Remove
    rm_p = subparsers.add_parser("remove", help="Remove login item")
    rm_p.add_argument("--name", required=True, help="Item name to remove")

    # Detect
    subparsers.add_parser("detect", help="Detect suspicious login items")

    args = parser.parse_args()

    if args.action == "list":
        report = list_login_items()
        print(format_report(report))

    elif args.action == "add":
        if args.dry_run:
            print(f"[DRY RUN] Would add login item:")
            print(f"  Name  : {args.name}")
            print(f"  Path  : {args.path}")
            print(f"  Hidden: {args.hidden}")
        else:
            add_login_item(args.name, args.path, args.hidden)
        print_detection_guide()

    elif args.action == "remove":
        remove_login_item(args.name)

    elif args.action == "detect":
        report = list_login_items()
        detect_suspicious(report)
        print(format_report(report))
        print_detection_guide()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
