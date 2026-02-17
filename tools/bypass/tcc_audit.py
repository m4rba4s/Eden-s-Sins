#!/usr/bin/env python3
"""
TCC Auditor — The Eden's Sins Phase 2
MITRE ATT&CK: T1548 Abuse Elevation Control Mechanism

Audits macOS Transparency, Consent, and Control (TCC) database:
- Reads user and system TCC.db
- Shows all granted/denied permissions
- Identifies apps with dangerous access (FDA, Accessibility, Screen Recording)
- Finds potential proxy applications for TCC abuse
- Checks for known TCC bypass paths

Usage:
    python3 tcc_audit.py [--system] [--json] [--check-bypasses]

Author: The Eden's Sins / Purple Team
"""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# TCC service name → human-readable description + risk level
TCC_SERVICES = {
    "kTCCServiceAccessibility": ("Accessibility", "CRITICAL"),
    "kTCCServiceAddressBook": ("Contacts", "HIGH"),
    "kTCCServiceCalendar": ("Calendar", "MEDIUM"),
    "kTCCServiceCamera": ("Camera", "HIGH"),
    "kTCCServiceMicrophone": ("Microphone", "HIGH"),
    "kTCCServicePhotos": ("Photos", "MEDIUM"),
    "kTCCServiceReminders": ("Reminders", "LOW"),
    "kTCCServiceScreenCapture": ("Screen Recording", "CRITICAL"),
    "kTCCServiceSystemPolicyAllFiles": ("Full Disk Access", "CRITICAL"),
    "kTCCServiceSystemPolicyDesktopFolder": ("Desktop", "MEDIUM"),
    "kTCCServiceSystemPolicyDocumentsFolder": ("Documents", "MEDIUM"),
    "kTCCServiceSystemPolicyDownloadsFolder": ("Downloads", "MEDIUM"),
    "kTCCServiceSystemPolicyNetworkVolumes": ("Network Volumes", "MEDIUM"),
    "kTCCServiceSystemPolicyRemovableVolumes": ("Removable Volumes", "MEDIUM"),
    "kTCCServiceSystemPolicySysAdminFiles": ("Admin Files", "HIGH"),
    "kTCCServiceAppleEvents": ("AppleEvents/Automation", "HIGH"),
    "kTCCServicePostEvent": ("Input Monitoring", "CRITICAL"),
    "kTCCServiceListenEvent": ("Input Monitoring (Listen)", "CRITICAL"),
    "kTCCServiceDeveloperTool": ("Developer Tools", "HIGH"),
    "kTCCServiceLocation": ("Location", "MEDIUM"),
    "kTCCServiceMediaLibrary": ("Media Library", "LOW"),
    "kTCCServiceSpeechRecognition": ("Speech Recognition", "MEDIUM"),
    "kTCCServiceBluetoothAlways": ("Bluetooth", "MEDIUM"),
}

# Auth values
AUTH_VALUES = {
    0: "Denied",
    1: "Unknown",
    2: "Allowed",
    3: "Limited",
}


@dataclass
class TCCEntry:
    """Single TCC permission entry."""
    service: str
    service_friendly: str
    client: str
    auth_value: int
    auth_status: str
    risk_level: str
    last_modified: str = ""
    is_proxy_candidate: bool = False


@dataclass
class TCCAuditReport:
    """Complete TCC audit report."""
    user_db_path: str = ""
    system_db_path: str = ""
    user_entries: list = field(default_factory=list)
    system_entries: list = field(default_factory=list)
    critical_grants: list = field(default_factory=list)
    proxy_candidates: list = field(default_factory=list)
    bypass_checks: list = field(default_factory=list)
    total_grants: int = 0
    risk_score: int = 0


def read_tcc_db(db_path: str) -> list[TCCEntry]:
    """Read entries from a TCC database."""
    entries = []

    if not os.path.exists(db_path):
        return entries

    try:
        # TCC.db may be locked — try read-only with immutable
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Try modern schema first
        try:
            cursor.execute("""
                SELECT service, client, client_type, auth_value,
                       auth_reason, last_modified
                FROM access
                ORDER BY service, client
            """)
        except sqlite3.OperationalError:
            # Fallback for older schema
            cursor.execute("""
                SELECT service, client, client_type, allowed as auth_value,
                       '' as auth_reason, 0 as last_modified
                FROM access
                ORDER BY service, client
            """)

        for row in cursor.fetchall():
            service = row["service"]
            info = TCC_SERVICES.get(
                service, (service, "UNKNOWN")
            )
            auth_val = row["auth_value"]

            entry = TCCEntry(
                service=service,
                service_friendly=info[0],
                client=row["client"],
                auth_value=auth_val,
                auth_status=AUTH_VALUES.get(auth_val, f"Unknown({auth_val})"),
                risk_level=info[1],
                last_modified=str(row["last_modified"]) if row["last_modified"] else "",
            )

            # Check if this app could be used as a proxy
            if auth_val == 2 and info[1] in ("CRITICAL", "HIGH"):
                entry.is_proxy_candidate = True

            entries.append(entry)

        conn.close()
    except sqlite3.OperationalError as e:
        print(f"[!] Cannot read {db_path}: {e}")
        print("[*] TCC.db access may require Full Disk Access or SIP disabled")
    except Exception as e:
        print(f"[-] Error reading {db_path}: {e}")

    return entries


def check_known_bypasses(report: TCCAuditReport) -> None:
    """Check for known TCC bypass vectors."""

    bypasses = [
        {
            "name": "Terminal.app FDA Proxy",
            "check": "Terminal has Full Disk Access → can access protected files",
            "mitre": "T1548",
            "found": False,
        },
        {
            "name": "SSH TCC Bypass",
            "check": "SSH logins may bypass TCC checks on some versions",
            "mitre": "T1548",
            "found": False,
        },
        {
            "name": "Finder Automation Proxy",
            "check": "AppleEvents to Finder can access files without TCC",
            "mitre": "T1059.002",
            "found": False,
        },
        {
            "name": "Accessibility → Keystroke Injection",
            "check": "Accessibility access allows CGEvent keystroke injection",
            "mitre": "T1056.001",
            "found": False,
        },
        {
            "name": "Screen Recording → Credential Theft",
            "check": "Screen capture can sniff password dialogs",
            "mitre": "T1113",
            "found": False,
        },
    ]

    # Check which bypasses have the prerequisite permissions granted
    all_entries = report.user_entries + report.system_entries

    for bypass in bypasses:
        if "Terminal" in bypass["name"]:
            for entry in all_entries:
                if (
                    "Terminal" in entry.client
                    and "AllFiles" in entry.service
                    and entry.auth_value == 2
                ):
                    bypass["found"] = True
                    break

        elif "Accessibility" in bypass["name"]:
            for entry in all_entries:
                if (
                    "Accessibility" in entry.service
                    and entry.auth_value == 2
                ):
                    bypass["found"] = True
                    break

        elif "Screen Recording" in bypass["name"]:
            for entry in all_entries:
                if (
                    "ScreenCapture" in entry.service
                    and entry.auth_value == 2
                ):
                    bypass["found"] = True
                    break

        elif "Finder" in bypass["name"]:
            for entry in all_entries:
                if (
                    "AppleEvents" in entry.service
                    and entry.auth_value == 2
                ):
                    bypass["found"] = True
                    break

    report.bypass_checks = bypasses


def analyze_report(report: TCCAuditReport) -> None:
    """Analyze entries and calculate risk."""
    all_entries = report.user_entries + report.system_entries

    for entry in all_entries:
        if entry.auth_value == 2:
            report.total_grants += 1

            if entry.risk_level == "CRITICAL":
                report.critical_grants.append(asdict(entry))
                report.risk_score += 20
            elif entry.risk_level == "HIGH":
                report.risk_score += 10

            if entry.is_proxy_candidate:
                report.proxy_candidates.append(asdict(entry))

    report.risk_score = min(100, report.risk_score)


def format_text_report(report: TCCAuditReport) -> str:
    """Format report as text."""
    lines = [
        "=" * 65,
        "  THE EDEN'S SINS — TCC Audit Report",
        "=" * 65,
        "",
        f"  User TCC DB   : {report.user_db_path}",
        f"  System TCC DB : {report.system_db_path}",
        f"  Total grants  : {report.total_grants}",
        f"  Critical grants: {len(report.critical_grants)}",
        f"  Proxy candidates: {len(report.proxy_candidates)}",
        f"  Risk score    : {report.risk_score}/100",
        "",
    ]

    # User entries
    if report.user_entries:
        lines.extend([
            "─" * 65,
            "  USER TCC PERMISSIONS",
            "─" * 65,
        ])
        for entry in report.user_entries:
            if entry.auth_value == 2:
                risk_icon = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🟢",
                }.get(entry.risk_level, "⚪")
                lines.append(
                    f"  {risk_icon} {entry.service_friendly:25s} "
                    f"→ {entry.client}"
                )

    # Critical grants
    if report.critical_grants:
        lines.extend([
            "",
            "─" * 65,
            "  🔴 CRITICAL PERMISSIONS (Attack Surface)",
            "─" * 65,
        ])
        for grant in report.critical_grants:
            lines.append(
                f"\n  Service: {grant['service_friendly']}"
            )
            lines.append(f"  Client : {grant['client']}")
            lines.append(f"  Risk   : {grant['risk_level']}")

    # Proxy candidates
    if report.proxy_candidates:
        lines.extend([
            "",
            "─" * 65,
            "  ⚠️  PROXY CANDIDATES (TCC Abuse Vectors)",
            "─" * 65,
            "",
            "  These apps have critical/high TCC permissions and could",
            "  be used as proxies to access protected resources:",
        ])
        for proxy in report.proxy_candidates:
            lines.append(
                f"  → {proxy['client']} "
                f"({proxy['service_friendly']})"
            )

    # Bypass checks
    if report.bypass_checks:
        lines.extend([
            "",
            "─" * 65,
            "  KNOWN TCC BYPASS VECTORS",
            "─" * 65,
        ])
        for bypass in report.bypass_checks:
            status = "✅ POSSIBLE" if bypass["found"] else "❌ Not available"
            lines.append(f"\n  [{status}] {bypass['name']}")
            lines.append(f"    {bypass['check']}")
            lines.append(f"    MITRE: {bypass['mitre']}")

    # Detection guidance
    lines.extend([
        "",
        "─" * 65,
        "  BLUE TEAM — Detection & Hardening",
        "─" * 65,
        "",
        "  Detection:",
        "    • Monitor TCC.db modifications (ESF file event)",
        "    • Log tccutil reset/modify commands",
        "    • Track AppleEvent IPC for automation abuse",
        "    • osquery: SELECT * FROM system_extensions WHERE identifier NOT LIKE 'com.apple%'",
        "    • Alert on new Full Disk Access grants",
        "",
        "  Hardening:",
        "    • MDM-manage TCC permissions (PPPC profiles)",
        "    • Minimize Full Disk Access grants",
        "    • Restrict Accessibility access to trusted apps only",
        "    • Disable AppleEvents for non-essential apps",
        "    • Regular TCC permission audit (this tool!)",
        "",
        "=" * 65,
    ])

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TCC Auditor — The Eden's Sins",
    )
    parser.add_argument(
        "--system", action="store_true",
        help="Include system TCC database (may require root)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output as JSON",
    )
    parser.add_argument(
        "--check-bypasses", action="store_true",
        help="Check for known TCC bypass vectors",
    )
    parser.add_argument(
        "--save", type=str, metavar="FILE",
        help="Save report to file",
    )
    args = parser.parse_args()

    report = TCCAuditReport()

    # User TCC database
    report.user_db_path = os.path.expanduser(
        "~/Library/Application Support/com.apple.TCC/TCC.db"
    )
    report.system_db_path = (
        "/Library/Application Support/com.apple.TCC/TCC.db"
    )

    print("[*] THE EDEN'S SINS — TCC Auditor")
    print(f"[*] Reading user TCC: {report.user_db_path}")

    report.user_entries = read_tcc_db(report.user_db_path)

    if args.system:
        print(f"[*] Reading system TCC: {report.system_db_path}")
        report.system_entries = read_tcc_db(report.system_db_path)

    if args.check_bypasses:
        check_known_bypasses(report)

    analyze_report(report)

    if args.json:
        # Convert entries to dicts
        output_data = asdict(report) if hasattr(report, '__dataclass_fields__') else {}
        output_data["user_entries"] = [asdict(e) for e in report.user_entries]
        output_data["system_entries"] = [asdict(e) for e in report.system_entries]
        output = json.dumps(output_data, indent=2, ensure_ascii=False)
    else:
        output = format_text_report(report)

    print(output)

    if args.save:
        Path(args.save).write_text(output, encoding="utf-8")
        print(f"\n[+] Report saved to {args.save}")


if __name__ == "__main__":
    main()
