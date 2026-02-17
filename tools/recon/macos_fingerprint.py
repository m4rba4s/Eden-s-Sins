#!/usr/bin/env python3
"""
macOS System Fingerprinter — The Eden's Sins Phase 1
MITRE ATT&CK: T1082 System Information Discovery

Collects comprehensive system information for attack surface assessment:
- macOS version, build, architecture
- SIP / Gatekeeper / FileVault status
- TCC permissions overview
- Installed security tools
- Network interfaces and services
- Running daemons and agents

Usage:
    python3 macos_fingerprint.py [--output json|text] [--full]

Author: The Eden's Sins / Purple Team
"""

import argparse
import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class SecurityControl:
    """Single security control status."""
    name: str
    enabled: bool
    details: str = ""
    risk_note: str = ""


@dataclass
class SystemFingerprint:
    """Complete system fingerprint."""
    timestamp: str = ""
    hostname: str = ""
    os_version: str = ""
    os_build: str = ""
    architecture: str = ""
    cpu_brand: str = ""
    is_apple_silicon: bool = False
    kernel_version: str = ""
    serial_number: str = ""
    security_controls: list = field(default_factory=list)
    tcc_summary: dict = field(default_factory=dict)
    running_security_tools: list = field(default_factory=list)
    network_interfaces: list = field(default_factory=list)
    launch_agents_count: int = 0
    launch_daemons_count: int = 0
    attack_surface_score: int = 0
    notes: list = field(default_factory=list)


def _run(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", f"Timeout after {timeout}s"


def check_platform() -> None:
    """Bail out early if not macOS."""
    if platform.system() != "Darwin":
        print(
            "[!] This tool is designed for macOS. "
            f"Current platform: {platform.system()}"
        )
        print("[*] Running in dry-run / documentation mode.")


def get_basic_info(fp: SystemFingerprint) -> None:
    """Populate basic OS and hardware info."""
    fp.timestamp = datetime.now(timezone.utc).isoformat()
    fp.hostname = platform.node()
    fp.architecture = platform.machine()
    fp.kernel_version = platform.release()
    fp.is_apple_silicon = fp.architecture == "arm64"

    # macOS version
    rc, out, _ = _run(["sw_vers", "-productVersion"])
    fp.os_version = out if rc == 0 else platform.mac_ver()[0]

    rc, out, _ = _run(["sw_vers", "-buildVersion"])
    fp.os_build = out if rc == 0 else "unknown"

    # CPU brand
    rc, out, _ = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
    fp.cpu_brand = out if rc == 0 else "unknown"

    # Serial (useful for asset tracking in pentests)
    rc, out, _ = _run([
        "ioreg", "-l", "-d", "2"
    ])
    if rc == 0:
        for line in out.splitlines():
            if "IOPlatformSerialNumber" in line:
                parts = line.split("=")
                if len(parts) == 2:
                    fp.serial_number = parts[1].strip().strip('"')
                break


def check_sip(fp: SystemFingerprint) -> None:
    """Check System Integrity Protection status."""
    rc, out, _ = _run(["csrutil", "status"])
    enabled = "enabled" in out.lower() if rc == 0 else None
    risk = "" if enabled else "SIP disabled — full kernel/system access possible"
    fp.security_controls.append(asdict(SecurityControl(
        name="SIP (System Integrity Protection)",
        enabled=bool(enabled),
        details=out if rc == 0 else "Unable to determine",
        risk_note=risk,
    )))
    if not enabled:
        fp.attack_surface_score += 30
        fp.notes.append("CRITICAL: SIP is disabled")


def check_gatekeeper(fp: SystemFingerprint) -> None:
    """Check Gatekeeper status."""
    rc, out, _ = _run(["spctl", "--status"])
    enabled = "enabled" in out.lower() if rc == 0 else None
    risk = "" if enabled else "Gatekeeper disabled — unsigned code can execute"
    fp.security_controls.append(asdict(SecurityControl(
        name="Gatekeeper",
        enabled=bool(enabled),
        details=out if rc == 0 else "Unable to determine",
        risk_note=risk,
    )))
    if not enabled:
        fp.attack_surface_score += 20
        fp.notes.append("WARNING: Gatekeeper is disabled")


def check_filevault(fp: SystemFingerprint) -> None:
    """Check FileVault disk encryption status."""
    rc, out, _ = _run(["fdesetup", "status"])
    enabled = "on" in out.lower() if rc == 0 else None
    risk = "" if enabled else "Disk not encrypted — physical access = full compromise"
    fp.security_controls.append(asdict(SecurityControl(
        name="FileVault",
        enabled=bool(enabled),
        details=out if rc == 0 else "Unable to determine (needs root?)",
        risk_note=risk,
    )))
    if not enabled:
        fp.attack_surface_score += 25


def check_firewall(fp: SystemFingerprint) -> None:
    """Check macOS Application Firewall status."""
    rc, out, _ = _run([
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        "--getglobalstate",
    ])
    enabled = "enabled" in out.lower() if rc == 0 else None
    risk = "" if enabled else "Firewall disabled — all inbound connections allowed"
    fp.security_controls.append(asdict(SecurityControl(
        name="Application Firewall",
        enabled=bool(enabled),
        details=out if rc == 0 else "Unable to determine",
        risk_note=risk,
    )))
    if not enabled:
        fp.attack_surface_score += 15


def check_xprotect(fp: SystemFingerprint) -> None:
    """Check XProtect (built-in malware detection) version."""
    xprotect_plist = (
        "/Library/Apple/System/Library/CoreServices/"
        "XProtect.bundle/Contents/Info.plist"
    )
    if os.path.exists(xprotect_plist):
        rc, out, _ = _run([
            "defaults", "read", xprotect_plist, "CFBundleShortVersionString"
        ])
        fp.security_controls.append(asdict(SecurityControl(
            name="XProtect",
            enabled=True,
            details=f"Version: {out}" if rc == 0 else "Present but version unknown",
        )))
    else:
        fp.security_controls.append(asdict(SecurityControl(
            name="XProtect",
            enabled=False,
            details="XProtect bundle not found",
            risk_note="No built-in malware detection",
        )))
        fp.attack_surface_score += 10


def audit_tcc(fp: SystemFingerprint) -> None:
    """Quick audit of TCC database permissions."""
    tcc_user = os.path.expanduser(
        "~/Library/Application Support/com.apple.TCC/TCC.db"
    )
    tcc_system = "/Library/Application Support/com.apple.TCC/TCC.db"

    summary = {"user_db_exists": False, "system_db_exists": False}

    if os.path.exists(tcc_user):
        summary["user_db_exists"] = True
        rc, out, _ = _run([
            "sqlite3", tcc_user,
            "SELECT service, client, auth_value FROM access "
            "WHERE auth_value = 2 LIMIT 20;"
        ])
        if rc == 0 and out:
            granted = []
            for line in out.splitlines():
                parts = line.split("|")
                if len(parts) >= 2:
                    granted.append({
                        "service": parts[0],
                        "client": parts[1],
                    })
            summary["user_granted_permissions"] = granted
            fp.notes.append(
                f"TCC: {len(granted)} user-level permissions granted"
            )

    if os.path.exists(tcc_system):
        summary["system_db_exists"] = True

    fp.tcc_summary = summary


def detect_security_tools(fp: SystemFingerprint) -> None:
    """Detect running security tools (EDR, AV, etc.)."""
    known_tools = {
        "CrowdStrike": ["falcon", "csfalcon"],
        "Carbon Black": ["cbdaemon", "cbosxsensor"],
        "SentinelOne": ["sentineld", "sentinelagent"],
        "Jamf Protect": ["JamfProtect", "jamf"],
        "Sophos": ["SophosAntiVirus", "sophos"],
        "Norton": ["Norton", "symantec"],
        "Malwarebytes": ["Malwarebytes", "mbam"],
        "Little Snitch": ["Little Snitch"],
        "LuLu": ["LuLu"],
        "BlockBlock": ["BlockBlock"],
        "OverSight": ["OverSight"],
        "KnockKnock": ["KnockKnock"],
        "Santa": ["santa", "santad", "santactl"],
    }

    rc, out, _ = _run(["ps", "aux"])
    if rc != 0:
        return

    processes = out.lower()
    for tool_name, signatures in known_tools.items():
        for sig in signatures:
            if sig.lower() in processes:
                fp.running_security_tools.append(tool_name)
                fp.attack_surface_score -= 5  # Security tools reduce score
                break


def enumerate_network(fp: SystemFingerprint) -> None:
    """Enumerate active network interfaces."""
    rc, out, _ = _run(["ifconfig", "-a"])
    if rc != 0:
        return

    current_iface = None
    for line in out.splitlines():
        if not line.startswith("\t") and ":" in line:
            current_iface = line.split(":")[0]
        elif current_iface and "inet " in line:
            parts = line.strip().split()
            if len(parts) >= 2:
                fp.network_interfaces.append({
                    "interface": current_iface,
                    "ip": parts[1],
                })


def count_persistence_items(fp: SystemFingerprint) -> None:
    """Count LaunchAgents and LaunchDaemons."""
    agent_dirs = [
        os.path.expanduser("~/Library/LaunchAgents"),
        "/Library/LaunchAgents",
        "/System/Library/LaunchAgents",
    ]
    daemon_dirs = [
        "/Library/LaunchDaemons",
        "/System/Library/LaunchDaemons",
    ]

    for d in agent_dirs:
        if os.path.isdir(d):
            fp.launch_agents_count += len([
                f for f in os.listdir(d) if f.endswith(".plist")
            ])

    for d in daemon_dirs:
        if os.path.isdir(d):
            fp.launch_daemons_count += len([
                f for f in os.listdir(d) if f.endswith(".plist")
            ])


def calculate_risk_score(fp: SystemFingerprint) -> None:
    """Final attack surface score normalization."""
    # Clamp to 0-100
    fp.attack_surface_score = max(0, min(100, fp.attack_surface_score))

    if fp.attack_surface_score >= 60:
        fp.notes.append(
            f"ATTACK SURFACE SCORE: {fp.attack_surface_score}/100 — HIGH RISK"
        )
    elif fp.attack_surface_score >= 30:
        fp.notes.append(
            f"ATTACK SURFACE SCORE: {fp.attack_surface_score}/100 — MEDIUM RISK"
        )
    else:
        fp.notes.append(
            f"ATTACK SURFACE SCORE: {fp.attack_surface_score}/100 — LOW RISK"
        )


def format_text(fp: SystemFingerprint) -> str:
    """Format fingerprint as human-readable text."""
    lines = [
        "=" * 60,
        "  THE EDEN'S SINS — macOS Fingerprint Report",
        "=" * 60,
        "",
        f"  Timestamp   : {fp.timestamp}",
        f"  Hostname    : {fp.hostname}",
        f"  macOS       : {fp.os_version} (Build {fp.os_build})",
        f"  Arch        : {fp.architecture}"
        f" {'(Apple Silicon)' if fp.is_apple_silicon else '(Intel)'}",
        f"  CPU         : {fp.cpu_brand}",
        f"  Kernel      : {fp.kernel_version}",
        f"  Serial      : {fp.serial_number or 'N/A'}",
        "",
        "─" * 60,
        "  SECURITY CONTROLS",
        "─" * 60,
    ]

    for ctrl in fp.security_controls:
        status = "✅ ON" if ctrl["enabled"] else "❌ OFF"
        lines.append(f"  [{status}] {ctrl['name']}")
        if ctrl.get("details"):
            lines.append(f"          {ctrl['details']}")
        if ctrl.get("risk_note"):
            lines.append(f"          ⚠️  {ctrl['risk_note']}")

    lines.extend([
        "",
        "─" * 60,
        "  SECURITY TOOLS DETECTED",
        "─" * 60,
    ])
    if fp.running_security_tools:
        for tool in fp.running_security_tools:
            lines.append(f"  🛡️  {tool}")
    else:
        lines.append("  ⚠️  No known security tools detected!")

    lines.extend([
        "",
        "─" * 60,
        "  NETWORK INTERFACES",
        "─" * 60,
    ])
    for iface in fp.network_interfaces:
        lines.append(f"  {iface['interface']}: {iface['ip']}")

    lines.extend([
        "",
        "─" * 60,
        f"  PERSISTENCE: {fp.launch_agents_count} LaunchAgents, "
        f"{fp.launch_daemons_count} LaunchDaemons",
        "─" * 60,
        "",
    ])

    for note in fp.notes:
        lines.append(f"  📌 {note}")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="macOS System Fingerprinter — The Eden's Sins"
    )
    parser.add_argument(
        "--output", choices=["json", "text"], default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--full", action="store_true",
        help="Include extended checks (TCC deep audit, etc.)",
    )
    parser.add_argument(
        "--save", type=str, metavar="FILE",
        help="Save output to file",
    )
    args = parser.parse_args()

    check_platform()

    fp = SystemFingerprint()

    # Collect data
    get_basic_info(fp)
    check_sip(fp)
    check_gatekeeper(fp)
    check_filevault(fp)
    check_firewall(fp)
    check_xprotect(fp)
    detect_security_tools(fp)
    enumerate_network(fp)
    count_persistence_items(fp)

    if args.full:
        audit_tcc(fp)

    calculate_risk_score(fp)

    # Output
    if args.output == "json":
        output = json.dumps(asdict(fp), indent=2, ensure_ascii=False)
    else:
        output = format_text(fp)

    print(output)

    if args.save:
        Path(args.save).write_text(output, encoding="utf-8")
        print(f"\n[+] Saved to {args.save}")


if __name__ == "__main__":
    main()
