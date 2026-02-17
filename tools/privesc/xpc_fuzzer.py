#!/usr/bin/env python3
"""
XPC Service Enumerator & Fuzzer — The Eden's Sins Phase 4
MITRE ATT&CK: T1559 Inter-Process Communication

Enumerates and analyzes macOS XPC services for privilege escalation.

Usage:
    python3 xpc_fuzzer.py list [--filter root]
    python3 xpc_fuzzer.py analyze --service com.apple.example
    python3 xpc_fuzzer.py detect
"""

import argparse
import json
import os
import plistlib
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class XPCService:
    label: str
    plist_path: str = ""
    program: str = ""
    mach_services: list = field(default_factory=list)
    user: str = ""
    is_privileged: bool = False
    has_sandbox: bool = False
    risk_notes: list = field(default_factory=list)


def _run(cmd, timeout=15):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return -1, "", ""


def enumerate_services():
    services = []
    rc, out, _ = _run(["launchctl", "list"])
    if rc == 0:
        for line in out.splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) >= 3:
                svc = XPCService(label=parts[2])
                if parts[0] != "-":
                    svc.risk_notes.append(f"Running (PID {parts[0]})")
                services.append(svc)
    return services


def find_plists():
    dirs = [
        "/Library/LaunchDaemons", "/Library/LaunchAgents",
        "/System/Library/LaunchDaemons", "/System/Library/LaunchAgents",
        os.path.expanduser("~/Library/LaunchAgents"),
    ]
    mapping = {}
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for f in Path(d).glob("*.plist"):
            try:
                with open(f, "rb") as fh:
                    data = plistlib.load(fh)
                label = data.get("Label", "")
                if label:
                    mapping[label] = str(f)
            except Exception:
                pass
    return mapping


def analyze_service(label):
    svc = XPCService(label=label)
    plists = find_plists()
    if label in plists:
        svc.plist_path = plists[label]
        try:
            with open(svc.plist_path, "rb") as f:
                data = plistlib.load(f)
            svc.program = data.get("Program", " ".join(data.get("ProgramArguments", ["?"])))
            mach = data.get("MachServices", {})
            svc.mach_services = list(mach.keys()) if isinstance(mach, dict) else list(mach)
            svc.user = data.get("UserName", "")
            if not svc.user and "LaunchDaemons" in svc.plist_path:
                svc.user = "root"
                svc.is_privileged = True
            svc.has_sandbox = bool(data.get("Sandbox"))
            if svc.is_privileged and svc.mach_services:
                svc.risk_notes.append("PRIVESC: Root service exposing Mach ports")
            if not svc.has_sandbox:
                svc.risk_notes.append("No sandbox profile")
        except Exception as e:
            svc.risk_notes.append(f"Parse error: {e}")
    return svc


def fmt(svc):
    icon = "🔴" if svc.is_privileged else "🟢"
    lines = [
        f"\n  {icon} {svc.label}",
        f"     Program: {svc.program or 'N/A'} | User: {svc.user or 'N/A'}",
        f"     Privileged: {svc.is_privileged} | Sandbox: {svc.has_sandbox}",
    ]
    if svc.mach_services:
        lines.append(f"     Mach: {', '.join(svc.mach_services[:5])}")
    for n in svc.risk_notes:
        lines.append(f"     ⚠️  {n}")
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="XPC Fuzzer — The Eden's Sins")
    sp = p.add_subparsers(dest="action")
    lp = sp.add_parser("list")
    lp.add_argument("--filter", choices=["root","user","all"], default="all")
    ap = sp.add_parser("analyze")
    ap.add_argument("--service", required=True)
    sp.add_parser("detect")
    args = p.parse_args()

    if args.action == "list":
        svcs = enumerate_services()
        plists = find_plists()
        for s in svcs:
            if s.label in plists:
                s.plist_path = plists[s.label]
                try:
                    with open(s.plist_path, "rb") as f:
                        d = plistlib.load(f)
                    if "LaunchDaemons" in s.plist_path:
                        s.is_privileged = True
                        s.user = d.get("UserName", "root")
                    m = d.get("MachServices", {})
                    s.mach_services = list(m.keys()) if isinstance(m, dict) else []
                except Exception:
                    pass
        if args.filter == "root":
            svcs = [s for s in svcs if s.is_privileged]
        elif args.filter == "user":
            svcs = [s for s in svcs if not s.is_privileged]
        print(f"  Total: {len(svcs)} | Root: {sum(1 for s in svcs if s.is_privileged)}")
        for s in svcs[:50]:
            if s.is_privileged or s.mach_services:
                print(fmt(s))

    elif args.action == "analyze":
        s = analyze_service(args.service)
        print(fmt(s))

    elif args.action == "detect":
        print("""
  BLUE TEAM — XPC Security
  ════════════════════════
  • Validate client identity with audit_token
  • Check entitlements before granting access
  • Use sandbox profiles for XPC services
  • Monitor: log show --predicate 'subsystem == "com.apple.xpc"'
  • ESF: ES_EVENT_TYPE_NOTIFY_XPC_CONNECT
  • Watch for crashes in XPC services (CrashReporter)
  • Common vulns: missing audit_token check, TOCTOU, path traversal
        """)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
