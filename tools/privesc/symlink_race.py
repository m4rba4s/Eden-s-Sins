#!/usr/bin/env python3
"""
Symlink Race Condition PoC — The Eden's Sins Phase 4
MITRE ATT&CK: T1068 Exploitation for Privilege Escalation

Demonstrates TOCTOU (Time-of-Check to Time-of-Use) attacks via symlinks.
When a privileged daemon checks a file then later operates on it,
a symlink swap in between can redirect the operation.

This is a SAFE DEMONSTRATOR — it creates a controlled race condition
in /tmp to show the concept without exploiting any real service.

Usage:
    python3 symlink_race.py demo          # Safe self-contained demo
    python3 symlink_race.py scan          # Find potential targets
    python3 symlink_race.py detect        # Blue team guidance
"""

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def safe_demo():
    """Self-contained TOCTOU demonstration."""
    print("=" * 55)
    print("  THE EDEN'S SINS — Symlink Race Demo")
    print("  MITRE: T1068 TOCTOU via Symlinks")
    print("=" * 55)
    print()
    print("  Concept:")
    print("  1. Privileged process checks file X exists")
    print("  2. Attacker replaces X with symlink to /etc/target")
    print("  3. Privileged process writes to X (now /etc/target)")
    print()

    with tempfile.TemporaryDirectory(prefix="ct_race_") as tmpd:
        target = os.path.join(tmpd, "legit_file")
        poison = os.path.join(tmpd, "attacker_target")

        # Step 1: Create legitimate file
        Path(target).write_text("legitimate content\n")
        Path(poison).write_text("this should NOT be modified\n")

        print(f"  [1] Created legit file: {target}")
        print(f"  [1] Attacker target:    {poison}")
        print(f"  [1] Legit content: {Path(target).read_text().strip()}")

        # Step 2: Simulate check phase
        print(f"\n  [2] CHECK: File exists? {os.path.exists(target)} ✓")
        print("  [2] Privileged process would now proceed to write...")

        # Step 3: RACE — swap file with symlink
        print("\n  [3] RACE WINDOW: Swapping file with symlink...")
        os.unlink(target)
        os.symlink(poison, target)
        print(f"  [3] {target} → {os.readlink(target)}")

        # Step 4: Simulate write phase (USE)
        print("\n  [4] USE: Privileged process writes to 'checked' path...")
        with open(target, "w") as f:
            f.write("POISONED by attacker!\n")

        # Step 5: Show result
        poisoned = Path(poison).read_text().strip()
        print(f"\n  [5] RESULT: Attacker target now contains: '{poisoned}'")

        if "POISONED" in poisoned:
            print("\n  💀 TOCTOU SUCCESSFUL — file was redirected via symlink!")
        else:
            print("\n  ✅ Race condition did not succeed (timing)")

    print()
    print("  Defense:")
    print("    • Use O_NOFOLLOW when opening files")
    print("    • Use fchmod/fchown instead of chmod/chown (fd-based)")
    print("    • Create files with mkstemp (atomic)")
    print("    • Avoid operating on files in world-writable dirs")
    print("    • Use os.open() with O_CREAT|O_EXCL for atomic creates")
    print()


def scan_targets():
    """Scan for potential TOCTOU targets."""
    print("Scanning for potential TOCTOU targets...\n")
    print("Privileged processes writing to /tmp or world-writable dirs:\n")

    if os.uname().sysname != "Darwin":
        print("  (Documentation mode — run on macOS for live results)")
        print()
        print("  Common macOS TOCTOU targets:")
        print("    • Installer packages (.pkg) with preinstall/postinstall")
        print("    • Privileged helper tools writing to /tmp")
        print("    • Update mechanisms with temp file staging")
        print("    • Print spooler operations")
        print()
        print("  Scan commands on macOS:")
        print("    fs_usage -f filesys | grep '/tmp'")
        print("    dtrace -n 'syscall::open:entry /uid==0/ { trace(copyinstr(arg0)); }'")
        return

    # Check for root processes writing to /tmp
    rc = subprocess.run(
        ["lsof", "+D", "/tmp"],
        capture_output=True, text=True, timeout=10,
    )
    if rc.returncode == 0:
        for line in rc.stdout.splitlines():
            parts = line.split()
            if len(parts) > 2:
                cmd, pid = parts[0], parts[1]
                # Check if PID is root
                ps_out = subprocess.run(
                    ["ps", "-p", pid, "-o", "user="],
                    capture_output=True, text=True,
                ).stdout.strip()
                if ps_out == "root":
                    print(f"  🔴 Root process in /tmp: {cmd} (PID {pid})")


def detect_guide():
    """Blue team detection guidance."""
    print("""
  BLUE TEAM — TOCTOU/Symlink Race Detection
  ══════════════════════════════════════════

  Detection:
    • Monitor symlink creation in /tmp, /var/tmp (ESF file events)
    • Alert on rapid file delete→symlink sequences
    • Track root processes accessing world-writable directories
    • dtrace: syscall::symlink:entry { trace(copyinstr(arg0)); }
    • osquery: SELECT * FROM file WHERE symlink = 1 AND directory = '/tmp'

  Hardening:
    • Use O_NOFOLLOW flag in all privileged file operations
    • Prefer fd-based ops (fchmod, fchown, fstat)
    • Create temp files with mkstemp() or O_CREAT|O_EXCL
    • Set sticky bit on /tmp (default on macOS)
    • Validate file ownership after opening
    • Use dedicated directories with restricted permissions

  macOS-Specific:
    • Installer packages: verify scripts don't use /tmp unsafely
    • Privileged helper tools: audit file operations
    • Endpoint Security Framework can monitor symlink creation
    """)


def main():
    p = argparse.ArgumentParser(description="Symlink Race PoC — The Eden's Sins")
    sp = p.add_subparsers(dest="action")
    sp.add_parser("demo", help="Safe TOCTOU demonstration")
    sp.add_parser("scan", help="Scan for potential targets")
    sp.add_parser("detect", help="Blue team guidance")
    args = p.parse_args()

    if args.action == "demo":
        safe_demo()
    elif args.action == "scan":
        scan_targets()
    elif args.action == "detect":
        detect_guide()
    else:
        p.print_help()


if __name__ == "__main__":
    main()
