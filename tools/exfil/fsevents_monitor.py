#!/usr/bin/env python3
"""
FSEvents Monitor — The Eden's Sins Phase 5
MITRE ATT&CK: T1083 File and Directory Discovery

Monitors macOS FSEvents to discover file activity patterns.
Useful for identifying high-value files before exfiltration.

Usage:
    python3 fsevents_monitor.py --watch ~/Documents --duration 60
    python3 fsevents_monitor.py --history
    python3 fsevents_monitor.py --detect
"""

import argparse, json, os, subprocess, sys, time
from pathlib import Path
from collections import Counter


def watch_fsevents(path, duration=30):
    """Monitor file changes using fswatch or log stream."""
    print(f"[*] Watching {path} for {duration}s...")
    print("[*] Files accessed during this period:\n")

    # Try fswatch first, fallback to log stream
    try:
        proc = subprocess.Popen(
            ["fswatch", "-r", "--event", "Updated", "--event", "Created",
             "--event", "Removed", path],
            stdout=subprocess.PIPE, text=True,
        )

        end_time = time.time() + duration
        events = Counter()

        while time.time() < end_time:
            line = proc.stdout.readline().strip()
            if line:
                events[line] += 1
                print(f"  📄 {line}")

        proc.terminate()

        print(f"\n[+] Top accessed files:")
        for f, count in events.most_common(20):
            print(f"  {count:3d}x  {f}")

    except FileNotFoundError:
        print("[!] fswatch not installed. Using log stream fallback...")
        print(f"[*] Install: brew install fswatch")
        print()
        print("[*] Alternative: reading FSEvents log from disk...")

        # Parse .fseventsd
        fse_dir = os.path.join(path, ".fseventsd")
        if os.path.isdir(fse_dir):
            print(f"  Found .fseventsd at {fse_dir}")
            for f in sorted(os.listdir(fse_dir))[:10]:
                print(f"    📋 {f}")
        else:
            print("  No .fseventsd directory found")

        # Fallback to log show
        rc = subprocess.run(
            ["log", "show", "--last", f"{duration}s",
             "--predicate", f'eventMessage contains "{path}"',
             "--style", "compact"],
            capture_output=True, text=True, timeout=duration + 10,
        )
        if rc.returncode == 0 and rc.stdout:
            for line in rc.stdout.splitlines()[:20]:
                print(f"  {line[:120]}")


def show_history():
    """Show recent file system activity from FSEvents."""
    print("[*] Recent file system events (from .fseventsd):\n")

    fse_root = "/.fseventsd"
    if os.path.isdir(fse_root):
        entries = sorted(os.listdir(fse_root))
        print(f"  FSEvents logs: {len(entries)} entries")
        for e in entries[-10:]:
            fpath = os.path.join(fse_root, e)
            size = os.path.getsize(fpath) if os.path.isfile(fpath) else 0
            print(f"    {e} ({size} bytes)")
    else:
        print("  [!] /.fseventsd not accessible (need root or FDA)")

    # Also check common hot directories
    hot_dirs = [
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~/Downloads"),
    ]
    print("\n  Recent activity in user directories:")
    for d in hot_dirs:
        if os.path.isdir(d):
            recent = sorted(
                Path(d).rglob("*"),
                key=lambda p: p.stat().st_mtime if p.is_file() else 0,
                reverse=True,
            )[:5]
            print(f"\n  📁 {d}:")
            for f in recent:
                if f.is_file():
                    mtime = time.ctime(f.stat().st_mtime)
                    print(f"    {f.name} (modified: {mtime})")


def detect_guide():
    print("""
  BLUE TEAM — FSEvents Monitoring Detection
  ══════════════════════════════════════════
  Detection:
    • Monitor access to /.fseventsd directory
    • Alert on fswatch/fs_usage execution by non-admin
    • Track Spotlight queries (mdfind) for sensitive patterns
    • ESF: ES_EVENT_TYPE_NOTIFY_OPEN on sensitive directories

  Hardening:
    • Restrict FSEvents log access via TCC (Full Disk Access)
    • Monitor for data staging in /tmp before exfil
    • Use DLP tools to track sensitive file access patterns
    • Enable FileVault to protect data at rest
    """)


def main():
    p = argparse.ArgumentParser(description="FSEvents Monitor — The Eden's Sins")
    p.add_argument("--watch", help="Directory to watch")
    p.add_argument("--duration", type=int, default=30, help="Watch duration (seconds)")
    p.add_argument("--history", action="store_true", help="Show recent FS history")
    p.add_argument("--detect", action="store_true", help="Detection guidance")
    args = p.parse_args()

    if args.detect:
        detect_guide()
    elif args.watch:
        watch_fsevents(args.watch, args.duration)
    elif args.history:
        show_history()
    else:
        p.print_help()


if __name__ == "__main__":
    main()
