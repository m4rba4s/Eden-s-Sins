#!/usr/bin/env python3
"""
Cron/Periodic/At Persistence Scanner — The Eden's Sins
MITRE ATT&CK: T1053.003 Scheduled Task/Job: Cron

Enumerates and manages cron-based persistence on macOS:
- User crontabs
- System crontabs (/etc/crontab, /etc/cron.d/)
- Periodic scripts (/etc/periodic/daily|weekly|monthly)
- at/batch jobs

Usage:
    python3 cron_persist.py scan              # Enumerate all
    python3 cron_persist.py install --cmd "..." --schedule "*/5 * * * *"
    python3 cron_persist.py detect            # Blue team guidance
"""

import argparse, json, os, subprocess, sys
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class CronEntry:
    source: str          # "user_cron", "system_cron", "periodic", "at_job"
    user: str = ""
    schedule: str = ""
    command: str = ""
    file_path: str = ""
    suspicious: bool = False
    risk_notes: list = field(default_factory=list)


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return -1, "", ""


SUSPICIOUS_PATTERNS = [
    "/tmp/", "/var/tmp/", "/Users/Shared/",
    "curl ", "wget ", "nc ", "ncat ",
    "base64", "eval ", "python -c", "bash -c",
    "reverse", "shell", "beacon", ".hidden",
]


def check_suspicious(entry: CronEntry) -> None:
    """Flag suspicious cron entries."""
    cmd_lower = entry.command.lower()
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.lower() in cmd_lower:
            entry.suspicious = True
            entry.risk_notes.append(f"Suspicious pattern: {pattern.strip()}")


def scan_user_crontab() -> list[CronEntry]:
    """Scan current user's crontab."""
    entries = []
    rc, out, _ = _run(["crontab", "-l"])
    if rc != 0 or not out:
        return entries

    user = os.environ.get("USER", "unknown")
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(None, 5)
        if len(parts) >= 6:
            entry = CronEntry(
                source="user_cron",
                user=user,
                schedule=" ".join(parts[:5]),
                command=parts[5],
            )
            check_suspicious(entry)
            entries.append(entry)

    return entries


def scan_system_crontab() -> list[CronEntry]:
    """Scan system-wide crontab and cron.d."""
    entries = []

    for cron_path in ["/etc/crontab", "/etc/cron.d"]:
        p = Path(cron_path)
        if not p.exists():
            continue

        files = [p] if p.is_file() else list(p.glob("*"))
        for f in files:
            if not f.is_file():
                continue
            try:
                for line in f.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(None, 6)
                    if len(parts) >= 7:
                        entry = CronEntry(
                            source="system_cron",
                            user=parts[5],
                            schedule=" ".join(parts[:5]),
                            command=parts[6],
                            file_path=str(f),
                        )
                        check_suspicious(entry)
                        entries.append(entry)
            except PermissionError:
                entries.append(CronEntry(
                    source="system_cron",
                    file_path=str(f),
                    risk_notes=["Permission denied"],
                ))

    return entries


def scan_periodic() -> list[CronEntry]:
    """Scan /etc/periodic scripts."""
    entries = []
    base = Path("/etc/periodic")
    if not base.exists():
        return entries

    for period in ["daily", "weekly", "monthly"]:
        period_dir = base / period
        if not period_dir.exists():
            continue

        for script in sorted(period_dir.iterdir()):
            if not script.is_file():
                continue

            entry = CronEntry(
                source="periodic",
                schedule=period,
                command=script.name,
                file_path=str(script),
            )

            # Check if it's a standard Apple script
            try:
                content = script.read_text(errors="ignore")[:500]
                if "Apple" not in content and "Copyright" not in content:
                    entry.risk_notes.append("Non-Apple periodic script")
                    entry.suspicious = True
            except PermissionError:
                pass

            check_suspicious(entry)
            entries.append(entry)

    return entries


def scan_at_jobs() -> list[CronEntry]:
    """Scan at/batch jobs."""
    entries = []
    rc, out, _ = _run(["atq"])
    if rc != 0 or not out:
        return entries

    for line in out.splitlines():
        parts = line.split()
        if parts:
            entry = CronEntry(
                source="at_job",
                schedule=line,
                command="[use `at -c JOB_ID` to view]",
            )
            entries.append(entry)

    return entries


def install_cron(command: str, schedule: str, dry_run: bool = True) -> bool:
    """Install a cron job for persistence."""
    cron_line = f"{schedule} {command}"

    if dry_run:
        print(f"[DRY] Would add to crontab: {cron_line}")
        return True

    # Get existing crontab
    rc, existing, _ = _run(["crontab", "-l"])
    existing = existing if rc == 0 else ""

    # Append new job
    new_crontab = existing + "\n" + cron_line + "\n"

    proc = subprocess.Popen(
        ["crontab", "-"],
        stdin=subprocess.PIPE, text=True,
    )
    proc.communicate(input=new_crontab)
    return proc.returncode == 0


def format_report(entries: list[CronEntry]) -> str:
    """Format text report."""
    lines = [
        "=" * 60,
        "  THE EDEN'S SINS — Scheduled Tasks Report",
        "=" * 60, "",
    ]

    suspicious_count = sum(1 for e in entries if e.suspicious)
    lines.append(f"  Total entries: {len(entries)}")
    lines.append(f"  Suspicious:    {suspicious_count}")
    lines.append("")

    for source in ["user_cron", "system_cron", "periodic", "at_job"]:
        source_entries = [e for e in entries if e.source == source]
        if not source_entries:
            continue

        icon = {"user_cron": "👤", "system_cron": "🖥️",
                "periodic": "📅", "at_job": "⏰"}.get(source, "📋")
        name = {"user_cron": "User Crontab", "system_cron": "System Crontab",
                "periodic": "Periodic Scripts", "at_job": "At/Batch Jobs"}.get(source, source)

        lines.append(f"  {icon} {name}")
        lines.append("  " + "─" * 54)

        for e in source_entries:
            flag = "🔴" if e.suspicious else "🟢"
            lines.append(f"    {flag} [{e.schedule}] {e.command[:60]}")
            if e.user:
                lines.append(f"        User: {e.user}")
            if e.file_path:
                lines.append(f"        File: {e.file_path}")
            for note in e.risk_notes:
                lines.append(f"        ⚠️  {note}")

        lines.append("")

    lines.extend([
        "─" * 60,
        "  BLUE TEAM — Detection & Hardening",
        "─" * 60, "",
        "  Detection:",
        "    • Monitor crontab -e/-l executions",
        "    • Track file changes in /etc/periodic/",
        "    • Alert on new at/batch job creation",
        "    • ESF: file events on /var/at/jobs/",
        "    • osquery: SELECT * FROM crontab", "",
        "  Hardening:",
        "    • Restrict cron access: /etc/cron.allow",
        "    • Monitor /etc/periodic for unauthorized scripts",
        "    • Disable at daemon if not needed: launchctl unload com.apple.atrun",
        "    • Use launchd instead of cron (Apple recommended)",
        "=" * 60,
    ])

    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="Cron Persist — The Eden's Sins")
    sp = p.add_subparsers(dest="action")

    sp.add_parser("scan", help="Enumerate all scheduled tasks")

    inst = sp.add_parser("install", help="Install cron persistence")
    inst.add_argument("--cmd", required=True, help="Command to execute")
    inst.add_argument("--schedule", default="*/15 * * * *", help="Cron schedule")
    inst.add_argument("--dry-run", action="store_true", default=True)
    inst.add_argument("--live", action="store_true")

    sp.add_parser("detect", help="Blue team guidance")

    args = p.parse_args()

    if args.action == "scan":
        entries = []
        entries.extend(scan_user_crontab())
        entries.extend(scan_system_crontab())
        entries.extend(scan_periodic())
        entries.extend(scan_at_jobs())
        print(format_report(entries))

    elif args.action == "install":
        dry = not args.live
        ok = install_cron(args.cmd, args.schedule, dry_run=dry)
        if ok:
            print(f"[+] Cron job {'previewed' if dry else 'installed'}")
        else:
            print("[-] Failed to install cron job")

    elif args.action == "detect":
        print("  Monitor: crontab -e, /etc/periodic/ changes, atq additions")
        print("  Harden: /etc/cron.allow, disable atrun, use launchd instead")

    else:
        p.print_help()


if __name__ == "__main__":
    main()
